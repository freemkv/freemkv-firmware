"""Exercise source-bound G01 density detours on ARM926, without flashing.

The gate tests all state bytes and reachable NZCV combinations against the
original displaced instructions. The downstream tests run the source worker
from its detour through the source consumer and hardware writes. The measured
value is explicitly supplied at the measurement routine boundary; arithmetic
MMIO is modeled in software. This is not physical drive or media validation.
Requires Python packages unicorn and capstone.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ)
from unicorn import arm_const as reg

STUB = 0x300000  # ADR blob requires a four-byte-aligned stub base.
SP = 0x03008000
FLAG = 0x02000e43
HIGH = (1860, 2547, 3745, 4869)
NORMAL = (2100, 3400, 5000, 6500)
REGS = tuple(getattr(reg, 'UC_ARM_REG_R%d' % i) for i in range(13))
FLAGS = tuple(nz | cv for nz in (0, 0x40000000, 0x80000000)
              for cv in (0, 0x10000000, 0x20000000, 0x30000000))


class Machine:
    def __init__(self, data, contract, candidate=None):
        self.contract = d = contract
        self.patched = candidate is not None
        self.stop = d['continuation']
        self.consumer_end = d['call_site'] + 4
        assert STUB % 4 == 0 and d['continuation'] == d['site'] + 4
        code = bytearray(data)
        if candidate:
            assert candidate['site'] == d['site'] and len(candidate['original']) == 4
            assert code[d['site']:d['site'] + 4] == bytes(candidate['original'])
            assert len(code) <= STUB
            delta = (STUB - d['site'] - 4) >> 1
            assert -(1 << 21) <= delta < (1 << 21)
            code[d['site']:d['site'] + 4] = struct.pack('<HH', 0xf000 | ((delta >> 11) & 0x7ff), 0xf800 | (delta & 0x7ff))
            code.extend(bytes(STUB - len(code)))
            code.extend(bytes(candidate['bytes']))
        self.cpu = c = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for addr, size in ((0, 0x400000), (0x01ff0000, 0x40000),
                           (0x03000000, 0x10000), (0x04000000, 0x300000)):
            c.mem_map(addr, size)
        c.mem_write(0, bytes(code))
        # Source logging helper: its inputs and result do not set the target;
        # intercept just as the external measurement input is intercepted.
        dis = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        insn = list(dis.disasm(data[d['consumer'] + 0xbe:d['consumer'] + 0xc2], d['consumer'] + 0xbe))
        assert len(insn) == 1 and insn[0].mnemonic == 'bl'
        self.log_helper = int(insn[0].op_str.lstrip('#'), 0)
        self.initial = c.context_save()
        c.hook_add(UC_HOOK_CODE, self.step)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)
        c.hook_add(UC_HOOK_MEM_READ, self.read)

    def step(self, c, at, _size, _):
        if self.downstream and at in (self.contract['measurement'], self.log_helper):
            c.reg_write(reg.UC_ARM_REG_R0, self.measured if at == self.contract['measurement'] else 0)
            c.reg_write(reg.UC_ARM_REG_PC, c.reg_read(reg.UC_ARM_REG_LR))
        if at == (self.consumer_end if self.downstream else self.stop):
            self.result = (tuple(c.reg_read(r) for r in REGS), c.reg_read(reg.UC_ARM_REG_SP),
                           c.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000)
            c.emu_stop()

    def write(self, c, _access, addr, size, value, _):
        if self.downstream:
            if 0x04200000 <= addr < 0x04300000:
                self.writes.append((addr, size, value))
            if addr == 0x04042018:
                self.math = (value, int.from_bytes(c.mem_read(0x04042010, 4), 'little'),
                             int.from_bytes(c.mem_read(0x04042014, 4), 'little'))
        else:
            assert SP - 128 <= addr and addr + size <= SP + 128, ('unexpected gate write', hex(addr))

    def read(self, c, _access, addr, _size, _value, _):
        if self.downstream and addr == 0x04042018 and self.math:
            op, x, y = self.math
            assert op in (1, 2) and (op != 2 or y), ('unexpected arithmetic MMIO', self.math)
            value = x * y if op == 1 else x // y
            c.mem_write(0x04042010, (value & 0xffffffff).to_bytes(4, 'little'))
            c.mem_write(0x04042018, bytes(4))

    def run(self, state, feature, index, flags, downstream=False, measured=2547):
        c = self.cpu
        c.context_restore(self.initial)
        self.downstream, self.measured, self.result, self.math, self.writes = downstream, measured, None, None, []
        if downstream:
            c.mem_write(0x01ff0000, bytes(0x40000))
            c.mem_write(0x04000000, bytes(0x300000))
            c.mem_write(SP - 256, bytes(512))
            c.mem_write(self.contract['packed_mode'], b'\x02')
        c.mem_write(self.contract['state'], bytes([state]))
        c.mem_write(FLAG, bytes([feature]))
        c.reg_write(reg.UC_ARM_REG_CPSR, 0x30 | flags)
        for i, r in enumerate(REGS):
            c.reg_write(r, 0x1000 + i)
        c.reg_write(reg.UC_ARM_REG_R6, index * 2)
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        c.reg_write(reg.UC_ARM_REG_LR, 0x200001)
        c.emu_start(self.contract['site'] | 1, 0x400000, count=100000 if downstream else 2000)
        assert self.result, ('continuation not reached', state, feature, index, flags, downstream, hex(c.reg_read(reg.UC_ARM_REG_PC)))
        assert self.result[1] == SP
        return self.result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('scan', 'plans', 'hoard', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    plans = {r['sha256']: r['plan'] for r in json.loads(a.plans.read_text())}
    rows, no_candidate, total = [], [], 0
    for source in json.loads(a.scan.read_text())['images']:
        digest = source['sha256']
        plan = plans[digest]
        d = plan.get('density_contract')
        candidates = [c for c in plan.get('candidates', []) if d and c['gap'] == 'G01' and c['site'] == d['site']]
        assert len(candidates) <= 1
        if not candidates:
            no_candidate.append(digest)
            continue
        data = (a.hoard / source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        assert tuple(struct.unpack_from('<4H', data, d['normal_table'])) == NORMAL
        native, patched = Machine(data, d), Machine(data, d, candidates[0])
        gate_cases = downstream_cases = 0
        for state in range(256):
            for feature in (0, 1, 255):
                for flags in FLAGS:
                    index = (state + feature + (flags >> 28)) % 4
                    ref = native.run(state, feature, index, flags)
                    out = patched.run(state, feature, index, flags)
                    chosen = HIGH if feature == 1 and 0xc7 <= state <= 0xcb else NORMAL
                    if d['lookup_displaced']:
                        value = out[0][0]
                    else:
                        value = int.from_bytes(patched.cpu.mem_read(out[0][0] + index * 2, 2), 'little')
                    assert value == chosen[index], (digest, state, feature, flags, index, value, chosen)
                    # LR is excluded because the detour uses BL. The source
                    # analyzer independently establishes a saved-LR frame.
                    assert out[0][1:] == ref[0][1:] and out[1:] == ref[1:], (digest, state, feature, flags, ref, out)
                    gate_cases += 1
        for state in (0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc):
            for feature in (0, 1, 255):
                for index in range(4):
                    for measured in (1860, 2547, 3400, 6500):
                        out = patched.run(state, feature, index, 0, True, measured)
                        selected = HIGH if feature == 1 and 0xc7 <= state <= 0xcb else NORMAL
                        target = int.from_bytes(patched.cpu.mem_read(d['target_cell'], 2), 'little')
                        assert target == selected[index] and patched.writes, (digest, state, feature, index, measured, target, patched.writes)
                        if feature != 1 or not 0xc7 <= state <= 0xcb:
                            actual_writes = patched.writes[:]
                            ref = native.run(state, feature, index, 0, True, measured)
                            assert out == ref and actual_writes == native.writes, (digest, state, feature, index, measured)
                        downstream_cases += 1
        helper = {'source_sha256': digest, 'gap': 'G01', 'site': d['site'],
                  'bytes_sha256': hashlib.sha256(bytes(candidates[0]['bytes'])).hexdigest(),
                  'original_sha256': hashlib.sha256(bytes(candidates[0]['original'])).hexdigest()}
        rows.append({'sha256': digest, 'helper': helper, 'site': d['site'], 'lookup_displaced': d['lookup_displaced'],
                     'gate_cases': gate_cases, 'downstream_cases': downstream_cases})
        total += gate_cases + downstream_cases
        print('PASS', digest[:12], gate_cases, 'gate cases,', downstream_cases, 'downstream cases', flush=True)
    expected = sum(sum(1 for c in plan.get('candidates', []) if plan.get('density_contract') and c['gap'] == 'G01' and c['site'] == plan['density_contract']['site']) for plan in plans.values())
    assert len(rows) == expected, ('missing density candidates', len(rows), expected)
    assert len(rows) + len(no_candidate) == len(plans)
    unresolved = [h for h in no_candidate if 'G01' in plans[h].get('gaps', [])]
    a.output.write_text(json.dumps({'scope': __doc__, 'cpu': 'ARM926', 'cases': total, 'result': 'pass',
                                    'plans_sha256': hashlib.sha256(a.plans.read_bytes()).hexdigest(),
                                    'scan_sha256': hashlib.sha256(a.scan.read_bytes()).hexdigest(),
                                    'suite_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                    'helpers': [row['helper'] for row in rows], 'unqualified': unresolved,
                                    'native_no_candidate_count': len(no_candidate) - len(unresolved),
                                    'limits': 'Worker segment through native consumer; measurement and arithmetic MMIO are modeled. No installed BIN, optical drive, or physical media qualification.',
                                    'candidate_images': rows, 'without_candidate': no_candidate}, indent=2) + '\n')
    print('PASS:', total, 'cases across', len(rows), 'candidate images;', len(no_candidate), 'without candidate')


if __name__ == '__main__':
    main()
