"""Execute prepared G05 candidates and original MT1959 arithmetic on ARM926.

This is numerical and CPU-state evidence only, not hardware or media validation.
The emitted candidate is installed in emulator memory, never in a firmware file.
Requires Python unicorn. Inputs are the scan and conversion-audit JSON receipts.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

STUB = 0x300000
INPUT = 0x03002000
SP = 0x03008000
FLAG = 0x02000e43
VALUES = (0, 1, 9, 10, 11, 19, 20, 21, 99, 100, 101, 32767, 32768,
          50719, 50720, 50729, 50730, 50739, 50740, 65525, 65529, 65530, 65534, 65535)
BASES = ((0, 0), (0x1234, 0x4321), (0xffff, 0x1234), (0x5534, 0x3fd2))
CV = (0, 0x10000000, 0x20000000, 0x30000000)
REGS = [getattr(reg, 'UC_ARM_REG_R%d' % i) for i in range(13)]


def taken_bne(data, at):
    """Follow the source's chain of already-taken BNE instructions."""
    seen = set()
    while True:
        assert at not in seen
        seen.add(at)
        h = int.from_bytes(data[at:at + 2], 'little')
        if h >> 8 != 0xd1:
            return at
        disp = h & 255
        if disp & 128:
            disp -= 256
        at += 4 + 2 * disp
        assert 0 <= at < len(data)


class Machine:
    def __init__(self, data, area, state, contract, candidate=None):
        self.area, self.state, self.contract = area, state, contract
        site = contract['site']
        assert site == area['site'] + 10
        assert data[site:site + 2] == b'\x82\x43'
        assert data[site + 3] == 0xd1
        self.accept = site + 4
        self.reject = taken_bne(data, site + 2)
        self.cpu = c = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for at, size in ((0, 0x400000), (0x01ff0000, 0x40000), (0x03000000, 0x10000)):
            c.mem_map(at, size)
        code = bytearray(data)
        if candidate:
            assert candidate['site'] == site
            original = bytes(candidate['original'])
            assert len(original) == 4 and code[site:site + 4] == original
            assert len(code) <= STUB or all(x in (0, 255) for x in code[STUB:STUB + len(candidate['bytes'])])
            delta = (STUB - site - 4) >> 1
            assert -(1 << 21) <= delta < (1 << 21)
            code[site:site + 4] = struct.pack('<HH', 0xf000 | ((delta >> 11) & 0x7ff), 0xf800 | (delta & 0x7ff))
            if len(code) < STUB:
                code.extend(bytes(STUB - len(code)))
            code[STUB:STUB + len(candidate['bytes'])] = bytes(candidate['bytes'])
        c.mem_write(0, bytes(code))
        c.hook_add(UC_HOOK_CODE, self.step)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.initial = c.context_save()

    def step(self, c, at, size, _):
        self.count += 1
        if self.gate:
            stop = at in (self.accept, self.reject)
        else:
            # This is the native consumer's input-restoration store, after R6
            # has passed through the native normalization sequence.
            stop = (c.reg_read(reg.UC_ARM_REG_CPSR) & 0x20 and
                    bytes(c.mem_read(at, 2)) == b'\x20\x80' and
                    c.reg_read(reg.UC_ARM_REG_R4) == INPUT)
        if stop:
            self.result = (at, tuple(c.reg_read(r) for r in REGS),
                           c.reg_read(reg.UC_ARM_REG_SP), c.reg_read(reg.UC_ARM_REG_LR),
                           c.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000)
            c.emu_stop()

    def write(self, _c, _access, at, size, value, _):
        assert SP - 256 <= at and at + size <= SP + 256, ('non-stack write', hex(at), size, value)

    def run(self, value, base7, base5, state, feature, mode, cv, gate=False):
        c = self.cpu
        c.context_restore(self.initial)
        self.count, self.result, self.gate = 0, None, gate
        c.mem_write(0x01ff0000, bytes(0x40000))
        c.mem_write(SP - 256, bytes(512))
        c.mem_write(self.state, bytes([state]))
        c.mem_write(self.contract['mode'], bytes([mode]))
        c.mem_write(FLAG, bytes([feature]))
        c.mem_write(INPUT, value.to_bytes(2, 'little'))
        for r in REGS:
            c.reg_write(r, 0)
        c.reg_write(reg.UC_ARM_REG_CPSR, 0x30 | cv)
        c.reg_write(reg.UC_ARM_REG_R0, state if gate else value)
        c.reg_write(reg.UC_ARM_REG_R1, self.state)
        c.reg_write(reg.UC_ARM_REG_R2, 0xc8 if gate else 0)
        c.reg_write(reg.UC_ARM_REG_R3, 0x87654321)
        c.reg_write(reg.UC_ARM_REG_R4, INPUT)
        c.reg_write(reg.UC_ARM_REG_R5, base5)
        c.reg_write(reg.UC_ARM_REG_R6, value)
        c.reg_write(reg.UC_ARM_REG_R7, base7)
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        c.reg_write(reg.UC_ARM_REG_LR, 0x12345679)
        c.mem_write(SP, struct.pack('<I', value) * 64)
        c.emu_start((self.contract['site'] if gate else self.area['site']) | 1, 0x400000, count=5000)
        assert self.result is not None, ('did not reach continuation', hex(state), feature, mode, self.count, hex(c.reg_read(reg.UC_ARM_REG_PC)))
        assert self.result[2] == SP
        return self.result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('scan', 'plans', 'hoard', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    plans = {r['sha256']: r['plan'] for r in json.loads(a.plans.read_text())}
    rows, no_candidate, count = [], [], 0
    for source in json.loads(a.scan.read_text())['images']:
        digest = source['sha256']
        plan = plans[digest]
        candidates = [c for c in plan.get('candidates', []) if c['gap'] == 'G05']
        assert len(candidates) <= 1
        if not candidates:
            no_candidate.append(digest)
            continue
        data = (a.hoard / source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        contract = plan['reverse_contract']
        assert contract and any('G05' in s for s in plan['pending'])
        area = next(x for x in source['uhd_code']['areas'] if x['role'] == 'ReverseCalculation')
        state = source['uhd_code']['state_cell']
        native = Machine(data, area, state, contract)
        modified = Machine(data, area, state, contract, candidates[0])
        arithmetic = gates = 0
        for value in VALUES:
            for base7, base5 in BASES:
                for mode in (0, 1, 2, 255):
                    actual = modified.run(value, base7, base5, 0xc7, 1, mode, CV[value % 4])
                    expected = ((base7 - 12 * (value // 10)) if mode == 0 else (base5 - 9 * (value // 10))) & 0xffff
                    assert actual[1][6] == expected, (digest, value, base7, base5, mode, actual, expected)
                    arithmetic += 1
        # Exhaustive byte states for Off/Passthrough and all non-C7 states when
        # enabled. Compare the actual native branch destination, low/high regs,
        # SP and NZCV. BL-based detouring changes live LR; SavedLink validates
        # the enclosing native frame, so LR is not the live return contract here.
        for state_byte in range(256):
            for feature in (0, 1, 255):
                if state_byte == 0xc7 and feature == 1:
                    continue
                for cv in CV:
                    args = (4321, 0x5534, 0x3fd2, state_byte, feature, 2, cv, True)
                    ref = native.run(*args)
                    out = modified.run(*args)
                    assert (out[0], out[1], out[2], out[4]) == (ref[0], ref[1], ref[2], ref[4]), (digest, state_byte, feature, cv, ref, out)
                    gates += 1
        downstream = 0
        for state_byte in (0, 0xc7, 0xc8, 0xcc, 0xff):
            for feature in (0, 1, 255):
                if state_byte == 0xc7 and feature == 1:
                    continue
                for mode in (0, 1, 2, 255):
                    for value in (0, 9, 10, 4321, 65535):
                        args = (value, 0x5534, 0x3fd2, state_byte, feature, mode, CV[value % 4])
                        ref = native.run(*args)
                        out = modified.run(*args)
                        assert (out[0], out[1], out[2], out[4]) == (ref[0], ref[1], ref[2], ref[4]), (digest, args, ref, out)
                        downstream += 1
        rows.append({'sha256': digest, 'helper': {'source_sha256':digest,'gap':'G05','site':candidates[0]['site'],'bytes_sha256':hashlib.sha256(bytes(candidates[0]['bytes'])).hexdigest(),'original_sha256':hashlib.sha256(bytes(candidates[0]['original'])).hexdigest()}, 'arithmetic_cases': arithmetic, 'gate_cases': gates, 'downstream_preservation_cases': downstream,
                     'mode': contract['mode'], 'divide': contract['divide'], 'normalize': contract['normalize']})
        count += arithmetic + gates + downstream
        print('PASS', digest[:12], arithmetic, 'downstream arithmetic,', gates, 'gate cases,', downstream, 'downstream preservation cases', flush=True)
    expected_candidates=sum(any(c['gap']=='G05' for c in plan.get('candidates',[])) for plan in plans.values())
    assert len(rows)==expected_candidates, ('missing G05 candidates',len(rows),expected_candidates)
    assert len(rows)+len(no_candidate)==len(plans)
    unresolved=[h for h in no_candidate if 'G05' in plans[h].get('gaps',[])]
    # An absent candidate for an unresolved gap is explicitly unqualified.
    # Native/no-gap images are inventory accounting, not executions by this suite.
    a.output.write_text(json.dumps({'scope': __doc__, 'cpu': 'ARM926', 'cases': count,'result':'pass',
                                    'plans_sha256':hashlib.sha256(a.plans.read_bytes()).hexdigest(),
                                    'scan_sha256':hashlib.sha256(a.scan.read_bytes()).hexdigest(),
                                    'suite_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                    'helpers':[row['helper'] for row in rows],
                                    'unqualified':unresolved,'native_no_candidate_count':len(no_candidate)-len(unresolved),
                                    'limits':'Native numerical worker and pre-restoration checkpoint; no producer-mode or full installed BIN/QA qualification.',
                                    'candidate_images': rows, 'without_candidate': no_candidate}, indent=2) + '\n')
    print('PASS:', count, 'cases across', len(rows), 'candidate images;', len(no_candidate), 'without candidate')


if __name__ == '__main__':
    main()
