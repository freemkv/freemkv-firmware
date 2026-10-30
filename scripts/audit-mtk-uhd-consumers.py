"""Execute matched MT1959 media-state consumers on ARM926 without hardware.

This checks selector outputs and calculation admission only. ControlField's
incoming R1 points to a supplied passive register bank; no caller/optical state
is fabricated as successful. Calculation workers are not run. Parameter tables
remain each image's own bytes. MMIO is passive memory, not a laser simulation.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

BANK = 0x04200000
INPUT = 0x03002000
STATES = (0x00, 0x40, 0x80, 0xc0, 0xc4, 0xc7, 0xc8, 0xcc)
ROLES = ('ControlBit', 'ControlField', 'ForwardCalculation', 'ReverseCalculation', 'ParameterNibble')


class Runner:
    def __init__(self, data, area, state_cell):
        self.data, self.area, self.state_cell = data, area, state_cell
        self.cpu = c = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for at, size in ((0, (len(data)+4095)&~4095), (0x01ff0000, 0x40000),
                         (0x03000000, 0x10000), (BANK, 0x20000)):
            c.mem_map(at, size)
        c.mem_write(0, data)
        self.decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        c.hook_add(UC_HOOK_CODE, self.code)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def stop(self, **result):
        self.result.update(result)
        self.cpu.emu_stop()

    def code(self, c, at, size, _user):
        self.trace.append(at)
        if not self.area['site']-1024 <= at <= self.area['site']+4096:
            self.stop(status='unhandled_exit', exit=at)
            return
        op = int.from_bytes(c.mem_read(at, 2), 'little')
        if op & 0xf800 == 0xf000:
            ins = next(self.decoder.disasm(bytes(c.mem_read(at, 4)), at, count=1))
            if ins.mnemonic in ('bl', 'blx'):
                self.stop(status='worker_call', site=at, target=int(ins.op_str.removeprefix('#'), 0),
                          arguments=[c.reg_read(getattr(reg, f'UC_ARM_REG_R{i}')) for i in range(2)])

    def write(self, c, _access, at, size, value, _user):
        if BANK <= at < BANK+0x20000:
            self.stop(status='register_write', site=c.reg_read(reg.UC_ARM_REG_PC), address=at, size=size, value=value)
        elif at == INPUT and size == 2:
            self.stop(status='restoration_path_without_worker', site=c.reg_read(reg.UC_ARM_REG_PC), value=value)

    def run(self, state, word=0xa5a5a5a5, flag=0, index=0):
        c = self.cpu
        # Each run starts from independent supplied register/memory inputs.
        c.mem_write(BANK, struct.pack('<I', word)*0x8000)
        c.mem_write(0x01ff0000, bytes(0x40000))
        c.mem_write(0x03000000, bytes(0x10000))
        c.mem_write(self.state_cell, bytes([state]))
        for literal in self.area['literals']:
            at = literal['value']
            if 0x01ff0000 <= at < 0x02010000 and at != self.state_cell:
                c.mem_write(at, bytes([flag]))
        for i in range(13):
            c.reg_write(getattr(reg, f'UC_ARM_REG_R{i}'), 0)
        c.reg_write(reg.UC_ARM_REG_R0, index << 4)
        c.reg_write(reg.UC_ARM_REG_R1, BANK)
        c.reg_write(reg.UC_ARM_REG_R4, INPUT)
        c.reg_write(reg.UC_ARM_REG_R6, 0x12340000)
        c.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        c.mem_write(INPUT, b'\x34\x12')
        # The isolated region is entered after the native prologue. Supply the
        # known original input to its saved stack slots; no caller is executed.
        c.mem_write(0x03008000, b'\x34\x12\x00\x00' * 64)
        self.result, self.trace = {'status': 'instruction_limit'}, []
        c.emu_start(self.area['site'] | 1, 0x200000, count=256)
        self.result['trace'] = self.trace
        return self.result.copy()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--hoard', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    rows, executions = [], 0
    for row in json.loads(a.scan.read_text())['images']:
        data = (a.hoard/row['path']).read_bytes()
        assert len(data) == 2097152 and hashlib.sha256(data).hexdigest() == row['sha256']
        results = []
        for area in row['uhd_code']['areas']:
            if area['role'] not in ROLES or area['evidence'] == 'unknown':
                continue
            run = Runner(data, area, row['uhd_code']['state_cell'])
            cases = []
            if area['role'] == 'ParameterNibble':
                for state in (0xc0, 0xc7, 0xc8, 0xcc):
                    for flag in (0, 32):
                        for word in (0, 0xa5a5a5a5):
                            observations = [run.run(state, word, flag, index) for index in range(13)]
                            executions += 13
                            assert all(x['status'] == 'register_write' and x['size'] == 4 for x in observations), (row['sha256'], area, observations)
                            cases.append({'state': state, 'flag': flag, 'initial_word': word,
                                'outputs_by_index_0_to_12': [o['value'] for o in observations],
                                'write_sites': sorted({o['site'] for o in observations}),
                                'write_addresses': sorted({o['address'] for o in observations})})
            else:
                for state in STATES:
                    for word in (0, 0xa5a5a5a5):
                        result = run.run(state, word)
                        executions += 1
                        assert result['status'] not in ('instruction_limit', 'unhandled_exit'), (row['sha256'], area, result)
                        cases.append({'state': state, 'initial_word': word, **result})
            results.append({'role': area['role'], 'variant': area['variant'], 'site': area['site'], 'cases': cases})
        rows.append({'sha256': row['sha256'], 'roles': results})
    a.output.write_text('{"scope":'+json.dumps(__doc__)+',"executions":'+str(executions)+',"images":[\n'+',\n'.join(json.dumps(r,separators=(',',':')) for r in rows)+'\n]}\n')
    print(f'PASS: {executions} consumer-region executions across {len(rows)} full payloads')


if __name__ == '__main__':
    main()
