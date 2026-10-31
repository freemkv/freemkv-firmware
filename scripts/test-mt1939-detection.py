"""Execute the installed detection-only experiment on ARM926.

Hardware acquisition helpers are simulated, explicitly. The actual installed
branch, recognition stub, native format switch, layer math and return execute.
This validates a hardware test candidate, not physical disc detection.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

OEM_HASH = '43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3'
DONE = 0x1fe000
REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
HELPERS = {0xf5ce0, 0x4ade8, 0x4adec, 0xb9ff2, 0x4d3a4, 0xf6b3c, 0xabb52}


def machine(data, evidence):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base, size in ((0, 0x200000), (0x01ff0000, 0x20000),
                       (0x03000000, 0x10000), (0x04200000, 0x10000)):
        cpu.mem_map(base, size)
    cpu.mem_write(0, data)
    trace = []

    def visit(c, at, size, _user):
        if at == DONE:
            c.emu_stop()
            return
        if size != 4:
            return
        first, second = struct.unpack('<HH', c.mem_read(at, 4))
        if first & 0xf800 != 0xf000 or second & 0xf800 != 0xf800:
            return
        offset = ((first & 2047) << 12) | ((second & 2047) << 1)
        if offset & 0x400000:
            offset -= 0x800000
        target = at + 4 + offset
        if target in HELPERS:
            trace.append(target)
            if target in (0x4ade8, 0xb9ff2):
                c.reg_write(reg.UC_ARM_REG_R0, 0)
            c.reg_write(reg.UC_ARM_REG_LR, (at + 4) | 1)
            c.reg_write(reg.UC_ARM_REG_PC, (at + 4) | 1)

    cpu.hook_add(UC_HOOK_CODE, visit)
    return cpu, trace


def execute(machine_state, evidence, identifier, fmt, layers, attributes,
            initial, flag, ready=True, abort=False, nzcv=0):
    cpu, trace = machine_state
    trace.clear()
    cpu.mem_write(0x01ff0000, bytes(0x20000))
    cpu.mem_write(0x03000000, bytes(0x10000))
    cpu.mem_write(evidence['state'], bytes([initial]))
    cpu.mem_write(evidence['flag_base'] + 3, bytes([flag]))
    cpu.mem_write(0x02000b14, bytes([2 if ready else 0]))
    cpu.mem_write(0x01ffafc6, bytes([int(abort)]))
    cpu.mem_write(0x02000df0, struct.pack('<I', 0x02004000))
    cpu.mem_write(0x02004008, b'BD' + bytes([identifier, attributes, layers << 4, fmt]))
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30 | (nzcv << 28))
    for index, register in enumerate(REGISTERS):
        cpu.reg_write(register, 0x12000000 + index * 0x101)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, DONE | 1)
    saved = [cpu.reg_read(r) for r in REGISTERS[4:8]]
    cpu.emu_start(evidence['entry'] | 1, DONE, count=10000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == DONE
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
    assert [cpu.reg_read(r) for r in REGISTERS[4:8]] == saved
    return (cpu.reg_read(reg.UC_ARM_REG_R0),
            cpu.mem_read(evidence['state'], 1)[0],
            cpu.mem_read(evidence['format_flag'], 1)[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    original, candidate = args.original.read_bytes(), args.candidate.read_bytes()
    evidence = json.loads(args.receipt.read_text())
    digest = lambda data: hashlib.sha256(data).hexdigest()
    assert digest(original) == evidence['source_sha256'] == OEM_HASH
    assert digest(candidate) == evidence['output_sha256']
    assert candidate[evidence['stub_va']:evidence['stub_va'] + len(evidence['stub'])] == bytes(evidence['stub'])
    machines = [machine(data, evidence) for data in (original, candidate)]
    cases = preservation = recognition = 0
    for identifier in b'ORWU?':
        for fmt in (0, 1, 2, 5, 255):
            for layers in (1, 2, 3, 4):
                for attributes in (0, 0x10, 0x20, 0x30):
                    for flag in (0, 1, 2, 255):
                        for nzcv in (0, 3, 8, 15):
                            inputs = (identifier, fmt, layers, attributes, 0xc0, flag)
                            native = execute(machines[0], evidence, *inputs, nzcv=nzcv)
                            actual = execute(machines[1], evidence, *inputs, nzcv=nzcv)
                            allowed_attributes = (0,) if evidence.get('bu40n_attribute_validation') else (0, 0x30)
                            accept = (identifier == ord('U') and flag == 1
                                      and attributes in allowed_attributes
                                      and (fmt == 1 or (fmt == 5 and layers in (2, 3))))
                            if accept:
                                state = ((0xc0 & 0xf3) + (layers - 1) * 4) if fmt == 1 else {2: 0xc7, 3: 0xc8}[layers]
                                assert actual == (0, state, 2 if fmt == 1 else 32), (inputs, actual)
                                recognition += 1
                            else:
                                assert actual == native, (inputs, native, actual)
                                preservation += 1
                            cases += 1
    boundary = []
    for initial in (0xc0, 0xc7, 0xc8, 0xf0):
        for ready, abort in ((False, False), (True, True)):
            inputs = (ord('U'), 5, 2, 0, initial, 1)
            results = [execute(cpu, evidence, *inputs, ready=ready, abort=abort)
                       for cpu in machines]
            assert results[0] == results[1]
            assert results[1][0] == (11 if abort else 3)
            boundary.append({'initial': initial, 'di_ready': ready, 'abort': abort,
                             'return_status': results[1][0]})
    result = {'policy': __doc__, 'source_sha256': digest(original),
              'candidate_sha256': digest(candidate), 'cpu': 'ARM926',
              'cases': cases, 'recognized_cases': recognition,
              'oem_preservation_cases': preservation, 'early_boundaries': boundary}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: {cases} complete installed-parser cases; {recognition} recognition; '
          f'{preservation} OEM preservation; {len(boundary)} early-failure boundaries')


if __name__ == '__main__':
    main()
