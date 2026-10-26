"""Execute emitted CDB reset paths with an independent ARM CPU (unicorn 2.1.4)."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn import arm_const as reg


def literal(image, site):
    opcode = struct.unpack_from('<H', image, site)[0]
    assert opcode & 0xF800 == 0x4800
    address = ((site + 4) & ~3) + (opcode & 255) * 4
    return struct.unpack_from('<I', image, address)[0]


def run(image, handler, length, mode, saved, defaults):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(0x02000000, 0x2000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, 0x0300F001)
    preserved = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(4, 12)]
    for i, register in enumerate(preserved):
        cpu.reg_write(register, 0x12340000 + i)
    cdb = literal(image, handler)
    request = bytes([0x3C, 0x0E, 0xC0, 0xDE, 4, 0, mode, 0, 0, 0, 0, 0])
    cpu.mem_write(cdb, request)
    cpu.mem_write(0x02000E40, bytes([0x77] * 7))
    writes, commits, nv_reads = [], [], []

    def read(machine, _access, address, _size, _value, _data):
        if 0x1E8000 <= address < 0x1EC000 and not nv_reads:
            nv_reads.append(address)
            machine.mem_write(address, bytes([255] * 7) if saved is None else bytes(saved))

    def code(machine, address, _size, _data):
        if address == 0x0300F000:
            machine.emu_stop()
        elif not handler <= address < handler + length:
            a, b = machine.reg_read(reg.UC_ARM_REG_R0), machine.reg_read(reg.UC_ARM_REG_R1)
            if a < 64:
                assert b <= 255
                writes.append((a, b))
            else:
                commits.append(address)
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.hook_add(UC_HOOK_MEM_READ, read)
    cpu.emu_start(handler | 1, 0x0300F000, count=10000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x0300F000, 'handler did not return'
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
    assert [cpu.reg_read(r) for r in preserved] == [0x12340000 + i for i in range(8)]
    assert writes == [(i, 0) for i in range(64)], 'reset reply was not cleared exactly'
    assert len(commits) == 1, 'reset did not commit one reply'
    expected = bytes(defaults)
    if mode != 1 and saved is not None:
        expected = bytes([0x77, *saved[1:]])  # reload preserves the live marker
    assert bytes(cpu.mem_read(0x02000E40, 7)) == expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fw', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/WH16NS58_OEM_1.V9.bin'
    cases = 0
    configurations = [([], [255, 255, 255, 1, 1, 255, 255]),
                      (['--default', 'unrestricted=oem', '--default', 'hrl=off', '--default', 'speed=uncapped'],
                       [255, 1, 255, 255, 255, 0, 255])]
    with tempfile.TemporaryDirectory(prefix='freemkv-runtime-execution-') as directory:
        facts = None
        input_path = source
        for assignments, defaults in configurations:
            output = Path(directory) / f'modified-{cases}.bin'
            result = subprocess.run([str(args.fw.resolve()), 'modify', str(input_path), str(output), '--json', *assignments], capture_output=True, text=True, check=True)
            report = json.loads(result.stdout)
            if facts is None:
                facts = next(l['facts'] for l in report['levers'] if l['id'] == 'Identity')
            input_path = output
            image = output.read_bytes()
            for mode, saved in [(1, None), (0, None), (2, None), (0, [0, 0, 1, 255, 0, 1, 255])]:
                run(image, facts['handler_va'], facts['handler_len'], mode, saved, defaults)
                cases += 1
    print(f'PASS: {cases} CDB reset defaults, erased-NV fallback, unknown-mode fallback, saved reload; reply, return and preserved registers')


if __name__ == '__main__':
    main()
