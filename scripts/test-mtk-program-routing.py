"""Replay native programming selection and staging copy; no physical flash claim."""
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/cmac-research'


def machine():
    record = next(r for r in json.loads((ROOT / 'sources.json').read_text())
                  if r['file'] == 'uh12-program.bin')
    data = (ROOT / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for address, length in ((0, 0x200000), (0x01FF0000, 0x10000),
                            (0x02000000, 0x2000), (0x03000000, 0x10000),
                            (0x04000000, 0x20000), (0x06000000, 0x200000)):
        cpu.mem_map(address, length)
    cpu.mem_write(record['source_offset'], data)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    return cpu


def programming(start):
    cpu = machine()
    for cell, value in ((0x02000C58, start), (0x02000C60, start),
                        (0x02000C64, 0x200000 - start)):
        cpu.mem_write(cell, struct.pack('<I', value))
    calls = []

    def visit(machine, address, _size, _data):
        if address == 0x17284:
            machine.emu_stop()
        elif address == 0x17406:
            calls.append(tuple(machine.reg_read(r) for r in (
                reg.UC_ARM_REG_R0, reg.UC_ARM_REG_R1, reg.UC_ARM_REG_R2)))
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))
        elif not 0x17000 <= address < 0x17368:
            assert address in (0x173C4, 0x17DBA, 0x175FE), hex(address)
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    def ready(machine, _access, address, _size, _value, _data):
        # Emulate ready hardware status; execute the original erase/poll code.
        if address in (0x04011088, 0x04011010):
            machine.mem_write(address, struct.pack('<I', 1 if address == 0x04011088 else 2))
        elif address == 0x02001001:
            machine.mem_write(address, b'\0')

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.hook_add(UC_HOOK_MEM_READ, ready)
    cpu.emu_start(0x17001, 0x17338, count=100000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x17284
    assert struct.unpack('<I', cpu.mem_read(0x02000C64, 4))[0] == 0
    expected = [(at, at, 0x10000) for at in range(start, 0x1D0000, 0x10000)]
    expected += [(at, at, 0x1000) for at in range(0x1EC000, 0x1F0000, 0x1000)]
    assert calls == expected, calls
    return len(calls)


def staging_copy(offset):
    cpu = machine()
    payload = bytes((i * 37 + 19) & 255 for i in range(256))
    cpu.mem_write(0x06000000 + offset, payload)
    cpu.mem_write(0x02000C2C, struct.pack('<I', 0x06000000))
    for r, value in ((reg.UC_ARM_REG_R0, offset), (reg.UC_ARM_REG_R1, offset),
                     (reg.UC_ARM_REG_R2, 256)):
        cpu.reg_write(r, value)

    def visit(machine, address, _size, _data):
        if address == 0x17478:
            machine.emu_stop()
        elif address == 0x173C4:
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start(0x17407, 0x175FC, count=10000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x17478
    assert bytes(cpu.mem_read(0x02001004, 256)) == payload


counts = [programming(start) for start in (0, 0x10000)]
for offset in (0x18000, 0x18100, 0x18200, 0x18300):
    staging_copy(offset)
print(f'PASS: OEM programming calls {counts}, preserved skips, and 4 raw staging-page copies; hardware ready/helper completion simulated')
