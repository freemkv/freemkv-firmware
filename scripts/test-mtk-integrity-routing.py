"""Replay OEM CMAC range selection; crypto is stubbed, not validated here."""
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/cmac-research'
STAGING = 0x04000000
RETURN = 0x0300F000


def replay(entry=0x17C298, mask=1, endpoint=None, crypto_ok=True):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for address, length in ((0, 0x200000), (0x02000000, 0x2000),
                            (0x03000000, 0x10000), (STAGING, 0x200000)):
        cpu.mem_map(address, length)
    for record in json.loads((ROOT / 'sources.json').read_text()):
        if record['file'] not in ('uh12-native-checks.bin', 'uh12-integrity-table.bin'):
            continue
        data = (ROOT / record['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
        cpu.mem_write(record['source_offset'], data)
        if record['file'] == 'uh12-integrity-table.bin':
            cpu.mem_write(STAGING + record['source_offset'], data)
    if endpoint is not None:
        cpu.mem_write(STAGING + 0x10400 + 28 + 8, struct.pack('<I', endpoint))
    cpu.mem_write(0x02000C2C, struct.pack('<I', STAGING))
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, RETURN | 1)
    cpu.reg_write(reg.UC_ARM_REG_R0, mask)
    calls = []

    def visit(machine, address, _size, _data):
        if address == RETURN:
            machine.emu_stop()
        elif address == 0x17C0E0:
            args = tuple(machine.reg_read(r) for r in (
                reg.UC_ARM_REG_R0, reg.UC_ARM_REG_R1, reg.UC_ARM_REG_R2))
            calls.append(tuple(v - STAGING for v in args))
            machine.reg_write(reg.UC_ARM_REG_R0, int(crypto_ok))
            # The caller tests the helper's return flags directly.
            cpsr = machine.reg_read(reg.UC_ARM_REG_CPSR) & ~0xF0000000
            machine.reg_write(reg.UC_ARM_REG_CPSR, cpsr | (0 if crypto_ok else 0x40000000))
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))
        elif not 0x17C27A <= address < 0x17C33A:
            assert address in (0x18032, 0xE9788), hex(address)
            # OEM setup/logging calls do not supply a cryptographic result.
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start(entry | 1, RETURN, count=10000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == RETURN
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
    return calls, cpu.reg_read(reg.UC_ARM_REG_R0)


stock = [(0x11000, 0x15FFF, 0x1040C), (0x17000, 0x1806F, 0x10428),
         (0x18400, 0x18F4CF, 0x10444), (0x105C0, 0x105CF, 0x10460)]
assert replay() == (stock, 1)
extended = stock.copy()
extended[1] = (0x17000, 0x183FF, 0x10428)
assert replay(endpoint=0x183FF) == (extended, 1)
# Critically, this native walker skips this malformed range and returns success.
# A host-side validator must not mistake that for proof of a valid whole image.
assert replay(endpoint=0x200000) == (stock[:1] + stock[2:], 1)
assert replay(crypto_ok=False) == (stock[:1], 0)
assert replay(mask=0) == ([], 1)
assert replay(entry=0x17C27A) == ([(0x1000, 0xFFEF, 0xFFF0)], 1)
assert replay(entry=0x17C27A, crypto_ok=False) == ([(0x1000, 0xFFEF, 0xFFF0)], 0)


def selection(update_boot, boot_ok, application_ok):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_map(0x04002000, 0x1000)
    record = next(r for r in json.loads((ROOT / 'sources.json').read_text())
                  if r['file'] == 'uh12-integrity-selection.bin')
    data = (ROOT / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
    cpu.mem_write(record['source_offset'], data)
    cpu.mem_write(0x04002058, struct.pack('<I', int(update_boot)))
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    called = []
    reached = []

    def visit(machine, address, _size, _data):
        if address in (0xA78DA, 0xA78E4):
            reached.append(address)
            machine.emu_stop()
        elif address in (0x17C27A, 0x17C298):
            called.append(address)
            if address == 0x17C298:
                assert machine.reg_read(reg.UC_ARM_REG_R0) == 1
            machine.reg_write(reg.UC_ARM_REG_R0, int(boot_ok if address == 0x17C27A else application_ok))
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start(0xA78BD, 0x200000, count=100)
    expected_calls = [0x17C27A] if update_boot else []
    if not update_boot or boot_ok:
        expected_calls.append(0x17C298)
    assert called == expected_calls
    assert reached == [0xA78E4 if (not update_boot or boot_ok) and application_ok else 0xA78DA]


for update_boot in (False, True):
    for boot_ok in (False, True):
        for application_ok in (False, True):
            selection(update_boot, boot_ok, application_ok)


PROFILES = (
    ('uh12-integrity-selection.bin', 0xA7930, 0x17C44E, 0xA7946, 0x02000C58, 0x02000C60, 0x02000C64, 7),
    ('wp50-tail.bin', 0x9C9AA, 0x13B522, 0x9C9C0, 0x02000CA4, 0x02000CAC, 0x02000CB0, 7),
    ('bu40-a103-tail.bin', 0x9DC86, 0x13E9D2, 0x9DC9C, 0x02000CA8, 0x02000CB0, 0x02000CB4, 6),
    ('be16-tail.bin', 0x9D89C, 0x140DD6, 0x9D93C, 0x02000C60, 0x02000C68, 0x02000C6C, 7),
)


def programming_arguments(profile, destination, source_offset, length, failed):
    name, entry, target, continuation, destination_cell, source_cell, length_cell, failure_register = profile
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_map(0x02000000, 0x2000)
    record = next(r for r in json.loads((ROOT / 'sources.json').read_text())
                  if r['file'] == name)
    data = (ROOT / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
    cpu.mem_write(record['source_offset'], data)
    for cell, value in ((destination_cell, destination), (source_cell, source_offset),
                        (length_cell, length)):
        cpu.mem_write(cell, struct.pack('<I', value))
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_R4, destination_cell)
    cpu.reg_write(getattr(reg, f'UC_ARM_REG_R{failure_register}'), 0x02000010)
    cpu.mem_write(0x02000010, bytes([int(failed)]))
    calls = []
    reached = []

    def visit(machine, address, _size, _data):
        if address == continuation:
            reached.append('skip')
            machine.emu_stop()
        elif address == target:
            reached.append('program')
            calls.append(tuple(machine.reg_read(r) for r in (
                reg.UC_ARM_REG_R0, reg.UC_ARM_REG_R1,
                reg.UC_ARM_REG_R2, reg.UC_ARM_REG_R3)))
            machine.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start(entry | 1, 0x200000, count=20)
    assert calls == ([] if failed else [(source_offset, destination, length, 3)])
    assert reached == ['skip' if failed else 'program']


for profile in PROFILES:
    for failed in (False, True):
        for values in ((0, 0, 0x200000), (0x10000, 0x10000, 0x1F0000), (0x12000, 0x18000, 0x4000)):
            programming_arguments(profile, *values, failed)
print('PASS: 7 native range/boot, 8 integrity-selection and 24 program/skip argument cases (crypto stubbed)')
