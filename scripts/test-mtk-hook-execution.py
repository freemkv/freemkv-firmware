"""Execute original/replacement WH auth-cell blocks using an independent ARM CPU.

Run after building freemkv-fw; requires unicorn==2.1.4 in the test environment.
No drive access. All generated firmware and reports stay in a temporary directory.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
from unicorn import arm_const


def execute(image, site, deny, value, setting, value_register, flag_base=0x02000e40, refusal=None):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(0x02000000, 0x2000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xA0000030)
    registers = [getattr(arm_const, f'UC_ARM_REG_R{i}') for i in range(13)]
    before = [0x76540000 + i * 0x101 for i in range(13)]
    before[value_register] = value
    for register, initial in zip(registers, before):
        cpu.reg_write(register, initial)
    cpu.reg_write(UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(UC_ARM_REG_LR, 0x12345679)
    cpu.mem_write(flag_base+3, bytes([setting]))
    reached = []

    def stop(machine, address, _size, _data):
        if address in (site + 4, deny, refusal):
            reached.append(address)
            machine.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, stop)
    cpu.emu_start(site | 1, 0x200000, count=100)
    assert len(reached) == 1, 'hook did not reach a validated continuation'
    after = [cpu.reg_read(register) for register in registers]
    assert after == before, (value, setting, 'live general register was changed', before, after)
    assert cpu.reg_read(UC_ARM_REG_SP) == 0x03008000, 'unbalanced stack'
    return reached[0], cpu.reg_read(UC_ARM_REG_CPSR) & 0xF0000000



def execute_bd(image, site, unrestricted, retired, media_class):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(0x02000000, 0x2000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xA0000030)
    registers = [getattr(arm_const, f'UC_ARM_REG_R{i}') for i in range(13)]
    before = [0x76540000 + i * 0x101 for i in range(13)]
    before[2] = 0x02001000
    for register, value in zip(registers, before):
        cpu.reg_write(register, value)
    cpu.reg_write(UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(UC_ARM_REG_LR, 0x12345679)
    cpu.mem_write(0x02001007, bytes([media_class]))
    cpu.mem_write(0x02000e43, bytes([unrestricted, retired]))
    reached = []
    def stop(machine, address, _size, _data):
        if address == site + 4:
            reached.append(address)
            machine.emu_stop()
    cpu.hook_add(UC_HOOK_CODE, stop)
    cpu.emu_start(site | 1, 0x200000, count=100)
    assert reached == [site + 4]
    after = [cpu.reg_read(register) for register in registers]
    assert after[0] == media_class
    assert all(after[i] == before[i] for i in range(13) if i not in (0, 3))
    assert cpu.reg_read(UC_ARM_REG_SP) == 0x03008000
    return cpu.reg_read(UC_ARM_REG_CPSR) & 0xF0000000


def execute_boot_arguments(image):
    """Run the actual BU40N boot detour up to/through its native init call."""
    for return_flags in (0, 0xA0000000, 0xF0000000):
        cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        cpu.mem_map(0, 0x200000)
        cpu.mem_write(0, image)
        cpu.mem_map(0x02000000, 0x2000)
        cpu.mem_map(0x03000000, 0x10000)
        stack = 0x03008000
        cpu.reg_write(UC_ARM_REG_CPSR, 0xA0000030)
        before = [0x76540000 + i * 0x101 for i in range(12)]
        for i, value in enumerate(before):
            cpu.reg_write(getattr(arm_const, f'UC_ARM_REG_R{i}'), value)
        cpu.reg_write(UC_ARM_REG_SP, stack)
        cpu.reg_write(UC_ARM_REG_LR, 0x0300F001)
        cpu.mem_write(stack - 64, bytes([0xA5]) * 80)
        reached = []
        result = 0x1234ABCD

        def visit(machine, address, _size, _data):
            if address == 0xA1DD0:
                reached.append('native')
                actual = [machine.reg_read(getattr(arm_const, f'UC_ARM_REG_R{i}')) for i in range(12)]
                assert actual == before, ('boot detour changed native arguments/registers', before, actual)
                assert machine.reg_read(UC_ARM_REG_SP) == stack - 8
                machine.reg_write(arm_const.UC_ARM_REG_R0, result)
                machine.reg_write(UC_ARM_REG_CPSR, return_flags | 0x30)
                machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
            elif address == 0x13D42C:
                reached.append('returned')
                machine.emu_stop()

        cpu.hook_add(UC_HOOK_CODE, visit)
        cpu.emu_start(0x13D429, 0x200000, count=100)
        assert reached == ['native', 'returned'], reached
        assert cpu.reg_read(UC_ARM_REG_SP) == stack
        assert cpu.reg_read(arm_const.UC_ARM_REG_R0) == result
        assert cpu.reg_read(UC_ARM_REG_CPSR) & 0xF0000000 == return_flags
        assert [cpu.reg_read(getattr(arm_const, f'UC_ARM_REG_R{i}')) for i in range(4, 12)] == before[4:]
        assert cpu.mem_read(stack - 64, 40) == bytes([0xA5]) * 40
        assert cpu.mem_read(stack, 16) == bytes([0xA5]) * 16


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fw', required=True, type=Path)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures'
    cases = 0
    for name, expected_site in [('WH16NS58_OEM_1.V9.bin', 0x13aa96),
                                ('BU40N_OEM_1.00.bin', 0x136826)]:
        original_path = fixtures / name
        original = original_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix='freemkv-hook-execution-') as temp:
            output = Path(temp) / 'modified.bin'
            result = subprocess.run([str(args.fw.resolve()), 'modify', str(original_path), str(output), '--json'], capture_output=True, text=True, check=True)
            report = json.loads(result.stdout)
            facts = next(lever['facts'] for lever in report['levers'] if lever['id'] == 'RawRead')
            site = facts['auth_cell_site']
            assert site == expected_site, 'selected the wrong semantic check'
            comparison = int.from_bytes(original[site:site + 2], 'little')
            assert comparison in (0x280c, 0x290c)
            value_register = (comparison >> 8) & 7
            branch = int.from_bytes(original[site + 2:site + 4], 'little')
            assert branch & 0xff00 == 0xd100
            displacement = int.from_bytes(bytes([branch & 255]), 'little', signed=True)
            deny = site + 6 + displacement * 2
            modified = output.read_bytes()
            if name == 'BU40N_OEM_1.00.bin':
                execute_boot_arguments(modified)
                bd_site = facts['bd_site']
                for setting in (0, 1, 255):
                    for retired in (0, 1, 255):
                        for media_class in range(16):
                            old_flags = execute_bd(original, bd_site, setting, retired, media_class)
                            flags = execute_bd(modified, bd_site, setting, retired, media_class)
                            if setting == 0:
                                assert flags & 0x40000000 == 0, (setting, retired, media_class, 'Off must refuse')
                            else:
                                assert flags == old_flags, (setting, retired, media_class, 'retired flag altered native BD decision')
                            cases += 1
            for setting in (0, 1, 255, 2):
                for value in range(16):
                    old_target, old_flags = execute(original, site, deny, value, setting, value_register)
                    target, flags = execute(modified, site, deny, value, setting, value_register)
                    expected = deny if setting == 0 else site + 4 if setting == 1 else old_target
                    assert target == expected, (name, value, setting, hex(target), hex(expected))
                    assert flags == old_flags, (name, value, setting, 'CMP flags were not preserved')
                    cases += 1
    original_path = fixtures / 'BE14NU40_MT1939_JB7_1.01.bin'
    original = original_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix='freemkv-classic-hook-') as temp:
        output = Path(temp) / 'modified.bin'
        result = subprocess.run([str(args.fw.resolve()), 'modify', str(original_path), str(output), '--json'], capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        facts = {key: value for lever in report['levers'] for key, value in lever['facts'].items()}
        site = facts['auth_cell_site']
        assert site == 0x180818
        comparison = int.from_bytes(original[site:site+2], 'little')
        assert comparison == 0x280c
        branch = int.from_bytes(original[site+2:site+4], 'little')
        assert branch & 0xff00 == 0xd100
        deny = site + 6 + int.from_bytes(bytes([branch & 255]), 'little', signed=True)*2
        refusal = facts['auth_cell_native_refusal']
        modified = output.read_bytes()
        for setting in (0, 1, 255):
            for value in range(256):
                old_target, old_flags = execute(original, site, deny, value, setting, 0, facts['flag_base'])
                target, flags = execute(modified, site, deny, value, setting, 0, facts['flag_base'], refusal)
                expected = refusal if setting == 0 and value == 12 else old_target
                assert target == expected, (value, setting, target, expected)
                assert flags == old_flags, (value, setting, 'classic CMP flags changed')
                cases += 1
    print(f'PASS: {cases} modern/classic authentication and BD cases; runtime flag, continuations, registers, SP and CMP flags')


if __name__ == '__main__':
    main()
