"""Execute emitted conversion components; never writes a firmware output.

The normal Modify routing stubs are tested at native instruction regions, through
native arithmetic and saved parent returns. This does not establish correctness
of other consumers or prove physical UHD reading.
"""
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
STUB = 0x1ff000


def machine(data):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, data)
    cpu.mem_map(0x01ff0000, 0x20000)
    cpu.mem_map(0x04200000, 0x10000)
    cpu.mem_map(0x04040000, 0x10000)
    cpu.mem_map(0x04080000, 0x10000)
    cpu.mem_map(0x040b0000, 0x10000)
    cpu.mem_map(0x03000000, 0x10000)
    return cpu


def setup(cpu, state_cell, flags, state, flag, cv):
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30 | (cv << 28))
    for n, register in enumerate(REGISTERS):
        cpu.reg_write(register, 0x10000 + n * 0x111)
    cpu.reg_write(reg.UC_ARM_REG_R1, 0x0420b180)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, 0x12345)
    cpu.mem_write(state_cell, bytes([state]))
    cpu.mem_write(flags + 3, bytes([flag]))
    cpu.mem_write(0x0420903c, struct.pack('<I', 0x12345678))
    cpu.mem_write(0x0420b1b0, struct.pack('<I', 0x89abcdef))


def routing(data, evidence, states):
    count = 0
    for candidate in evidence['candidates']:
        native, patched = machine(data), machine(data)
        patched.mem_write(STUB, bytes(candidate['stub']))
        # Actual Thumb BL; this loop checks scratch/flag/branch behavior.
        # Separate library CFG and parent-return tests cover local LR lifetime.
        site = candidate['site']
        delta = (STUB - site - 4) & 0xffffffff
        signed = delta if delta < 0x80000000 else delta - 0x100000000
        first = 0xf000 | ((signed >> 12) & 0x7ff)
        second = 0xf800 | ((signed >> 1) & 0x7ff)
        patched.mem_write(site, struct.pack('<HH', first, second))
        if len(candidate['original']) == 6:
            patched.mem_write(site + 4, b'\xc0\x46')
        reached = [None, None]
        stops = {candidate['accept']: True, candidate['reject']: False}
        if candidate.get('bypass') is not None:
            stops[candidate['bypass']] = 'bypass'

        def visit(index):
            def hook(cpu, address, _size, _user):
                if address in stops:
                    reached[index] = stops[address]
                    cpu.emu_stop()
            return hook

        native.hook_add(UC_HOOK_CODE, visit(0))
        patched.hook_add(UC_HOOK_CODE, visit(1))
        for state in states:
            for flag in (0, 1, 2, 255):
                for cv in (0, 1, 2, 3):
                    reached[:] = [None, None]
                    for cpu in (native, patched):
                        setup(cpu, evidence['state'], evidence['flag_base'], state, flag, cv)
                        if candidate['area'] in ('PositionSetupInput','PositionSetupCommand'):
                            cpu.reg_write(reg.UC_ARM_REG_R6,evidence['state'])
                            cpu.reg_write(reg.UC_ARM_REG_R7,0xc8)
                        if candidate['area'] in ('ControllerTiming','ControllerMode'):
                            cpu.reg_write(reg.UC_ARM_REG_R2,0x04208240)
                        if candidate['area'] == 'ReadControl':
                            cpu.reg_write(reg.UC_ARM_REG_R0,0x042080c0)
                        if candidate['area'] in ('ReadUpperRange','ReadLowerRange'):
                            cpu.reg_write(reg.UC_ARM_REG_R6,evidence['state'])
                            cpu.reg_write(reg.UC_ARM_REG_R2,0xc8)
                        if candidate['area'] == 'PositionOutput':
                            cpu.reg_write(reg.UC_ARM_REG_R6,evidence['state'])
                            cpu.reg_write(reg.UC_ARM_REG_R7,0xc8)
                        if candidate['area'] == 'ParameterTable':
                            cpu.reg_write(reg.UC_ARM_REG_R0,0)
                        try:
                            cpu.emu_start(candidate['region_start'] | 1, 0x200000, count=250)
                        except Exception as error:
                            raise AssertionError((candidate['area'], state, flag, cv, hex(cpu.reg_read(reg.UC_ARM_REG_PC)))) from error
                    assert reached[0] is not None and reached[1] is not None, candidate
                    expected = True if state == 0xc7 and flag == 1 else reached[0]
                    assert reached[1] == expected, (candidate['area'], state, flag, cv, reached)
                    assert [native.reg_read(r) for r in REGISTERS] == [patched.reg_read(r) for r in REGISTERS], (candidate['area'], state, flag, cv, 'registers')
                    assert native.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000 == patched.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000, (candidate['area'], state, flag, cv, 'flags')
                    assert patched.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                    assert patched.mem_read(0x0420903c, 4) == native.mem_read(0x0420903c, 4)
                    assert patched.mem_read(0x0420b1b0, 4) == native.mem_read(0x0420b1b0, 4)
                    count += 1
    return count


def parameters(data, evidence):
    """Execute complete native parameter getters through their real pop-PC.

    Media-selected C7/On uses that image's native C8 coefficient entries while
    retaining its six-entry C7 rate list. State-independent getters stay native.
    """
    profile = evidence['parameter_profile']
    native, patched = machine(data), machine(data)
    if profile['patch_required']:
        candidate = next(c for c in evidence['candidates'] if c['area'] == 'ParameterTable')
        site = candidate['site']
        delta = STUB - site - 4
        patched.mem_write(STUB, bytes(candidate['stub']))
        patched.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff),
                                           0xf800 | ((delta >> 1) & 0x7ff)))
    done = 0x1fe000
    for cpu in (native, patched):
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user: c.emu_stop() if at == done else None)
    rates = list(data[profile['rates']:profile['rates'] + 6])
    assert len(rates) == 6 and all(rates) and rates == sorted(rates)
    count = 0
    for request in range(min(12, rates[-1]) + 1):
        index = next(i for i, value in enumerate(rates) if value >= request)
        for state in (0xc0, 0xc7, 0xc8, 0xcc, 0xe8, 0xf8):
            for flag in (0, 1, 2, 255):
                values = []
                for cpu in (native, patched):
                    setup(cpu, evidence['state'], evidence['flag_base'], state, flag, 3)
                    cpu.reg_write(reg.UC_ARM_REG_R0, request)
                    cpu.reg_write(reg.UC_ARM_REG_LR, done | 1)
                    saved = [cpu.reg_read(r) for r in REGISTERS[4:8]]
                    cpu.emu_start(profile['entry'] | 1, 0x200000, count=2000)
                    assert cpu.reg_read(reg.UC_ARM_REG_PC) == done, (profile['variant'], state, flag, request)
                    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                    assert [cpu.reg_read(r) for r in REGISTERS[4:8]] == saved
                    values.append(cpu.reg_read(reg.UC_ARM_REG_R0))
                if profile['variant'] == 'StateIndependent' or (state == 0xc7 and flag == 1):
                    expected = struct.unpack_from('<H', data, profile['coefficients'] + index * 2)[0]
                else:
                    expected = values[0]
                assert values[1] == expected, (profile['variant'], state, flag, request, values, expected)
                count += 1
    return count


def calculations(data, evidence):
    """Run the emitted gates through the real native arithmetic and division.

    C7 selects the existing C8 baseline policy. This deliberately
    does not transplant the newer hardware/calibration flag producer.
    """
    count = 0
    # Both native paths share the final forward rejection, after its BNE.
    # Never stop at an interior native branch that another installed BL owns.
    reject = next(c['reject'] for c in evidence['candidates']
                  if c['area'] == 'ForwardCalculation')
    for candidate in evidence['candidates']:
        if candidate['calculation_end'] is None:
            continue
        cpu = machine(data)
        group = evidence['calculation_group']
        assert len(group) == 2
        for part in group:
            cpu.mem_write(part['stub_va'], bytes(part['stub']))
            cpu.mem_write(part['site'], bytes(part['branch']))
        reached = [None]

        def stop(c, address, _size, _user):
            if address in (candidate['calculation_end'], reject):
                reached[0] = address
                c.emu_stop()

        cpu.hook_add(UC_HOOK_CODE, stop)
        for value in (0, 1, 9, 10, 19, 20, 255, 1000, 32767, 65535):
            for state in (0xc0, 0xc7, 0xc8, 0xcc):
                for flag in (0, 1, 2, 255):
                    reached[0] = None
                    setup(cpu, evidence['state'], evidence['flag_base'], state, flag, 3)
                    cpu.reg_write(reg.UC_ARM_REG_R4, 0x02000100)
                    cpu.mem_write(0x02000100, struct.pack('<H', value))
                    cpu.reg_write(reg.UC_ARM_REG_R5, 0x3fd2)
                    cpu.reg_write(reg.UC_ARM_REG_R7, 0x5534)
                    cpu.emu_start(candidate['region_start'] | 1, 0x200000, count=2000)
                    accepted = state & 0xc8 == 0xc8 or (state == 0xc7 and flag == 1)
                    assert reached[0] == (candidate['calculation_end'] if accepted else reject), (candidate['area'], state, flag, value, reached)
                    if accepted:
                        delta, base = ((value // 20) * 23, 0x51b1) if state & 0xcc == 0xcc else ((value // 10) * 12, 0x5534)
                        expected = base - delta if candidate['area'] == 'ReverseCalculation' else base + delta
                        assert cpu.reg_read(reg.UC_ARM_REG_R0) == expected & 0xffffffff, (candidate['area'], state, flag, value)
                    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                    count += 1
    return count


def di_entry(data, evidence):
    """Execute the actual eight-byte entry detour and native format/layer code."""
    candidate = evidence.get('di_entry')
    assert candidate is not None, 'classic DI contract missing'
    native, patched = machine(data), machine(data)
    site = candidate['site']
    delta = STUB - site - 4
    patched.mem_write(STUB, bytes(candidate['stub']))
    patched.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff),
                                       0xf800 | ((delta >> 1) & 0x7ff)) + b'\xc0\x46' * 2)
    reached = [None, None]
    for index, cpu in enumerate((native, patched)):
        def stop(c, address, _size, _user, index=index):
            if address in (candidate['resume'], candidate['format']):
                reached[index] = address
                c.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, stop)
    count = 0
    for flag in (0, 1, 2, 255):
        for identifier in b'ORWU?':
            for fmt in (0, 1, 2, 5, 255):
                for layers in (0, 1, 2, 3, 4, 5):
                    for attributes in (0, 0x10, 0x20, 0x30, 0xc0, 0xf0):
                        for cv in (0, 1, 2, 3):
                            reached[:] = [None, None]
                            for cpu in (native, patched):
                                setup(cpu, evidence['state'], evidence['flag_base'], 0xf4, flag, cv)
                                cpu.reg_write(reg.UC_ARM_REG_R4, evidence['state'])
                                cpu.reg_write(reg.UC_ARM_REG_R5, 0)
                                cpu.mem_write(0x0300800c, bytes([ord('B'), ord('D'), 0, 0,
                                                               identifier, attributes, layers << 4, fmt]))
                                cpu.emu_start(site | 1, 0x200000, count=150)
                            yes = (flag == 1 and identifier == ord('U') and fmt == 5
                                   and layers in (2, 3) and attributes & 0x30 in (0, 0x30))
                            assert reached[0] == candidate['resume']
                            assert reached[1] == (candidate['format'] if yes else candidate['resume'])
                            if yes:
                                expected = 0xc7 if layers == 2 else 0xc8
                                assert patched.mem_read(evidence['state'], 1)[0] == expected
                                assert patched.reg_read(REGISTERS[candidate['one_register']]) == 1
                                assert patched.reg_read(REGISTERS[2]) == expected
                                assert [patched.reg_read(r) for r in REGISTERS[4:]] == [native.reg_read(r) for r in REGISTERS[4:]]
                            else:
                                assert [native.reg_read(r) for r in REGISTERS] == [patched.reg_read(r) for r in REGISTERS], (flag, identifier, fmt, layers, attributes, cv, 'registers')
                                assert native.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000 == patched.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000, (flag, identifier, fmt, layers, attributes, cv, 'flags')
                                assert patched.mem_read(evidence['state'], 1)[0] == 0xf4
                            assert patched.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                            count += 1
    # Run the native ARM format switch and native layer normalization after
    # the emitted recognition path; no replacement layer helper is installed.
    for layers, expected in ((2, 0xc7), (3, 0xc8)):
        cpu = machine(data)
        cpu.mem_write(STUB, bytes(candidate['stub']))
        cpu.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff),
                                       0xf800 | ((delta >> 1) & 0x7ff)) + b'\xc0\x46' * 2)
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _s, _u: c.emu_stop() if at == candidate['layer_store'] + 2 else None)
        setup(cpu, evidence['state'], evidence['flag_base'], 0xf4, 1, 0)
        cpu.reg_write(reg.UC_ARM_REG_R4, evidence['state'])
        cpu.reg_write(reg.UC_ARM_REG_R5, 0)
        saved = [0x70000000 + i * 0x101 for i in range(4)]
        cpu.mem_write(0x03008014, struct.pack('<IIIII', *saved, 0x1fe001))
        cpu.mem_write(0x0300800c, bytes([ord('B'), ord('D'), 0, 0, ord('U'), 0, layers << 4, 5]))
        cpu.emu_start(site | 1, 0x200000, count=300)
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == candidate['layer_store'] + 2
        assert cpu.mem_read(evidence['state'], 1)[0] == expected
        assert cpu.mem_read(candidate['format_flag'], 1)[0] == 0x20
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        assert candidate['caller']['stack_bytes'] == 40
        assert cpu.mem_read(0x03008014, 20) == struct.pack('<IIIII', *saved, 0x1fe001)
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _s, _u: c.emu_stop() if at == 0x1fe000 else None)
        cpu.emu_start(candidate['epilogue'] | 1, 0x200000, count=4)
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x1fe000
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008028
        assert [cpu.reg_read(r) for r in REGISTERS[4:8]] == saved
        count += 1
    return count


def parent_returns(data, evidence):
    """Run emitted detours with a saved parent frame, then native pop-PC exits."""
    count = 0
    done = 0x1fe000
    for candidate in evidence['candidates']:
        caller = candidate['caller']
        assert caller['entry'] < candidate['site'] and caller['returns']
        for finish in caller['returns']:
            pop = struct.unpack_from('<H', data, finish)[0]
            assert pop & 0xff00 == 0xbd00
            registers = [i for i in range(8) if pop & (1 << i)]
            locals_size = caller['stack_bytes'] - (len(registers) + 1) * 4
            assert locals_size >= 0
            epilogue = finish
            if locals_size:
                adjustment = struct.unpack_from('<H', data, finish - 2)[0]
                assert adjustment & 0xff80 == 0xb000 and (adjustment & 127) * 4 == locals_size, (candidate['area'], hex(finish), locals_size)
                epilogue -= 2
            for flag in (1, 255):
                cpu = machine(data)
                cpu.mem_write(STUB, bytes(candidate['stub']))
                site = candidate['site']
                delta = STUB - site - 4
                cpu.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff),
                                               0xf800 | ((delta >> 1) & 0x7ff)))
                if len(candidate['original']) == 6:
                    cpu.mem_write(site + 4, b'\xc0\x46')
                setup(cpu, evidence['state'], evidence['flag_base'], 0xc7, flag, 0)
                if candidate['area'] in ('PositionSetupInput','PositionSetupCommand'):
                    cpu.reg_write(reg.UC_ARM_REG_R6,evidence['state'])
                    cpu.reg_write(reg.UC_ARM_REG_R7,0xc8)
                if candidate['area'] == 'ReadControl':
                    cpu.reg_write(reg.UC_ARM_REG_R0,0x042080c0)
                if candidate['area'] in ('ReadUpperRange','ReadLowerRange'):
                    cpu.reg_write(reg.UC_ARM_REG_R6,evidence['state'])
                    cpu.reg_write(reg.UC_ARM_REG_R2,0xc8)
                if candidate['area'] == 'PositionOutput':
                    cpu.reg_write(reg.UC_ARM_REG_R6, evidence['state'])
                    cpu.reg_write(reg.UC_ARM_REG_R7, 0xc8)
                if candidate['area'] == 'ParameterTable':
                    cpu.reg_write(reg.UC_ARM_REG_R0, 0)
                saved = [0x60000000 + register * 0x101 for register in registers]
                frame = b'\xa5' * locals_size + struct.pack('<' + 'I' * (len(saved) + 1), *saved, done | 1)
                cpu.mem_write(0x03008000, frame)
                stops = (candidate['accept'], candidate['reject'])
                handle = cpu.hook_add(UC_HOOK_CODE, lambda c, at, _s, _u: c.emu_stop() if at in stops else None)
                cpu.emu_start(candidate['region_start'] | 1, 0x200000, count=250)
                assert cpu.reg_read(reg.UC_ARM_REG_PC) in stops
                assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                # Native regions may write their own local stack slots. Saved registers
                # and the parent's return address must remain byte-for-byte intact.
                # PUSH r1-r3 may reserve writable locals; only r4-r7 and
                # saved LR are callee-preserved by the native ABI.
                protected = [i for i, r in enumerate(registers) if r >= 4] + [len(registers)]
                for index in protected:
                    offset = locals_size + index * 4
                    assert cpu.mem_read(0x03008000 + offset, 4) == frame[offset:offset + 4]
                cpu.hook_del(handle)
                cpu.hook_add(UC_HOOK_CODE, lambda c, at, _s, _u: c.emu_stop() if at == done else None)
                cpu.emu_start(epilogue | 1, 0x200000, count=4)
                assert cpu.reg_read(reg.UC_ARM_REG_PC) == done
                assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000 + caller['stack_bytes']
                assert [cpu.reg_read(REGISTERS[r]) for r in registers if r >= 4] == [value for r, value in zip(registers, saved) if r >= 4]
                count += 1
    return count


def helpers(data, evidence):
    count = 0
    done = 0x1fe000
    for name in ('di_recognition', 'di_layers'):
        cpu = machine(data)
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _s, _u: c.emu_stop() if at == done else None)
        cpu.mem_write(STUB, bytes(evidence[name]))
        for flag in (0, 1, 2, 255):
            for identifier in ('O', 'R', 'W', 'U', '?') if name == 'di_recognition' else range(256):
                for field in range(6):
                    for fmt in (0, 1, 5, 255) if name == 'di_recognition' else (0,):
                        setup(cpu, evidence['state'], evidence['flag_base'], 0xc0, flag, 0)
                        values = [ord(identifier), fmt, field, 0xabcdef] if name == 'di_recognition' else [identifier, field, 0x123456, 0xabcdef]
                        for register, value in zip(REGISTERS, values):
                            cpu.reg_write(register, value)
                        cpu.reg_write(reg.UC_ARM_REG_LR, done | 1)
                        cpu.emu_start(STUB | 1, 0x200000, count=100)
                        assert cpu.reg_read(reg.UC_ARM_REG_PC) == done
                        if name == 'di_recognition':
                            expected = {2: 0xc7, 3: 0xc8}.get(field, 0) if flag == 1 and identifier == 'U' and fmt == 5 else 0
                        else:
                            expected = identifier if not 1 <= field <= 4 or (flag == 1 and identifier == 0xc7 and field == 2) else (identifier & 0xf3) | ((field - 1) << 2)
                        assert cpu.reg_read(REGISTERS[0]) == expected, (name, flag, identifier, fmt, field)
                        assert [cpu.reg_read(r) for r in REGISTERS[1:4]] == values[1:]
                        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                        assert cpu.reg_read(reg.UC_ARM_REG_LR) == done | 1
                        count += 1
    return count


def di_mode(data, evidence):
    candidate = next(c for c in evidence['candidates'] if c['area'] == 'DiMode')
    start, site = candidate['region_start'], candidate['site']
    # Stop after the native STRB and before its hardware programming call.
    end = start + 28
    load_at = site + 2
    op = struct.unpack_from('<H', data, load_at)[0]
    pool = ((load_at + 4) & ~3) + (op & 255) * 4
    destination = struct.unpack_from('<I', data, pool)[0]
    cpu = machine(data)
    cpu.mem_write(STUB, bytes(candidate['stub']))
    delta = STUB - site - 4
    cpu.mem_write(site, struct.pack('<HHH', 0xf000 | ((delta >> 12) & 0x7ff), 0xf800 | ((delta >> 1) & 0x7ff), 0x46c0))
    cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user: c.emu_stop() if at == end else None)
    count = 0
    for state in range(256):
        for flag in (0, 1, 2, 255):
            setup(cpu, evidence['state'], evidence['flag_base'], state, flag, 0)
            cpu.mem_write(destination, b'\xa5')
            cpu.emu_start(start | 1, 0x200000, count=250)
            expected = 0x15 if state & 0xcc == 0xcc else 0x1c if state & 0xc8 == 0xc8 or (state == 0xc7 and flag == 1) else 7
            assert cpu.reg_read(reg.UC_ARM_REG_PC) == end
            assert cpu.mem_read(destination, 1)[0] == expected, (state, flag)
            count += 1
    return count


def read_boundary(data, evidence):
    candidate = next(c for c in evidence['candidates'] if c['area'] == 'ReadBoundary')
    start, site = candidate['region_start'], candidate['site']
    cpu = machine(data)
    cpu.mem_write(STUB, bytes(candidate['stub']))
    delta = STUB - site - 4
    cpu.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff), 0xf800 | ((delta >> 1) & 0x7ff)))
    end = start + 108
    cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user: c.emu_stop() if at == end else None)
    cells = []
    for offset in (14, 34, 58):
        at = start + offset
        op = struct.unpack_from('<H', data, at)[0]
        assert op & 0xff00 == 0x4a00
        cells.append(struct.unpack_from('<I', data, ((at + 4) & ~3) + (op & 255) * 4)[0])
    count = 0
    for boundaries in ((100, 200, 300), (1000, 2000, 3000)):
        for request in (0, 32, *boundaries, *(b + 1 for b in boundaries)):
            for state in (0xc7, 0xc8, 0xcc):
                setup(cpu, evidence['state'], evidence['flag_base'], state, 1, 0)
                for cell, value in zip(cells, boundaries):
                    cpu.mem_write(cell, struct.pack('<I', value))
                cpu.reg_write(reg.UC_ARM_REG_R0, (request - 32) & 0xffffffff)
                cpu.emu_start(start | 1, 0x200000, count=250)
                expected = request
                for boundary, maximum in zip(boundaries, (3 << 26, 1 << 27, 1 << 26)):
                    if request == boundary + 1:
                        expected = maximum - boundary - 1
                        break
                assert cpu.reg_read(reg.UC_ARM_REG_PC) == end
                assert struct.unpack('<I', cpu.mem_read(0x03008004, 4))[0] == expected
                count += 1
    return count


def position(data, evidence):
    parts = [c for c in evidence['candidates'] if c['area'] in ('PositionInput', 'PositionOutput')]
    assert len(parts) == 2
    entry = parts[0]['caller']['entry']
    at = entry + 16
    op = struct.unpack_from('<H', data, at)[0]
    mode = struct.unpack_from('<I', data, ((at + 4) & ~3) + (op & 255) * 4)[0]
    native, patched = machine(data), machine(data)
    for index, candidate in enumerate(parts):
        target = STUB + index * 0x400
        patched.mem_write(target, bytes(candidate['stub']))
        site = candidate['site']
        delta = target - site - 4
        patched.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff), 0xf800 | ((delta >> 1) & 0x7ff)))
    done = 0x1fe000
    for cpu in (native, patched):
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user: c.emu_stop() if at == done else None)
        # Controller completion is simulated; +0x10 retains the programmed input.
        # This proves native software scaling, not physical controller behavior.
        cpu.hook_add(UC_HOOK_MEM_READ, lambda c, _access, address, _size, _value, _user: c.mem_write(address, b'\0' * 4) if address == 0x04042018 else None)
    count = 0
    for state in (0xc0, 0xc4, 0xc7, 0xc8, 0xcc, 0xe8):
        for flag in (0, 1, 2, 255):
            for value in (0, 1, 7, 8, 100, 1000, 10000, 0x100000):
                outputs = []
                for index, cpu in enumerate((native, patched)):
                    expected_state = 0xc8 if index == 0 and state == 0xc7 and flag == 1 else state
                    setup(cpu, evidence['state'], evidence['flag_base'], expected_state, flag, 0)
                    cpu.mem_write(mode, b'\x1c')
                    cpu.reg_write(reg.UC_ARM_REG_R0, value)
                    cpu.reg_write(reg.UC_ARM_REG_LR, done | 1)
                    preserved = [cpu.reg_read(r) for r in REGISTERS[4:8]]
                    cpu.emu_start(entry | 1, 0x200000, count=500)
                    assert cpu.reg_read(reg.UC_ARM_REG_PC) == done
                    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
                    assert [cpu.reg_read(r) for r in REGISTERS[4:8]] == preserved
                    outputs.append(cpu.reg_read(reg.UC_ARM_REG_R0))
                assert outputs[0] == outputs[1], (state, flag, value, outputs)
                count += 1
    return count


def calibration(data, evidence):
    contract=evidence.get('calibration')
    if contract is None:
        assert evidence['parameter_profile']['variant']=='StateIndependent'
        return 0
    site=contract['site'];native,patched=machine(data),machine(data)
    patched.mem_write(STUB,bytes(contract['stub']))
    delta=STUB-site-4
    patched.mem_write(site,struct.pack('<HHH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff),0x46c0))
    for cpu in (native,patched):
        cpu.hook_add(UC_HOOK_CODE,lambda c,at,_size,_user:c.emu_stop() if at==contract['resume'] else None)
    count=0
    for state in (0,0xc0,0xc4,0xc7,0xc8,0xcc,0xe8,255):
        for flag in (0,1,2,255):
            for index in range(6):
                for cv in range(16):
                    outputs=[]
                    for cpu in (native,patched):
                        setup(cpu,evidence['state'],evidence['flag_base'],state,flag,cv)
                        cpu.reg_write(reg.UC_ARM_REG_R6,index*2)
                        cpu.emu_start(site|1,0x200000,count=100)
                        assert cpu.reg_read(reg.UC_ARM_REG_PC)==contract['resume']
                        outputs.append(([cpu.reg_read(r) for r in REGISTERS],cpu.reg_read(reg.UC_ARM_REG_CPSR)&0xf0000000))
                        assert cpu.reg_read(reg.UC_ARM_REG_SP)==0x03008000
                    base=contract['coefficients'] if state==0xc7 and flag==1 else contract['original_base']+0x58
                    assert outputs[1][0][0]==struct.unpack_from('<H',data,base+index*2)[0]
                    assert outputs[0][0][1:]==outputs[1][0][1:]
                    assert outputs[0][1]==outputs[1][1]
                    count+=1
    return count


def read_position(data, evidence):
    fixture=Path(__file__).resolve().parents[1]/'crates/freemkv-fw/tests/fixtures/mtk-uhd-read-position-modern.json'
    source=json.loads(fixture.read_text())
    assert source['source_sha256']=='648a16d024eea31ef4901f3ac2180cbfffeda1161d70f9096335d8a6097445bc'
    modern=bytearray(b'\xff'*0x200000)
    for part in source['parts']:
        raw=bytes.fromhex(part['hex'])
        assert hashlib.sha256(raw).hexdigest()==part['sha256']
        modern[part['offset']:part['offset']+len(raw)]=raw
    modern=bytes(modern)
    p=evidence['read_position'];patched=machine(data);native=machine(data);new=machine(modern)
    parts=[(p['site'],p['stub'])]+[(c['site'],c['stub']) for c in evidence['candidates'] if c['area'] in ('ReadUpperRange','ReadLowerRange')]
    for n,(site,stub) in enumerate(parts):
     target=STUB+n*0x400;patched.mem_write(target,bytes(stub));delta=target-site-4
     patched.mem_write(site,struct.pack('<HH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff)))
    done=0x1fe000
    # Actual native routines execute. Only logging and the modern notification helper
    # are intercepted; those calls do not define the position/layer/range result.
    call_targets=set()
    for image,start,end in ((data,p['entry'],p['entry']+0x14c),(modern,0xda0a8,0xda262)):
     for at in range(start,end-2,2):
      first,second=struct.unpack_from('<HH',image,at)
      if first&0xf800==0xf000 and second&0xf800==0xf800:
       high=first&0x7ff
       if high&0x400:high-=0x800
       call_targets.add(at+4+(high<<12)+((second&0x7ff)<<1))
    def hook(c,at,_size,_user):
     if at==done:c.emu_stop()
     elif at in call_targets:c.reg_write(reg.UC_ARM_REG_PC,c.reg_read(reg.UC_ARM_REG_LR))
    for cpu in (native,patched,new):cpu.hook_add(UC_HOOK_CODE,hook)
    count=0
    for byte in (0,0x1b,0x1c,0x21,0x22,0x3f,0x40,0x41,0x5b,0x5c,0x61,0x62,0x7f,0x80,0xc0,255):
     for low in (0,0x1234,0xffff):
      for layer in range(4):
       for cache in range(4):
        for flag in (0,1,2,255):
         results=[]
         for cpu,is_modern in ((new if flag==1 else native,flag==1),(patched,False)):
          setup(cpu,0x1ff9e00 if is_modern else evidence['state'],evidence['flag_base'],0xc7,flag,0)
          position=0x2000b38 if is_modern else p['position'];layer_cell=0x2000b02 if is_modern else p['layer'];cache_cell=0x2000b03 if is_modern else p['cached_layer'];status=0x2000b0f if is_modern else p['status']
          cpu.mem_write(position,struct.pack('<I',(byte<<16)|low));cpu.mem_write(layer_cell,bytes([layer]));cpu.mem_write(cache_cell,bytes([cache]));cpu.mem_write(status,b'\0')
          cpu.reg_write(reg.UC_ARM_REG_R4,layer_cell if is_modern else position)
          if is_modern:cpu.reg_write(reg.UC_ARM_REG_R6,position)
          cpu.mem_write(0x03008000,struct.pack('<6I',3,4,5,6,7,done|1))
          start=0xda0e0 if is_modern else p['entry']+0x32
          try:cpu.emu_start(start|1,0x200000,count=500)
          except Exception as error:raise AssertionError((is_modern,byte,low,layer,cache,flag,hex(cpu.reg_read(reg.UC_ARM_REG_PC)))) from error
          assert cpu.reg_read(reg.UC_ARM_REG_PC)==done,(hex(cpu.reg_read(reg.UC_ARM_REG_PC)),is_modern,byte,low,layer,cache,flag)
          assert cpu.reg_read(reg.UC_ARM_REG_SP)==0x03008018
          results.append((bytes(cpu.mem_read(position,4)),bytes(cpu.mem_read(layer_cell,1)),cpu.mem_read(status,1)[0]&0x10))
         assert results[0]==results[1],(byte,low,layer,cache,flag,results)
         count+=1
    return count


def read_control(data,evidence):
    candidate=next(c for c in evidence['candidates'] if c['area']=='ReadControl')
    native,patched=machine(data),machine(data)
    patched.mem_write(STUB,bytes(candidate['stub']))
    site=candidate['site'];delta=STUB-site-4
    patched.mem_write(site,struct.pack('<HHH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff),0x46c0))
    end=candidate['region_start']+64
    for cpu in (native,patched):
        cpu.hook_add(UC_HOOK_CODE,lambda c,at,_s,_u:c.emu_stop() if at==end else None)
    count=0
    for state in (0,0xc0,0xc4,0xc7,0xc8,0xcc,0xe8,255):
        for flag in (0,1,2,255):
            for seed in (0,0xffffffff,0x89abcdef,0x12345678):
                outputs=[]
                for index,cpu in enumerate((native,patched)):
                    compare_state=0xc8 if index==0 and state==0xc7 and flag==1 else state
                    setup(cpu,evidence['state'],evidence['flag_base'],compare_state,flag,0)
                    cpu.reg_write(reg.UC_ARM_REG_R0,0x042080c0)
                    for offset in (0x18,0x1c,0x28,0x2c):cpu.mem_write(0x042080c0+offset,struct.pack('<I',seed))
                    cpu.emu_start(candidate['region_start']|1,0x200000,count=250)
                    assert cpu.reg_read(reg.UC_ARM_REG_PC)==end
                    assert cpu.reg_read(reg.UC_ARM_REG_SP)==0x03008000
                    outputs.append([bytes(cpu.mem_read(0x042080c0+offset,4)) for offset in (0x18,0x1c,0x28,0x2c)])
                assert outputs[0]==outputs[1],(state,flag,seed)
                count+=1
    return count


def position_setup(data,evidence):
    parts=[c for c in evidence['candidates'] if c['area'] in ('PositionSetupInput','PositionSetupCommand')]
    assert len(parts)==2
    entry=parts[0]['caller']['entry']
    def literal(offset):
        at=entry+offset;op=struct.unpack_from('<H',data,at)[0]
        return struct.unpack_from('<I',data,((at+4)&~3)+(op&255)*4)[0]
    working,mode=literal(16),literal(18)
    layer,status=literal(0xa4),literal(0xa8)
    native,patched=machine(data),machine(data)
    for n,candidate in enumerate(parts):
        target=STUB+n*0x400;patched.mem_write(target,bytes(candidate['stub']))
        site=candidate['site'];delta=target-site-4
        patched.mem_write(site,struct.pack('<HH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff)))
    done=0x1fe000;traces=[[],[]]
    for index,cpu in enumerate((native,patched)):
        cpu.hook_add(UC_HOOK_CODE,lambda c,at,_s,_u:c.emu_stop() if at==done else None)
        cpu.hook_add(UC_HOOK_MEM_READ,lambda c,_a,address,_s,_v,_u:c.mem_write(address,b'\0'*4) if address==0x04042018 else None)
        cpu.hook_add(UC_HOOK_MEM_WRITE,lambda _c,_a,address,_s,value,_u,index=index:traces[index].append((address,value)) if address in (0x04042010,0x04042014,0x04042018) else None)
    count=0
    for state in (0xc0,0xc4,0xc7,0xc8,0xcc,0xe8):
        for flag in (0,1,2,255):
            for value in (0,1,100,10000,0x100000):
                for media_mode in (7,0x15,0x1c):
                    results=[]
                    for index,cpu in enumerate((native,patched)):
                        compare_state=0xc8 if index==0 and state==0xc7 and flag==1 else state
                        setup(cpu,evidence['state'],evidence['flag_base'],compare_state,flag,0)
                        cpu.mem_write(working,struct.pack('<I',value));cpu.mem_write(mode,bytes([media_mode]))
                        cpu.mem_write(layer,b'\0');cpu.mem_write(status,b'\0')
                        cpu.reg_write(reg.UC_ARM_REG_R0,value+0x100)
                        cpu.reg_write(reg.UC_ARM_REG_LR,done|1)
                        preserved=[cpu.reg_read(r) for r in REGISTERS[4:8]]
                        traces[index].clear()
                        cpu.emu_start(entry|1,0x200000,count=600)
                        assert cpu.reg_read(reg.UC_ARM_REG_PC)==done
                        assert cpu.reg_read(reg.UC_ARM_REG_SP)==0x03008000
                        assert [cpu.reg_read(r) for r in REGISTERS[4:8]]==preserved
                        results.append(cpu.reg_read(reg.UC_ARM_REG_R0))
                    assert results[0]==results[1],(state,flag,value,media_mode,results)
                    assert traces[0]==traces[1],(state,flag,value,media_mode,traces)
                    count+=1
    return count


def media_defaults(data,evidence):
    candidate=next(c for c in evidence['candidates'] if c['area']=='MediaDefaults')
    start,site=candidate['region_start'],candidate['site']
    at=candidate['caller']['entry']+16;op=struct.unpack_from('<H',data,at)[0]
    mode=struct.unpack_from('<I',data,((at+4)&~3)+(op&255)*4)[0]
    branch=start+20;op=struct.unpack_from('<H',data,branch)[0];delta=op&0x7ff
    if delta&0x400:delta-=0x800
    store=branch+4+delta*2;end=store+2
    assert struct.unpack_from('<H',data,store)[0]==0x7011
    cpu=machine(data);cpu.mem_write(STUB,bytes(candidate['stub']))
    delta=STUB-site-4
    cpu.mem_write(site,struct.pack('<HH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff)))
    cpu.hook_add(UC_HOOK_CODE,lambda c,at,_s,_u:c.emu_stop() if at==end else None)
    count=0
    for state in range(256):
        for flag in (0,1,2,255):
            for initial in (7,0x15,0x1c):
                setup(cpu,evidence['state'],evidence['flag_base'],state,flag,0)
                cpu.reg_write(reg.UC_ARM_REG_R2,mode);cpu.mem_write(mode,bytes([initial]))
                cpu.emu_start(start|1,0x200000,count=250)
                expected=0x15 if state&0xcc==0xcc else 0x1c if state&0xc8==0xc8 or (state==0xc7 and flag==1) else initial
                assert cpu.reg_read(reg.UC_ARM_REG_PC)==end
                assert cpu.mem_read(mode,1)[0]==expected,(state,flag,initial)
                assert cpu.reg_read(reg.UC_ARM_REG_R2)==mode
                assert cpu.reg_read(reg.UC_ARM_REG_SP)==0x03008000
                count+=1
    return count


def recovery_dispatch(data,evidence):
    """C7/C8 must already select the same native ROM read-entry call and status path."""
    p=evidence['completion'];start,end=p['recovery_region'],p['recovery_end']
    branch=end-2;op=struct.unpack_from('<H',data,branch)[0]
    assert op&0xff00==0xd100
    delta=op&255;delta=delta if delta<128 else delta-256
    failed=branch+4+delta*2
    cpu=machine(data);calls=[]
    def hook(c,at,_size,_user):
        if at in (end,failed):c.emu_stop();return
        op=struct.unpack_from('<H',data,at)[0]
        if op&0xf800==0xf000:
            second=struct.unpack_from('<H',data,at+2)[0]
            assert second&0xf800==0xf800
            offset=((op&0x7ff)<<12)|((second&0x7ff)<<1)
            if offset&(1<<22):offset-=1<<23
            calls.append((at+4+offset,tuple(c.reg_read(r) for r in REGISTERS[:4])))
            c.reg_write(reg.UC_ARM_REG_R0,returned[0])
            c.reg_write(reg.UC_ARM_REG_LR,(at+4)|1)
            c.reg_write(reg.UC_ARM_REG_PC,(at+4)|1)
    cpu.hook_add(UC_HOOK_CODE,hook);returned=[0];count=0
    for parameter in (0,1,8,255):
        for flag in (0,1):
            for result in (0,1,0x20,0xb0):
                observed=[]
                for state in (0xc7,0xc8):
                    cpu.mem_write(0x01ff0000,b'\0'*0x20000)
                    setup(cpu,evidence['state'],evidence['flag_base'],state,1,0)
                    # Execute the actual pointer producer, not an assumed state register.
                    cpu.emu_start(p['recovery_state_load']|1,0x200000,count=2)
                    assert cpu.reg_read(REGISTERS[p['recovery_state_register']])==evidence['state']
                    cpu.reg_write(reg.UC_ARM_REG_R0,0)
                    cpu.reg_write(REGISTERS[p['recovery_request_register']],0x02004000)
                    cpu.reg_write(REGISTERS[p['recovery_flag_register']],flag)
                    cpu.mem_write(0x02004000,b'\0'*32)
                    cpu.mem_write(0x0200400b,bytes([parameter]));calls.clear();returned[0]=result
                    cpu.emu_start(start|1,0x200000,count=100)
                    assert len(calls)==1 and calls[0][1][0]==parameter
                    assert cpu.reg_read(reg.UC_ARM_REG_PC)==(end if result==0 else failed)
                    assert cpu.mem_read(0x02004000,1)[0]==result
                    assert cpu.mem_read(0x0200400e,1)[0]==flag
                    assert cpu.mem_read(evidence['state'],1)[0]==state
                    observed.append((calls.copy(),bytes(cpu.mem_read(0x02004000,32))))
                assert observed[0]==observed[1],('native ROM recovery',parameter,flag,result,observed)
                count+=1
    return count


def completion(data, evidence):
    """Compare actual controller stores and read-completion reflection to native C8.

    OEM/Off/invalid flags use original media paths. No optical behavior simulated.
    """
    native, patched = machine(data), machine(data)
    parts = [c for c in evidence['candidates'] if c['area'] in ('ControllerTiming','ControllerMode','ReadCompletionBoundary')]
    assert len(parts)==3
    for index,candidate in enumerate(parts):
        stub=STUB+index*0x400; site=candidate['site'];delta=stub-site-4
        patched.mem_write(stub,bytes(candidate['stub']))
        patched.mem_write(site,struct.pack('<HH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff)))
        if len(candidate['original'])==6:patched.mem_write(site+4,b'\xc0\x46')
    p=evidence['completion'];count=0
    at=p['controller_region']+66;op=struct.unpack_from('<H',data,at)[0]
    assert op&0xff00==0x4800
    mode_cell=struct.unpack_from('<I',data,((at+4)&~3)+(op&255)*4)[0]-0x40+0x30
    targets=(0x04208260,0x04208810,mode_cell)
    stops={p['controller_end'],p['boundary_end'],parts[2]['reject']}
    for cpu in (native,patched):
        cpu.hook_add(UC_HOOK_CODE,lambda c,at,_size,_user:c.emu_stop() if at in stops else None)
    for state in (0x40,0xc0,0xc4,0xc7,0xc8,0xcc):
        for flag in (0,1,2,255):
            for initial in (0,0xffffffff,0x12345678,0xa5a55a5a):
                results=[]
                for index,cpu in enumerate((native,patched)):
                    reference=0xc8 if index==0 and state==0xc7 and flag==1 else state
                    setup(cpu,evidence['state'],evidence['flag_base'],reference,flag,0)
                    cpu.reg_write(reg.UC_ARM_REG_R1,0x04208810)
                    cpu.reg_write(reg.UC_ARM_REG_R2,0x04208260)
                    for addr in targets:cpu.mem_write(addr,struct.pack('<I',initial))
                    cpu.emu_start(p['controller_region']|1,0x200000,count=1000)
                    assert cpu.reg_read(reg.UC_ARM_REG_PC)==p['controller_end']
                    results.append([bytes(cpu.mem_read(addr,4)) for addr in targets])
                assert results[0]==results[1],('controller fields',state,flag,initial,results)
                count+=1
            for request in (0,99,100,101,199,200,201,299,300,301,0x3ffffff,0x7ffffff):
                results=[]
                for index,cpu in enumerate((native,patched)):
                    cpu.mem_write(0x01ff0000,b'\0'*0x20000)
                    reference=0xc8 if index==0 and state==0xc7 and flag==1 else state
                    setup(cpu,evidence['state'],evidence['flag_base'],reference,flag,0)
                    for cell,value in zip(p['boundaries'],(100,200,300)):cpu.mem_write(cell,struct.pack('<I',value))
                    cpu.mem_write(0x03008028,struct.pack('<I',request))
                    cpu.mem_write(0x040b0048,struct.pack('<I',0xdeadbeef))
                    try:
                        cpu.emu_start(p['boundary_region']|1,0x200000,count=1000)
                    except Exception as error:
                        raise AssertionError(('completion boundary',state,flag,request,index,hex(cpu.reg_read(reg.UC_ARM_REG_PC)),p)) from error
                    assert cpu.reg_read(reg.UC_ARM_REG_PC) in (p['boundary_end'],parts[2]['reject'])
                    results.append((bytes(cpu.mem_read(0x03008028,4)),bytes(cpu.mem_read(0x040b0048,4))))
                assert results[0]==results[1],('completion boundary',state,flag,request,results)
                count+=1
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--builder', type=Path, required=True)
    ap.add_argument('--image', type=Path, default=Path('crates/freemkv-fw/tests/fixtures/BE14NU40_MT1939_JB7_1.01.bin'))
    ap.add_argument('--corpus', type=Path)
    ap.add_argument('--hoard', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    if args.corpus:
        assert args.hoard
        records = []
        rows = json.loads(args.corpus.read_text())['images']
        for row in rows:
            if row['identity']['chip'] != 'MT1939':
                continue
            source = args.hoard / row['path']
            data = source.read_bytes()
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            evidence = json.loads(subprocess.check_output([str(args.builder.resolve()), str(source), 'uhd-conversion']))
            assert not evidence['pending'] and len(evidence['candidates']) == 25 + int(evidence['parameter_profile']['patch_required'])
            cases = routing(data, evidence, (0, 0x40, 0x80, 0xc0, 0xc4, 0xc7, 0xc8, 0xcb, 0xcc, 0xcf, 0xe0, 0xf0))
            arithmetic_cases = calculations(data, evidence)
            parameter_cases = parameters(data, evidence)
            mode_cases = di_mode(data, evidence)
            boundary_cases = read_boundary(data, evidence)
            position_cases = position(data, evidence)
            calibration_cases = calibration(data, evidence)
            read_position_cases = read_position(data, evidence)
            read_control_cases = read_control(data, evidence)
            position_setup_cases = position_setup(data, evidence)
            recovery_cases=recovery_dispatch(data,evidence)
            completion_cases=completion(data,evidence)
            media_defaults_cases = media_defaults(data, evidence)
            di_cases = di_entry(data, evidence)
            parent_cases = parent_returns(data, evidence)
            records.append({'sha256':row['sha256'], 'state_address':evidence['state'],'completion_cases':completion_cases,'native_recovery_cases':recovery_cases, 'routing_cases':cases, 'calculation_cases':arithmetic_cases, 'parameter_cases':parameter_cases, 'di_mode_cases':mode_cases, 'boundary_cases':boundary_cases, 'position_cases':position_cases, 'calibration_cases':calibration_cases, 'read_position_cases':read_position_cases, 'read_control_cases':read_control_cases, 'position_setup_cases':position_setup_cases, 'media_defaults_cases':media_defaults_cases, 'parameter_profile':evidence['parameter_profile'], 'di_cases':di_cases, 'parent_return_cases':parent_cases, 'callers':{c['area']:c['caller'] for c in evidence['candidates']}, 'pending':evidence['pending']})
            print(f"{row['sha256'][:12]}: {cases} native-versus-emitted cases passed", flush=True)
        if args.output:
            args.output.write_text(json.dumps({'policy':'complete experimental software contracts; public conversion gated; physical UHD reading unproven',
                'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'builder_sha256':hashlib.sha256(args.builder.read_bytes()).hexdigest(), 'images':records}, indent=2) + '\n')
        print(f"PASS: {len(records)} classic inputs; {sum(r['routing_cases'] for r in records)} routing comparisons; {sum(r['di_cases'] for r in records)} DI entry cases")
        return
    evidence = json.loads(subprocess.check_output([str(args.builder.resolve()), str(args.image), 'uhd-conversion']))
    assert not evidence['pending'], 'complete experimental software contracts required'
    assert len(evidence['candidates']) == 25 + int(evidence['parameter_profile']['patch_required'])
    data = args.image.read_bytes()
    cases = routing(data, evidence, range(256))
    arithmetic_cases = calculations(data, evidence)
    parameter_cases = parameters(data, evidence)
    mode_cases = di_mode(data, evidence)
    boundary_cases = read_boundary(data, evidence)
    position_cases = position(data, evidence)
    calibration_cases = calibration(data, evidence)
    read_position_cases = read_position(data, evidence)
    read_control_cases = read_control(data, evidence)
    position_setup_cases = position_setup(data, evidence)
    recovery_cases=recovery_dispatch(data,evidence)
    completion_cases=completion(data,evidence)
    media_defaults_cases = media_defaults(data, evidence)
    di_cases = di_entry(data, evidence)
    parent_cases = parent_returns(data, evidence)
    helper_cases = helpers(data, evidence)
    print(f'PASS: {cases} native-versus-emitted routing cases; {arithmetic_cases} native arithmetic cases; {parameter_cases} native parameter cases; {mode_cases} DI mode cases; {boundary_cases} read-boundary cases; {position_cases} full position cases; {calibration_cases} calibration cases; {read_position_cases} native read-position cases; {read_control_cases} controller cases; {position_setup_cases} native setup cases; {media_defaults_cases} media-default cases; {recovery_cases} native recovery comparisons; {completion_cases} native completion cases; {helper_cases} DI helper cases; {di_cases} native DI entry cases; {parent_cases} parent-return cases; software contracts complete; normal Modify integration tested separately; physical UHD reading unproven')


if __name__ == '__main__':
    main()
