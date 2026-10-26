"""Execute emitted conversion components; never writes a firmware output.

The research routing stubs are tested at native instruction regions, through
native arithmetic and saved parent returns. This does not establish correctness
of other consumers or prove physical UHD reading.
"""
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
STUB = 0x1ff000


def machine(data):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, data)
    cpu.mem_map(0x01ff0000, 0x20000)
    cpu.mem_map(0x04200000, 0x10000)
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
                        if candidate['area'] == 'ParameterTable':
                            cpu.reg_write(reg.UC_ARM_REG_R0, 0)
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

    Experimental C7 selects the existing C8 baseline policy. This deliberately
    does not transplant the newer hardware/calibration flag producer.
    """
    count = 0
    for candidate in evidence['candidates']:
        if candidate['calculation_end'] is None:
            continue
        cpu = machine(data)
        cpu.mem_write(STUB, bytes(candidate['stub']))
        site = candidate['site']
        delta = STUB - site - 4
        cpu.mem_write(site, struct.pack('<HH', 0xf000 | ((delta >> 12) & 0x7ff),
                                       0xf800 | ((delta >> 1) & 0x7ff)))
        reached = [None]

        def stop(c, address, _size, _user):
            if address in (candidate['calculation_end'], candidate['reject']):
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
                    assert reached[0] == (candidate['calculation_end'] if accepted else candidate['reject']), (candidate['area'], state, flag, value, reached)
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
            assert evidence['pending'] and len(evidence['candidates']) == 14 + int(evidence['parameter_profile']['patch_required'])
            cases = routing(data, evidence, (0, 0x40, 0x80, 0xc0, 0xc4, 0xc7, 0xc8, 0xcb, 0xcc, 0xcf, 0xe0, 0xf0))
            arithmetic_cases = calculations(data, evidence)
            parameter_cases = parameters(data, evidence)
            mode_cases = di_mode(data, evidence)
            boundary_cases = read_boundary(data, evidence)
            di_cases = di_entry(data, evidence)
            parent_cases = parent_returns(data, evidence)
            records.append({'sha256':row['sha256'], 'state_address':evidence['state'], 'routing_cases':cases, 'calculation_cases':arithmetic_cases, 'parameter_cases':parameter_cases, 'di_mode_cases':mode_cases, 'boundary_cases':boundary_cases, 'parameter_profile':evidence['parameter_profile'], 'di_cases':di_cases, 'parent_return_cases':parent_cases, 'callers':{c['area']:c['caller'] for c in evidence['candidates']}, 'pending':evidence['pending']})
            print(f"{row['sha256'][:12]}: {cases} native-versus-emitted cases passed", flush=True)
        if args.output:
            args.output.write_text(json.dumps({'policy':'research stubs only; no conversion enabled',
                'builder_sha256':hashlib.sha256(args.builder.read_bytes()).hexdigest(), 'images':records}, indent=2) + '\n')
        print(f"PASS: {len(records)} classic inputs; {sum(r['routing_cases'] for r in records)} routing comparisons; {sum(r['di_cases'] for r in records)} DI entry cases")
        return
    evidence = json.loads(subprocess.check_output([str(args.builder.resolve()), str(args.image), 'uhd-conversion']))
    assert evidence['pending'], 'research components must not enable standard conversion'
    assert len(evidence['candidates']) == 14 + int(evidence['parameter_profile']['patch_required'])
    data = args.image.read_bytes()
    cases = routing(data, evidence, range(256))
    arithmetic_cases = calculations(data, evidence)
    parameter_cases = parameters(data, evidence)
    mode_cases = di_mode(data, evidence)
    boundary_cases = read_boundary(data, evidence)
    di_cases = di_entry(data, evidence)
    parent_cases = parent_returns(data, evidence)
    helper_cases = helpers(data, evidence)
    print(f'PASS: {cases} native-versus-emitted routing cases; {arithmetic_cases} native arithmetic cases; {parameter_cases} native parameter cases; {mode_cases} DI mode cases; {boundary_cases} read-boundary cases; {helper_cases} DI helper cases; {di_cases} native DI entry cases; {parent_cases} parent-return cases; conversion remains gated')


if __name__ == '__main__':
    main()
