"""Execute OEM MT1939 layer/state gates. This tests routing, not UHD support."""
import argparse
import subprocess
import json
import hashlib
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/mt1939-research'


def machine(name):
    record = next(r for r in json.loads((ROOT / 'sources.json').read_text()) if r['file'] == name + '.bin')
    data = (ROOT / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(record['source_offset'] - record['padding'], data)
    cpu.mem_map(0x01FF0000, 0x10000)
    cpu.mem_map(0x02000000, 0x2000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    return cpu


def literal(cpu, site):
    op = struct.unpack('<H', cpu.mem_read(site, 2))[0]
    assert op & 0xF800 == 0x4800
    return struct.unpack('<I', cpu.mem_read(((site + 4) & ~3) + (op & 255) * 4, 4))[0]


def route(cpu, start, stops):
    reached = []

    def visit(machine, address, _size, _data):
        if address in stops:
            reached.append(stops[address])
            machine.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start(start | 1, 0x200000, count=100)
    assert len(reached) == 1, 'did not reach a reviewed branch continuation'
    return reached[0]


def class_metric_cases():
    """Execute both native Thumb classifiers and their real ARM float helpers."""
    def execute(modern, state, mantissa, exponent):
        prefix = 'wh14-modern-class-' if modern else 'wh14-classic-class-'
        cpu = machine(prefix + 'metric')
        record = next(r for r in json.loads((ROOT / 'sources.json').read_text())
                      if r['file'] == prefix + 'math.bin')
        data = (ROOT / record['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
        cpu.mem_write(record['source_offset'], data)
        cpu.reg_write(reg.UC_ARM_REG_LR, 0x1fe001)
        for i in range(4, 12):
            cpu.reg_write(getattr(reg, f'UC_ARM_REG_R{i}'), 0x43210000 + i * 0x101)
        cpu.reg_write(reg.UC_ARM_REG_R0, ((mantissa & 255) << 8) | exponent)
        cell = 0x01ff9e00 if modern else 0x01ff9dd3
        cpu.mem_write(cell, bytes([state]))
        logs = []

        def log(machine, address, _size, _data):
            if address == (0xcadc4 if modern else 0xf5a38):
                logs.append((machine.reg_read(reg.UC_ARM_REG_R1), machine.reg_read(reg.UC_ARM_REG_R2)))
                machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

        cpu.hook_add(UC_HOOK_CODE, log)
        cpu.emu_start(0xfc71f if modern else 0x134c17, 0x1fe000, count=5000)
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x1fe000
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        for i in range(4, 12):
            assert cpu.reg_read(getattr(reg, f'UC_ARM_REG_R{i}')) == 0x43210000 + i * 0x101
        return cpu.mem_read(cell, 1)[0], logs[-1]

    count = 0
    for state in (0xc0, 0xc4, 0xe0, 0xe4, 0xf0, 0xf4):
        for mantissa in (0, 1, 80, 81, 97, 98, 127, -80, -81, -97, -98, -128):
            for exponent in (0, 1, 3):
                old = execute(False, state, mantissa, exponent)
                new = execute(True, state, mantissa, exponent)
                metric = abs(mantissa) * (2 ** exponent) / 128
                threshold = 0.63 if state & 0xcc == 0xc0 else 0.76
                expected = (state & 0xcc) if metric < threshold else state
                assert old == new and old[0] == expected, (state, mantissa, exponent, old, new)
                actual_metric = struct.unpack('<f', struct.pack('<I', old[1][0]))[0]
                assert actual_metric == metric
                count += 1
    return count


def read_entry_cases():
    """Compare actual native READ(10/12) preflight, without patching either gate."""
    def execute(modern, value, available, status):
        cpu = machine('wh14-modern-read-entry' if modern else 'wh14-classic-read-entry')
        cell = 0x01ff9e00 if modern else 0x01ff9dd3
        ready = 0x02000c20 if modern else 0x02000ddc
        cpu.mem_write(cell, bytes([value]))
        cpu.mem_write(ready, bytes([available]))
        cpu.mem_write(0x01ff9b29, bytes([status]))
        cpu.mem_write(0x01ff9b2b, bytes([0]))
        return route(cpu, 0xae73c if modern else 0xb4814,
                     {0xae76e: 'accept', 0xae766: 'refuse'} if modern else
                     {0xb484c: 'accept', 0xb4844: 'refuse'})

    count = 0
    for value in range(256):
        for available in (0, 1):
            for status in (0, 0x82):
                old = execute(False, value, available, status)
                new = execute(True, value, available, status)
                expected = 'refuse' if not available and value >> 4 == 15 and status != 0x82 else 'accept'
                assert old == new == expected, (value, available, status, old, new)
                count += 1
    return count


def candidate_cases(builder, source=None, records=None):
    source = source or ROOT / 'wh14-vid.bin'
    response = subprocess.run([str(builder.resolve()), str(source), 'auth-candidate', '02000e40'], capture_output=True, text=True, check=True)
    plan = json.loads(response.stdout)
    assert plan['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert plan['variant'] == 'R0StateR1Alternate'
    site, fallback = plan['site'], plan['fallback']
    blob = bytes.fromhex(plan['stub_hex'])
    source_bytes = source.read_bytes()
    registers = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]

    def execute(raw, setting, modified):
        value = raw >> 4
        cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        cpu.mem_map(0, max(0x4000, (len(source_bytes) + 4095) & ~4095))
        cpu.mem_write(0, source_bytes)
        cpu.mem_write(0x1000, blob)
        cpu.mem_map(0x02000000, 0x2000)
        cpu.mem_map(0x01FF0000, 0x10000)
        cpu.mem_write(plan['state_address'], bytes([raw]))
        cpu.mem_map(0x03000000, 0x10000)
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xA0000030)
        cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        before = [0x76540000 + i * 0x101 for i in range(13)]
        before[0] = value
        before[1] = plan['state_address']
        for register, initial in zip(registers, before):
            cpu.reg_write(register, initial)
        cpu.reg_write(reg.UC_ARM_REG_LR, (site + 4) | 1)
        cpu.mem_write(plan['flag_base'] + 3, bytes([setting]))
        result = route(cpu, 0x1000 if modified else site, {site + 4: 'C', fallback + 8: '4', plan['refusal']: 'refuse'})
        assert [cpu.reg_read(r) for r in registers] == before, 'changed live register or fallback pointer'
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000, 'unbalanced stack'
        return result, cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xF0000000

    cases = 0
    for setting in (0, 1, 255, 2):
        for raw in range(256):
            value = raw >> 4
            old, old_flags = execute(raw, setting, False)
            target, flags = execute(raw, setting, True)
            expected = 'C' if setting == 1 and value >= 12 else 'refuse' if setting == 0 and value >= 12 else old
            assert target == expected, (value, setting, target, old)
            assert flags == old_flags, 'did not preserve original CMP flags'
            cases += 1
    if records is not None:
        records.append({'sha256':plan['source_sha256'], 'candidate':plan, 'cpu_comparisons':cases})
    assert hashlib.sha256(source.read_bytes()).hexdigest() == plan['source_sha256']
    return cases


def type_classification_cases():
    def execute(name, start, end, measurement_call, state, status, measurement):
        cpu = machine(name)
        cpu.mem_map(0x04200000, 0x10000)
        cpu.mem_write(literal(cpu, start), bytes([state]))
        cpu.reg_write(reg.UC_ARM_REG_R4, state)
        cpu.reg_write(reg.UC_ARM_REG_R5, status)
        cpu.reg_write(reg.UC_ARM_REG_R6, 0x0420B240)
        samples = []

        def code(machine, address, _size, _data):
            if address == end:
                machine.emu_stop()
            elif not start <= address < end:
                if address == measurement_call:
                    arguments = [machine.reg_read(r) for r in [reg.UC_ARM_REG_R0, reg.UC_ARM_REG_R1, reg.UC_ARM_REG_R2, reg.UC_ARM_REG_R3]]
                    assert arguments == [0x76, 0, 7, 1], arguments
                    samples.append(arguments)
                    machine.reg_write(reg.UC_ARM_REG_R0, measurement)
                else:
                    machine.reg_write(reg.UC_ARM_REG_R0, 0)  # logging only
                machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

        cpu.hook_add(UC_HOOK_CODE, code)
        cpu.emu_start(start | 1, 0x200000, count=200)
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == end
        assert len(samples) == (1 if status == 0 else 0)
        return cpu.reg_read(reg.UC_ARM_REG_R4)

    cases = 0
    for state in (0xC0, 0xC4, 0xC8, 0xCC, 0xE4, 0xF4):
        for status in (0, 1, 2):
            for measurement in (0, 0x2FFF, 0x3000, 0x3001, 0x37FF, 0x3800, 0x3801):
                classic = execute('wh14-classic-type', 0x10822C, 0x1082D8, 0x615E6, state, status, measurement)
                modern = execute('wh14-modern-type', 0xDE7B4, 0xDE860, 0x5F586, state, status, measurement)
                special = state & 0xCC == 0xC4
                expected = state if status == 1 else (0xF4 if special else 0xF0) if status == 2 or measurement > (0x3000 if special else 0x3800) else (0xC4 if special else 0xC0)
                assert classic == modern == expected, (state, status, measurement, classic, modern, expected)
                cases += 1
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-builder', type=Path)
    parser.add_argument('--candidate-sources', type=Path)
    parser.add_argument('--hoard', type=Path)
    parser.add_argument('--candidate-output', type=Path)
    args = parser.parse_args()
    if args.candidate_sources:
        assert args.candidate_builder and args.hoard
        sources = json.loads(args.candidate_sources.read_text())['images']
        records = []
        for record in sources:
            source = args.hoard / record['path']
            assert hashlib.sha256(source.read_bytes()).hexdigest() == record['sha256']
            count = candidate_cases(args.candidate_builder, source, records)
            records[-1]['path'] = record['path']
            records[-1]['identity'] = record['identity']
            print(f"{record['sha256'][:12]}: {count} authentication comparisons passed", flush=True)
        if args.candidate_output:
            args.candidate_output.write_text(json.dumps({'scope':'research only; no classic UHD capability enabled', 'images':records}, indent=2) + '\n')
        print(f"PASS: {len(records)} originals; {sum(r['cpu_comparisons'] for r in records)} authentication comparisons")
        return
    state_cases = 0
    for value in range(256):
        cpu = machine('wh14-vid')
        state = literal(cpu, 0x17F59E)
        cpu.reg_write(reg.UC_ARM_REG_R1, state)
        cpu.mem_write(state, bytes([value]))
        actual = route(cpu, 0x17F5A4, {0x17F5B0: 'C', 0x17F62E: '4', 0x17F65E: 'other'})
        expected = {12: 'C', 4: '4'}.get(value >> 4, 'other')
        assert actual == expected, (value, actual, expected)
        state_cases += 1
    layer_cases = 0
    for media in range(4):
        for fmt in (0, 0x7F, 0x80, 0xFF):
            for layer in range(4):
                for available in (0, 1):
                    cpu = machine('wh14-bd-structure')
                    cdb = literal(cpu, 0xB67DA)
                    flag = literal(cpu, 0xB680E)
                    frame = bytearray(12)
                    frame[0], frame[1], frame[6], frame[7] = 0xAD, media, layer, fmt
                    cpu.mem_write(cdb, bytes(frame))
                    cpu.mem_write(flag, bytes([available]))
                    actual = route(cpu, 0xB67DA, {0xB67EE: 'media', 0xB68F6: 'layer', 0xB6816: 'accept'})
                    expected = 'media' if fmt < 0x80 and media != 1 else 'accept' if layer == 0 or (layer == 1 and available) else 'layer'
                    assert actual == expected, (media, fmt, layer, available, actual, expected)
                    layer_cases += 1
    metric_cases = class_metric_cases()
    read_cases = read_entry_cases()
    type_cases = type_classification_cases()
    candidates = candidate_cases(args.candidate_builder) if args.candidate_builder else 0
    print(f'PASS: {state_cases} OEM state-byte values, {layer_cases} media/format/layer/flag combinations, {type_cases} paired type-classification cases, {read_cases} paired native read-entry cases, {metric_cases} paired native class-metric cases, {candidates} candidate trampoline cases')


if __name__ == '__main__':
    main()
