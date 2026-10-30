"""Research checks of installed MT1939 read code against native behavior.

Pinned BH16NS48/WH16NS60 inputs only. No firmware is written or flashed.
DI acquisition is supplied; controller busy bits are simulated. No physical
sector payload, controller arithmetic, or active command-table registration is
proved. Native functions and installed stubs execute without code replacement.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'detection', Path(__file__).with_name('test-mt1939-detection.py'))
detection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detection)
NATIVE_HASH = '5e2ec51fb3559623e555aadf280c96268fee6da0acfa7b4000c0d4564e7da073'
DONE = detection.DONE
PROFILES = {
    'classic': dict(state=0x1ff9dd3, capacity=0x2000e18, request=0x2000ed8,
                    count=0x2000e28, position=0x2000e1c, available=0x2000ddc,
                    entry=0xb468c, handoff=0x197b70, cap_entry=0xb518e,
                    helpers={0xf5ce0, 0x49bb8}, record=0x1a70e0,
                    cap_record=0x1a7108, sense_helper=None),
    'modern': dict(state=0x1ff9e00, capacity=0x2000c60, request=0x2000cfc,
                   count=0x2000c70, position=0x2000c64, available=0x2000c24,
                   entry=0xaf120, handoff=0x13e7e4, cap_entry=0xafbb2,
                   helpers={0xcbd54}, record=0x14f8c4, cap_record=0x14f8ec,
                   sense_helper=0xa37fa),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_stubs(data, plan, receipt):
    parts = plan['candidates'] + [plan['read_position'], plan['calibration']]
    for part in parts:
        site = part['site']
        first, second = struct.unpack_from('<HH', data, site)
        assert first & 0xf800 == 0xf000 and second & 0xf800 == 0xf800
        offset = ((first & 2047) << 12) | ((second & 2047) << 1)
        if offset & 0x400000:
            offset -= 0x800000
        target = site + 4 + offset
        expected = bytes(part['stub']).replace(
            struct.pack('<I', plan['flag_base'] + 3),
            struct.pack('<I', receipt['flag_base'] + 3))
        assert data[target:target + len(expected)] == expected, (hex(site), hex(target))
    return len(parts)


def invoke(cpu, entry, value=0):
    for index, register in enumerate(detection.REGISTERS):
        cpu.reg_write(register, 0x12000000 + index * 0x101)
    cpu.reg_write(reg.UC_ARM_REG_R0, value)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, DONE | 1)
    saved = [cpu.reg_read(r) for r in detection.REGISTERS[4:8]]
    cpu.emu_start(entry | 1, DONE, count=10000)
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == DONE
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
    assert [cpu.reg_read(r) for r in detection.REGISTERS[4:8]] == saved
    return cpu.reg_read(reg.UC_ARM_REG_R0)


def linked_calls(images, plan, receipt):
    detection.HELPERS.add(0xabadc)  # Native diagnostic logger only.
    machines = {}
    for name, data in images.items():
        cpu, trace = detection.machine(data, receipt)
        cpu.mem_map(0x04040000, 0x10000)
        writes, calls = [], []
        cpu.hook_add(UC_HOOK_MEM_READ, lambda c, _a, at, _s, _v, _u:
                     c.mem_write(at, bytes(4)) if at == 0x04042018 else None)
        cpu.hook_add(UC_HOOK_MEM_WRITE, lambda _c, _a, at, _s, value, _u, w=writes:
                     w.append((hex(at), value)) if 0x04042010 <= at <= 0x04042018 else None)
        cpu.hook_add(UC_HOOK_CODE, lambda _c, at, _s, _u, out=calls:
                     out.append(hex(at)) if at in (0xfcc30, 0xfcb24) else None)
        machines[name] = cpu, trace, writes, calls
    records = []
    for fmt, layers in ((1, 2), (5, 2), (5, 3)):
        for low, high in ((0, 1), (0, 8191), (0, 8192), (8192, 16384),
                          (12345, 65535), (0x1b0000, 0x1c0000)):
            for direction in (0, 1):
                for layer in (0, 1, 2):
                    results = {}
                    for name, (cpu, trace, writes, calls) in machines.items():
                        if name == 'native_reference':
                            cpu.mem_write(0x01ff0000, bytes(0x20000))
                            reference = 0xc4 if fmt == 1 else 0xc8
                            cpu.mem_write(receipt['state'], bytes([reference]))
                            cpu.mem_write(receipt['flag_base'] + 3, b'\x01')
                            di = None
                        else:
                            di = detection.execute((cpu, trace), receipt,
                                                   ord('U'), fmt, layers, 0, 0xc0, 1)
                            assert di[0] == 0
                        invoke(cpu, 0x67728)
                        mode = cpu.mem_read(0x01ffa20d, 1)[0]
                        coefficient = invoke(cpu, plan['parameter_profile']['entry'], 4)
                        cpu.mem_write(0x02000b30, struct.pack('<I', low))
                        cpu.mem_write(0x02000b2c, struct.pack('<I', high))
                        cpu.mem_write(0x02000b16, bytes([direction]))
                        cpu.mem_write(0x02000b02, bytes([layer]))
                        writes.clear()
                        calls.clear()
                        result = invoke(cpu, 0xfcccc)
                        results[name] = dict(di=di, mode=mode, coefficient=coefficient,
                                             result=result, writes=writes.copy(), calls=calls.copy(),
                                             working=list(struct.unpack('<II', cpu.mem_read(0x02000b2c, 8))))
                    for field in ('mode', 'coefficient', 'result', 'writes', 'calls', 'working'):
                        assert results['read'][field] == results['native_reference'][field], (
                            fmt, layers, low, high, direction, layer, field)
                    records.append(dict(format=fmt, layers=layers, low=low, high=high,
                                        direction=direction, layer=layer, results=results))
    return records


def command_case(data, profile, state, last, opcode=None, lba=0, count=1):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base, size in ((0, 0x200000), (0x01ff0000, 0x20000),
                       (0x03000000, 0x10000), (0x04040000, 0x20000)):
        cpu.mem_map(base, size)
    cpu.mem_write(0, data)
    cpu.mem_write(profile['state'], bytes([state]))
    cpu.mem_write(profile['available'], b'\x01')
    cpu.mem_write(profile['capacity'], struct.pack('<I', last + 0x100001))
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, DONE | 1)
    if opcode is not None:
        cmd = bytearray(12)
        cmd[0] = opcode
        cmd[2:6] = lba.to_bytes(4, 'big')
        if opcode == 0x28:
            cmd[7:9] = count.to_bytes(2, 'big')
        else:
            cmd[6:10] = count.to_bytes(4, 'big')
        cpu.mem_write(profile['request'], bytes(cmd))
    fifo, outcome, sense = [], [], []

    def visit(c, at, _size, _user):
        if opcode is not None and at == profile['handoff']:
            outcome.append('handoff')
            c.emu_stop()
        elif opcode is not None and at == profile['sense_helper']:
            sense.extend(c.reg_read(r) for r in detection.REGISTERS[:3])
            outcome.append('error')
            c.emu_stop()
        elif at in profile['helpers']:
            c.reg_write(reg.UC_ARM_REG_R0, 0)
            c.reg_write(reg.UC_ARM_REG_PC, c.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.hook_add(UC_HOOK_MEM_WRITE, lambda _c, _a, at, _s, v, _u:
                 fifo.append(v) if at == 0x040400a8 else None)
    cpu.emu_start((profile['entry'] if opcode is not None else profile['cap_entry']) | 1,
                  DONE, count=5000)
    if not outcome:
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == DONE
        native_sense = cpu.mem_read(0x02000df8, 3)
        if opcode is not None and any(native_sense):
            sense.extend((native_sense[2], native_sense[1], native_sense[0]))
            outcome.append('error')
        else:
            outcome.append('returned')
    return dict(outcome=outcome[0], sense=sense, fifo=fifo,
                position=int.from_bytes(cpu.mem_read(profile['position'], 4), 'little'),
                count=int.from_bytes(cpu.mem_read(profile['count'], 4), 'little'))


def commands(images):
    records = []
    for name, data in images.items():
        profile = PROFILES['modern' if name == 'native_uhd' else 'classic']
        for at, opcode, target in ((profile['record'], 0x28, profile['entry']),
                                   (profile['record'] + 8, 0xa8, profile['entry']),
                                   (profile['cap_record'], 0x25, profile['cap_entry'])):
            assert struct.unpack_from('<BBHI', data, at) == (opcode, 2, 0, target | 1)
        for state in (0xc0, 0xc4, 0xc7, 0xc8):
            for last in (0x10000, 0x1ffffff, 0x3ffffff):
                capacity = command_case(data, profile, state, last)
                assert bytes(capacity['fifo']) == last.to_bytes(4, 'big') + b'\0\0\x08\0'
                count_cases = errors = 0
                for opcode in (0x28, 0xa8):
                    for count in (1, 2, 16, 256):
                        for lba in (0, 1, last - count, last - count + 1):
                            result = command_case(data, profile, state, last, opcode, lba, count)
                            assert result['outcome'] == 'handoff'
                            assert result['position'] == lba + 0x100000
                            assert result['count'] == count
                            count_cases += 1
                        invalid = command_case(data, profile, state, last, opcode,
                                               last - count + 2, count)
                        assert invalid['outcome'] == 'error'
                        assert invalid['sense'] == [5, 0x21, 0], invalid
                        errors += 1
                records.append(dict(image=name, state=state, last_lba=last,
                                    capacity_bytes=capacity['fifo'], read_handoffs=count_cases,
                                    out_of_range_errors=errors))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'detection', 'read', 'native', 'plan', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    images = {name: getattr(args, name).read_bytes()
              for name in ('original', 'detection', 'read', 'native')}
    assert digest(images['original']) == detection.OEM_HASH
    assert digest(images['native']) == NATIVE_HASH
    for name in ('detection', 'read'):
        receipt = json.loads(getattr(args, name).with_suffix('.json').read_text())
        assert digest(images[name]) == receipt['output_sha256']
        assert receipt['source_sha256'] == detection.OEM_HASH
    plan = json.loads(args.plan.read_text())
    receipt = json.loads(args.read.with_suffix('.json').read_text())
    installed = verify_stubs(images['read'], plan, receipt)
    chain = linked_calls(dict(detection=images['detection'], read=images['read'],
                              native_reference=images['original']), plan, receipt)
    command_results = commands(dict(oem=images['original'], detection=images['detection'],
                                    read=images['read'], native_uhd=images['native']))
    result = dict(policy=__doc__, cpu='ARM926',
                  script_sha256=digest(Path(__file__).read_bytes()),
                  detection_helper_sha256=digest(Path(detection.__file__).read_bytes()),
                  source_plan_sha256=digest(args.plan.read_bytes()),
                  hashes={name: digest(data) for name, data in images.items()},
                  verified_installed_stubs=installed, linked_call_scenarios=chain,
                  command_scenarios=command_results)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: {installed} installed stubs; {len(chain)} linked scenarios; '
          f'{len(command_results)} capacity responses; '
          f'{sum(r["read_handoffs"] for r in command_results)} READ(10/12) handoffs; '
          f'{sum(r["out_of_range_errors"] for r in command_results)} boundary errors')


if __name__ == '__main__':
    main()
