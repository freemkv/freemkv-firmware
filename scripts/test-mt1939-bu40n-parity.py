"""Compare installed MT1939 U/1 and U/5 recognition with actual BU40N OEM code.

DI bytes are supplied at the parser boundary. Optical acquisition is not
emulated. Only two/three-layer U/1 and U/5 recognition outcomes are compared;
the separate BU40N U flag and downstream hardware policy are not ported here.
"""
import argparse
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

BU40N = '221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4'
BH16 = '43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3'
PROFILES = {
    'bu40n': dict(start=0xe0d6a, state=0x01ff9e04, stack_di=0x44,
                  success=0xe0f0e, failure=0xe0e74, logger=0xcb3c0,
                  format_flag=0x02000b6d),
    'classic': dict(start=0x10a846, state=0x01ff9dd3, stack_di=12,
                    success=0x10a990, failure=0x10a91c, logger=0xf5ce0,
                    format_flag=0x02000b58),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def machine(data, profile):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base, size in ((0, 0x200000), (0x01ff0000, 0x20000),
                       (0x03000000, 0x10000)):
        cpu.mem_map(base, size)
    cpu.mem_write(0, data)
    stopped = []

    def visit(c, at, _size, _user):
        if at in (profile['success'], profile['failure']):
            stopped.append(at)
            c.emu_stop()
        elif at == profile['logger']:
            c.reg_write(reg.UC_ARM_REG_PC, c.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)

    def execute(state, attributes, fmt, layers, flag=1, prefix=b'BD'):
        stopped.clear()
        cpu.mem_write(0x01ff0000, bytes(0x20000))
        cpu.mem_write(0x03000000, bytes(0x10000))
        cpu.mem_write(profile['state'], bytes([state]))
        cpu.mem_write(0x02001213, bytes([flag]))
        cpu.reg_write(reg.UC_ARM_REG_R4, profile['state'])
        cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        cpu.mem_write(0x03008000 + profile['stack_di'],
                      prefix + b'\0\0U' + bytes([attributes, layers << 4, fmt]))
        cpu.emu_start(profile['start'] | 1, 0x200000, count=3000)
        assert len(stopped) == 1, hex(cpu.reg_read(reg.UC_ARM_REG_PC))
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        return (stopped[0] == profile['success'],
                cpu.mem_read(profile['state'], 1)[0],
                cpu.mem_read(profile['format_flag'], 1)[0])

    return execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'candidate', 'receipt', 'bu40n', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    original, candidate, bu40n = [p.read_bytes() for p in
                                   (args.original, args.candidate, args.bu40n)]
    receipt = json.loads(args.receipt.read_text())
    assert digest(original) == BH16 == receipt['source_sha256']
    assert digest(bu40n) == BU40N
    assert digest(candidate) == receipt['output_sha256']
    assert receipt['read_path'] and receipt['bu40n_attribute_validation']
    native = machine(bu40n, PROFILES['bu40n'])
    installed = machine(candidate, PROFILES['classic'])
    oem = machine(original, PROFILES['classic'])
    accepted = rejected = preservation = 0
    samples = []
    for state in range(256):
        for attributes in (0, 0x10, 0x20, 0x30):
            for fmt in (1, 5):
                for layers in (2, 3):
                    inputs = state, attributes, fmt, layers
                    expected, actual = native(*inputs), installed(*inputs)
                    assert expected == actual, (inputs, expected, actual)
                    accepted += actual[0]
                    rejected += not actual[0]
                    if state in (0xc0, 0xc7, 0xc8, 0xe8) and layers == 2:
                        samples.append(dict(initial=state, attributes=attributes,
                                            format=fmt, layers=layers,
                                            accepted=actual[0], state=actual[1]))
                    for flag in (0, 2, 255):
                        assert installed(*inputs, flag=flag) == oem(*inputs, flag=flag)
                        preservation += 1
    # Bad DI prefixes must retain the classic native failure behavior.
    for prefix in (b'XD', b'BX', b'\0\0'):
        assert installed(0xc0, 0, 5, 2, prefix=prefix) == oem(0xc0, 0, 5, 2, prefix=prefix)
        preservation += 1
    result = dict(policy=__doc__, cpu='ARM926',
                  source_sha256=digest(original), candidate_sha256=digest(candidate),
                  bu40n_sha256=digest(bu40n), native_cases=accepted + rejected,
                  accepted=accepted, rejected=rejected, preservation_cases=preservation,
                  samples=samples)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: {accepted + rejected} BU40N comparisons; '
          f'{preservation} classic preservation cases')


if __name__ == '__main__':
    main()
