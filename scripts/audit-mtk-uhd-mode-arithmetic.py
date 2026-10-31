"""Compare the native mode-entry coefficient helper across the older 24 images.

The observed UHD entry supplies scale -3 and option 0. Execute that exact native
helper, its lookup and division code, across every signed high-byte value and
four low-byte values. No helper call or arithmetic result is simulated. This
also compares native parameter 0x10/0x11 getters/setters on passive register memory,
including exact write effects. This does not prove physical hardware behavior
or mode acquisition.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

ENTRY = bytes.fromhex('40060016')
BODY = bytes.fromhex('37b582b06b46597b1500090604d5597b01244942597300e00024')
SP, RETURN = 0x03008000, 0x0300fff0
COEFFICIENTS = [(high << 8) | low for high in range(256) for low in (0, 1, 0x55, 0xff)]


def instruction(data, at):
    return next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[at:at+4], at, count=1))


def bind(data):
    found = []
    body = data.find(BODY)
    while body >= 0:
        if body % 2 == 0:
            site = body+len(BODY)
            variant = 'wrapper'
            entries = []
            if data[site:site+len(ENTRY)] == ENTRY:
                variant = 'inline_scale'
                entries = [body]
                site += len(ENTRY)
            else:
                at = data.find(ENTRY)
                while at >= 0:
                    if at % 2 == 0:
                        branch = instruction(data, at+4)
                        if branch.mnemonic == 'b' and int(branch.op_str.removeprefix('#'), 0) == body:
                            entries.append(at)
                    at = data.find(ENTRY, at+1)
            if entries:
                assert len(entries) == 1, entries
                lookup = instruction(data, site)
                divide = instruction(data, site+0x12)
                assert lookup.mnemonic == 'bl' and divide.mnemonic == 'blx'
                assert instruction(data, site+0x4c).mnemonic == 'pop'
                found.append({'entry': entries[0], 'body': body, 'variant': variant,
                              'factor_return': site+4,
                              'lookup': int(lookup.op_str.removeprefix('#'), 0),
                              'division': int(divide.op_str.removeprefix('#'), 0)})
        body = data.find(BODY, body+1)
    assert len(found) == 1, found
    return found[0]


def bind_parameters(data):
    # Literal load displacement varies; the complete register setup is fixed.
    getter_tail = bytes.fromhex('00213200ff320307340000913100403c1b0f6132ff252039')
    getters = [at-4 for at in range(4, len(data)-len(getter_tail), 2)
               if data[at:at+len(getter_tail)] == getter_tail
               and data[at-4:at-2] == bytes.fromhex('78b5')
               and data[at-1] == 0x4e]
    setter_prefix = bytes.fromhex('f3b585b06b46187d0f07ff260407240f200423050390200104936b460290587d2203019222020092')
    setters = []
    at = data.find(setter_prefix)
    while at >= 0:
        if at % 2 == 0:
            setters.append(at)
        at = data.find(setter_prefix, at+1)
    assert len(getters) == len(setters) == 1, (getters, setters)
    get, put = getters[0], setters[0]
    def literal(at):
        op = struct.unpack_from('<H', data, at)[0]
        assert op & 0xf800 == 0x4800
        return struct.unpack_from('<I', data, ((at+4)&~3)+(op&255)*4)[0]
    base = literal(get+2)
    assert base == literal(put+0x28)
    get_switch, put_switch = instruction(data, get+0x1c), instruction(data, put+0x36)
    assert get_switch.mnemonic == put_switch.mnemonic == 'blx'
    assert get_switch.op_str == put_switch.op_str
    return {'getter': get, 'setter': put, 'register_base': base,
            'switch_dispatcher': int(get_switch.op_str.removeprefix('#'), 0)}


class Parameters:
    def __init__(self, data, contract):
        self.contract = contract
        self.page = contract['register_base'] & ~0xfff
        assert 0x04000000 <= self.page < 0x05000000
        c = self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        c.mem_map(0, 0x200000)
        c.mem_write(0, data)
        c.mem_map(0x03000000, 0x10000)
        c.mem_map(self.page, 0x1000)
        c.hook_add(UC_HOOK_CODE, self.step)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.initial = c.context_save()

    def step(self, c, at, size, user):
        if at == RETURN:
            c.emu_stop()

    def write(self, c, access, at, size, value, user):
        if SP-256 <= at and at+size <= SP:
            return
        assert self.page <= at and at+size <= self.page+0x1000, (hex(at), size)
        self.writes.append((at, size, value))

    def call(self, role, r0, r1=0):
        c = self.cpu
        c.context_restore(self.initial)
        c.mem_write(SP-256, bytes(256))
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        c.reg_write(reg.UC_ARM_REG_LR, RETURN | 1)
        c.reg_write(reg.UC_ARM_REG_R0, r0)
        c.reg_write(reg.UC_ARM_REG_R1, r1)
        c.reg_write(reg.UC_ARM_REG_R2, 0)
        saved = {getattr(reg, f'UC_ARM_REG_R{i}'): 0x12340000+i for i in range(4, 12)}
        for register, value in saved.items():
            c.reg_write(register, value)
        c.emu_start(self.contract[role] | 1, RETURN+2, count=10000)
        assert c.reg_read(reg.UC_ARM_REG_PC) == RETURN
        assert c.reg_read(reg.UC_ARM_REG_SP) == SP
        assert all(c.reg_read(register) == value for register, value in saved.items())
        return c.reg_read(reg.UC_ARM_REG_R0)

    def run(self, parameter, coefficient, seed):
        c = self.cpu
        c.mem_write(self.page, bytes((i*37+seed)&255 for i in range(0x1000)))
        self.writes = []
        before = self.call('getter', parameter)
        assert not self.writes
        self.call('setter', coefficient, parameter)
        actual = self.call('getter', parameter)
        assert actual == coefficient & 0xff0f, (parameter, coefficient, actual)
        assert self.writes
        return before, actual, tuple(self.writes), hashlib.sha256(bytes(c.mem_read(self.page, 0x1000))).hexdigest()


class Native:
    def __init__(self, data, contract):
        self.contract = contract
        c = self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        c.mem_map(0, 0x200000)
        c.mem_write(0, data)
        c.mem_map(0x03000000, 0x10000)
        c.hook_add(UC_HOOK_CODE, self.step)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.initial = c.context_save()

    def step(self, c, at, size, user):
        if at == self.contract['factor_return']:
            self.factor = c.reg_read(reg.UC_ARM_REG_R0)
        if at == RETURN:
            c.emu_stop()

    def write(self, c, access, at, size, value, user):
        assert SP-256 <= at and at+size <= SP, ('unexpected native write', hex(at), size)

    def run(self, coefficient):
        c = self.cpu
        c.context_restore(self.initial)
        c.mem_write(SP-256, bytes(256))
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        c.reg_write(reg.UC_ARM_REG_LR, RETURN | 1)
        c.reg_write(reg.UC_ARM_REG_R0, 0xfffffffd)
        c.reg_write(reg.UC_ARM_REG_R1, coefficient)
        c.reg_write(reg.UC_ARM_REG_R2, 0)
        saved = {getattr(reg, f'UC_ARM_REG_R{i}'): 0x12340000+i for i in range(4, 12)}
        for register, value in saved.items():
            c.reg_write(register, value)
        self.factor = None
        c.emu_start(self.contract['entry'] | 1, RETURN+2, count=10000)
        assert c.reg_read(reg.UC_ARM_REG_PC) == RETURN
        assert c.reg_read(reg.UC_ARM_REG_SP) == SP
        assert all(c.reg_read(register) == value for register, value in saved.items())
        assert self.factor is not None
        return c.reg_read(reg.UC_ARM_REG_R0), self.factor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hoard', type=Path, required=True)
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--gaps', type=Path, required=True)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    scan = {x['sha256']: x for x in json.loads(args.scan.read_text())['images']}
    older = [x['sha256'] for x in json.loads(args.gaps.read_text())['images']
             if x['media_pipeline_gaps']]
    assert len(older) == 24, len(older)
    results, expected, count = [], None, 0
    parameter_expected, parameter_count = None, 0
    for digest in [args.reference] + older:
        source = scan[digest]
        data = (args.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        try:
            contract = bind(data)
        except AssertionError as error:
            raise AssertionError((digest, error.args)) from error
        worker = Native(data, contract)
        values = [worker.run(value) for value in COEFFICIENTS]
        if expected is None:
            expected = values
        assert values == expected, digest
        # Both bytes matter: compare signed coefficient arithmetic and preserve
        # the low byte for all chosen values, including signed boundaries.
        assert all(output & 255 == value & 255 for value, (output, factor) in zip(COEFFICIENTS, values))
        packed = b''.join(struct.pack('<II', *value) for value in values)
        results.append({'sha256': digest, 'binding': contract, 'cases': len(values),
                        'result_sha256': hashlib.sha256(packed).hexdigest(),
                        'lookup_factors': sorted({factor for output, factor in values})})
        count += len(values)
        parameter_contract = bind_parameters(data)
        parameters = Parameters(data, parameter_contract)
        parameter_values = [parameters.run(parameter, (high << 8) | low, seed)
                            for parameter in (0x10, 0x11) for seed in (0, 0xa5)
                            for high in range(256) for low in (0, 1, 15)]
        if parameter_expected is None:
            parameter_expected = parameter_values
        assert parameter_values == parameter_expected, digest
        results[-1]['parameters'] = {'binding': parameter_contract, 'cases': len(parameter_values),
            'result_sha256': hashlib.sha256(json.dumps(parameter_values).encode()).hexdigest()}
        parameter_count += len(parameter_values)
    args.output.write_text(json.dumps({'scope': __doc__, 'cpu': 'ARM926',
        'scale': -3, 'option': 0, 'signed_high_byte': 'all 256 encodings',
        'low_bytes': [0, 1, 0x55, 0xff], 'executions': count, 'parameter_round_trips': parameter_count, 'images': results}, indent=2)+'\n')
    print(f'PASS: {count} native coefficient executions and {parameter_count} native parameter round trips; reference plus all 24 older images agree')


if __name__ == '__main__':
    main()
