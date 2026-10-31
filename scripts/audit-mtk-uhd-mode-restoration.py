"""Bind each image's native calibration defaults and execute its restore blocks.

Compare six native parameter-loading blocks with the UHD reference on ARM926.
Each image supplies its own default addresses and setter; no calibration values
are copied from another image. Inputs and passive MMIO are supplied explicitly.
This does not execute mode acquisition, clock changes or physical side effects.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import arm_const as reg

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('arithmetic', Path(__file__).with_name('audit-mtk-uhd-mode-arithmetic.py'))
arithmetic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arithmetic)
PARAMETERS = (0, 0x10, 0x20, 1, 0x11, 0x21)
VALUES = [(high << 8) | low for high in (0, 1, 0x7f, 0x80, 0xff) for low in (0, 1, 15, 255)]
SP = arithmetic.SP


def literal(data, at):
    op = struct.unpack_from('<H', data, at)[0]
    assert op & 0xff00 == 0x4900
    value = struct.unpack_from('<I', data, ((at+4)&~3)+(op&255)*4)[0]
    assert 0x01ff0000 <= value < 0x02010000
    return value


def block(data, at, parameter, setter):
    if at < 0 or at+20 > len(data) or data[at+1] != 0x49:
        return False
    if data[at+2:at+10] != bytes.fromhex('6b46087818704878'):
        return False
    if data[at+10:at+16] != bytes([parameter, 0x21])+bytes.fromhex('58700098'):
        return False
    call = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[at+16:at+20], at+16, count=1), None)
    return call and call.mnemonic == 'bl' and int(call.op_str[1:], 0) == setter


def bind(data, parameters, interval=None):
    signature = bytes.fromhex('6b46087818704878002158700098')
    found = []
    at = data.find(signature)
    while at >= 0:
        start = at-2
        if at % 2 == 0 and (interval is None or interval[0] <= start < interval[1]) and all(block(data, start+i*20, p, parameters['setter']) for i, p in enumerate(PARAMETERS[:3])):
            ends = [end for end in range(start+60, start+0x100, 2)
                    if all(block(data, end+i*20, p, parameters['setter']) for i, p in enumerate(PARAMETERS[3:]))]
            if len(ends) == 1:
                sites = [start+i*20 for i in range(3)]+[ends[0]+i*20 for i in range(3)]
                found.append([{'parameter': p, 'site': site, 'default_address': literal(data, site)}
                              for p, site in zip(PARAMETERS, sites)])
        at = data.find(signature, at+1)
    assert len(found) == 1, found
    assert len({x['default_address'] for x in found[0]}) == 6
    return found[0]


class Restore(arithmetic.Parameters):
    def __init__(self, data, contract):
        super().__init__(data, contract)
        self.cpu.mem_map(0x01ff0000, 0x20000)
        self.initial = self.cpu.context_save()

    def step(self, cpu, at, size, user):
        if at == self.end:
            cpu.emu_stop()

    def write(self, cpu, access, at, size, value, user):
        if SP-256 <= at and at+size <= SP+4:
            return
        assert self.page <= at and at+size <= self.page+0x1000, (hex(at), size)
        self.writes.append((at, size, value))

    def run(self, binding, value, seed, upper):
        c = self.cpu
        c.context_restore(self.initial)
        c.mem_write(SP-256, bytes(256))
        c.mem_write(SP, struct.pack('<I', upper << 16))
        c.mem_write(self.page, bytes((i*37+seed)&255 for i in range(0x1000)))
        c.mem_write(binding['default_address'], value.to_bytes(2, 'little'))
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        saved = {getattr(reg, f'UC_ARM_REG_R{i}'): 0x12340000+i for i in range(4, 12)}
        for register, v in saved.items():
            c.reg_write(register, v)
        self.end = binding['site']+20
        self.writes = []
        c.emu_start(binding['site'] | 1, self.end+2, count=10000)
        assert c.reg_read(reg.UC_ARM_REG_PC) == self.end
        assert c.reg_read(reg.UC_ARM_REG_SP) == SP
        assert all(c.reg_read(register) == v for register, v in saved.items())
        assert bytes(c.mem_read(SP, 4)) == struct.pack('<I', (upper << 16) | value)
        assert self.writes
        return (tuple(self.writes), hashlib.sha256(bytes(c.mem_read(self.page, 0x1000))).hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hoard', type=Path, required=True)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--reference', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    rows = json.loads(a.scan.read_text())['images']
    reference_path = next(a.hoard.rglob(a.reference+'.bin'))
    reference = reference_path.read_bytes()
    assert hashlib.sha256(reference).hexdigest() == a.reference
    inputs = [{'sha256': a.reference, 'path': str(reference_path.relative_to(a.hoard))}]+rows
    expected, output, count = None, [], 0
    for row in inputs:
        data = (a.hoard/row['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        parameters = arithmetic.bind_parameters(data)
        interval = None
        if row['sha256'] == a.reference:
            stage_spec = importlib.util.spec_from_file_location('transition', Path(__file__).with_name('audit-mtk-uhd-mode-transition.py'))
            stage_module = importlib.util.module_from_spec(stage_spec)
            stage_spec.loader.exec_module(stage_module)
            stage = stage_module.bind(data)
            assert stage and stage['variant'] == 'coordinate_phase_transition'
            stage_module.bind_frame(data, stage)
            interval = (stage['leave'], stage['leave']+0x200)
        defaults = bind(data, parameters, interval)
        # A broken argument load or setter call must invalidate this binding.
        for offset in (2, 16):
            broken = bytearray(data)
            site = defaults[0]['site']+offset
            broken[site:site+2] = bytes.fromhex('c046')
            try:
                bind(broken, parameters, interval)
            except AssertionError:
                pass
            else:
                raise AssertionError(('corrupted restoration accepted', row['sha256'], offset))
        runner = Restore(data, parameters)
        results = []
        for binding in defaults:
            for value in VALUES:
                for seed in (0, 0xa5):
                    for upper in (0, 0xffff):
                        results.append(runner.run(binding, value, seed, upper))
                        count += 1
        if expected is None:
            expected = results
        assert results == expected, row['sha256']
        output.append({'sha256': row['sha256'], 'parameters': parameters,
                       'defaults': defaults, 'executions': len(results),
                       'refused_mutations': 2,
                       'observations_sha256': hashlib.sha256(json.dumps(results).encode()).hexdigest()})
        print('PASS', row['sha256'][:12], len(results), flush=True)
    a.output.write_text(json.dumps({'scope': __doc__, 'cpu': 'ARM926', 'result': 'pass',
        'reference': a.reference, 'executions': count, 'images': output,
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'values': VALUES, 'mmio_seeds': [0, 0xa5], 'scratch_upper_halves': [0, 0xffff],
        'refused_mutations': len(inputs)*2}, indent=2)+'\n')
    print(f'PASS: {count} native restoration block executions across {len(output)} images')


if __name__ == '__main__':
    main()
