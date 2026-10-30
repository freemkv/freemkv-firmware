"""Execute both explicit media-gate hooks from every retained Modify output."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]


class MediaCpu:
    def __init__(self, data):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.cpu.mem_map(0, 0x200000)
        self.cpu.mem_write(0, data)
        self.cpu.mem_map(0x01ff0000, 0x20000)
        self.cpu.mem_map(0x03000000, 0x10000)
        self.stop = None
        self.reached = False
        self.cpu.hook_add(UC_HOOK_CODE, self.visit)

    def visit(self, cpu, address, _size, _user):
        if address == self.stop:
            self.reached = True
            cpu.emu_stop()

    def execute(self, site, slot, setting, retired, media_class):
        cpu = self.cpu
        self.stop, self.reached = site + 4, False
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
        before = [0x76540000 + i * 0x101 for i in range(13)]
        before[2] = 0x02001000
        for register, value in zip(REGISTERS, before):
            cpu.reg_write(register, value)
        cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        cpu.reg_write(reg.UC_ARM_REG_LR, 0x12345)
        cpu.mem_write(0x02001007, bytes([media_class]))
        cpu.mem_write(slot, bytes([setting, retired]))
        cpu.emu_start(site | 1, 0x200000, count=100)
        assert self.reached, (site, 'missing native continuation')
        after = [cpu.reg_read(r) for r in REGISTERS]
        assert after[0] == media_class
        assert all(after[i] == before[i] for i in range(13) if i not in (0, 3))
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        return cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--hoard', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = cases = 0
    with args.output.open('w') as output:
        for row in json.loads(args.corpus.read_text())['images']:
            if (row.get('capability') or {}).get('status') != 'supported':
                continue
            folder = args.artifacts / row['sha256']
            report_path = folder / 'modify.json'
            report = json.loads(report_path.read_text())
            facts = {k: v for lever in report['levers'] for k, v in lever['facts'].items()}
            sites = [facts.get('bd_site', 0), facts.get('uhd_site', 0)]
            if not any(sites):
                continue
            assert all(sites), 'only one explicit media gate was installed'
            original, modified = args.hoard / row['path'], folder / 'modified.bin'
            data, patched = original.read_bytes(), modified.read_bytes()
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            assert hashlib.sha256(patched).hexdigest() == row['capability']['output_sha256']
            # The source-bound HRL evidence resolves the shared flag table from
            # the actual installed literal; Unrestricted precedes HRL by two bytes.
            evidence = json.loads(subprocess.check_output([
                str(args.builder.resolve()), str(original), 'installed-hrl',
                str(report_path), str(modified)]))
            slot = evidence['flag_slot'] - 2
            native, changed = MediaCpu(data), MediaCpu(patched)
            count = 0
            for site in sites:
                for setting in (0, 1, 255, 2):
                    for retired in (0, 1, 255):
                        for media_class in range(256):
                            expected = native.execute(site, slot, setting, retired, media_class)
                            actual = changed.execute(site, slot, setting, retired, media_class)
                            if setting == 0:
                                assert not actual & 0x40000000, (row['sha256'], site, media_class, 'Off accepted')
                            else:
                                assert actual == expected, (row['sha256'], site, media_class, 'native flags')
                            count += 1
            output.write(json.dumps({'input_sha256': row['sha256'],
                'output_sha256': row['capability']['output_sha256'],
                'sites': sites, 'cases': count, 'native_flags': 'passed',
                'registers': 'passed', 'stack': 'passed', 'off_refusal': 'passed'}) + '\n')
            output.flush()
            inputs += 1
            cases += count
            if inputs % 5 == 0:
                print(f'{inputs} inputs; {cases} comparisons', flush=True)
    print(f'PASS: {inputs} inputs; {cases} explicit BD/UHD comparisons')


if __name__ == '__main__':
    main()
