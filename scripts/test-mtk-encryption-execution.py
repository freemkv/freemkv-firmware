"""Execute AKE, VID and deny continuations; hardware reset calls are ABI simulations."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]


class EncryptionCpu:
    def __init__(self, data, evidence):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for start, size in ((0, 0x200000), (0x01ff0000, 0x20000), (0x03000000, 0x10000)):
            self.cpu.mem_map(start, size)
        self.cpu.mem_write(0, data)
        self.evidence = evidence
        self.cpu.hook_add(UC_HOOK_CODE, self.visit)
        self.stops = set()
        self.reached = None
        self.resets = 0

    def visit(self, cpu, address, _size, _user):
        if address == self.evidence['reset']:
            assert cpu.reg_read(reg.UC_ARM_REG_SP) % 8 == 0
            self.resets += 1
            returning = cpu.reg_read(reg.UC_ARM_REG_LR)
            # A conforming native call may destroy every caller-saved register
            # and NZCV. This checks the detour's actual save/restore obligations.
            for index in (0, 1, 2, 3, 12):
                cpu.reg_write(REGISTERS[index], 0xbad00000 + index)
            cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x50000030)
            cpu.reg_write(reg.UC_ARM_REG_PC, returning)
        elif address in self.stops:
            self.reached = address
            cpu.emu_stop()

    def execute(self, entry, stops, setting, value, state=1, selector=0xff):
        cpu = self.cpu
        self.stops, self.reached, self.resets = set(stops), None, 0
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
        before = [0x76540000 + i * 0x101 for i in range(13)]
        before[0], before[1], before[2] = value, state, 0x28
        for register, initial in zip(REGISTERS, before):
            cpu.reg_write(register, initial)
        cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        cpu.reg_write(reg.UC_ARM_REG_LR, 0x12345)
        cpu.mem_write(self.evidence['flag_slot'], bytes([setting]))
        cpu.mem_write(self.evidence['agid'] + 10, bytes([selector]))
        cpu.emu_start(entry | 1, 0x200000, count=300)
        assert self.reached is not None, (entry, cpu.reg_read(reg.UC_ARM_REG_PC))
        after = [cpu.reg_read(r) for r in REGISTERS]
        assert after[4:12] == before[4:12], (entry, 'callee-saved registers')
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        return {'target': self.reached, 'registers': after,
                'lr': cpu.reg_read(reg.UC_ARM_REG_LR), 'resets': self.resets,
                'flags': cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000,
                'selector': cpu.mem_read(self.evidence['agid'] + 10, 1)[0]}


def review(builder, original, modified, report_path):
    data, patched = original.read_bytes(), modified.read_bytes()
    evidence = json.loads(subprocess.check_output([str(builder.resolve()), str(original),
        'installed-encryption', str(report_path), str(modified)]))
    native, changed = EncryptionCpu(data, evidence), EncryptionCpu(patched, evidence)
    ake_cases = vid_cases = deny_cases = 0
    for setting in (0, 1, 255, 2):
        for value in (0, 1, 3, 63, 64, 127, 128, 191, 192, 255):
            for state in (1, 6):
                old = native.execute(evidence['ake_site'], [evidence['setter']], setting, value, state)
                new = changed.execute(evidence['ake_site'], [evidence['setter']], setting, value, state)
                assert new['registers'][0] == old['registers'][0], ('AGID', value, setting)
                assert new['registers'][1] == (6 if setting == 0 else old['registers'][1])
                assert new['lr'] == old['lr'], ('AKE native return', evidence['variant'])
                expected_resets = int(setting == 0 and evidence['variant'] != 'classic-shift')
                assert new['resets'] == expected_resets
                assert old['resets'] == 0
                ake_cases += 1
        for auth in (0, 1, 5, 6, 7, 12, 255):
            for selector in (0, 63, 64, 127, 128, 255):
                stops = [evidence['accept'], evidence['deny']]
                old = native.execute(evidence['gate_site'], stops, setting, auth, state=0x02005000, selector=selector)
                new = changed.execute(evidence['gate_site'], stops, setting, auth, state=0x02005000, selector=selector)
                assert new['target'] == (evidence['accept'] if setting == 0 else old['target'])
                assert new['registers'][0] == auth
                assert new['registers'] == old['registers'], ('VID live arguments', auth, setting)
                assert new['flags'] == old['flags'], ('VID native comparison flags', auth, setting)
                assert new['resets'] == int(setting == 0)
                assert new['selector'] == (selector & 63 if setting == 0 else selector)
                assert old['resets'] == 0
                vid_cases += 1
    if evidence['deny_site'] is not None:
        site = evidence['deny_site']
        for value in (0, 1, 6, 255):
            old = native.execute(site, [site + 6], 255, value)
            new = changed.execute(site, [site + 6], 255, value)
            assert new['registers'][:3] == old['registers'][:3] == [5, 0x6f, 2]
            assert new['resets'] == 1 and old['resets'] == 0
            deny_cases += 1
    return {'input_sha256': hashlib.sha256(data).hexdigest(),
            'output_sha256': hashlib.sha256(patched).hexdigest(), 'variant': evidence['variant'],
            'ake_cases': ake_cases, 'vid_cases': vid_cases, 'deny_cases': deny_cases,
            'hardware_reset_simulated': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--fw', type=Path)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--hoard', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    records = []
    if args.corpus:
        assert args.hoard and args.artifacts
        for row in json.loads(args.corpus.read_text())['images']:
            if (row.get('capability') or {}).get('status') != 'supported':
                continue
            folder = args.artifacts / row['sha256']
            report = json.loads((folder / 'modify.json').read_text())
            if not report['boot_settings']['encryption']['supported']:
                continue
            record = review(args.builder, args.hoard / row['path'], folder / 'modified.bin',
                            folder / 'modify.json')
            assert record['input_sha256'] == row['sha256']
            assert record['output_sha256'] == row['capability']['output_sha256']
            records.append(record)
            if len(records) % 25 == 0:
                print(f'{len(records)} encryption inputs passed', flush=True)
    else:
        assert args.fw
        fixtures = ROOT / 'crates/freemkv-fw/tests/fixtures'
        with tempfile.TemporaryDirectory(prefix='freemkv-encryption-cpu-') as temp:
            for name in ('BU40N_OEM_1.00.bin', 'BE14NU40_MT1939_JB7_1.01.bin'):
                original, modified = fixtures / name, Path(temp) / name
                result = subprocess.run([str(args.fw.resolve()), 'modify', str(original),
                    str(modified), '--json', '--audit'], capture_output=True, text=True, check=True)
                report = Path(temp) / f'{name}.json'
                report.write_text(result.stdout)
                records.append(review(args.builder, original, modified, report))
    if args.output:
        args.output.write_text(json.dumps({'images': records}, indent=2) + '\n')
    count = sum(r['ake_cases'] + r['vid_cases'] + r['deny_cases'] for r in records)
    print(f'PASS: {len(records)} inputs; {count} AKE/VID/deny comparisons (hardware reset simulated)')


if __name__ == '__main__':
    main()
