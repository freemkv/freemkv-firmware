"""Compare emitted HRL detours with their native continuations on an ARM CPU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
ROOT = Path(__file__).resolve().parents[1]


def execute(data, site, revoke, slot, flag, value, clean_end=None):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, data)
    cpu.mem_map(0x01ff0000, 0x20000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
    for index, register in enumerate(REGISTERS):
        cpu.reg_write(register, 0x02001000 + index * 0x100 if index >= 4 else 0x76540000 + index * 0x101)
    cpu.reg_write(reg.UC_ARM_REG_R0, value)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, 0x12345)
    cpu.mem_write(slot, bytes([flag]))
    reached = []

    def stop(machine, address, _size, _user):
        if address in (clean_end if clean_end is not None else site + 4, revoke):
            reached.append(address)
            machine.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, stop)
    cpu.emu_start(site | 1, 0x200000, count=100)
    assert len(reached) == 1, (site, reached)
    return (reached[0], [cpu.reg_read(r) for r in REGISTERS],
            cpu.reg_read(reg.UC_ARM_REG_SP), cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000)


def review(builder, original, modified, report_path):
    original_data, modified_data = original.read_bytes(), modified.read_bytes()
    evidence = json.loads(subprocess.check_output([
        str(builder.resolve()), str(original), 'installed-hrl', str(report_path), str(modified)]))
    assert evidence['sites'], 'no emitted HRL sites'
    cases = 0
    for item in evidence['sites']:
        site, revoke = item['site'], item['revoke']
        for flag in (0, 1, 255, 2):
            for value in (0, 1, 2, 255, 0x80000000):
                native = execute(original_data, site, revoke, evidence['flag_slot'], flag, value)
                patched = execute(modified_data, site, revoke, evidence['flag_slot'], flag, value)
                assert patched[0] == (site + 4 if flag == 0 else native[0])
                assert patched[1] == native[1], (site, flag, value, 'register preservation')
                assert patched[2] == native[2], (site, 'stack preservation')
                if flag != 0:
                    assert patched[3] == native[3], (site, 'native comparison flags')
                if flag == 0:
                    # A skipped HRL result must flow into the same clean native
                    # behavior as a genuine clean result, beyond the hook return.
                    clean = execute(original_data, site, revoke, evidence['flag_slot'], flag, 0,
                                    item['clean_end'])
                    bypassed = execute(modified_data, site, revoke, evidence['flag_slot'], flag, value,
                                       item['clean_end'])
                    assert bypassed == clean, (site, value, 'native clean workflow')
                cases += 1
    return {'input_sha256': hashlib.sha256(original_data).hexdigest(),
            'output_sha256': hashlib.sha256(modified_data).hexdigest(),
            'sites': evidence['sites'], 'cases': cases}


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
            if not report['boot_settings']['hrl']['supported']:
                continue
            record = review(args.builder, args.hoard / row['path'],
                            folder / 'modified.bin', folder / 'modify.json')
            assert record['input_sha256'] == row['sha256']
            assert record['output_sha256'] == row['capability']['output_sha256']
            records.append(record)
    else:
        assert args.fw
        fixtures = ROOT / 'crates/freemkv-fw/tests/fixtures'
        with tempfile.TemporaryDirectory(prefix='freemkv-hrl-cpu-') as temp:
            for name in ('BU40N_OEM_1.00.bin', 'BE14NU40_MT1939_JB7_1.01.bin'):
                original = fixtures / name
                modified = Path(temp) / name
                result = subprocess.run([str(args.fw.resolve()), 'modify', str(original),
                                         str(modified), '--json', '--audit'],
                                        capture_output=True, text=True, check=True)
                report = Path(temp) / f'{name}.json'
                report.write_text(result.stdout)
                records.append(review(args.builder, original, modified, report))
    if args.output:
        args.output.write_text(json.dumps({'images': records}, indent=2) + '\n')
    print(f"PASS: {len(records)} inputs; {sum(r['cases'] for r in records)} HRL continuation/register/stack comparisons")


if __name__ == '__main__':
    main()
