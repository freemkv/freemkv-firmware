"""Execute the installed DI parent on ARM926 to verify profile preservation.

DI data and hardware readiness are supplied, so this proves software behavior
and OEM preservation, not physical acquisition or successful disc detection.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from unicorn import UC_HOOK_CODE

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('detection', Path(__file__).with_name('test-mt1939-detection.py'))
    detection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detection)
    machines = []
    for path in (args.baseline, args.candidate):
        data = path.read_bytes()
        receipt = json.loads(path.with_suffix('.json').read_text())
        assert hashlib.sha256(data).hexdigest() == receipt['output_sha256']
        assert receipt['source_sha256'] == detection.OEM_HASH
        machine = detection.machine(data, receipt)
        # Bound source fixture's mode cell; exact addresses are test landmarks.
        machine[0].hook_add(UC_HOOK_CODE, lambda c, at, _size, _user:
            c.mem_write(0x01ffa20d, b'\x1c') if at == receipt['entry'] else None)
        machines.append((machine, receipt))
    assert not machines[0][1]['reacquisition_mode']
    assert machines[1][1]['reacquisition_mode']
    cases = changed = 0
    for state in range(256):
        for flag in (0, 1, 2, 255):
            for nzcv in (0, 3, 8, 15):
                results = []
                for machine, receipt in machines:
                    result = detection.execute(machine, receipt, ord('U'), 5, 2, 0, state, flag, nzcv=nzcv)
                    ram = bytearray(machine[0].mem_read(0x01ff0000, 0x20000))
                    mode = ram[0xa20d]
                    ram[0xa20d] = 0
                    results.append((result, ram, mode))
                assert results[0][:2] == results[1][:2], (state, flag, nzcv)
                if state == 0xc7 and flag == 1:
                    assert (results[0][2], results[1][2]) == (7, 28)
                    changed += 1
                else:
                    assert results[0][2] == results[1][2], (state, flag, nzcv)
                cases += 1
    args.output.write_text(json.dumps({'scope':__doc__, 'cases':cases,
        'changed_cases':changed, 'baseline_sha256':machines[0][1]['output_sha256'],
        'candidate_sha256':machines[1][1]['output_sha256'], 'cpu':'ARM926'}, indent=2) + '\n')
    print(f'PASS: {cases} complete DI-parent comparisons; only C7/On profile changes from 7 to 28; saved registers and stack preserved')


if __name__ == '__main__':
    main()
