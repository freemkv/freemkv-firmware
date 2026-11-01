#!/usr/bin/env python3
"""Execute real host SET commands and their consumers in production MediaTek outputs.

Stops at the first native response writer, then uses the observed flag write as
the consumer input. This does not simulate a completed transport reply or optics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'firmware_execution'))
from stages import run, STOP, STACK, unchanged


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(folder, commands):
    report = json.loads((folder / 'modify.json').read_text())
    original, modified = ((folder / name).read_bytes() for name in ('original.bin', 'modified.bin'))
    contracts = report['execution_contracts']
    base, engine = contracts['base'], report['engine']
    records = []
    for name, command in commands:
        record = {'command': name, 'cdb': command, 'cases': 0, 'failures': []}
        records.append(record)
        try:
            # Traverse the installed vendor entry, not a Python SET substitute.
            root, end = base['handler'], base['handler'] + base['handler_len']
            result = run(modified, engine, root, {base['writer']}, base['flags'],
                         memory=[(base['cdb'], bytes(command))],
                         allow_writes=[(base['flags'], base['flags'] + 7)],
                         boundary=lambda at: not root <= at < end)
            assert result['target'] == base['writer'], 'SET did not reach response writer'
            writes = [(a, n, v) for a, n, v in result['writes'] if base['flags'] <= a < base['flags'] + 7]
            assert writes == [(base['flags'] + command[5], 1, command[6])], 'SET flag write'
            feature, setting = writes[0][0] - base['flags'], writes[0][2]
            record['set_trace'] = result['trace']
            record['observed_setting'] = setting
            if name == 'speed_max':
                c = contracts['speed']
                for value in (0, 1, 2, 49, 50, 51, 254, 255, 256):
                    if c['variant'] == 'classic':
                        for maximum in (0, 1, 12, 24, 48, 49, 255):
                            kw = dict(registers={0: value}, memory=[(c['maximum_cell'], bytes([maximum]))])
                            native = run(original, engine, c['site'], {STOP}, base['flags'], **kw)
                            actual = run(modified, engine, c['site'], {STOP}, base['flags'], settings={feature: setting}, **kw)
                            expected = maximum if 0 < maximum <= 48 else value & 255
                            record['cases'] += 1
                            if actual['registers'][0] != expected:
                                record['failures'].append({'value': value, 'maximum': maximum, 'expected': expected, 'actual': actual['registers'][0]})
                            unchanged(native, actual, dead=(0,), flags=False)
                    else:
                        stops = {c['fallthrough'], c['exit']}
                        actual = run(modified, engine, c['site'], stops, base['flags'],
                                     settings={feature: setting}, registers={c['index']: value})
                        expected = c['exit'] if value > 255 else c['fallthrough']
                        record['cases'] += 1
                        if actual['target'] != expected:
                            record['failures'].append({'value': value, 'expected': expected, 'actual': actual['target']})
            else:
                site = contracts['facts']['region_emitter'] + 6
                for mask in (0, 0x55, 255):
                    result = run(modified, engine, site, {STOP}, base['flags'],
                        settings={feature: setting}, registers={0: 0x04001000, 1: 0, 2: 0xa5, 4: 1},
                        memory=[(STACK, bytes([0, 0, 0, mask]) + struct.pack('<II', 0x12345678, STOP | 1))],
                        allow_writes=[(0x04001008, 0x04001009)], allow_stack_delta=12)
                    actual = [v for a, n, v in result['writes'] if a == 0x04001008]
                    expected = [0, 0, 0, 0] if name == 'region_free' else [0xa5, 255 ^ (1 << (int(name[4:]) - 1)), 1, 0]
                    record['cases'] += 1
                    if actual != expected:
                        record['failures'].append({'native_mask': mask, 'expected': expected, 'actual': actual})
                    assert result['sp'] == STACK + 12, 'region return frame'
        except Exception as error:
            record['failures'].append({'error': str(error)})
    return {'source_sha256': sha(original), 'output_sha256': sha(modified),
            'report_sha256': sha((folder / 'modify.json').read_bytes()), 'engine': engine, 'commands': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--host-builder', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    raw = subprocess.check_output([str(args.host_builder.resolve())])
    commands = json.loads(raw)
    assert [name for name, _ in commands] == ['speed_max', 'region_free'] + [f'dvd_{r}' for r in range(1, 9)]
    images = []
    for row in json.loads(args.inventory.read_text())['images']:
        result = check(args.outputs / row['sha256'], commands)
        assert result['source_sha256'] == row['sha256'], 'inventory source mismatch'
        images.append(result)
    failed = sum(bool(c['failures']) for r in images for c in r['commands'])
    receipt = dict(scope='host CDB -> actual SET store -> actual speed/region consumer; response completion and physical effects untested',
        inventory_sha256=sha(args.inventory.read_bytes()), script_sha256=sha(Path(__file__).read_bytes()),
        host_builder_sha256=sha(args.host_builder.read_bytes()), host_commands=commands, images=images,
        failed_commands=failed, cases=sum(c['cases'] for r in images for c in r['commands']))
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'images': len(images), 'cases': receipt['cases'], 'failed_commands': failed}))
    return bool(failed)


if __name__ == '__main__':
    sys.exit(main())
