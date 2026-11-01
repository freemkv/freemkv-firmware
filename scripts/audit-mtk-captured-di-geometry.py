#!/usr/bin/env python3
"""Compare native geometry arithmetic with saved disc-structure/capacity pairs.

Read-only offline use of local captures. Executes actual record copies and native
geometry initialization as separate stages with explicit DI-ready status input.
Captured bytes are inputs, not a model of optical acquisition. Capture filenames
alone do not authenticate the drive firmware used when the files were recorded.
"""
import argparse
import importlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
consumer = importlib.import_module('audit-mtk-di-record-consumers')
run, sha, STOP = consumer.run, consumer.sha, consumer.STOP


def execute(folder, config, worker, media, records, variant='modified', setting=1,
            initial_di=None, initial_nzcv=0xa0000000, copy_media=None):
    assert variant in ('original', 'modified')
    original = (folder / 'original.bin').read_bytes()
    data = (folder / (variant + '.bin')).read_bytes()
    assert sha(original) == folder.name
    report = json.loads((folder / 'modify.json').read_text())
    flags = report['execution_contracts']['base']['flags']; engine = report['engine']
    base, src, dest = 0x02010000, 0x1000, 0x2000
    copy = run(data, engine, worker['copy_block'], {worker['copy_stop']}, flags,
        settings={3: setting},
        initial_nzcv=initial_nzcv,
        registers={4:src, 5:worker['di']},
        memory=[(worker['translation'], struct.pack('<I', base)), (worker['di'], struct.pack('<I', dest)),
                (config['state'], bytes([media if copy_media is None else copy_media])),
                (base + src, records), (base + dest, initial_di if initial_di is not None else bytes(0x150)), (0x04050010, bytes(4))],
        allow_writes=[(base + dest, base + dest + 0x150), (0x04050010, 0x04050014)],
        observe_memory=[(base + dest, 0x150)], strict_reads=True)
    memory = [(a, bytes(n)) for a, n in config['controls'] + config['outputs']]
    memory += [(config['state'], bytes([media])), (config['status'], b'\x02'),
               (worker['translation'], struct.pack('<I', base)), (worker['di'], struct.pack('<I', dest)),
               (base + dest, bytes.fromhex(copy['memory'][str(base + dest)]))]
    observed = config['outputs'] + [(config['state'], 1)]
    result = run(data, engine, config['entry'], {STOP}, flags, memory=memory,
                 settings={3: setting},
                 initial_nzcv=initial_nzcv,
                 allow_writes=[(a, a + n) for a, n in observed], observe_memory=observed, strict_reads=True)
    descriptor = bytes.fromhex(result['memory'][str(config['descriptor'])])
    start = struct.unpack_from('<I', descriptor, 4)[0]
    end = int.from_bytes(bytes.fromhex(result['memory'][str(config['end_cell'])]), 'little')
    assert result['registers'][0] == 1
    return dict(source_sha256=sha(original), output_sha256=sha(data), label=config['label'],
                variant=variant, unrestricted_setting=setting, observed_memory=result['memory'],
                copy_state=media if copy_media is None else copy_media,
                registers=result['registers'], nzcv=result['nzcv'], sp=result['sp'],
                copied_di=copy['memory'][str(base + dest)],
                state=media, descriptor=descriptor[:16].hex(), first_address=start,
                exclusive_end=end, computed_sector_count=(end - start) & 0xffffffff,
                copy_trace=copy['trace'], initialization_trace=result['trace'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--outputs', type=Path, required=True)
    p.add_argument('--worker-receipt', type=Path, required=True)
    p.add_argument('--captures', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    a = p.parse_args()
    workers = {r['source_sha256']:r for r in json.loads(a.worker_receipt.read_text())['images']}
    rows = []
    for path in sorted(a.captures.glob('*/ds_00.bin')):
        capacity_path = path.with_name('capacity.bin')
        if not capacity_path.exists():
            continue
        raw, capacity = path.read_bytes(), capacity_path.read_bytes()
        assert len(capacity) == 8 and int.from_bytes(capacity[4:], 'big') == 2048
        assert len(raw) >= 196 and raw[4:6] == b'DI' and raw[12:14] == b'BD'
        records = raw[4:196]
        identifier, layers, fmt = chr(records[10]), records[12] >> 4, records[13]
        if identifier == 'U' and fmt == 5 and layers in (2, 3):
            media = 0xc7 if layers == 2 else 0xc8
        elif identifier in ('O', 'U') and fmt in (1, 2) and layers in (1, 2):
            media = 0xc0 + 4 * (layers - 1)
        else:
            raise AssertionError(f'unqualified capture identity {path}: {identifier}/{fmt}/{layers}')
        count = int.from_bytes(capacity[:4], 'big') + 1
        results = [execute(a.outputs / source, config, workers[source]['contract'], media, records)
                   for source, config in consumer.SOURCES.items()]
        for result in results:
            result['matches_captured_capacity'] = result['computed_sector_count'] == count
        rows.append(dict(capture=str(path), disc=path.parent.name, structure_sha256=sha(raw),
                         capacity_sha256=sha(capacity), structure_length=len(raw), identifier=identifier,
                         format=fmt, layers=layers, captured_sector_count=count, results=results))
    totals = dict(captures=len(rows), uhd_captures=sum(r['identifier'] == 'U' for r in rows),
                  matches_by_source={source:sum(next(x for x in r['results'] if x['source_sha256'] == source)['matches_captured_capacity'] for r in rows)
                                     for source in consumer.SOURCES})
    a.receipt.write_text(json.dumps(dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        worker_receipt_sha256=sha(a.worker_receipt.read_bytes()), totals=totals, captures=rows,
        qualification='Agreement with independently saved capacity values validates this arithmetic on those metadata inputs. It does not prove physical reads or authenticate capture-time firmware. No source code is patched by this audit.'), indent=2) + '\n')
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
