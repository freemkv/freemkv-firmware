#!/usr/bin/env python3
"""Trace copied DI bytes into two exact-source native geometry initializers.

The DI-copy block and geometry initializer are explicitly stitched stages. The
initializer receives status bit 1 as an input, not as a simulated acquisition
result. Native byte readers and address-conversion leaves execute normally.
No physical-media validity is asserted for the synthetic metadata values.
"""
import argparse
import importlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
worker_audit = importlib.import_module('audit-mtk-di-worker')
from stages import run, STOP
sha = worker_audit.sha

SOURCES = {
    '43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3': dict(
        label='BH16NS48 1.02', entry=0xb988c, descriptor=0x01ff9c00, end_cell=0x02000e18,
        state=0x01ff9dd3, status=0x02000b14,
        controls=[(0x02000ddc, 1), (0x01ffafc6, 1), (0x02000b05, 1)],
        outputs=[(0x01ffb054, 1), (0x02000e18, 4), (0x01ffb079, 1), (0x01ff9b20, 0x30),
                 (0x02000f44, 2), (0x01ffafc2, 1), (0x01ffb016, 1), (0x01ff9c00, 0x40),
                 (0x02000f4c, 4), (0x02000f50, 4), (0x02000f84, 0x10), (0x02000bb2, 1)]),
    'dd03cdae194de03a710b5f6e88dfedf421fd20667a3cc9ec58e828bd769ab2ed': dict(
        label='BC-12D2HT 3.00', entry=0xbb72e, descriptor=0x01ff9be0, end_cell=0x02000c58,
        state=0x01ff9da0, status=0x02000b0e,
        controls=[(0x02000c18, 1), (0x01ffb5d1, 1), (0x02000b04, 1)],
        outputs=[(0x01ffb67c, 1), (0x02000c58, 4), (0x01ffb6a5, 1), (0x01ff9b50, 0x30),
                 (0x02000d60, 2), (0x01ffb5ce, 1), (0x01ffb63e, 1), (0x01ff9be0, 0x40),
                 (0x02000d68, 4), (0x02000d6c, 4), (0x02000d70, 4),
                 (0x02000da4, 0x10), (0x02000bbd, 1)])
}


def audit(folder, source_hash, worker):
    config = SOURCES[source_hash]
    original = (folder / 'original.bin').read_bytes()
    modified = (folder / 'modified.bin').read_bytes()
    assert sha(original) == source_hash
    report = json.loads((folder / 'modify.json').read_text())
    flags = report['execution_contracts']['base']['flags']; engine = report['engine']
    assert config['state'] == report['execution_contracts']['native_media_roles']['state']
    assert original[config['entry']:config['entry'] + 2] == bytes.fromhex('f8b5')
    w = worker['contract']; base, src, dest = 0x02010000, 0x1000, 0x2000
    rows = []
    for media, layers in ((0xc4, 2), (0xc7, 2), (0xc8, 3)):
        for third_word in (0x00812340, 0x01845678):
            records = bytearray(0xc0)
            for i in range(3):
                records[i * 0x40:i * 0x40 + 2] = b'DI'
                records[i * 0x40 + 8:i * 0x40 + 11] = b'BDU'
                records[i * 0x40 + 11] = 1
                records[i * 0x40 + 12] = layers << 4
                records[i * 0x40 + 13] = 5
                for offset, value in ((0x14, 0x01f23456), (0x18, 0x00812340 + i * 0x100000), (0x1c, 0x01234560 + i * 0x100000)):
                    struct.pack_into('>I', records, i * 0x40 + offset, value)
            struct.pack_into('>I', records, 0x98, third_word)
            staged = run(modified, engine, w['copy_block'], {w['copy_stop']}, flags,
                registers={4:src, 5:w['di']},
                memory=[(w['translation'], struct.pack('<I', base)), (w['di'], struct.pack('<I', dest)),
                        (base + src, bytes(records)), (base + dest, bytes(0x150)), (0x04050010, bytes(4))],
                allow_writes=[(base + dest, base + dest + 0x150), (0x04050010, 0x04050014)],
                observe_memory=[(base + dest, 0x150)], strict_reads=True)
            copied = bytes.fromhex(staged['memory'][str(base + dest)])
            # Zero third record models the missing data for the native consumer
            # only. It is not labelled as an actual classic acquisition result.
            variants = [('actual-copy-stage', copied), ('third-record-zeroed', copied[:0xe0] + bytes(0x70))]
            for variant, di in variants:
                memory = [(a, bytes(n)) for a, n in config['controls'] + config['outputs']]
                memory += [(config['state'], bytes([media])), (config['status'], b'\x02'),
                           (w['translation'], struct.pack('<I', base)), (w['di'], struct.pack('<I', dest)),
                           (base + dest, di)]
                observed = config['outputs'] + [(config['state'], 1)]
                def execute(data):
                    return run(data, engine, config['entry'], {STOP}, flags, memory=memory,
                               allow_writes=[(a, a + n) for a, n in observed],
                               observe_memory=observed, strict_reads=True)
                old, new = execute(original), execute(modified)
                assert old['memory'] == new['memory'] and old['registers'] == new['registers']
                assert new['registers'][0] == 1
                descriptor = bytes.fromhex(new['memory'][str(config['descriptor'])])
                word = struct.unpack_from('<I', descriptor, 12)[0]
                if w['record_count'] == 3 and media in (0xc7, 0xc8):
                    assert word == (third_word >> 3 if variant == 'actual-copy-stage' else 0)
                else:
                    assert word == (0 if media == 0xc8 else (0x00912340 >> 3))
                rows.append(dict(media=media, layers=layers, third_word=third_word, variant=variant,
                                 descriptor=descriptor.hex(), descriptor_word_12=word,
                                 resulting_end=new['memory'][str(config['end_cell'])], trace=new['trace']))
    return dict(source_sha256=source_hash, output_sha256=sha(modified), source_contract=config,
                worker_contract=w, cases=rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--outputs', type=Path, required=True)
    p.add_argument('--worker-receipt', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    a = p.parse_args()
    workers = {r['source_sha256']:r for r in json.loads(a.worker_receipt.read_text())['images']}
    rows = [audit(a.outputs / source, source, workers[source]) for source in SOURCES]
    a.receipt.write_text(json.dumps(dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        worker_receipt_sha256=sha(a.worker_receipt.read_bytes()), images=rows,
        cases=sum(len(r['cases']) for r in rows),
        finding='Newer native C7/C8 geometry initialization consumes record 3 at DI+0xf8. The classic initializer instead reads DI+0x88 for C7 and stores zero for C8. Copying a third record alone cannot close the difference.',
        limitations='Synthetic metadata proves data flow, not valid optical parameters. Consumer field hardware meaning, complete address-translation lifecycle and same-hardware applicability remain unqualified.'), indent=2) + '\n')
    print(json.dumps({'images':len(rows), 'cases':sum(len(r['cases']) for r in rows)}))


if __name__ == '__main__':
    main()
