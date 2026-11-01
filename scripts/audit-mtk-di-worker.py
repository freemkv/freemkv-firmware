#!/usr/bin/env python3
"""Execute visible native DI worker routing and its separate record-copy block.

Acquisition calls are stops. Copy tests start at the post-acquisition block with
explicit source bytes; they execute the real memory-copy leaf and stop before
metadata processing. They never invent an acquisition result or claim a read.
"""
import argparse
from collections import Counter
import hashlib
import importlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
mode_audit = importlib.import_module('audit-mtk-di-acquisition')
from stages import run, STOP, branch
half, literal = mode_audit.half, mode_audit.literal


def sha(data):
    return hashlib.sha256(data).hexdigest()


def contract(data, entry, state):
    assert half(data, entry) == 0xb5f8
    marker = literal(data, entry + 2, 0) + 8
    assert data[entry + 4:entry + 12] == bytes.fromhex('0026002400210172')
    status = literal(data, entry + 12, 2)
    assert data[entry + 14:entry + 18] == bytes.fromhex('10788007')
    assert half(data, entry + 18) & 0xff00 == 0xd400
    assert literal(data, entry + 20, 7) == state
    assert data[entry + 22:entry + 28] == bytes.fromhex('387840090728')
    assert half(data, entry + 28) & 0xff00 == 0xd100
    alternative_call = branch(data, entry + 28)
    assert next(mode_audit.DECODER.disasm(data[alternative_call:alternative_call + 4], alternative_call)).mnemonic == 'bl'
    primary = branch(data, entry + 30)
    alternative = branch(data, alternative_call)
    candidates = [at for at in range(entry, entry + 0x300, 2)
                  if half(data, at) & 0xff00 == 0x4900 and literal(data, at, 1) == 0x04050000]
    assert len(candidates) == 1
    start = candidates[0]
    assert data[start + 2:start + 16] == bytes.fromhex('0869022210430861286840222100')
    copy = branch(data, start + 16)
    assert data[start + 20:start + 28] == bytes.fromhex('28684022a1187030')
    selectors = [at for at in range(entry, start, 2)
                 if data[at:at + 4] == bytes.fromhex('38784009')
                 and half(data, at + 4) & 0xff00 == 0x4d00
                 and half(data, at + 6) == 0x2807
                 and half(data, at + 8) & 0xff00 == 0xd100
                 and branch(data, at + 8) == start]
    assert len(selectors) == 1
    di = literal(data, selectors[0] + 4, 5)
    assert branch(data, start - 10) == copy
    metadata = branch(data, start - 6)
    if half(data, start + 28) & 0xf800 == 0xe000:
        assert branch(data, start + 28) == start - 10
        count = 2
    else:
        assert branch(data, start + 28) == copy
        assert data[start + 32:start + 42] == bytes.fromhex('2868402221008031e030')
        assert branch(data, start + 42) == start - 10
        count = 3
    # Both native copy leaves use a source-bound translation-base literal.
    first = half(data, copy + 10)
    assert first & 0xf800 == 0x4800
    translation = literal(data, copy + 10, (first >> 8) & 7)
    return dict(entry=entry, marker=marker, status=status, state=state,
                primary=primary, alternative=alternative, copy_block=start,
                copy=copy, translation=translation, di=di, metadata=metadata,
                copy_stop=start - 6, record_count=count,
                prefix_sha256=sha(data[entry:entry + 34]))


def audit(folder, mode_row):
    original = (folder / 'original.bin').read_bytes()
    modified = (folder / 'modified.bin').read_bytes()
    assert sha(original) == mode_row['source_sha256']
    assert sha(modified) == mode_row['output_sha256']
    report = json.loads((folder / 'modify.json').read_text())
    c = report['execution_contracts']; flags = c['base']['flags']
    worker = mode_row['contract']['worker']
    result = dict(source_sha256=sha(original), output_sha256=sha(modified), engine=report['engine'])
    if not worker['body_in_main_image']:
        return dict(result, status='resident body not bound', worker=worker, route_cases=0, copy_cases=0)
    assert worker['thumb']
    w = contract(original, worker['body'], c['native_media_roles']['state'])
    counts = Counter(); examples = []
    for media in range(256):
        for status in (0, 1, 2, 3, 0xfd, 0xff):
            expected = STOP if status & 2 else w['primary'] if media >> 5 == 7 else w['alternative']
            memory = [(w['marker'], b'\xa5'), (w['status'], bytes([status])), (w['state'], bytes([media]))]
            def route(data):
                return run(data, report['engine'], w['entry'], {STOP, w['primary'], w['alternative']}, flags,
                           memory=memory, allow_writes=[(w['marker'], w['marker'] + 1)],
                           observe_memory=[(w['marker'], 1), (w['status'], 1), (w['state'], 1)], strict_reads=True)
            old, new = route(original), route(modified)
            assert old['target'] == new['target'] == expected
            assert old['memory'] == new['memory'] and new['memory'][str(w['marker'])] == '00'
            assert old['registers'] == new['registers'] and old['sp'] == new['sp']
            counts['cached' if expected == STOP else 'primary' if expected == w['primary'] else 'alternative'] += 1
            if media in (0xc0, 0xc7, 0xc8, 0xf8) and status in (0, 2):
                examples.append(dict(state=media, status=status, target=expected, trace=new['trace']))
    copy_examples = []
    for alignment in range(4):
        base = 0x02010000
        source_offset, dest_offset = 0x1000 + alignment, 0x2000 + alignment
        source = bytes((i * 13 + 7) & 255 for i in range(0xc0))
        before = bytes([0xa5] * 0x160)
        expected = bytearray(before)
        for record in range(w['record_count']):
            expected[8 + record * 0x70:8 + record * 0x70 + 0x40] = source[record * 0x40:(record + 1) * 0x40]
        output_start = base + dest_offset - 8
        memory = [(w['translation'], struct.pack('<I', base)), (w['di'], struct.pack('<I', dest_offset)),
                  (base + source_offset, source), (output_start, before), (0x04050010, struct.pack('<I', 0xa5))]
        def stage(data):
            return run(data, report['engine'], w['copy_block'], {w['copy_stop']}, flags,
                       registers={4:source_offset, 5:w['di']}, memory=memory,
                       allow_writes=[(output_start, output_start + len(before)), (0x04050010, 0x04050014)],
                       observe_memory=[(output_start, len(before)), (0x04050010, 4)], strict_reads=True)
        old, new = stage(original), stage(modified)
        assert old['memory'] == new['memory']
        assert new['memory'][str(output_start)] == expected.hex()
        assert new['memory'][str(0x04050010)] == struct.pack('<I', 0xa7).hex()
        assert old['sp'] == new['sp'] and old['registers'] == new['registers']
        copy_examples.append(dict(alignment=alignment, copied_records=w['record_count'],
                                  source_sha256=sha(source), result_sha256=sha(bytes(expected)), trace=new['trace']))
    return dict(result, status='bounded routes and copy stage passed', contract=w,
                route_cases=sum(counts.values()), route_counts=dict(counts), examples=examples,
                copy_cases=len(copy_examples), copy_examples=copy_examples)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode-receipt', type=Path, required=True)
    p.add_argument('--outputs', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    a = p.parse_args()
    rows = [audit(a.outputs / row['source_sha256'], row)
            for row in json.loads(a.mode_receipt.read_text())['images']]
    counts = Counter(str(r['contract']['record_count']) for r in rows if 'contract' in r)
    totals = dict(images=len(rows), executed_images=sum('contract' in r for r in rows),
                  route_cases=sum(r['route_cases'] for r in rows), copy_cases=sum(r['copy_cases'] for r in rows),
                  record_copy_cohorts=dict(counts))
    a.receipt.write_text(json.dumps(dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        mode_receipt_sha256=sha(a.mode_receipt.read_bytes()), totals=totals, images=rows,
        qualification='Two versus three copied records is a proven software difference. Required record count, downstream consumers and hardware applicability remain to be established before any patch.'), indent=2) + '\n')
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
