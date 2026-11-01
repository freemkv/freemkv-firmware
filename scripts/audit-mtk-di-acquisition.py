#!/usr/bin/env python3
"""Bind and execute the pre-DI mode selection, stopping before acquisition.

The worker transfer is decoded independently from original bytes. Resident
targets are recorded, not supplied with fabricated code or successful returns.
State inputs are explicit; this does not prove their upstream provenance.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / 'firmware_execution'))
from stages import run, branch, DECODER


def sha(data):
    return hashlib.sha256(data).hexdigest()


def half(data, at):
    return struct.unpack_from('<H', data, at)[0]


def literal(data, at, register):
    op = half(data, at)
    assert op & 0xff00 == 0x4800 + register * 0x100
    return struct.unpack_from('<I', data, ((at + 4) & ~3) + (op & 255) * 4)[0]


def inspect(data, state, di):
    candidates = []
    for at in range(max(0, di - 0x900), di, 2):
        if data[at + 2:at + 6] != bytes.fromhex('c8218143'):
            continue
        # LDRB R0,[Rn]; MOVS R1,C8; BICS R1,R0; LDR R0,=mode.
        op = half(data, at)
        if op & ~0x38 != 0x7800:
            continue
        rn = (op >> 3) & 7
        if half(data, at + 6) & 0xff00 != 0x4800:
            continue
        loads = [p for p in range(max(0, at - 0x100), at, 2)
                 if half(data, p) & 0xff00 == 0x4800 + rn * 0x100
                 and literal(data, p, rn) == state]
        if not loads:
            continue
        mode = literal(data, at + 6, 0)
        assert 0x01ff0000 <= mode < 0x02040000
        modern = half(data, at + 8) & 0xff00 == 0xd000
        if modern:
            assert rn == 1
            assert branch(data, at + 8) == at + 18
            assert literal(data, at + 10, 1) == state
            assert data[at + 12:at + 16] == bytes.fromhex('0978c729')
            assert half(data, at + 16) & 0xff00 == 0xd100
            reject = branch(data, at + 16)
            assert literal(data, at + 18, 1) == state
            assert half(data, at + 20) == 0x780a
            body = at + 22
        else:
            assert half(data, at + 8) & 0xff00 == 0xd100
            reject = branch(data, at + 8)
            assert half(data, at + 10) == 0x7802 + (rn << 3)
            body = at + 12
        assert data[body:body + 14] == bytes.fromhex('cc21914301d1152100e01c210170')
        call = body + 14
        assert data[reject:reject + 2] == bytes.fromhex('0721')
        assert branch(data, reject + 2) == call - 2
        assert call + 4 <= reject < call + 0x70
        instruction = next(DECODER.disasm(data[call:call + 4], call, count=1))
        assert instruction.mnemonic in ('bl', 'blx')
        target = branch(data, call)
        worker = dict(call=call, target=target, instruction=instruction.mnemonic,
                      call_bytes=data[call:call + 4].hex())
        if instruction.mnemonic == 'blx' and data[target:target + 4] == bytes.fromhex('04f01fe5'):
            pointer = struct.unpack_from('<I', data, target + 4)[0]
            worker.update(kind='literal-veneer', pointer=pointer, body=pointer & ~1,
                          thumb=bool(pointer & 1), body_in_main_image=(pointer & ~1) < len(data))
        else:
            worker.update(kind='direct', body=target, thumb=instruction.mnemonic == 'bl',
                          body_in_main_image=target < len(data))
        candidates.append(dict(entry=at, state_register=rn, state_literal=loads[-1],
                               mode=mode, native_c7=modern, worker=worker,
                               span_sha256=sha(data[at:reject + 4])))
    assert len(candidates) == 1, f'expected one pre-DI mode contract, got {len(candidates)} at DI {di:#x}'
    return candidates[0]


def audit(folder, source_hash):
    original = (folder / 'original.bin').read_bytes()
    modified = (folder / 'modified.bin').read_bytes()
    assert sha(original) == source_hash
    report = json.loads((folder / 'modify.json').read_text())
    c = report['execution_contracts']
    state = c['native_media_roles']['state']
    di = next(r for r in c['native_media_roles']['roles'] if r['role'] == 'DiscInformation')['site']
    contract = inspect(original, state, di)
    counts = Counter()
    examples = []
    for media in range(256):
        for setting in (0, 1, 2, 255):
            active = media == 0xc7 and setting == 1 and not contract['native_c7']
            def execute(data, supplied_state):
                return run(data, report['engine'], contract['entry'], {contract['worker']['call']},
                           c['base']['flags'], settings={3: setting},
                           registers={contract['state_register']: state},
                           memory=[(state, bytes([supplied_state])), (contract['mode'], b'\xa5')],
                           strict_reads=True, allow_writes=[(contract['mode'], contract['mode'] + 1)],
                           observe_memory=[(contract['mode'], 1)])
            expected = execute(original, 0xc8 if active else media)
            actual = execute(modified, media)
            # The native dense arm leaves its second state load in R2. The
            # conversion must retain C7 identity, not copy the oracle's C8.
            if active:
                assert expected['registers'][2] == 0xc8
                expected['registers'][2] = media
            assert actual['target'] == expected['target']
            assert actual['memory'] == expected['memory'], f'mode mismatch {media:#x}/{setting}'
            assert actual['registers'] == expected['registers'], f'worker input mismatch {media:#x}/{setting}'
            assert actual['sp'] == expected['sp']
            # Stop is the actual BL/BLX instruction: it replaces LR. A prior
            # helper's LR is not an input to the acquisition worker.
            assert actual['nzcv'] == expected['nzcv']
            mode = int(actual['memory'][str(contract['mode'])], 16)
            counts[f'{mode:02x}'] += 1
            if media in (0xc0, 0xc7, 0xc8, 0xcc) and setting in (0, 1):
                examples.append(dict(media=media, setting=setting, mode=mode, trace=actual['trace']))
    return dict(source_sha256=source_hash, output_sha256=sha(modified), engine=report['engine'],
                contract=contract, cases=sum(counts.values()), mode_counts=dict(counts), examples=examples)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--outputs', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    args = p.parse_args()
    rows = []
    for item in json.loads(args.inventory.read_text())['images']:
        rows.append(audit(args.outputs / item['sha256'], item['sha256']))
        if len(rows) % 10 == 0:
            print(f'{len(rows)} inputs accounted for', flush=True)
    totals = dict(images=len(rows), cases=sum(r['cases'] for r in rows),
                  native_c7_images=sum(r['contract']['native_c7'] for r in rows),
                  worker_body_in_main_image=sum(r['contract']['worker']['body_in_main_image'] for r in rows))
    result = dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
                  inventory_sha256=sha(args.inventory.read_bytes()), totals=totals, images=rows,
                  limitations=['Execution starts at the mode-selection block, with an explicitly supplied state pointer and state byte.',
                               'It stops before the acquisition call; no worker success, DI status, readiness or sector reads are simulated.',
                               'Body outside main image means no binding supplied here; it does not identify ROM versus mapped/sealed backing.'])
    args.receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
