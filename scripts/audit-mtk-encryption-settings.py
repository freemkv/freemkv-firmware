#!/usr/bin/env python3
"""Exercise settings transitions against actual native authentication bytes.

SET, GET, identity, unknown verbs and RAM RESET paths execute the real response
writer and stop at commit. OEM RESET stops at native flash PROGRAM; a separately
labelled ABI-continuation test uses the saved frame with caller-clobbered values.
It does not execute PROGRAM or assert that flash persistence succeeds.
"""
import argparse
from collections import Counter
import importlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
transition = importlib.import_module('audit-mtk-encryption-transition')
run, sha, setter_contract, writer_contract = (transition.run, transition.sha,
                                             transition.setter_contract, transition.writer_contract)
from stages import STACK


def audit(folder, source_hash, modified_override=None):
    original = (folder / 'original.bin').read_bytes()
    modified = (folder / 'modified.bin').read_bytes() if modified_override is None else modified_override
    assert sha(original) == source_hash
    report = json.loads((folder / 'modify.json').read_text())
    c = report['execution_contracts']; base = c['base']
    native = c['native_media_roles']; response = native['response']; nv = native['nv']
    setter = setter_contract(original, c['facts']); writer = writer_contract(original, base['writer'])
    assert (writer['first_cell'], writer['second_cell']) == (setter['first_cell'], setter['second_cell'])
    native_base = 0x02010000
    mask = 0xffff if setter['shape'] in ('common', 'adjusted_common') else 0xffffff
    auth, output = native_base + (setter['offset'] & mask), native_base + writer['offset']
    relocation = [(setter['first_cell'], bytes(4)), (setter['second_cell'], struct.pack('<I', native_base))]
    observed = [(base['flags'], 7), (auth, 2), (output, 64), (response['length_cell'], 2)]
    allowed = [(a, a + n) for a, n in observed]
    counts = Counter(); examples = []

    def command_case(name, old, verb, feature, value, expected_flags, saved=None, debug=False, states=b'\x06\x03'):
        flags = bytes([0x55, 255, 255, 1, 1, 255, old])
        command = bytes([0x3c, 14, 0xde if debug else 0xc0, 0xb9 if debug else 0xde,
                         verb, feature, value, 0, 0, 0, 0, 0])
        memory = relocation + [(base['flags'], flags), (base['cdb'], command), (auth, states),
                  (output, bytes([0xa5] * 64)), (response['length_cell'], b'\xa5\xa5')]
        if saved is not None:
            memory.append((nv['home'], saved))
        result = run(modified, report['engine'], base['handler'], {response['commit']}, base['flags'],
                     memory=memory, allow_writes=allowed, observe_memory=observed, strict_reads=True)
        assert result['memory'][str(base['flags'])] == expected_flags.hex(), name
        invalidate = not debug and verb in (2, 4) and old == 0 and expected_flags[6] != 0
        assert result['memory'][str(auth)] == (b'\x01\x01' if invalidate else states).hex(), name
        assert result['memory'][str(response['length_cell'])] == '4000', name
        assert result['registers'][0] == response['buffer_offset'], name
        if verb not in (1, 3) or debug:
            assert result['memory'][str(output)] == bytes(64).hex(), name
        counts[name] += 1
        if invalidate and counts[name] == 1:
            examples.append(dict(case=name, old=old, requested=value, auth_after=result['memory'][str(auth)], trace=result['trace']))

    for old in (0, 1, 2, 255):
        flags = bytes([0x55, 255, 255, 1, 1, 255, old])
        for new in (0, 1, 2, 255):
            for states in (b'\x06\x03', b'\x03\x06'):
                command_case('set-encryption', old, 2, 6, new, flags[:6] + bytes([new]), states=states)
        for feature in (0, 1, 2, 3, 4, 5, 7, 255):
            expected = bytearray(flags)
            if 1 <= feature <= 5:
                expected[feature] = 0
            command_case('set-other-or-invalid-feature', old, 2, feature, 0, bytes(expected))
        for verb in (1, 3, 0, 255):
            command_case('nonmutating-safe-command', old, verb, 6, 1, flags)
        for verb in (1, 2, 3, 4, 255):
            command_case('safe-id-under-debug-knock', old, verb, 6, 1, flags, debug=True)
        command_case('reset-defaults', old, 4, 0, 1, bytes(base['defaults']))
        for mode in (0, 2, 254):
            command_case('reset-erased-fallback', old, 4, 0, mode, bytes(base['defaults']), saved=bytes([255] * 7))
            for new in (0, 1, 2, 255):
                saved = bytes([0, 1, 2, 255, 0, 1, new])
                command_case('reset-saved', old, 4, 0, mode, flags[:1] + saved[1:], saved=saved)

        # Observe the real staging loop and PROGRAM call; do not emulate its
        # hardware effects or substitute a success return.
        staging_offset = 0x8000
        staging = native_base + staging_offset
        command = bytes([0x3c, 14, 0xc0, 0xde, 4, 0, 255, 0, 0, 0, 0, 0])
        memory = relocation + [(base['flags'], flags), (base['cdb'], command), (auth, b'\x06\x03'),
                  (nv['dram_base_cell'], struct.pack('<II', native_base, staging_offset)),
                  (staging, bytes(7)), (output, bytes([0xa5] * 64)), (response['length_cell'], b'\xa5\xa5')]
        boundary = run(modified, report['engine'], base['handler'], {nv['program']}, base['flags'],
                       memory=memory, allow_writes=allowed + [(staging, staging + 7)],
                       observe_memory=observed + [(staging, 7), (STACK - 28, 28)], strict_reads=True)
        assert boundary['registers'][:4] == [staging_offset, nv['home'], 7, 1]
        assert boundary['memory'][str(base['flags'])] == 'ff' * 7
        assert boundary['memory'][str(staging)] == 'ff' * 7
        assert boundary['memory'][str(auth)] == '0603'
        assert boundary['sp'] == STACK - 28
        frame = bytes.fromhex(boundary['memory'][str(STACK - 28)])
        assert struct.unpack_from('<I', frame)[0] == old
        counts['oem-reset-program-boundary'] += 1
        for clobber in (0, 0xdeadbeef):
            registers = dict(enumerate(boundary['registers']))
            for register in (0, 1, 2, 3, 12):
                registers[register] = clobber
            # Rebase the observed saved frame to the harness's entry SP.
            # Continuation assumes only ordinary callee-saved ABI preservation.
            continuation_memory = relocation + [(base['flags'], bytes([255] * 7)), (base['cdb'], command),
                (auth, b'\x06\x03'), (output, bytes([0xa5] * 64)),
                (response['length_cell'], b'\xa5\xa5'), (STACK, frame)]
            tail = run(modified, report['engine'], boundary['lr'] & ~1, {response['commit']}, base['flags'],
                       registers=registers, memory=continuation_memory, allow_writes=allowed,
                       observe_memory=observed, strict_reads=True, allow_stack_delta=28)
            assert tail['memory'][str(auth)] == ('0101' if old == 0 else '0603')
            assert tail['memory'][str(base['flags'])] == 'ff' * 7
            assert tail['memory'][str(output)] == bytes(64).hex()
            assert tail['memory'][str(response['length_cell'])] == '4000'
            assert tail['sp'] == STACK + 8
            counts['oem-reset-abi-continuation-only'] += 1
    return dict(source_sha256=source_hash, output_sha256=sha(modified), cases=sum(counts.values()),
                case_counts=dict(counts), examples=examples)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--outputs', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    a = p.parse_args(); rows = []
    for item in json.loads(a.inventory.read_text())['images']:
        try:
            rows.append(audit(a.outputs / item['sha256'], item['sha256']))
        except Exception:
            print('FAILED', item['sha256'], flush=True)
            raise
        if len(rows) % 10 == 0:
            print(f'{len(rows)} inputs accounted for', flush=True)
    totals = dict(images=len(rows), cases=sum(r['cases'] for r in rows))
    a.receipt.write_text(json.dumps(dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        inventory_sha256=sha(a.inventory.read_bytes()), totals=totals, images=rows), indent=2) + '\n')
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
