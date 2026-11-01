#!/usr/bin/env python3
"""Execute native HRL searches and actual installed gates with explicit lists.

Inputs start at source-owned lookup calls, after certificate acquisition. Native
count/read helpers execute without replacement. Stops are the actual clean or
reject continuation; certificate verification and later authentication remain
outside this contract.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / 'firmware_execution'))
from stages import run, branch, DECODER, STACK
from ake_setter import literal, half


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bind(data, sites):
    candidates = []
    start = 0
    while True:
        at = data.find(bytes.fromhex('f3b583b003980c00'), start)
        if at < 0:
            break
        start = at + 2
        if at % 2 == 0 and data[at + 12:at + 16] == bytes.fromhex('07002000') and half(data, at + 20) == 0x9002:
            candidates.append(at)
    assert len(candidates) == 1, ('native lookup ambiguity', candidates)
    lookup = candidates[0]
    count = branch(data, lookup + 8)
    read32 = branch(data, lookup + 16)
    assert lookup < count < lookup + 256
    assert data[count:count + 4] == bytes.fromhex('10b51430')
    assert branch(data, count + 4) == read32
    assert literal(data, count + 8) == 0xff8
    assert literal(data, count + 14) == 0xffff
    calls = {branch(data, i.address) for i in DECODER.disasm(data[lookup:count], lookup) if i.mnemonic == 'bl'}
    assert len(calls) == 3 and {count, read32} <= calls
    read16 = next(iter(calls - {count, read32}))
    base_cell = literal(data, read32)
    assert literal(data, read16) == base_cell and 0x01ff0000 <= base_cell < 0x02040000
    # Follow only direct native BLs and unconditional joins to the installed
    # gates. Five older images jump over literal pools; no linear pool decode.
    callers = {}
    for at in range(0, len(data) - 4, 2):
        if half(data, at) & 0xf800 != 0xf000 or half(data, at + 2) & 0xf800 != 0xf800:
            continue
        if branch(data, at) != lookup:
            continue
        join = at + 4
        for _ in range(4):
            if join in sites:
                assert join not in callers
                callers[join] = at
                break
            if half(data, join) & 0xf800 != 0xe000:
                break
            join = branch(data, join)
    assert set(callers) == set(sites), ('unbound caller', sites, callers)
    return dict(lookup=lookup, count=count, read32=read32, read16=read16,
                base_cell=base_cell, callers=callers)


def vectors():
    # Each record is a 16-bit inclusive range extent and 48-bit first host ID.
    for first, extent in ((0x123456780020, 0), (0x123456780020, 5),
                          (0x12345678fffe, 5), (0x123456780020, 0xffff)):
        for host in sorted({first - 1, first, first + 1, first + extent, first + extent + 1}):
            yield dict(name='range', records=[(first, extent)], host=host)
    yield dict(name='empty', records=[], host=0x123456780020)
    yield dict(name='second-record-hit', records=[(0x111111110000, 3), (0x123456780020, 2)], host=0x123456780021)
    for count in (0xff9, 0xffff, 0xffffffff):
        yield dict(name='invalid-count', records=[], host=0x123456780020, count=count)


def execute(folder, source_hash):
    original, modified = ((folder / f).read_bytes() for f in ('original.bin', 'modified.bin'))
    assert sha(original) == source_hash
    report = json.loads((folder / 'modify.json').read_text())
    c = report['execution_contracts']; facts = c['facts']; base = c['base']
    sites = [facts[k] for k in ('hrl_site', 'hrl_site2', 'hrl_site3') if facts.get(k)]
    contract = bind(original, sites)
    result = dict(source_sha256=source_hash, output_sha256=sha(modified), contract=contract,
                  status='passed', sequences=0, native_searches=0, examples=[])
    for site, caller in contract['callers'].items():
        deny = branch(original, site + 2)
        for vector in vectors():
            count = vector.get('count', len(vector['records']))
            table = bytearray(24)
            table[20:24] = count.to_bytes(4, 'big')
            for first, extent in vector['records']:
                table.extend(extent.to_bytes(2, 'big') + first.to_bytes(6, 'big'))
            # Relocation is an explicit input, not a guessed runtime address.
            memory = [(contract['base_cell'], struct.pack('<I', 0x02010000)),
                      (0x02010100, bytes(table)), (0x02010800, vector['host'].to_bytes(6, 'big'))]
            kw = dict(registers={0:0x100, 1:0x800}, memory=memory, strict_reads=True)
            expected = 2 if count > 0xff8 else int(any(first <= vector['host'] <= first + extent for first, extent in vector['records']))
            old = run(original, report['engine'], caller, {site + 4, deny}, base['flags'], **kw)
            assert old['registers'][0] == expected, ('native search differs from range oracle', vector, old['registers'][0])
            assert old['target'] == (deny if expected else site + 4)
            result['native_searches'] += 1
            for setting in (0, 1, 2, 255):
                new = run(modified, report['engine'], caller, {site + 4, deny}, base['flags'], settings={5:setting}, **kw)
                assert new['target'] == (site + 4 if setting == 0 else old['target'])
                assert new['registers'] == old['registers'], 'installed gate changed native register result'
                assert new['sp'] == old['sp'] == STACK
                assert contract['lookup'] in new['trace'] and contract['count'] in new['trace'] and contract['read32'] in new['trace']
                assert all(STACK - 0x100 <= a < STACK for a, n, v in new['writes']), 'lookup mutated list or external state'
                if setting != 0:
                    assert new['nzcv'] == old['nzcv']
                result['sequences'] += 1
                if vector['name'] != 'range' and setting in (0, 255):
                    result['examples'].append(dict(site=site, input=vector, setting=setting,
                        native_result=expected, target=new['target'], trace=new['trace']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for source in json.loads(args.inventory.read_text())['images']:
        try:
            rows.append(execute(args.outputs / source['sha256'], source['sha256']))
        except Exception as error:
            print('FAILED', source['sha256'], str(error), flush=True)
            raise
        if len(rows) % 10 == 0:
            print(f'{len(rows)} inputs executed', flush=True)
    receipt = dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        inventory_sha256=sha(args.inventory.read_bytes()), images=rows,
        sequences=sum(r['sequences'] for r in rows), native_searches=sum(r['native_searches'] for r in rows),
        limitations='Explicit list and host-ID inputs at native lookup calls. Does not qualify certificate acquisition, maximum-length lists, signature verification, subsequent authentication, or settings lifetime.')
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k:receipt[k] for k in ('sequences', 'native_searches')}))


if __name__ == '__main__':
    main()
