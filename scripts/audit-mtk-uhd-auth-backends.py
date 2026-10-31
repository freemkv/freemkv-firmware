"""Compare source-bound extended authentication backend payloads.

Read-only evidence for the newer-layout scope. No backend is executed, decoded,
transplanted or treated as a proven optical acquisition requirement. Exact-byte
absence does not exclude a differently encoded or implemented equivalent.
"""
import argparse
import collections
import hashlib
import json
import math
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def half(data, at):
    return struct.unpack_from('<H', data, at)[0]


def literal(data, at):
    op = half(data, at)
    assert op & 0xff00 == 0x4800, (hex(at), hex(op))
    address = ((at + 4) & ~3) + (op & 255) * 4
    return struct.unpack_from('<I', data, address)[0]


def backend(data, service):
    selectors = service['reviewed_extended_operation_selectors']
    target = next(s['target'] for s in selectors if s['operation'] == 0xb3)
    assert all(s['target'] == target for s in selectors if s['condition'] == 'eq')
    # This positive grammar binds both range-register writes and the actual
    # ARM entry call from the registered certificate -> service chain.
    checks = {
        2: 0x0021, 8: 0x6a70, 10: 0x43a8, 12: 0x6270,
        16: 0x62b0, 20: 0x3881, 22: 0x62f0,
        24: 0x6a70, 26: 0x4328, 28: 0x6270,
        34: 0x9902, 36: 0x0020,
    }
    for offset, expected in checks.items():
        assert half(data, target + offset) == expected, (hex(target), offset)
    start, end = literal(data, target + 14), literal(data, target + 18) - 0x81
    call = target + 38
    ins = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[call:call+4], call, count=1))
    assert ins.mnemonic == 'blx'
    entry = int(ins.op_str.removeprefix('#'), 0)
    assert start == entry + 0x80 and start <= end < len(data)
    # ARM supervisor entry followed by the complete 31-NOP entry window.
    assert data[entry:entry+0x80] == bytes.fromhex('d3f021e3') + bytes.fromhex('0000a0e1') * 31
    payload = data[start:end+1]
    frequencies = collections.Counter(payload)
    entropy = -sum(n/len(payload)*math.log2(n/len(payload)) for n in frequencies.values())
    return {'entry': entry, 'range_start': start, 'range_end_inclusive': end,
            'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
            'byte_entropy': entropy}, payload


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--services', type=Path, required=True)
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--hoard', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    sources = {r['sha256']: r for r in json.loads(a.scan.read_text())['images']}
    services = {r['sha256']: r for r in json.loads(a.services.read_text())['images']}
    rows, modules, pending = [], {}, []
    for source in json.loads(a.scope.read_text())['images']:
        sha = source['sha256']
        data = (a.hoard/sources[sha]['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha
        row = {'sha256': sha, 'extended_service': services[sha]['extended_worker']}
        if row['extended_service']:
            row['backend'], payload = backend(data, services[sha])
            modules[row['backend']['sha256']] = payload
        else:
            pending.append((row, data))
        rows.append(row)
    for row, data in pending:
        row['exact_native_payload_matches'] = [
            {'sha256': sha, 'offset': data.find(payload)}
            for sha, payload in modules.items() if payload in data]
        row['native_prefix_256_matches'] = [
            {'sha256': sha, 'offset': data.find(payload[:256])}
            for sha, payload in modules.items() if payload[:256] in data]
    inputs = {key: hashlib.sha256(getattr(a, key).read_bytes()).hexdigest()
              for key in ('scan', 'services', 'scope')}
    a.output.write_text(json.dumps({'scope': __doc__, 'input_sha256': inputs,
                                   'images': rows}, indent=2)+'\n')
    print(f'PASS: {len(rows)} newer-layout images; {len(rows)-len(pending)} bound backends; '
          f'{len(modules)} distinct protected payloads; {len(pending)} unresolved equivalents')


if __name__ == '__main__':
    main()
