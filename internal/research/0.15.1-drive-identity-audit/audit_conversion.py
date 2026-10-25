"""Offline audit of the UD02 movement adaptation across nine target images.

Research candidates only. No device access, production rules, or reverse rules.
Inputs: existing private rebadge audit, original UD02 capture, known candidates.
Output: reviewable JSON plus private decoded candidates. Nothing is flashed.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

BASE = 0x410000
REF = '8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141'
OLD = '6042da6069fec90d0e8052613f3f2d6e8ebb7e0d41dc770a5cf4c601f3960d4e'
DONOR_SHA = '84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750'
KNOWN_UD04 = 'ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815'
SLOTS = [(0x12962e, 0x12966e), (0x129766, 0x1297a8), (0x1297a8, 0x1297da)]
DONOR_SLOTS = [(0x5466e2, 0x546716), (0x5467e4, 0x54681c), (0x54681c, 0x54684a)]
DONOR_TO_REF = {0x57cbfe: 0x575a00, 0x545d1e: 0x538c7a,
                0x545c00: 0x538b74, 0x57cb8e: 0x575990,
                0x53f538: 0x531a86, 0x545b98: 0x538b0c}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksum(data):
    assert len(data) % 4 == 0
    return sum(v[0] for v in struct.iter_unpack('>I', data)) & 0xffffffff


def pattern(data):
    """Match fixed instruction layout, wildcarding aligned absolute JSR targets.

    This deliberately supports only these already inspected H8 routine layouts.
    Wildcards are subsequently captured/bound, never used as arbitrary writes.
    """
    out, at = [], 0
    while at < len(data):
        if at % 2 == 0 and data[at] == 0x5e and at + 4 <= len(data):
            out.append(re.escape(data[at:at+1]) + b'.{3}')
            at += 4
        else:
            out.append(re.escape(data[at:at+1]))
            at += 1
    return re.compile(b''.join(out), re.S)


def unique(matches, label):
    if len(matches) != 1:
        raise ValueError(f'{label}: expected one match, found {len(matches)}')
    return matches[0]


def locate(body, reference, start, end, label):
    return unique([m.start() for m in pattern(reference[start:end]).finditer(body)
                   if m.start() % 2 == 0], label)


def literal(body, data, label):
    return unique([m.start() for m in re.finditer(re.escape(data), body)
                   if m.start() % 2 == 0], label)


def build(body, reference, old_reference, donor, compressed_spans):
    if checksum(body):
        raise ValueError('source checksum invalid')
    result = bytearray(body)
    edits = []
    occupied = set(range(0x10, 0x14))

    def edit(offset, before, after, reason):
        if len(before) != len(after) or body[offset:offset+len(before)] != before:
            raise ValueError(f'{reason}: expected bytes mismatch at {offset:#x}')
        span = set(range(offset, offset+len(before)))
        if occupied.intersection(span):
            raise ValueError(f'{reason}: overlapping edits')
        if any(offset < lo+size and lo < offset+len(before) for lo, size in compressed_spans):
            raise ValueError(f'{reason}: compressed storage cannot be patched as instructions')
        occupied.update(span)
        result[offset:offset+len(after)] = after
        edits.append(dict(offset=hex(offset), size=len(before), reason=reason,
                          before_sha256=sha(before), after_sha256=sha(after)))

    # Unique instruction context establishes each layout's phase helper location.
    phase = locate(body, reference, 0x128ef6, 0x128f18, 'phase helper') + 16
    noop = int.from_bytes(body[phase+0x33:phase+0x36], 'big')
    byte_extract = int.from_bytes(body[phase+0x43:phase+0x46], 'big')
    if body[noop-BASE:noop-BASE+2] != bytes.fromhex('5470'):
        raise ValueError('inlined no-op callee is not RTS')
    if body[byte_extract-BASE:byte_extract-BASE+4] != bytes.fromhex('0c085470'):
        raise ValueError('inlined byte extraction callee differs')
    for delta, old, new in [
        (0, '6f300002', '69300000'), (0x12, '6f300002', '69300000'),
        (-0x172, '8808', '88f8'), (-0x16a, '1888', 'f810'),
        (-0x166, 'f820', 'f830'), (-0x154, '88f8', '8808'),
        (-0x14c, 'f810', '1888'), (-0x148, 'f830', 'f820'),
        (-0x88, '7900061319c0', '0dc07910012a'),
        (-0x80, '7900013219c079100009', '0dc07910060200000000'),
    ]:
        edit(phase+delta, bytes.fromhex(old), bytes.fromhex(new),
             'phase/order/mode2/coefficient destination convention')
    edit(phase+0x30, b'\x69\x30\x5e'+noop.to_bytes(3, 'big'),
         bytes.fromhex('6f3000020000'), 'ordered phase output; inline proven no-op')
    edit(phase+0x40, b'\x69\x30\x5e'+byte_extract.to_bytes(3, 'big'),
         bytes.fromhex('6f3000020c08'), 'ordered phase output; inline proven byte extraction')

    branch = locate(body, reference, 0x1299de, 0x129a00, 'assisted direction branch')+16
    edit(branch, bytes.fromhex('4622'), bytes.fromhex('4722'), 'assisted movement direction')
    commands = bytes.fromhex('7900ec08ae014602f8881899')
    command_at = branch + literal(body[branch:branch+0xa0], commands, 'assisted EC command')
    edit(command_at, commands, bytes.fromhex('7900ec88ae014602f8081899'),
         'assisted command direction convention')

    tables = []
    for ref_offset, donor_address, size, kind in [
        (0x1a5804, 0x59ebf8, 256, 'selected UD02 waveform'),
        (0x1a5904, 0x59ecf8, 256, 'selected UD02 waveform'),
        (0x1a5c04, None, 72, 'assisted coefficient layout'),
        (0x1a5c4c, None, 72, 'assisted coefficient layout'),
    ]:
        original = reference[ref_offset:ref_offset+size]
        offset = literal(body, original, kind)
        # Both table contents AND their address-bearing initializer match.
        ptr = (BASE+offset).to_bytes(4, 'big')
        refs = [m.start() for m in re.finditer(re.escape(ptr), body)]
        ref_ptr = unique(refs, kind+' pointer')
        ref_va = (BASE+ref_offset).to_bytes(4, 'big')
        old_ptr = unique([m.start() for m in re.finditer(re.escape(ref_va), reference)],
                         kind+' reference pointer')
        if ref_ptr-phase != old_ptr-0x128f06:
            raise ValueError('table is not selected by the matched phase initializer')
        model = None
        if donor_address:
            payload = donor[donor_address-BASE:donor_address-BASE+size]
        else:
            values = list(struct.iter_unpack('>hh', original))
            adapted = [(values[i+1][0] if i < 17 else -values[0][0], pair[1])
                       for i, pair in enumerate(values)]
            expected = [((0x12a if i < 9 else 0x602)+i,
                         ((values[i][1] >> 8 & 255) << 8) |
                         ((values[i+1][0] if i < 17 else -values[0][0]) >> 8 & 255))
                        for i in range(18)]
            actual = [((0x12a if i < 9 else 0x602)+i,
                       ((pair[1] >> 8 & 255) << 8) | (pair[0] >> 8 & 255))
                      for i, pair in enumerate(adapted)]
            assert actual == expected
            payload = b''.join(struct.pack('>hh', *pair) for pair in adapted)
            model = dict(register_value_pairs=18, emitted_values_equal_ud02_model=True)
        edit(offset, original, payload, kind)
        tables.append(dict(kind=kind, address=hex(BASE+offset),
                           initializer_pointer=hex(BASE+ref_ptr), model=model))

    # Three complete stock coordinate routines are identical except absolute
    # calls. Bind each reference callee consistently across every call site.
    relocation = {}
    slots = []
    for start, end in SLOTS:
        target = locate(body, reference, start, end, 'coordinate routine')
        for pos in range(0, end-start-3, 2):
            if reference[start+pos] == 0x5e:
                old = int.from_bytes(reference[start+pos+1:start+pos+4], 'big')
                new = int.from_bytes(body[target+pos+1:target+pos+4], 'big')
                if old in relocation and relocation[old] != new:
                    raise ValueError('inconsistent coordinate callee binding')
                if not BASE <= new < BASE+len(body):
                    raise ValueError('coordinate callee outside image')
                relocation[old] = new
        slots.append((target, end-start))
    assert set(relocation) == set(DONOR_TO_REF.values())
    for (donor_start, donor_end), (target, size) in zip(DONOR_SLOTS, slots):
        payload = bytearray(donor[donor_start-BASE:donor_end-BASE])
        assert payload[-2:] == bytes.fromhex('5470') and len(payload) <= size
        for pos in range(0, len(payload)-3, 2):
            if payload[pos] == 0x5e:
                old = int.from_bytes(payload[pos+1:pos+4], 'big')
                payload[pos+1:pos+4] = relocation[DONOR_TO_REF[old]].to_bytes(3, 'big')
        payload.extend(bytes(size-len(payload)))
        edit(target, body[target:target+size], payload, 'UD02 coordinate conversion with bound calls')

    # UD03 1.03 already has the old whole-word getter. Other seven images use
    # the split-byte getter and need the same guarded two-byte UD04 adaptation.
    split = [m.start()+16 for m in pattern(reference[0xe5116:0xe5138]).finditer(body)
             if m.start() % 2 == 0]
    whole = [m.start() for m in pattern(old_reference[0xe3c76:0xe3c9c]).finditer(body)
             if m.start() % 2 == 0]
    if len(split) == 1 and not whole:
        getter = split[0]
        edit(getter, bytes.fromhex('0c08'), bytes.fromhex('0000'), 'preserve UD02 calibration byte interpretation')
        getter_report = dict(status='split-byte getter adapted', offset=hex(getter))
    elif len(whole) == 1 and not split:
        getter_report = dict(status='whole-word getter already compatible; no change', offset=hex(whole[0]))
    else:
        raise ValueError('calibration getter missing or ambiguous')

    result[0x10:0x14] = ((int.from_bytes(result[0x10:0x14], 'big')-checksum(result)) & 0xffffffff).to_bytes(4, 'big')
    changes = [i for i, (a, b) in enumerate(zip(body, result)) if a != b]
    assert checksum(result) == 0 and len(result) == len(body) and set(changes) <= occupied
    return bytes(result), dict(phase_helper=hex(BASE+phase), assisted_branch=hex(BASE+branch),
        coordinate_slots=[dict(address=hex(BASE+at), bytes=size) for at, size in slots],
        coordinate_callees={hex(a):hex(b) for a,b in relocation.items()},
        tables=tables, getter=getter_report, edits=edits, changed_bytes=len(changes))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private_root', type=Path)
    p.add_argument('private_output', type=Path)
    p.add_argument('report', type=Path)
    p.add_argument('--paired-overrides', type=Path, help='Verified context-decoded inputs indexed by Normal envelope SHA')
    args = p.parse_args()
    root = args.private_root/'rebadge-audit'
    reference = (root/REF/'normal.bin').read_bytes()
    old_reference = (root/OLD/'normal.bin').read_bytes()
    donor = (args.private_root/'live-ud02-normal.bin').read_bytes()
    assert sha(reference) == '87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1'
    assert sha(old_reference) == '95664992a098ff6c3c8a9c4bae228209d956f4a1462c238fb37863b910b72149'
    assert sha(donor) == DONOR_SHA
    args.private_output.mkdir(parents=True, exist_ok=True)
    overrides = json.loads(args.paired_overrides.read_text()) if args.paired_overrides else {}
    rows = []
    for entry in json.loads((root/'inventory.json').read_text()):
        if entry['embedded_model'] == 'BDR-UD02D':
            continue
        directory = root/entry['normal_sha256']
        body = (directory/'normal.bin').read_bytes()
        assert sha(body) == entry['normal_decoded_sha256']
        standalone_sha = sha(body)
        context = overrides.get(entry['normal_sha256'])
        if context:
            body = Path(context['path']).read_bytes()
            assert sha(body) == context['decoded_sha256'] and checksum(body) == 0
        spans = json.loads((directory/'motion-spans.json').read_text())
        candidate, result = build(body, reference, old_reference, donor, spans)
        if body == reference:
            assert sha(candidate) == KNOWN_UD04, 'must reproduce exact working UD04 candidate'
        output = args.private_output/(entry['normal_sha256']+'.bin')
        output.write_bytes(candidate)
        rows.append(dict(model=entry['embedded_model'], revision=entry['revision'],
            normal_envelope_sha256=entry['normal_sha256'], decoded_sha256=sha(body),
            candidate_sha256=sha(candidate), standalone_decoded_sha256=standalone_sha, context_decoding=context, kernel_supplied=entry['kernel_sha256'] is not None,
            audit='all movement conversion groups map with guarded edits',
            operational_state='unresolved; offline applicability is not a new live validation', **result))
    assert len(rows) == 9
    report = dict(status='Offline mapping audit complete; production transition states unchanged',
        input_images=9, distinct_decoded_images=len({r['decoded_sha256'] for r in rows}),
        mapped_images=len(rows), donor_profile='This UD02 unit: parameter 0x028F = 0x0001',
        rows=rows,
        limits=['No live flash or disc test performed.',
                'This ports the movement-only UD04 adaptation; the working UD03 candidate also included earlier experimental groups whose necessity is unresolved.',
                'No production conversion or reverse rule registered.',
                'Only the original UD02 mechanism/profile is represented; do not generalize to every UD02 calibration/profile.',
                'Decoded checksum and code applicability do not by themselves prove receiver acceptance, all mechanisms or full BD/UHD reading.'])
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['status','input_images','distinct_decoded_images','mapped_images']}, indent=2))


if __name__ == '__main__':
    main()
