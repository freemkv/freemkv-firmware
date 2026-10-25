"""Offline census of the local hoard and captured factory identity evidence.

Firmware-package identity is never treated as factory identity. Reads only
saved files; does not access drives. Reports coverage, not universal validity.
"""
import argparse
import collections
import datetime
import hashlib
import json
import re
import struct
from pathlib import Path


def factory_date(raw):
    if len(raw) != 90 or not re.fullmatch(rb'[A-Z0-9+-]{90}', raw):
        return None
    try:
        return datetime.datetime.strptime(raw[76:82].decode(), '%y%m%d').date().isoformat()
    except ValueError:
        return None


def classify(raw):
    if len(raw) != 2048:
        return dict(status='wrong_length')
    tag, code = raw[0x84:0x88], raw[0x90:0x9f]
    tagged = bool(re.fullmatch(rb'kw0[0-9]', tag))
    printable = all(32 <= x < 127 for x in code) and bool(code.rstrip())
    date = factory_date(raw[0xc0:0xc0+90])
    # Research proposal only: absent marker needs independent structural evidence.
    untagged = (tag == b'\xff'*4 and printable
                and re.fullmatch(rb'(?:BDR|BDC|DVR|DVD|CDR)-[A-Z0-9+._-]+', code.rstrip())
                and date is not None)
    return dict(status='tagged' if tagged and printable else
                'untagged_candidate' if untagged else 'unrecognized',
                current_parser_accepts=bool(tagged and printable),
                proposed_parser_accepts=bool((tagged and printable) or untagged),
                product=code.decode('ascii').rstrip() if printable else None,
                factory_test_date=date, tag_hex=tag.hex(),
                response_sha256=hashlib.sha256(raw).hexdigest())


def read_capture(path):
    with path.open('rb') as f:
        size = path.stat().st_size
        if size < 64:
            return None
        f.seek(-64, 2)
        footer = f.read(64)
        if footer[:8] != b'FMVKDMP1':
            return None
        version, length, offset, count = struct.unpack('<IIQQ', footer[8:32])
        assert version == 1 and length == 64 and offset+count == size-64
        f.seek(offset)
        directory = f.read(count)
        assert hashlib.sha256(directory).digest() == footer[32:]
        meta = json.loads(directory)
        sections = {}
        for s in meta['sections']:
            if s['name'] not in ('parameters', 'inquiry', 'identity'):
                continue
            lo, n = s['file_offset'], s['length']
            assert 0 <= lo <= lo+n <= offset
            f.seek(lo)
            raw = f.read(n)
            assert hashlib.sha256(raw).hexdigest() == s['sha256']
            reads = [r for r in meta['reads'] if r['file_offset'] == lo]
            valid = any(r.get('status') == 'captured' and r.get('received') == n
                        and r.get('requested') == n for r in reads)
            sections[s['name']] = raw if valid else None
        raw = sections.get('parameters')
        record = classify(raw) if raw is not None else dict(status='not_captured')
        inquiry = sections.get('inquiry') or b''
        identity = sections.get('identity') or b''
        return dict(capture_complete=meta['complete'],
                    firmware_product=inquiry[16:32].decode('ascii', 'replace').strip(),
                    firmware_revision=inquiry[32:36].decode('ascii', 'replace').strip(),
                    unit_key=hashlib.sha256(identity[:16]).hexdigest() if identity else None,
                    production=record)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    inventory, captures, errors = {}, [], []
    for name in ('hoard', 'hoard-bdplayer', 'user-dump', 'user-backup'):
        root = args.root/name
        files = sorted(x for x in root.rglob('*') if x.is_file())
        digest = hashlib.sha256()
        suffixes = collections.Counter()
        candidates = 0
        for path in files:
            relative = str(path.relative_to(args.root))
            digest.update((relative+'\t'+str(path.stat().st_size)+'\n').encode())
            suffixes[path.suffix.lower()] += 1
            if path.suffix.lower() not in ('.bin', '.dump', '.raw'):
                continue
            candidates += 1
            try:
                result = read_capture(path)
                if result is not None:
                    captures.append(dict(path=relative, **result))
            except Exception as e:
                errors.append(dict(path=relative, error=repr(e)))
        inventory[name] = dict(files=len(files), suffixes=dict(suffixes),
                               inventory_sha256=digest.hexdigest(),
                               binary_capture_candidates_checked=candidates)
    hoard = args.root/'hoard'
    identities = json.loads((hoard/'index/identities.json').read_text())['identities']
    images = {image['sha256']: image for group in identities for image in group['images']}
    packages = json.loads((hoard/'index/packages.json').read_text())['packages']
    missing_images = [x['path'] for x in images.values() if not (hoard/x['path']).is_file()]
    unique = {x['production'].get('response_sha256'): x['production'] for x in captures
              if x['production'].get('response_sha256')}
    cases = collections.Counter(x['status'] for x in unique.values())
    proposed_only = [x for x in unique.values() if x.get('proposed_parser_accepts')
                     and not x.get('current_parser_accepts')]
    report = dict(scope=__doc__, inventory=inventory,
                  catalog=dict(identity_groups=len(identities), distinct_images=len(images),
                               groups_by_family=dict(collections.Counter(x['family'] for x in identities)),
                               packages=len(packages),
                               indexed_missing_images=missing_images,
                               unique_normal_images=len({x['normal_sha256'] for x in packages}),
                               firmware_metadata_is_not_factory_evidence=True),
                  capture_count=len(captures), unique_parameter_responses=len(unique),
                  unique_units_with_identity=len({x['unit_key'] for x in captures if x['unit_key']}),
                  production_status_counts=dict(cases), proposed_only=proposed_only,
                  captures=captures, errors=errors,
                  limitation='Only captured A0 responses validate factory parsing. OEM packages '
                  'and player firmware do not contain evidence of a particular drive factory record. '
                  'This census does not prove a proposed parser on unrepresented hardware.')
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('catalog','capture_count',
                      'unique_parameter_responses','unique_units_with_identity',
                      'production_status_counts','proposed_only','errors')}, indent=2))


if __name__ == '__main__':
    main()
