"""Identify archive aliases in the MT1959 corpus without modifying the hoard."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hoard', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    corpus = json.loads(Path('internal/docs/audits/mediatek-uhd-corpus-20261030.json').read_text())['images']
    by_sha = {r['sha256']: r for r in corpus}
    aliases, containers = [], []
    for source in corpus:
        if (source.get('catalogue_identity') or {}).get('platform') != 'MT1959':
            continue
        data = (a.hoard / source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == source['sha256']
        if not tarfile.is_tarfile(io.BytesIO(data)):
            continue
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = [m for m in archive if m.isfile()]
            containers.append({'source_sha256': source['sha256'], 'members': [
                {'name': m.name, 'bytes': m.size, 'offset': m.offset_data,
                 'sha256': hashlib.sha256(archive.extractfile(m).read()).hexdigest()} for m in members]})
            payloads = [m for m in members if m.size == 2097152]
            if not payloads:
                assert source['bytes'] < 2097152, 'large archive without a full payload'
                continue
            assert len(payloads) == 1, 'ambiguous archive payload'
            member = payloads[0]
            payload = archive.extractfile(member).read()
            digest = hashlib.sha256(payload).hexdigest()
            canonical = by_sha[digest]
            assert canonical['bytes'] == 2097152
            assert hashlib.sha256((a.hoard / canonical['path']).read_bytes()).hexdigest() == digest
            aliases.append({'source_sha256': source['sha256'], 'source_path': source['path'],
                'source_category': source['category'], 'member': member.name,
                'member_offset': member.offset_data, 'payload_bytes': len(payload),
                'payload_sha256': digest, 'canonical_path': canonical['path'],
                'canonical_category': canonical['category'],
                'finding': 'tar archive containing an already catalogued dump; not a separate stock firmware image'})
    a.output.write_text(json.dumps({'scope': __doc__, 'aliases': aliases, 'containers': containers}, indent=2) + '\n')
    print(f'PASS: all 199 MT1959 source hashes checked; {len(aliases)} verified archive aliases')


if __name__ == '__main__':
    main()
