#!/usr/bin/env python3
"""Collect compact, read-only ISO samples and independently saved physical DI.

Root-directory ISOs are classified UHD by user instruction. Subdirectories keep
their own media classification. ISO size is logical image size, never invented
physical DI. Capture associations require equal capacity and metadata hashes;
they are evidence of matching content, not proof of capture-time drive firmware.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

SECTOR = 2048
METADATA_LBAS = (0, 16, 17, 18, 32, 33, 34, 256, 257, 512)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture_samples(path):
    with path.open('rb') as f:
        header = f.read(12)
        if header[:4] == b'BDSM':
            version, count = struct.unpack('<II', header[4:])
            assert version == 1 and count <= 10000
            table = f.read(count * 8)
            assert len(table) == count * 8
            offset = 12 + count * 8
            ranges = []
            for start, length in struct.iter_unpack('<II', table):
                ranges.append((start, length, offset)); offset += length * SECTOR
            assert offset == path.stat().st_size
        else:
            assert path.stat().st_size % SECTOR == 0
            ranges = [(0, path.stat().st_size // SECTOR, 0)]
        result = {}
        for lba in METADATA_LBAS:
            for start, count, offset in ranges:
                if start <= lba < start + count:
                    f.seek(offset + (lba - start) * SECTOR)
                    value = f.read(SECTOR); assert len(value) == SECTOR
                    result[lba] = value
                    break
        return result


def geometry(raw, capacity):
    assert len(raw) >= 196 and raw[4:6] == b'DI' and raw[12:14] == b'BD'
    assert len(capacity) == 8 and int.from_bytes(capacity[4:], 'big') == SECTOR
    data = raw[4:]; layers = data[12] >> 4
    assert 1 <= layers <= 3
    last = struct.unpack_from('>I', data, 20)[0]
    segments, logical = [], 0
    for layer in range(layers):
        start, recorded_end = struct.unpack_from('>II', data, layer * 64 + 24)
        end = min(recorded_end + 1, last)
        assert end >= start
        length = end - start + 1
        segments.append(dict(layer=layer, physical_start=start, recorded_end_field=recorded_end,
                             inclusive_data_end=end, first_logical_sector=logical, sector_count=length))
        logical += length
    count = int.from_bytes(capacity[:4], 'big') + 1
    assert logical == count, 'DI ranges disagree with saved capacity; refuse guessed geometry'
    return dict(identifier=chr(data[10]), format=data[13], layers=layers, sector_count=count,
                segments=segments, qualification='Range interpretation checked against independently saved capacity; not an optical acquisition simulation.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--iso-root', type=Path, required=True)
    p.add_argument('--captures', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=True)
    blob = bytearray(); blocks = {}
    def save(data):
        digest = sha(data)
        if digest not in blocks:
            blocks[digest] = dict(offset=len(blob), length=len(data)); blob.extend(data)
        return digest
    captures = []
    for path in sorted(a.captures.glob('*/ds_00.bin')):
        cap_path, sectors_path = path.with_name('capacity.bin'), path.with_name('sectors.bin')
        if not cap_path.exists() or not sectors_path.exists():
            continue
        raw, capacity = path.read_bytes(), cap_path.read_bytes()
        captures.append(dict(name=path.parent.name, structure_source=str(path), capacity_source=str(cap_path),
            structure=save(raw), capacity=save(capacity), geometry=geometry(raw, capacity),
            samples={str(lba):save(data) for lba, data in capture_samples(sectors_path).items()},
            provenance='Existing local testbed captures; capture-time firmware not independently authenticated here.'))
    images = []
    paths = sorted(p for p in a.iso_root.rglob('*') if p.is_file() and p.suffix.lower() == '.iso')
    for path in paths:
        relative = path.relative_to(a.iso_root)
        family = 'uhd' if len(relative.parts) == 1 else relative.parts[0].lower()
        before = path.stat()
        assert before.st_size % SECTOR == 0 and before.st_size >= 513 * SECTOR
        count = before.st_size // SECTOR
        selected = set(METADATA_LBAS) | {count // 2, count - 1, count - 256}
        selected.update(lba for point in (1 << 24, 1 << 25) for lba in (point - 1, point, point + 1) if lba < count)
        samples = {}
        with path.open('rb') as f:
            def sample(lba):
                if lba not in samples and 0 <= lba < count:
                    f.seek(lba * SECTOR); value = f.read(SECTOR)
                    assert len(value) == SECTOR
                    samples[lba] = save(value)
            for lba in sorted(selected):
                sample(lba)
            associations = []
            for cap in captures:
                if cap['geometry']['sector_count'] != count:
                    continue
                compared = [int(lba) for lba, digest in cap['samples'].items()
                            if digest != sha(bytes(SECTOR)) and int(lba) in samples]
                if 32 not in compared or 256 not in compared or len(compared) < 3:
                    continue
                if all(samples[lba] == cap['samples'][str(lba)] for lba in compared):
                    associations.append(dict(capture=cap['name'], matching_metadata_lbas=compared,
                                             basis='Equal logical size and matching saved metadata sectors; content association, not drive provenance.'))
                    for segment in cap['geometry']['segments'][1:]:
                        boundary = segment['first_logical_sector']
                        for lba in (boundary - 1, boundary, boundary + 1):
                            sample(lba)
        after = path.stat()
        assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'ISO changed during collection'
        images.append(dict(path=str(path), relative_path=str(relative), media_family=family,
            family_basis='user: root ISOs are UHD' if family == 'uhd' else 'containing directory',
            bytes=before.st_size, logical_sector_count=count, mtime_ns=before.st_mtime_ns,
            samples={str(k):v for k,v in sorted(samples.items())}, physical_capture_associations=associations,
            full_image_hash_computed=False,
            physical_geometry_status='associated captured DI' if associations else 'not present in ISO; not synthesized'))
        if len(images) % 20 == 0:
            print(f'{len(images)}/{len(paths)} ISOs sampled', flush=True)
    result = dict(schema=1, scope=__doc__, collector_sha256=sha(Path(__file__).read_bytes()),
                  iso_root=str(a.iso_root), captures=captures, images=images, blocks=blocks,
                  blob=dict(file='sectors.bin', bytes=len(blob), sha256=sha(blob)),
                  totals=dict(images=len(images), media_families=dict(Counter(i['media_family'] for i in images)),
                              physical_captures=len(captures), associated_images=sum(bool(i['physical_capture_associations']) for i in images)))
    (a.output / 'sectors.bin').write_bytes(blob)
    (a.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['totals']))


if __name__ == '__main__':
    main()
