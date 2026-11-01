"""Captured-disc regression contracts; unknown firmware paths never pass.

Only independently bound geometry initializers execute. ISO bytes provide
logical samples and content associations, not physical DI or emulated reads.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import importlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
geometry_audit = importlib.import_module('audit-mtk-captured-di-geometry')
collector = importlib.import_module('build-mtk-disc-fixtures')
worker_audit = geometry_audit.consumer.worker_audit
sha = lambda data: hashlib.sha256(data).hexdigest()
from stages import DECODER, STOP, branch, run


def bind_geometry(data, state):
    """Bind observed initializer instructions and their source-owned RAM roles.

    This is an execution contract, not a firmware patch or a whole-function
    equivalence proof. BL targets remain the actual source calls and must execute
    successfully under strict memory bounds in every subsequent captured test.
    """
    path = Path(__file__).with_name('disc_geometry_templates.json')
    templates = read_json(path)['templates']
    matches = []
    for template in templates:
        instructions = template['instructions']
        prefix = bytearray.fromhex(''.join(i['bytes'] for i in instructions if 0 <= i['offset'] < 16))
        assert len(prefix) == 16
        wildcard = {i['offset'] for i in instructions if i['offset'] < 16 and 'literal' in i}
        pattern = re.compile(b''.join(b'.' if i in wildcard else re.escape(bytes([byte]))
                                      for i, byte in enumerate(prefix)), re.S)
        for match in pattern.finditer(data):
            entry = match.start()
            if entry % 2:
                continue
            mapping = {}
            try:
                for item in instructions:
                    pc = entry + item['offset']
                    expected = bytes.fromhex(item['bytes'])
                    ins = next(DECODER.disasm(expected, template['config']['entry'] + item['offset'], count=1))
                    actual = next(DECODER.disasm(data[pc:pc + 4], pc, count=1))
                    assert actual.mnemonic == ins.mnemonic and actual.size == ins.size
                    if 'literal' in item:
                        half = int.from_bytes(actual.bytes, 'little')
                        assert half & 0xff00 == int.from_bytes(expected, 'little') & 0xff00
                        address = ((pc + 4) & ~3) + 4 * (half & 255)
                        value = struct.unpack_from('<I', data, address)[0]
                        old = item['literal']
                        if 0x01ff0000 <= old < 0x02030000:
                            assert 0x01ff0000 <= value < 0x02030000
                            assert old not in mapping or mapping[old] == value
                            mapping[old] = value
                        else:
                            assert value == old
                    elif ins.mnemonic in ('bl', 'blx'):
                        assert 0 <= branch(data, pc) < len(data)
                    elif ins.mnemonic in ('b', 'beq', 'bne', 'bhs', 'blo', 'bmi', 'bpl',
                                          'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble'):
                        expected_target = int(ins.op_str.lstrip('#'), 16) - template['config']['entry']
                        assert branch(data, pc) - entry == expected_target
                    else:
                        assert bytes(actual.bytes) == expected
                assert len(set(mapping.values())) == len(mapping), 'aliased source RAM roles'
                reference = template['config']
                config = dict(label='Source-bound ' + reference['label'] + ' initializer layout', entry=entry)
                for key in ('descriptor', 'end_cell', 'state', 'status'):
                    config[key] = mapping[reference[key]]
                for key in ('controls', 'outputs'):
                    config[key] = [(mapping[address], size) for address, size in reference[key]]
                if 'physical_to_logical_offset' in template:
                    config['physical_to_logical_entry'] = entry + template['physical_to_logical_offset']
                assert config['state'] == state
                matches.append((config, dict(template_source_sha256=template['source_sha256'],
                    template_file_sha256=sha(path.read_bytes()), matched_instructions=len(instructions),
                    ram_mapping=mapping)))
            except (AssertionError, KeyError, StopIteration, struct.error):
                continue
    assert len(matches) <= 1, 'ambiguous geometry initializer binding'
    return matches[0] if matches else (None, None)


def read_json(path):
    data = Path(path).read_bytes()
    return json.loads(gzip.decompress(data) if str(path).endswith('.gz') else data)


def load_fixtures(directory):
    directory = Path(directory)
    manifest_bytes = (directory / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest['schema'] == 1
    assert manifest['blob']['file'] == 'sectors.bin'
    blob = (directory / 'sectors.bin').read_bytes()
    assert len(blob) == manifest['blob']['bytes'] and sha(blob) == manifest['blob']['sha256']
    blocks = {}
    for digest, span in manifest['blocks'].items():
        offset, length = span['offset'], span['length']
        assert 0 <= offset and 0 < length and offset + length <= len(blob)
        data = blob[offset:offset + length]
        assert sha(data) == digest, 'fixture block hash mismatch'
        blocks[digest] = data
    captures = {}
    for capture in manifest['captures']:
        assert capture['name'] not in captures, 'duplicate capture name'
        raw, capacity = blocks[capture['structure']], blocks[capture['capacity']]
        derived = collector.geometry(raw, capacity)
        assert derived == capture['geometry'], 'fixture geometry differs from captured bytes'
        for lba, digest in capture['samples'].items():
            assert 0 <= int(lba) < derived['sector_count'] and len(blocks[digest]) == 2048
        captures[capture['name']] = capture
    for image in manifest['images']:
        assert image['bytes'] == image['logical_sector_count'] * 2048
        for lba, digest in image['samples'].items():
            assert 0 <= int(lba) < image['logical_sector_count'] and len(blocks[digest]) == 2048
        for association in image['physical_capture_associations']:
            capture = captures[association['capture']]
            assert capture['geometry']['sector_count'] == image['logical_sector_count']
            compared = association['matching_metadata_lbas']
            assert {32, 256} <= set(compared) and len(set(compared)) >= 3
            for lba in compared:
                digest = capture['samples'][str(lba)]
                assert digest != sha(bytes(2048)) and image['samples'][str(lba)] == digest
            for segment in capture['geometry']['segments'][1:]:
                boundary = segment['first_logical_sector']
                assert all(str(lba) in image['samples'] for lba in (boundary - 1, boundary, boundary + 1))
    return dict(manifest=manifest, blocks=blocks,
                binding=dict(manifest_sha256=sha(manifest_bytes), blob_sha256=sha(blob),
                             physical_captures=len(captures), iso_images=len(manifest['images']),
                             associated_images=sum(bool(i['physical_capture_associations']) for i in manifest['images'])))


def media_state(raw):
    records = raw[4:196]
    identity, layers, fmt = chr(records[10]), records[12] >> 4, records[13]
    if identity == 'U' and fmt == 5 and layers in (2, 3):
        return (0xc7 if layers == 2 else 0xc8), True
    if identity in ('O', 'U') and fmt in (1, 2) and layers in (1, 2):
        return 0xc0 + 4 * (layers - 1), False
    raise AssertionError(f'unbound captured media class {identity}/{fmt}/{layers}')


def audit_image(folder, fixtures, workers):
    folder = Path(folder)
    source = folder.name
    original, modified = [(folder / name).read_bytes() for name in ('original.bin', 'modified.bin')]
    assert sha(original) == source
    result = dict(stage='captured-disc-geometry', source_sha256=source,
        output_sha256=sha(modified), fixture_binding=fixtures['binding'], cases=0,
        status='unqualified', results=[], address_results=[], variants=['original', 'modified'],
        coverage_gaps=[
            'Acquisition and recognition excluded: copied captured DI and classified state are explicit inputs.',
            'ISO samples have not passed through firmware READ dispatch or optical hardware.',
            'Capacity agreement alone does not qualify address translation, layer transitions or physical UHD reading.'])
    report = json.loads((folder / 'modify.json').read_text())
    state = report['execution_contracts']['native_media_roles']['state']
    config, binding = bind_geometry(original, state)
    result['geometry_binding'] = binding
    if config is None:
        result['coverage_gaps'].append('Source-specific complete geometry initializer not yet bound for either OEM or modified output.')
        return result
    assert config['state'] == state
    from capacity import consumers
    capacity_consumers = consumers(original, config['end_cell'])
    assert capacity_consumers, 'native BD capacity normalization not bound'
    result['capacity_consumers'] = capacity_consumers
    result['capacity_results'] = []
    classic = None
    read_value = next((h for h in report['execution_contracts'].get('media_conversion_helpers', [])
                       if h['role'] == 'ReadValue'), None)
    if not config.get('physical_to_logical_entry') and read_value is not None:
        from classic_mapping import bind
        classic = bind(original, read_value)
        config['physical_to_logical_entry'] = classic['forward']
        config['outputs'].append((classic['boundary2'], 4))
        result['classic_mapping_binding'] = classic
    saved_worker = workers[source]['contract']
    # Rebind actual source instructions; an old output digest is not authority.
    worker = worker_audit.contract(original, saved_worker['entry'], state)
    assert worker == saved_worker, 'worker receipt does not match source instructions'
    all_pass = True
    for capture in fixtures['manifest']['captures']:
        raw = fixtures['blocks'][capture['structure']]
        media, uhd = media_state(raw)
        count = capture['geometry']['sector_count']
        expected_original = None
        for variant, setting in (('original', 255), ('modified', 0), ('modified', 1), ('modified', 255)):
            executed = geometry_audit.execute(folder, config, worker, media, raw[4:196], variant, setting)
            match = executed['computed_sector_count'] == count
            if variant == 'original':
                expected_original = executed['observed_memory']
            preserve = executed['observed_memory'] == expected_original
            # Unsupported OEM UHD geometry is recorded, not an OEM regression.
            # Modified On must agree with captured capacity; Off/OEM preserve OEM.
            required = (not uhd or variant == 'modified' and setting == 1)
            passed = (not required or match) and (variant == 'original' or setting == 1 or preserve)
            all_pass &= passed
            result['results'].append(dict(disc=capture['name'], uhd=uhd,
                captured_sector_count=count, matches_captured_capacity=match,
                capacity_match_required=required, preserves_oem_geometry=preserve,
                status='passed' if passed else 'failed', **executed))
            if variant == 'modified' and setting == 1:
                for pc in capacity_consumers:
                    normalized = run(modified, report['engine'], pc, {pc + 8},
                        report['execution_contracts']['base']['flags'], settings={3:setting},
                        memory=[(int(a), bytes.fromhex(v)) for a,v in executed['observed_memory'].items()],
                        strict_reads=True)
                    correct = normalized['registers'][0] == count - 1
                    all_pass &= correct
                    result['capacity_results'].append(dict(disc=capture['name'], entry=pc,
                        expected_last_lba=count - 1, computed_last_lba=normalized['registers'][0],
                        status='passed' if correct else 'failed', trace=normalized['trace']))
            if uhd and config.get('physical_to_logical_entry') and (
                    classic is None or variant == 'modified' and setting == 1):
                # Feed this variant's initialized native RAM into its real mapper.
                # Samples annotate address inputs; their bytes are never supplied
                # as a pretend firmware READ response.
                points = {}
                segments = capture['geometry']['segments']
                for segment in segments:
                    start, length = segment['first_logical_sector'], segment['sector_count']
                    for offset in (0, 1, length - 2, length - 1):
                        points.setdefault(start + offset, [])
                for image in fixtures['manifest']['images']:
                    if any(a['capture'] == capture['name'] for a in image['physical_capture_associations']):
                        for lba, digest in image['samples'].items():
                            points.setdefault(int(lba), []).append(dict(iso=image['relative_path'], sector_sha256=digest))
                for lba, samples in sorted(points.items()):
                    segment = next(s for s in segments if s['first_logical_sector'] <= lba < s['first_logical_sector'] + s['sector_count'])
                    psn = segment['physical_start'] + lba - segment['first_logical_sector']
                    mapped = run(original if variant == 'original' else modified, report['engine'],
                        config['physical_to_logical_entry'], {STOP}, report['execution_contracts']['base']['flags'],
                        settings={3:setting}, registers={0:psn},
                        memory=[(int(a), bytes.fromhex(value)) for a,value in executed['observed_memory'].items()],
                        strict_reads=True)
                    correct = mapped['registers'][0] == lba
                    inverse = routed = None
                    if classic is not None:
                        memory = [(int(a), bytes.fromhex(value)) for a,value in executed['observed_memory'].items()]
                        inverse = run(modified, report['engine'], classic['inverse'], {STOP},
                            report['execution_contracts']['base']['flags'], settings={3:setting},
                            registers={0:lba + 0x100000}, memory=memory, strict_reads=True)
                        routed = run(modified, report['engine'], read_value['contract']['region_start'],
                            {classic['read_stop']}, report['execution_contracts']['base']['flags'],
                            settings={3:setting}, memory=memory + [
                                (classic['read_value'], struct.pack('<I', lba + 0x100000))],
                            allow_writes=[(classic['read_value'], classic['read_value'] + 4)],
                            observe_memory=[(classic['read_value'], 4)], strict_reads=True)
                        correct &= inverse['registers'][0] == psn
                        correct &= int.from_bytes(bytes.fromhex(routed['memory'][str(classic['read_value'])]), 'little') == psn
                    all_pass &= correct
                    result['address_results'].append(dict(disc=capture['name'], variant=variant,
                        unrestricted_setting=setting, physical_address=psn, expected_lba=lba,
                        computed_lba=mapped['registers'][0], status='passed' if correct else 'failed',
                        associated_iso_samples=samples, trace=mapped['trace'],
                        inverse_trace=inverse['trace'] if inverse else None,
                        route_trace=routed['trace'] if routed else None))
    result['cases'] = len(result['results']) + len(result['address_results']) + len(result['capacity_results'])
    result['status'] = 'passed' if all_pass else 'failed'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--worker-receipt', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    fixtures = load_fixtures(args.fixtures)
    workers = {r['source_sha256']:r for r in read_json(args.worker_receipt)['images']}
    inventory = read_json(args.inventory)['images']
    assert len({r['sha256'] for r in inventory}) == len(inventory)
    rows = []
    for row in inventory:
        try:
            result = audit_image(args.outputs / row['sha256'], fixtures, workers)
        except Exception as error:
            result = dict(source_sha256=row['sha256'], status='failed', cases=0, error=str(error))
        rows.append(result)
    receipt = dict(schema=1, images=rows, inventory_sha256=sha(args.inventory.read_bytes()),
        script_sha256=sha(Path(__file__).read_bytes()), fixture_binding=fixtures['binding'],
        worker_receipt_sha256=sha(args.worker_receipt.read_bytes()),
        totals=dict(Counter(r['status'] for r in rows)), cases=sum(r['cases'] for r in rows),
        physical_uhd_qualified=False)
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k:receipt[k] for k in ('totals', 'cases', 'fixture_binding')}))
    return int(any(r['status'] == 'failed' for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
