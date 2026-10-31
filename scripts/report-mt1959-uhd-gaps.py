"""Generate the MT1959 OEM UHD reference/gap inventory from read-only evidence.

Hashes bind receipts and reference provenance, never choose a firmware patch.
Unknown evidence is not a missing feature. No output is a flashable image.
"""
import argparse
import collections
import csv
import json
from pathlib import Path

ROLE_GAPS = {
    'ControlBit': 'S02', 'ControlField': 'S03',
    'ForwardCalculation': 'S04', 'ReverseCalculation': 'S05',
    'ParameterNibble': 'S06',
}


def consumer_gaps(receipt):
    gaps, observations = [], {}
    for role in (receipt or {}).get('roles', []):
        cases = [c for c in role['cases'] if c['state'] == 0xc7 and c['initial_word'] == 0]
        assert cases
        name = role['role']
        if name == 'ControlBit':
            value = cases[0]['value']
            assert cases[0]['status'] == 'register_write' and value in (0, 1 << 31)
            observations[name] = 'sets bit31' if value else 'clears bit31'
            if value == 0:
                gaps.append('G02')
        elif name == 'ControlField':
            value = cases[0]['value']
            assert cases[0]['status'] == 'register_write' and cases[0]['address'] == 0x04200030 and value in (0, 0x30)
            observations[name] = f'field bits7:4 = {value >> 4}'
            if value != 0:
                gaps.append('G03')
        elif name in ('ForwardCalculation', 'ReverseCalculation'):
            status = cases[0]['status']
            assert status in ('worker_call', 'restoration_path_without_worker')
            observations[name] = status
            if status != 'worker_call':
                gaps.append('G04' if name == 'ForwardCalculation' else 'G05')
        elif name == 'ParameterNibble':
            case = next(c for c in cases if c['flag'] == 32)
            values = case['outputs_by_index_0_to_12']
            observations[name] = 'flag5 set: ' + ('fixed nibble2' if values == [2] * 13 else 'table ' + ','.join(map(str, values)))
            if values != [2] * 13:
                gaps.append('G06')
    if receipt:
        assert set(observations) == set(ROLE_GAPS), 'incomplete consumer receipt'
    return gaps, observations


def qualification_gap(source, alias):
    identity = source['catalogue_identity']
    hardware, revision = identity['hardware'], identity['revision']
    if alias:
        return 'Archive duplicate of a dump; not a stock image reference.'
    if source['bytes'] < 2097152:
        return 'Incomplete metadata/partial dump; full stock firmware unavailable in this source.'
    if source['category'] != 'oem':
        return 'Dump or modified-source provenance; not locked as a stock manufacturer UHD reference.'
    if revision == 'INTM':
        return 'Intermediate updater payload; not a locked shipping-production firmware reference.'
    if hardware.startswith('hp '):
        return 'HP-specific firmware; no exact OEM SKU UHD advertising locked. Generic retail BU40N support does not qualify this variant.'
    if 'BU50N' in hardware:
        return 'Stock updater exists, but manufacturer UHD advertising tied to this exact variant has not been established.'
    if 'BU40N' in hardware and revision == 'A103':
        return 'Dell A103 updater is identified; no exact Dell SKU UHD-playback advertising locked.'
    if 'BU40N' in hardware and revision == 'TK03':
        return 'Official Dynabook TK03 updater hash verified; exact host/drive SKU UHD advertising not locked.'
    if 'BU40N' in hardware and revision in ('1.01', 'U101'):
        return 'Regional R/M firmware variant; exact advertised UHD retail SKU mapping remains unverified.'
    return 'Not locked to a manufacturer-advertised stock UHD product; see executed gaps and unresolved requirements.'


def worker_observations(receipt):
    if receipt is None:
        return [], 'unresolved', 'unresolved'
    cases = receipt['certificate_allocation_cases']
    cap = next(c['value'] for c in cases if c['mode'] == 1 and c['allocation'] == 1024)
    assert cap in (116, 180)
    route39 = next(c['status'] for c in receipt['cases'] if c['mode'] == 1 and c['key_class'] == 3 and c['format'] == 0x39)
    if cap == 116:
        assert receipt['mode_cell'] is None and route39 == 'native_return'
        return ['G08'], 'fixed 116-byte certificate/nonce response cap', '0x39 takes invalid-format return'
    assert receipt['mode_cell'] is not None and route39 == 'worker_call'
    return [], 'native mode selects 116/180-byte certificate/nonce response cap', '0x39 reaches a worker'


def classify(source, scan, di, keys, references, alias=None, consumers=None, workers=None, mode_init=None):
    sha = source['sha256']
    full = source['bytes'] == 2097152
    code = (scan or source)['uhd_code']
    roles = {a['role']: a for a in code['areas']}
    cases = (di or {}).get('cases', [])
    u_cases = [c for c in cases if c['identifier'] == 'U' and c['layers'] in (2, 3)]
    gaps, differences = [], []
    if len(u_cases) == 2:
        if all(c['state_store'] is None for c in u_cases):
            di_result = 'rejects tested U/5 at DI gate'
            gaps.append('G01')
        elif [c['state_store'] for c in u_cases] == [199, 200]:
            di_result = 'U/5: 2L=C7; 3L=C8'
        else:
            di_result = 'unresolved DI result'
    else:
        di_result = 'unresolved; no executed DI receipt'
    consumer_gap_ids, consumer_observations = consumer_gaps(consumers)
    gaps.extend(consumer_gap_ids)
    for role, gap in ROLE_GAPS.items():
        if roles[role]['evidence'] == 'recognized_legacy_path' and not consumers:
            differences.append(gap)
    key_cases = (keys or {}).get('cases', [])
    refusals = [c for c in key_cases if c.get('classes', {}).get('3', {}).get('status') == 'worker_refusal']
    if refusals:
        assert all(c['classes']['3']['matches_sense_setter'] and c['classes']['3']['refusal_args'] == [5, 48, 2] for c in refusals)
        key_result = 'class3 REPORT KEY -> 05/30/02; SEND KEY worker differs'
        gaps.append('G07')
    elif (keys or {}).get('compared_cases') == 30 and keys['same_class2_class3_workers'] == 30:
        key_result = 'same workers for classes 2/3: 30/30 cases'
    else:
        key_result = 'unresolved key routing'
    worker_gaps, worker_response, worker_format39 = worker_observations(workers)
    gaps.extend(worker_gaps)
    if not full and alias is None:
        gaps, differences = [], []
        di_result = key_result = 'unresolved: fragment only'
    reference = references.get(sha)
    if reference:
        assert full and source['category'] == 'oem' and not source.get('catalogue_patched')
        assert not gaps and not differences
    unknown_roles = [a['role'] for a in roles.values() if a['evidence'] == 'unknown']
    unresolved = ['physical acquisition/init and density handling', 'full caller reachability and remaining media-state consumers',
                  'DL/TL sector reads']
    if alias:
        unresolved.insert(0, 'archive duplicate; evidence belongs to canonical payload ' + alias['payload_sha256'])
    elif not full:
        unresolved.insert(0, 'obtain full stock payload')
    elif key_result.startswith('unresolved'):
        unresolved.insert(0, 'bind native key-command handlers')
    if unknown_roles:
        unresolved.insert(0, 'unbound code roles: ' + ', '.join(unknown_roles))
    media_gaps = [g for g in gaps if g in ('G01','G02','G03','G04','G05','G06')]
    media_complete = full and not media_gaps and not differences and not unknown_roles and len(u_cases) == 2 and bool(consumers)
    identity = source['catalogue_identity']
    return {
        'sha256': sha, 'hardware': identity['hardware'], 'revision': identity['revision'],
        'destination': identity['destination'], 'category': source['category'],
        'bytes': source['bytes'], 'payload': 'archive duplicate' if alias else 'full source' if full else 'fragment',
        'canonical_payload_sha256': alias['payload_sha256'] if alias else sha if full else '',
        'classification': 'OEM UHD' if media_complete else '1959 non UHD' if full else 'unresolved',
        'classification_basis': '100% of G01-G06 media contracts' if media_complete else
            'G01-G06 media gaps or incomplete evidence; G07/G08 excluded',
        'manufacturer_backed_reference': bool(reference),
        'G01_G06_complete': media_complete,
        'reference_product': reference['product'] if reference else '',
        'reference_url': reference['url'] if reference else '',
        'manufacturer_reference_provenance_gap': '' if reference else qualification_gap(source, alias),
        'comparison_baseline': 'WH16NS60 1.01 / BU40N 1.02; semantic roles, not hardware constants',
        **{name: ('unknown' if not full and alias is None else 'gap' if gap in gaps else 'reviewed match')
           for gap, name in (
               ('G01', 'disc_information_admission'), ('G02', 'C7_control_bit'),
               ('G03', 'C7_control_field'), ('G04', 'C7_forward_calculation_admission'),
               ('G05', 'C7_reverse_calculation_admission'), ('G06', 'C7_conditional_parameter'),
               ('G07', 'class3_key_routing'), ('G08', 'extended_key_response_path'))},
        'di_gate': di_result, 'key_routing': key_result,
        'C7_consumer_observations': json.dumps(consumer_observations, separators=(',', ':')),
        'key_worker_response': worker_response, 'key_worker_format39': worker_format39,
        'key_mode_initialization': (mode_init or {}).get('status', 'unresolved_incomplete_source'),
        'key_mode_selector_variant': (mode_init or {}).get('variant', 'unresolved'),
        'key_mode_invalid_header': {
            'clear_first': 'clear before validation',
            'preserve_supplied': 'preserve supplied prior mode in isolated selector',
            'clear_on_other_type': 'clear unless low24 header is 0x141003 or 0x151003',
        }.get((mode_init or {}).get('invalid_header_policy'), 'unresolved'),
        'media_pipeline_gaps': ','.join(g for g in gaps if g in ('G01','G02','G03','G04','G05','G06')),
        'internal_authentication_differences': ','.join(g for g in gaps if g in ('G07','G08')),
        'proven_gaps': ','.join(gaps), 'structural_differences_to_resolve': ','.join(differences),
        'unresolved': '; '.join(unresolved), 'path': source['path'],
        'stock_provenance': json.dumps((scan or {}).get('provenance', {}).get('sources', []), separators=(',', ':')),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--di', type=Path, required=True)
    p.add_argument('--keys', type=Path, required=True)
    p.add_argument('--consumers', type=Path, default=Path('internal/docs/audits/mt1959-uhd-consumer-receipts-20261030.json'))
    p.add_argument('--workers', type=Path, default=Path('internal/docs/audits/mt1959-uhd-key-worker-receipts-20261030.json'))
    p.add_argument('--mode-init', type=Path, default=Path('internal/docs/audits/mt1959-uhd-key-mode-init-receipts-20261030.json'))
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    audit = Path('internal/docs/audits')
    corpus = json.loads((audit / 'mediatek-uhd-corpus-20261030.json').read_text())['images']
    sources = [r for r in corpus if (r.get('catalogue_identity') or {}).get('platform') == 'MT1959']
    scans = {r['sha256']: r for r in json.loads(a.scan.read_text())['images']}
    dis = {r['source_sha256']: r for r in json.loads(a.di.read_text())['images']}
    keys = {r['sha256']: r for r in json.loads(a.keys.read_text())['images']}
    consumers = {r['sha256']: r for r in json.loads(a.consumers.read_text())['images']}
    workers = {r['sha256']: r for r in json.loads(a.workers.read_text())['images']}
    mode_init = {r['sha256']: r for r in json.loads(a.mode_init.read_text())['images']}
    refs = json.loads((audit / 'mt1959-oem-uhd-references-20261030.json').read_text())['references']
    references = {r['sha256']: r for r in refs}
    aliases = {r['source_sha256']: r for r in json.loads((audit / 'mt1959-source-containers-20261030.json').read_text())['aliases']}
    rows = []
    for s in sources:
        alias = aliases.get(s['sha256'])
        payload_sha = alias['payload_sha256'] if alias else s['sha256']
        rows.append(classify(s, scans.get(payload_sha), dis.get(payload_sha), keys.get(payload_sha), references, alias, consumers.get(payload_sha), workers.get(payload_sha), mode_init.get(payload_sha)))
    rows.sort(key=lambda r: (r['category'] != 'oem', r['payload'] != 'full source', r['hardware'], r['revision'], r['sha256']))
    assert len(rows) == len({r['sha256'] for r in rows}) == 199
    assert sum(r['payload'] == 'full source' for r in rows) == 171
    assert sum(r['category'] == 'oem' and r['payload'] == 'full source' for r in rows) == 67
    assert sum(r['payload'] == 'archive duplicate' for r in rows) == 2
    assert sum(r['manufacturer_backed_reference'] for r in rows) == len(references)
    assert sum(r['classification'] == 'OEM UHD' for r in rows) == 147
    v9 = next(r for r in rows if r['sha256'].startswith('97b28707'))
    assert v9['classification'] == 'OEM UHD' and not v9['media_pipeline_gaps'] and v9['internal_authentication_differences'] == 'G07,G08'
    assert len(scans) == len(dis) == len(keys) == len(consumers) == len(workers) == 171
    assert set(scans) == set(dis) == set(keys) == set(consumers) == set(workers) == set(mode_init)
    assert set(scans) == {s['sha256'] for s in sources if s['bytes'] == 2097152}
    a.out.mkdir(parents=True, exist_ok=True)
    with (a.out / 'mt1959-uhd-gap-table-20261030.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader(); w.writerows(rows)
    (a.out / 'mt1959-uhd-gap-table-20261030.json').write_text(json.dumps({'scope': __doc__, 'images': rows}, indent=2) + '\n')
    full_rows = [r for r in rows if r['payload'] == 'full source']
    active = [r for r in full_rows if r['G01_G06_complete']]
    md = ['# MT1959 OEM UHD comparison and gap table', '',
        '**Definition agreed with the user: OEM UHD = 100% of G01-G06.** G07/G08 are known internal authentication differences only. They do not affect this classification, block conversion or generate patches. Existing freemkv AKE/encryption bypasses remain separate.', '',
        '**Active scope: 147/147 newer-layout payloads meet all six reviewed media contracts (100%).** They already contain these contracts; no G01-G06 conversion edits are needed for this group. The 24 older-layout MT1959 payloads are deferred alongside MT1939. No physical UHD read or playback success is implied by the six-contract classification.', '',
        '199 catalogue entries comprise 171 distinct full payloads, 26 incomplete sources and two archive aliases. The full OEM source bucket has 67 images. Source provenance, manufacturer advertising and physical testing are separate from the requested six-contract definition. Incomplete sources remain unresolved.', '',
        '| Required media contract | Meaning |', '| --- | --- |',
        '| G01 | U/5 DI admission and C7/C8 layer state |',
        '| G02 | C7 control-bit selection |',
        '| G03 | C7 control-field selection |',
        '| G04 | C7 forward calculation |',
        '| G05 | C7 reverse calculation and native mode selection |',
        '| G06 | C7 conditional parameter |', '',
        'The numerical surveys execute native division workers. The reverse alternatives use R7 minus 12 times the quotient in mode zero, and R5 minus 9 times the quotient in nonzero mode. Mode production and calibration remain unresolved for the deferred older layouts. The original DI/consumer receipt assumptions remain recorded in their source JSONs; optical acquisition and sector reads require hardware validation.', '',
        '## Manufacturer-backed comparison references', '',
        'These nine stock images anchor the comparison. They are not the only images classified OEM UHD under the revised definition.', '',
        '| Product | Revision | SHA prefix | Specification |', '| --- | --- | --- | --- |']
    for ref in refs:
        r = next(r for r in rows if r['sha256'] == ref['sha256'])
        md.append(f"| {ref['product']} | {r['revision']} | `{r['sha256'][:12]}` | [Specification]({ref['url']}) |")
    md += ['', '## Internal authentication findings (no patches)', '',
        'G07 records class-3 REPORT/SEND KEY routing differences. G08 records extended response/session/backend differences. In the active 147, 94 have both differences and 53 have neither in the reviewed paths. Neither finding changes the G01-G06 result. Their necessity for freemkv reading with bypasses enabled has not been demonstrated. Do not infer successful native authentication from the media classification.', '',
        '## All firmware entries', '',
        '| Source | Hardware / revision / destination | SHA prefix | OEM UHD (G01-G06) | Required media gaps | Internal auth differences |',
        '| --- | --- | --- | --- | --- | --- |']
    for r in rows:
        vals = [r['category'] + ' / ' + r['payload'], r['hardware'] + ' / ' + r['revision'] + ' / ' + r['destination'],
                '`' + r['sha256'][:12] + '`', r['classification'],
                r['media_pipeline_gaps'] or ('none' if r['G01_G06_complete'] else 'unresolved'),
                r['internal_authentication_differences'] or ('none observed' if r['payload'] == 'full source' else 'unresolved')]
        md.append('| ' + ' | '.join(v.replace('|', '/') for v in vals) + ' |')
    md += ['', '## Evidence and reproduction', '',
        'The adjacent CSV/JSON retain source hashes, relative hoard paths, manufacturer-reference provenance, stage observations and unresolved physical checks. G01-G06 media requirements are separate from internal G07/G08 observations. The implementation checkpoint records compiler tests, CPU validation and installer behavior.', '',
        '```sh',
        'python3 scripts/report-mt1959-uhd-gaps.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --di internal/docs/audits/mt1959-uhd-di-receipts-20261030.json --keys internal/docs/audits/mt1959-uhd-keys-receipts-20261030.json --out internal/docs/audits',
        '```', '',
        'All 171 full payloads have source-bound DI, consumer, key and mode receipts. Historical authentication receipts remain diagnostic evidence; their presence does not authorize authentication edits.', '']
    (a.out / 'mt1959-uhd-gap-table-20261030.md').write_text('\n'.join(md).rstrip() + '\n')
    print(json.dumps({'entries': len(rows), 'references': len(refs), 'full_sources_with_protocol_scan': len(scans),
        'stock_full_proven_gap_groups': dict(collections.Counter(r['proven_gaps'] or 'none established' for r in rows if r['category'] == 'oem' and r['payload'] == 'full source'))}, indent=2))


if __name__ == '__main__':
    main()
