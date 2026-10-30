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


def classify(source, scan, di, keys, references):
    sha = source['sha256']
    full = source['bytes'] >= 2097152
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
    for role, gap in ROLE_GAPS.items():
        if roles[role]['evidence'] == 'recognized_legacy_path':
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
    if not full:
        gaps, differences = [], []
        di_result = key_result = 'unresolved: fragment only'
    reference = references.get(sha)
    if reference:
        assert full and source['category'] == 'oem' and not source.get('catalogue_patched')
        assert not gaps and not differences
    unknown_roles = [a['role'] for a in roles.values() if a['evidence'] == 'unknown']
    unresolved = ['physical acquisition/init and density handling', 'complete downstream media-state use',
                  'AACS2 exchange/keys and hardware dependencies', 'DL/TL sector reads']
    if not full:
        unresolved.insert(0, 'obtain full stock payload')
    elif key_result.startswith('unresolved'):
        unresolved.insert(0, 'bind native key-command handlers')
    if unknown_roles:
        unresolved.insert(0, 'unbound code roles: ' + ', '.join(unknown_roles))
    identity = source['catalogue_identity']
    return {
        'sha256': sha, 'hardware': identity['hardware'], 'revision': identity['revision'],
        'destination': identity['destination'], 'category': source['category'],
        'bytes': source['bytes'], 'payload': 'full source' if full else 'fragment',
        'classification': 'OEM UHD' if reference else '1959 non UHD',
        'classification_basis': 'manufacturer UHD product + stock provenance' if reference else
            'not qualified as an OEM UHD stock reference; not a physical inability verdict',
        'reference_product': reference['product'] if reference else '',
        'reference_url': reference['url'] if reference else '',
        'comparison_baseline': 'WH16NS60 1.01 / BU40N 1.02; semantic roles, not hardware constants',
        'di_gate': di_result, 'key_routing': key_result,
        'proven_gaps': ','.join(gaps), 'structural_differences_to_resolve': ','.join(differences),
        'unresolved': '; '.join(unresolved), 'path': source['path'],
        'stock_provenance': json.dumps((scan or {}).get('provenance', {}).get('sources', []), separators=(',', ':')),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--di', type=Path, required=True)
    p.add_argument('--keys', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    audit = Path('internal/docs/audits')
    corpus = json.loads((audit / 'mediatek-uhd-corpus-20261030.json').read_text())['images']
    sources = [r for r in corpus if (r.get('catalogue_identity') or {}).get('platform') == 'MT1959']
    scans = {r['sha256']: r for r in json.loads(a.scan.read_text())['images']}
    dis = {r['source_sha256']: r for r in json.loads(a.di.read_text())['images']}
    keys = {r['sha256']: r for r in json.loads(a.keys.read_text())['images']}
    refs = json.loads((audit / 'mt1959-oem-uhd-references-20261030.json').read_text())['references']
    references = {r['sha256']: r for r in refs}
    rows = [classify(s, scans.get(s['sha256']), dis.get(s['sha256']), keys.get(s['sha256']), references) for s in sources]
    rows.sort(key=lambda r: (r['category'] != 'oem', r['payload'] != 'full source', r['hardware'], r['revision'], r['sha256']))
    assert len(rows) == len({r['sha256'] for r in rows}) == 199
    assert sum(r['payload'] == 'full source' for r in rows) == 173
    assert sum(r['category'] == 'oem' and r['payload'] == 'full source' for r in rows) == 69
    assert sum(r['classification'] == 'OEM UHD' for r in rows) == len(references)
    v9 = next(r for r in rows if r['sha256'].startswith('97b28707'))
    assert v9['classification'] == '1959 non UHD' and v9['proven_gaps'] == 'G07'
    a.out.mkdir(parents=True, exist_ok=True)
    with (a.out / 'mt1959-uhd-gap-table-20261030.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    (a.out / 'mt1959-uhd-gap-table-20261030.json').write_text(json.dumps({'scope': __doc__, 'images': rows}, indent=2) + '\n')
    md = ['# MT1959 OEM UHD comparison and gap table', '',
        'OEM UHD means stock firmware tied to a manufacturer-advertised UHD product. Everything else is classified 1959 non UHD for this comparison, including unqualified variants, modified images and incomplete sources. That classification alone does not prove physical inability.', '',
        '199 catalogue entries: 173 full-sized sources and 26 fragments. The stock-source comparison has 69 full-sized OEM entries plus 24 OEM fragments. Two full sources have a 2,560-byte suffix. Counts are source hashes, not independent drives or tested successes.', '',
        'Manufacturer support establishes the OEM references. No image has a local physical detection/sector-read receipt in this investigation. Matching the reviewed paths does not establish complete OEM equivalence. Unknown is not absent. No firmware patch or new BIN is produced by this report.', '',
        'DI execution begins after prefix/attribute validation and stops at the first state write or outgoing gate edge. Key execution supplies success only to the recorded wrapper guard and stops at a key worker, except the positively matched CSS refusal worker is followed to the role-bound sense setter. Crypto, acquisition and sector reads are not simulated as successful.', '',
        '## Manufacturer-backed stock references', '',
        '| Product | Revision | SHA-256 prefix | Manufacturer evidence |', '| --- | --- | --- | --- |']
    stock_full = [r for r in rows if r['category'] == 'oem' and r['payload'] == 'full source']
    summary = collections.Counter(
        'OEM UHD reference' if r['classification'] == 'OEM UHD' else
        r['proven_gaps'] or ('key routing unresolved' if r['key_routing'].startswith('unresolved') else
                             'no proven gap in reviewed paths; full equivalence unresolved')
        for r in stock_full)
    md[md.index('## Manufacturer-backed stock references'):md.index('## Manufacturer-backed stock references')] = [
        '## Summary of the 69 full stock sources', '',
        '| Status | Images |', '| --- | --- |',
        *[f'| {status} | {count} |' for status, count in summary.items()], '',
        'G01 is DI rejection; G07 is key-class routing. No-proven-gap rows are not promoted to OEM UHD. These results do not establish 100% functional coverage.', '',
    ]
    for ref in refs:
        r = next(r for r in rows if r['sha256'] == ref['sha256'])
        md.append(f"| {ref['product']} | {r['revision']} | `{r['sha256'][:12]}` | [Specification]({ref['url']}) |")
    md += ['', '## Gap-to-patch contracts', '',
        'These are patch designs, not implemented conversions. Proven gaps and structural differences are kept separate. One logical patch may edit coordinated sites. Address/hash/model tables must never select a patch.', '',
        '| ID | Detection | Focused patch design | Verification required |',
        '| --- | --- | --- | --- |',
        '| G01 — DI rejection (proven) | Bind the DI identifier/density gate and its native state cell; execute U/5 with two/three layers and observe no state assignment. | Add OEM-equivalent U/5 admission and C7/C8 assignment while retaining existing exits and stack/register contracts. | CPU cases for supported/invalid layers and identifiers; unchanged BD/DVD/CD behavior; then actual acquisition. |',
        '| S02 — control-bit difference | Positively match legacy ControlBit semantics and state binding; absence of a native signature alone is insufficient. | Resolve whether C7/C8 need the reference control-bit path; edit only if equivalent behavior is missing. | Execute both variants with native state/MMIO contracts before declaring a functional gap. |',
        '| S03 — control-field difference | Positively match legacy ControlField semantics. | Resolve and add the missing C7/C8 field selection if required. | Verify actual selected field and downstream use; preserve other states. |',
        '| S04 — forward-calculation difference | Positively match legacy ForwardCalculation semantics. | Resolve and supply the UHD forward mapping if required. | Boundary/layer address vectors against the reference; no invented hardware constants. |',
        '| S05 — reverse-calculation difference | Positively match legacy ReverseCalculation semantics. | Resolve and supply the UHD reverse mapping if required. | Round-trip address/layer vectors plus reference parity. |',
        '| S06 — parameter difference | Positively match legacy ParameterNibble semantics. | Resolve which UHD parameter selection is required; retain native hardware policy. | Trace selected values into their consumers; optical settings are not copied between mechanisms. |',
        '| G07 — key-class routing (proven) | Bind registered A3/A4 handlers, CDB buffer, media state and native workers; execute classes 2/3. REPORT KEY class3 reaches matched sense 05/30/02 and SEND KEY selects a different worker. | Extend both native wrappers to route class3 to their own AACS workers with the OEM guards preserved; separately audit those workers for AACS2 behavior. | Repeat 30 class-pair cases, invalid classes/formats and guard failures; then complete AACS2 exchange on hardware. Wrapper parity alone is insufficient. |', '',
        'Hardware defaults are a separate native policy, not an automatic patch gap. Unresolved acquisition, initialization, crypto/keys, hardware and reading requirements cannot honestly be assigned a successful patch yet. Complete coverage requires all of those to be resolved for each supported firmware/hardware family.', '',
        '## All firmware entries', '',
        'Full SHA-256, exact source path, provenance, comparison baseline and unresolved checks are in the adjacent CSV/JSON. S IDs are structural differences awaiting semantic validation; G IDs are demonstrated functional gaps.', '',
        '| Source | Hardware / revision / destination | SHA prefix | OEM UHD? | DI gate | Key routing | Proven gaps | Structural differences |',
        '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        vals = [r['category'] + ' / ' + r['payload'], r['hardware'] + ' / ' + r['revision'] + ' / ' + r['destination'],
                '`' + r['sha256'][:12] + '`', r['classification'], r['di_gate'], r['key_routing'], r['proven_gaps'] or 'none established', r['structural_differences_to_resolve'] or ('unresolved: fragment' if r['payload'] == 'fragment' else 'none in reviewed roles')]
        md.append('| ' + ' | '.join(v.replace('|', '/') for v in vals) + ' |')
    md += ['', '## Reproduce the evidence', '',
        'Use the pinned firmware dependency and Python with Unicorn/Capstone. The scanner and both CPU harnesses read firmware only. The protocol receipts retain relative hoard paths and full source hashes.', '',
        '```sh',
        'python3 scripts/audit-mtk-uhd-di-gates.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --hoard /path/to/hoard --output /tmp/mt1959-di.json',
        'python3 scripts/audit-mtk-key-class-routing.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --hoard /path/to/hoard --output /tmp/mt1959-keys.json',
        'python3 scripts/report-mt1959-uhd-gaps.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --di /tmp/mt1959-di.json --keys /tmp/mt1959-keys.json --out /tmp/mt1959-report',
        '```', '',
        'Validation: all 173 full sources scanned, 1,038 DI-gate executions, 5,130 class-pair checks (two sources have unresolved dispatch contracts). The scanner fixture tests, formatting and Clippy checks pass. No live AACS or disc-reading test was run.',
    ]
    (a.out / 'mt1959-uhd-gap-table-20261030.md').write_text('\n'.join(md) + '\n')
    print(json.dumps({'entries': len(rows), 'references': len(refs), 'full_sources_with_protocol_scan': len(scans),
        'stock_full_proven_gap_groups': dict(collections.Counter(r['proven_gaps'] or 'none established' for r in rows if r['category'] == 'oem' and r['payload'] == 'full source'))}, indent=2))


if __name__ == '__main__':
    main()
