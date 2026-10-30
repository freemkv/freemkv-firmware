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
                  'AACS2 exchange/keys and hardware dependencies', 'DL/TL sector reads']
    if alias:
        unresolved.insert(0, 'archive duplicate; evidence belongs to canonical payload ' + alias['payload_sha256'])
    elif not full:
        unresolved.insert(0, 'obtain full stock payload')
    elif key_result.startswith('unresolved'):
        unresolved.insert(0, 'bind native key-command handlers')
    if unknown_roles:
        unresolved.insert(0, 'unbound code roles: ' + ', '.join(unknown_roles))
    identity = source['catalogue_identity']
    return {
        'sha256': sha, 'hardware': identity['hardware'], 'revision': identity['revision'],
        'destination': identity['destination'], 'category': source['category'],
        'bytes': source['bytes'], 'payload': 'archive duplicate' if alias else 'full source' if full else 'fragment',
        'canonical_payload_sha256': alias['payload_sha256'] if alias else sha if full else '',
        'classification': 'OEM UHD' if reference else '1959 non UHD',
        'classification_basis': 'manufacturer UHD product + stock provenance' if reference else
            'not qualified as an OEM UHD stock reference; not a physical inability verdict',
        'reference_product': reference['product'] if reference else '',
        'reference_url': reference['url'] if reference else '',
        'oem_qualification_gap': '' if reference else qualification_gap(source, alias),
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
        'key_mode_invalid_header': ('clear before validation' if mode_init.get('clears_mode_before_validation') else
                                   'preserve supplied prior mode in isolated selector')
                                  if mode_init and mode_init['status'] == 'bound_header_selector' else 'unresolved',
        'media_pipeline_gaps': ','.join(g for g in gaps if g in ('G01','G02','G03','G04','G05','G06')),
        'OEM_authentication_gaps': ','.join(g for g in gaps if g in ('G07','G08')),
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
    assert sum(r['classification'] == 'OEM UHD' for r in rows) == len(references)
    v9 = next(r for r in rows if r['sha256'].startswith('97b28707'))
    assert v9['classification'] == '1959 non UHD' and v9['proven_gaps'] == 'G07,G08'
    assert len(scans) == len(dis) == len(keys) == len(consumers) == len(workers) == 171
    assert set(scans) == set(dis) == set(keys) == set(consumers) == set(workers) == set(mode_init)
    assert set(scans) == {s['sha256'] for s in sources if s['bytes'] == 2097152}
    a.out.mkdir(parents=True, exist_ok=True)
    with (a.out / 'mt1959-uhd-gap-table-20261030.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader(); w.writerows(rows)
    (a.out / 'mt1959-uhd-gap-table-20261030.json').write_text(json.dumps({'scope': __doc__, 'images': rows}, indent=2) + '\n')
    md = ['# MT1959 OEM UHD comparison and gap table', '',
        'OEM UHD means stock firmware tied to a manufacturer-advertised UHD product. Everything else is classified 1959 non UHD for this comparison, including unqualified variants, modified images and incomplete sources. That classification alone does not prove physical inability.', '',
        '199 catalogue entries: 171 distinct full firmware payloads, 26 incomplete sources and two tar-archive duplicates of existing dumps. The OEM bucket has 67 full images, 24 incomplete sources and those two misbucketed dump archives. The archives are not firmware with a suffix: their actual payload starts at byte 1,536. All 24 incomplete OEM-bucket entries are metadata/partial-dump archives. Counts are source hashes, not independent drives or tested successes.', '',
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
        '## Summary of the 67 full OEM-bucket images', '',
        '| Status | Images |', '| --- | --- |',
        *[f'| {status} | {count} |' for status, count in summary.items()], '',
        'G01 is DI rejection; G02–G06 are executed C7 consumer mismatches; G07 is key-class routing; G08 is the extended key-response worker path. G01–G06 concern the media pipeline; G07/G08 concern OEM authentication and are not established causes of failed physical detection. No-proven-gap rows are not promoted to OEM UHD. These results do not establish 100% functional coverage.', '',
    ]
    for ref in refs:
        r = next(r for r in rows if r['sha256'] == ref['sha256'])
        md.append(f"| {ref['product']} | {r['revision']} | `{r['sha256'][:12]}` | [Specification]({ref['url']}) |")
    md += ['', 'A current download of the WH16NS60 N1.01 package from LG matches the held original byte for byte (archive SHA-256 198c01224a0a; inner WH16NS60.exe SHA-256 e99cf91b8829). The [manufacturer support page](https://www.lg.com/us/support/product/lg-WH16NS60.AUSU10B) both advertises UHD playback and lists N1.01. Full hashes and URLs are retained in mt1959-oem-variant-evidence-20261030.json.', '']
    md += ['', '## Stock-source variants with no proven gap in the reviewed paths', '',
        'These ten images are still 1959 non UHD under the requested definition. None is promoted by its code matches. Their qualification and full behavioral equivalence remain unresolved.', '',
        '| Hardware / revision | SHA prefix | OEM qualification still needed |', '| --- | --- | --- |']
    for r in rows:
        if r['category'] == 'oem' and r['payload'] == 'full source' and r['classification'] != 'OEM UHD' and not r['proven_gaps']:
            md.append(f"| {r['hardware']} / {r['revision']} | `{r['sha256'][:12]}` | {r['oem_qualification_gap']} |")
    md += ['', 'Dell identifies [A103 and its exact updater filename](https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=hn7y6), but that source does not establish UHD-playback qualification. A [firsthand HP BU40N BW40 report](https://h30434.www3.hp.com/t5/Desktop-Hardware-and-Upgrade-Questions/Upgrade-firmware-for-Blu-ray-Burner-HP-BU40N/td-p/7039865) describes failed UHD playback on a reportedly compliant host; BW40 is not our BW41/BW42 sample, so that failure is not assigned to either of our hashes.', '']
    md += ['', 'The held TK03 source also matches the current [official Dynabook updater](https://dynabook.com/assistpc/download/modify/dynabook/t85/xxc/oddfw/index_j.htm) byte for byte (source SHA-256 starts 3e72a0e0c814). That proves updater provenance, while UHD product qualification remains unresolved; see mt1959-oem-variant-evidence-20261030.json.', '']
    md += ['', '## Gap-to-patch contracts', '',
        'These are patch designs, not implemented conversions. G IDs have executed stage-level differences versus the OEM UHD references. One logical patch may edit coordinated sites. Address/hash/model tables must never select a patch.', '',
        '| ID | Detection | Focused patch design | Verification required |',
        '| --- | --- | --- | --- |',
        '| G01 — DI rejection (proven) | Bind the DI identifier/density gate and its native state cell; execute U/5 with two/three layers and observe no state assignment. | Add OEM-equivalent U/5 admission and C7/C8 assignment while retaining existing exits and stack/register contracts. | CPU cases for supported/invalid layers and identifiers; unchanged BD/DVD/CD behavior; then actual acquisition. |',
        '| G02 — control-bit mismatch | Bound ControlBit execution clears bit31 for C7; OEM UHD sets it. | Extend the selector so C7 uses the native bit-set path, preserving other states and native register address. | CPU output/preservation checks for all states; actual optical initialization remains separate. |',
        '| G03 — control-field mismatch | Bound ControlField execution selects field value3 for C7; OEM UHD selects0. Observed in early BP50NB40 1.00 only. | Add C7 to the native field-clear path. | Verify the supplied register-bank output and preserve every other state; then trace the full caller. |',
        '| G04 — forward-calculation admission | C7 takes the restoration path without calling the calculation worker; OEM UHD calls its native worker. | Admit C7 to the appropriate native calculation continuation. | Verify admission and existing-state preservation, then full numerical boundary vectors. No worker math is inferred from admission alone. |',
        '| G05 — reverse-calculation admission | C7 takes the restoration path without calling the calculation worker; OEM UHD calls its native worker. | Add OEM-equivalent C7 admission and native mode-flag selection; bind the flag before implementation. | Verify branch/flag selection, then complete reverse and round-trip calculations. |',
        '| G06 — conditional parameter mismatch | With native flag bit5 supplied set, C7 uses a lookup table while OEM UHD selects nibble2. Tested all13 input indices and two initial words. | Include C7 in the existing special-case selector, retaining its native flag and table for other paths. | Verify both flag values, all indices and preserved upper bits; establish caller/flag reachability. Register meaning is not assumed. |',
        '| G07 — key-class routing (proven) | Bind registered A3/A4 handlers, CDB buffer, media state and native workers; execute classes 2/3. REPORT KEY class3 reaches matched sense 05/30/02 and SEND KEY selects a different worker. | Extend both native wrappers to route class3 to their own AACS workers with the OEM guards preserved; separately audit those workers for AACS2 behavior. | Repeat 30 class-pair cases, invalid classes/formats and guard failures; then complete AACS2 exchange on hardware. Wrapper parity alone is insufficient. |',
        '| G08 — extended key-response worker path | The source-bound REPORT KEY format 1 worker caps the response at 116 bytes for every tested allocation/mode. OEM UHD references select 180 in their extended native mode; their dispatcher also has a 0x39 branch absent in the older worker. | Bind and adapt the complete extended-mode worker/session path and its buffer/crypto-service contracts. Increasing the length constant alone does not create the missing response contents. | Repeat allocation boundaries and dispatch vectors, then verify actual nonce/certificate contents, SEND KEY/crypto/session behavior and available device credentials/services. |', '',
        'Hardware defaults are a separate native policy, not an automatic patch gap. Unresolved acquisition, initialization, crypto/keys, hardware and reading requirements cannot honestly be assigned a successful patch yet. Complete coverage requires all of those to be resolved for each supported firmware/hardware family.', '',
        '## Key-worker comparison and its limits', '',
        'The additional worker survey executes 6,156 REPORT KEY dispatch cases and 3,078 certificate-response allocation cases over all 171 full payloads. Of these, 112 have a fixed 116-byte path and 59 have a native mode-selected 116/180-byte path; within the full OEM bucket the counts are 46 and 21. All nine locked OEM UHD references have the extended path. 1.V9 has both G07 and G08, superseding the earlier routing-only gap statement.', '',
        'Worker dispatch begins after any recorded setup call, whose effects are not assumed. Allocation execution begins after assumed valid AGID/session validation and stops at the response-length store. It neither generates nor verifies a certificate or nonce. These are source-bound protocol-stage differences, not a complete AACS2 exchange or proof that no other AACS2 code exists elsewhere.', '',
        'The [AACS common specification, section 4.14.2.2](https://aacsla.com/wp-content/uploads/2019/02/AACS_Spec_Common_Final_0953.pdf) describes the older 20-byte nonce and 92-byte certificate response. Primary reverse-engineering research [SGX.Fail, appendix D.2](https://sgx.fail/files/sgx.fail.pdf) describes AACS2 using 32-byte nonces and 256-bit ECC with SHA256. This explains why the older response width cannot simply be treated as complete OEM UHD authentication. Format 0x39 is recorded as another reference difference; its necessity is not inferred from its presence alone.', '',
        '## Native mode initialization', '',
        'The selector survey executes 3,168 cases across 48 bound selectors, including all 21 extended-worker images in the full OEM bucket and all nine OEM UHD references. Eleven other dump/modified images have extended workers but an unresolved selector layout. The 112 single-mode worker images have no mode cell bound by that worker contract; that alone is not an absence claim about every other routine.', '',
        'For matched selectors, a header word with low 16 bits 0x1003 selects mode 1 when bits 23:20 are nonzero and mode 0 otherwise. This links the reviewed protocol mode to header data. Header acquisition and device/crypto services remain outside the executed region, so it does not prove hardware support. The caller supplies an already-read word; any intermediate auxiliary call is explicitly excluded; its side effects are not assumed.', '',
        'OEM references themselves differ on invalid-header cleanup: some selectors clear the mode before validating the word, while others preserve the supplied previous value in this isolated stage. This revision difference is recorded, not declared another UHD gap. Full caller cleanup is not inferred from the isolated selector.', '',
        '## All firmware entries', '',
        'Full SHA-256, exact source path, provenance, comparison baseline and unresolved checks are in the adjacent CSV/JSON. G IDs are demonstrated stage-level gaps; execution assumptions and remaining validation are stated above. The CSV retains exact observed C7 consumer outputs.', '',
        '| Source | Hardware / revision / destination | SHA prefix | OEM UHD? | DI gate | Key routing | Key-response worker | Proven gaps | C7 consumer comparison |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        vals = [r['category'] + ' / ' + r['payload'], r['hardware'] + ' / ' + r['revision'] + ' / ' + r['destination'],
                '`' + r['sha256'][:12] + '`', r['classification'], r['di_gate'], r['key_routing'], r['key_worker_response'], r['proven_gaps'] or 'none established', ('unresolved: fragment' if r['payload'] == 'fragment' else 'differences: ' + ','.join(g for g in r['proven_gaps'].split(',') if g in ('G02','G03','G04','G05','G06')) if any(g in r['proven_gaps'] for g in ('G02','G03','G04','G05','G06')) else '5 reviewed C7 outputs match')]
        md.append('| ' + ' | '.join(v.replace('|', '/') for v in vals) + ' |')
    md += ['', '## Reproduce the evidence', '',
        'Use the pinned firmware dependency and Python with Unicorn/Capstone. The scanner and CPU harnesses read firmware only. The protocol receipts retain relative hoard paths and full source hashes.', '',
        '```sh',
        'python3 scripts/audit-mtk-uhd-di-gates.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --hoard /path/to/hoard --output /tmp/mt1959-di.json',
        'python3 scripts/audit-mtk-key-class-routing.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --hoard /path/to/hoard --output /tmp/mt1959-keys.json',
        'python3 scripts/audit-mtk-uhd-consumers.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --hoard /path/to/hoard --output /tmp/mt1959-consumers.json',
        'python3 scripts/audit-mtk-key-workers.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --routing /tmp/mt1959-keys.json --hoard /path/to/hoard --output /tmp/mt1959-workers.json',
        'python3 scripts/audit-mtk-key-mode-init.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --workers /tmp/mt1959-workers.json --hoard /path/to/hoard --output /tmp/mt1959-mode-init.json',
        'python3 scripts/report-mt1959-uhd-gaps.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --di /tmp/mt1959-di.json --keys /tmp/mt1959-keys.json --consumers /tmp/mt1959-consumers.json --workers /tmp/mt1959-workers.json --mode-init /tmp/mt1959-mode-init.json --out /tmp/mt1959-report',
        '```', '',
        'Validation: 46,512 consumer-region executions (passive register bank; workers not executed). All 199 source hashes checked; archive members hash-bound to existing dump payloads. All 171 distinct full payloads have DI/key receipts: 1,026 DI-gate executions and 5,130 class-pair checks. The earlier executions against two archive containers are withdrawn. The scanner fixture tests, formatting and Clippy checks pass. No live AACS or disc-reading test was run.',
    ]
    (a.out / 'mt1959-uhd-gap-table-20261030.md').write_text('\n'.join(md) + '\n')
    print(json.dumps({'entries': len(rows), 'references': len(refs), 'full_sources_with_protocol_scan': len(scans),
        'stock_full_proven_gap_groups': dict(collections.Counter(r['proven_gaps'] or 'none established' for r in rows if r['category'] == 'oem' and r['payload'] == 'full source'))}, indent=2))


if __name__ == '__main__':
    main()
