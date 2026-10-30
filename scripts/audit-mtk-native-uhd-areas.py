"""Inventory native UHD-related code shapes; matches are research leads, not patches.

Requires Capstone. Operates on the hashed corpus manifest, preserves register and
non-address immediate operands, and ignores only literal/branch relocations when
locating reviewed reference shapes. An unmatched image is unresolved, never
assigned a generation-wide implementation by its model or chipset alone.
"""
import argparse
import collections
import hashlib
import json
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

REFERENCES = {
    'hardware_control_bit': [( 'classic', '40eb760e', 0x36472, 0x3648e), ('modern', '648a16d0', 0x26706, 0x2672e), ('modern_base40', '08d14869', 0x28f5c, 0x28f84), ('classic_base40', '148d89cc', 0x2905c, 0x2907a), ('classic_base80', 'c88a6901', 0x27196, 0x271b4)],
    'hardware_control_field': [('classic', '40eb760e', 0x32140, 0x3216c), ('modern', '648a16d0', 0x32e6a, 0x32e82), ('modern_redundant_c8_test', '08d14869', 0x35442, 0x35460), ('classic_register_variant', 'c88a6901', 0x33a14, 0x33a26)],
    'speed_defaults_hardware_sensitive': [('classic', '40eb760e', 0x678c4, 0x67900), ('modern', '648a16d0', 0x6875a, 0x687a2), ('classic_default8', '0b2cdb82', 0x67780, 0x677b8), ('slim_fixed6_c7_aware', '08d14869', 0xdab74, 0xdabb2), ('slim_fixed6_no_c7_test', '148d89cc', 0xd9a9a, 0xd9aca), ('desktop_default8_c7_aware', '5e2ec51f', 0xdb3c8, 0xdb42e), ('modern_reader_register_variant', '243a7b0b', 0x68820, 0x6886e), ('slim_early_fixed6', 'c88a6901', 0x691aa, 0x691da)],
    'forward_calculation': [('classic', '40eb760e', 0xfd15a, 0xfd180), ('modern', '648a16d0', 0xd8e64, 0xd8e88)],
    'reverse_calculation': [('classic', '40eb760e', 0xfd1d2, 0xfd1e8), ('modern', '648a16d0', 0xd8ede, 0xd8f06)],
    'hardware_parameter_nibble': [('classic', '40eb760e', 0xfd4cc, 0xfd514), ('modern', '648a16d0', 0xd9424, 0xd9472), ('modern_register_variant', '08d14869', 0xd8ca4, 0xd8cf2), ('classic_register_variant', '148d89cc', 0xd7aea, 0xd7b32)],
    'di_identifier_recognition': [('classic', '40eb760e', 0x10a546, 0x10a562), ('modern', '648a16d0', 0xe09ac, 0xe09d0), ('classic_register_variant', 'b093a736', 0x10a5f6, 0x10a612), ('modern_u_flag_variant', '08d14869', 0xe0b9e, 0xe0bcc), ('modern_u_flag_store_variant', '5e2ec51f', 0xe27e2, 0xe2812), ('no_u_modern_register_variant', '148d89cc', 0xdf44c, 0xdf468), ('no_u_modern_early_variant', 'c88a6901', 0xe30a8, 0xe30c6)],
}


def pattern(data, start, end, decoder):
    parts = []
    instructions = list(decoder.disasm(data[start:end], start))
    assert sum(i.size for i in instructions) == end - start, (hex(start), hex(end))
    for ins in instructions:
        raw = bytes(ins.bytes)
        half = int.from_bytes(raw[:2], 'little')
        if ins.size == 2 and half & 0xf800 == 0x4800:  # PC literal LDR: retain Rt
            parts.append(b'.' + re.escape(raw[1:]))
        elif ins.size == 2 and half & 0xf000 == 0xd000 and half & 0x0f00 < 0x0e00:
            parts.append(b'.' + re.escape(raw[1:]))  # retain branch condition
        elif ins.size == 2 and half & 0xf800 == 0xe000:
            parts.append(b'.[\\xe0-\\xe7]')
        elif ins.size == 4 and ins.mnemonic in ('bl', 'blx'):
            parts.append(b'....')
        else:
            parts.append(re.escape(raw))
    return re.compile(b''.join(parts), re.DOTALL), instructions


def details(data, start, size, decoder):
    literals = []
    edges = []
    for ins in decoder.disasm(data[start:start + size], start):
        half = int.from_bytes(ins.bytes[:2], 'little')
        if ins.size == 2 and half & 0xf800 == 0x4800:
            pool = ((ins.address + 4) & ~3) + (half & 255) * 4
            if pool + 4 <= len(data):
                value = struct.unpack_from('<I', data, pool)[0]
                literals.append({'instruction': ins.address, 'pool': pool, 'value': value,
                                 'bytes_at_value_if_in_file': data[value:value + 16].hex()
                                 if 0 < value < len(data) else None})
        if ins.mnemonic.startswith('b') and ins.op_str.startswith('#'):
            target = int(ins.op_str[1:], 0)
            edges.append({'instruction_offset': ins.address - start,
                          'target_offset': target - start if start <= target < start + size else None})
    # Separate exact instruction shape (pattern) from literal values and branch
    # layout. References locate roles; neither alone proves whole-function parity.
    return {'literals': literals, 'local_branch_layout': edges}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, default=Path('internal/docs/audits/mediatek-current-full-corpus-20261025.json'))
    ap.add_argument('--classic', type=Path, default=Path('internal/docs/audits/mt1939-24-auth-candidates-20261026.json'))
    ap.add_argument('--hoard', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    rows = json.loads(args.manifest.read_text())['images']
    selected_classic = {r['sha256'] for r in json.loads(args.classic.read_text())['images']}
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    sources = {}
    for prefix in sorted({ref[1] for refs in REFERENCES.values() for ref in refs}):
        record = next(r for r in rows if r['sha256'].startswith(prefix))
        data = (args.hoard / record['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['sha256']
        sources[prefix] = data
    templates = {}
    for area, refs in REFERENCES.items():
        templates[area] = [(style, prefix, start, end, pattern(sources[prefix], start, end, decoder)[0])
                           for style, prefix, start, end in refs]
    for area, refs in templates.items():
        for style, prefix, start, end, regex in refs:
            assert regex.fullmatch(sources[prefix][start:end]), (area, style)
    results = []
    for record in rows:
        ident = ((record.get('capability') or {}).get('identity') or {})
        if record['sha256'] not in selected_classic and ident.get('chip') != 'MT1959':
            continue
        data = (args.hoard / record['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['sha256']
        assert ident['chip'].encode() in data[0x3000:0x3100]
        regions = {}
        for area, refs in templates.items():
            hits = []
            for style, prefix, start, end, regex in refs:
                for match in regex.finditer(data):
                    if match.start() % 2:
                        continue
                    expected_instructions = list(decoder.disasm(sources[prefix][start:end], start))
                    actual_instructions = list(decoder.disasm(data[match.start():match.start() + end - start], match.start()))
                    if [(i.mnemonic, i.size) for i in actual_instructions] != [(i.mnemonic, i.size) for i in expected_instructions]:
                        continue
                    info = details(data, match.start(), end - start, decoder)
                    if style.startswith('no_u_modern'):
                        linked = False
                        for prior in range(max(0, match.start() - 40), match.start(), 2):
                            pair = list(decoder.disasm(data[prior:prior + 4], prior))
                            if len(pair) == 2 and pair[0].mnemonic == 'cmp' and pair[0].op_str.endswith(', #0x52') and pair[1].mnemonic == 'bne' and int(pair[1].op_str[1:], 0) == match.start():
                                linked = True
                        if not linked:
                            continue
                    if area in ('forward_calculation', 'reverse_calculation'):
                        # Follow the fall-through CC-mask calculation path,
                        # crossing unconditional pool islands, without treating
                        # literal data as instructions. Calls return to the next
                        # instruction; this is a static binding, not execution.
                        pc = match.start()
                        constant_site = None
                        visited = set()
                        operation = None
                        target = None
                        for _ in range(40):
                            if pc in visited or not 0 <= pc < len(data) - 4:
                                break
                            visited.add(pc)
                            ins = next(decoder.disasm(data[pc:pc + 4], pc), None)
                            if ins is None:
                                break
                            half = int.from_bytes(ins.bytes[:2], 'little')
                            if ins.size == 2 and half & 0xf800 == 0x4800:
                                pool = ((pc + 4) & ~3) + (half & 255) * 4
                                if pool + 4 <= len(data) and struct.unpack_from('<I', data, pool)[0] == 0x51b1:
                                    constant_site = pc
                            if constant_site is not None and ins.mnemonic in ('adds', 'subs'):
                                operation, target = ins.mnemonic, pc
                                break
                            if ins.mnemonic == 'b':
                                pc = int(ins.op_str[1:], 0)
                            else:
                                pc += ins.size
                        if operation != ('adds' if area == 'forward_calculation' else 'subs'):
                            continue
                        info['coefficient_constant_site'] = constant_site
                        info['coefficient_continuation'] = target
                    hits.append({'reference_style': style, 'address': match.start(),
                                 'bytes': end - start,
                                 **info})
            regions[area] = {'status': 'unique_reference_match' if len(hits) == 1 else
                             'unresolved' if not hits else 'ambiguous', 'matches': hits}
        results.append({'sha256': record['sha256'], 'path': record['path'],
                        'identity': ident, 'areas': regions})
    summary = {}
    for chip in ('MT1939', 'MT1959'):
        group = [r for r in results if r['identity']['chip'] == chip]
        summary[chip] = {'images': len(group), 'areas': {area: dict(collections.Counter(
            r['areas'][area]['matches'][0]['reference_style'] if r['areas'][area]['status'] == 'unique_reference_match'
            else r['areas'][area]['status'] for r in group)) for area in REFERENCES}}
    public_modern = [r for r in results if r['identity']['chip'] == 'MT1959' and r['path'].split('/')[0] in ('oem', 'dump')]
    summary['MT1959_oem_dump'] = {'images': len(public_modern), 'areas': {area: dict(collections.Counter(
        r['areas'][area]['matches'][0]['reference_style'] if r['areas'][area]['status'] == 'unique_reference_match'
        else r['areas'][area]['status'] for r in public_modern)) for area in REFERENCES}}
    core_areas = [area for area in REFERENCES if not area.startswith('speed_')]
    combinations = {}
    for row in results:
        if row['identity']['chip'] != 'MT1959':
            continue
        key = tuple(row['areas'][area]['matches'][0]['reference_style'] if row['areas'][area]['status'] == 'unique_reference_match' else row['areas'][area]['status'] for area in core_areas)
        group = combinations.setdefault(key, [])
        group.append(row)
    summary['MT1959_core_combinations'] = [
        {'styles': dict(zip(core_areas, key)), 'images': len(group),
         'oem_dump_images': sum(row['path'].split('/')[0] in ('oem', 'dump') for row in group),
         'models': sorted({row['identity']['model'] for row in group}),
         'sha256s': [row['sha256'] for row in group]}
        for key, group in combinations.items()]
    output = {'schema': 1, 'manifest_sha256': hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
              'classic_selection_sha256': hashlib.sha256(args.classic.read_bytes()).hexdigest(), 'scope': 'Native code-shape inventory only; partial regions, no conversion or physical support claim. Unmatched is unresolved, not a new variant count.',
              'references': REFERENCES, 'summary': summary, 'images': results}
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'MT1959_core_combinations'}, indent=2))
    print('MT1959 core combinations:', len(combinations))


if __name__ == '__main__':
    main()
