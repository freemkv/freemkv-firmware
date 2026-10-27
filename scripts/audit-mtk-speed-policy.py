"""Execute native media-speed defaults and requested-rate clamps; never patch firmware.

Locators come from mediatek-optical through the evidence builder. Full-source
runs verify every input hash; fixture runs verify provenance-bound excerpts.
"""
import argparse
import collections
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg


def sha(data):
    return hashlib.sha256(data).hexdigest()


def machine(data):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, data)
    cpu.mem_map(0x01ff0000, 0x20000)
    cpu.mem_map(0x03000000, 0x10000)
    return cpu


def execute(data, plan):
    cpu = machine(data)
    coverage = {}
    pools = set()
    seen = {}
    clamp = plan['clamp']
    phase = ['defaults']

    def code(c, at, size, _user):
        coverage[at] = size
        op = struct.unpack_from('<H', data, at)[0]
        if op & 0xf800 == 0x4800:
            pools.add(((at + 4) & ~3) + (op & 255) * 4)
        if phase[0] == 'clamp' and at == clamp['after_clamp']:
            c.emu_stop()

    def write(c, _access, at, size, value, _user):
        if phase[0] == 'defaults' and at in (plan['maximum_cell'], plan['optimum_cell']):
            assert size == 1
            seen[at] = value
            if len(seen) == 2:
                c.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    cases = []
    for media in (0xc7, 0xc8):
        for hardware in (0, 1, 2, 255):
            cpu.mem_write(0x01ff0000, b'\0' * 0x20000)
            for index in range(13):
                cpu.reg_write(getattr(reg, f'UC_ARM_REG_R{index}'), 0x12340000 + index * 0x101)
            cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
            cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
            cpu.reg_write(reg.UC_ARM_REG_LR, 0x1fe001)
            cpu.mem_write(plan['media_cell'], bytes([media]))
            cpu.mem_write(plan['hardware_cell'], bytes([hardware]))
            seen.clear()
            cpu.emu_start(plan['entry'] | 1, 0x200000, count=1000)
            assert len(seen) == 2, (plan, media, hardware, seen)
            maximum, optimum = (seen[plan[k]] for k in ('maximum_cell', 'optimum_cell'))
            assert maximum == optimum and 0 < maximum <= 48
            cases.append(dict(media=media, hardware=hardware, maximum=maximum, optimum=optimum))
    phase[0] = 'clamp'
    register = getattr(reg, f"UC_ARM_REG_R{clamp['request_register']}")
    clamp_cases = 0
    for maximum in sorted({c['maximum'] for c in cases if c['media'] == 0xc7}):
        for requested in range(256):
            for index in range(13):
                cpu.reg_write(getattr(reg, f'UC_ARM_REG_R{index}'), 0x12340000 + index * 0x101)
            cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
            cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
            cpu.reg_write(reg.UC_ARM_REG_LR, 0x1fe001)
            cpu.reg_write(reg.UC_ARM_REG_R0, requested)
            cpu.mem_write(plan['maximum_cell'], bytes([maximum]))
            cpu.emu_start(clamp['entry'] | 1, 0x200000, count=50)
            assert cpu.reg_read(reg.UC_ARM_REG_PC) == clamp['after_clamp']
            assert cpu.reg_read(register) == min(requested, maximum)
            assert cpu.mem_read(plan['maximum_cell'], 1)[0] == maximum
            clamp_cases += 1
    return cases, clamp_cases, coverage, pools


def excerpts(data, coverage, pools, plan):
    # Keep only executed instructions and the actual referenced literal pools.
    pools = set(pools)
    for at in range(plan['entry'], plan['entry'] + plan['length'], 2):
        op = struct.unpack_from('<H', data, at)[0]
        if op & 0xf800 == 0x4800:
            pools.add(((at + 4) & ~3) + (op & 255) * 4)
    ranges = sorted([(plan['entry'], plan['entry'] + plan['length'])] + [(a, a + size) for a, size in coverage.items()] + [(a, a + 4) for a in pools])
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return [dict(offset=a, sha256=sha(data[a:b]), hex=data[a:b].hex()) for a, b in merged]


def source_path(hoard, hint):
    hint = Path(hint)
    tail = Path(*hint.parts[1:])
    return next(p for p in [hoard / hint] + [hoard / bucket / tail for bucket in ('oem', 'dump', 'mk', 'omni')] if p.is_file())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--builder', type=Path, required=True)
    ap.add_argument('--inventory', type=Path)
    ap.add_argument('--hoard', type=Path)
    ap.add_argument('--catalog', type=Path)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--write-fixtures', type=Path)
    ap.add_argument('--fixtures', type=Path, default=Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/native-speed-policy')
    args = ap.parse_args()
    if args.inventory:
        assert args.hoard and args.output
        sources = json.loads(args.inventory.read_text())['images']
    else:
        sources = json.loads((args.fixtures / 'sources.json').read_text())
    records = []
    witnesses = {}
    for row in sources:
        if args.inventory:
            path = source_path(args.hoard, row['path'])
            data = path.read_bytes()
            assert sha(data) == row['sha256']
        else:
            data = bytearray(b'\xff' * 0x200000)
            for part in row['parts']:
                blob = bytes.fromhex(part['hex'])
                assert sha(blob) == part['sha256']
                data[part['offset']:part['offset'] + len(blob)] = blob
            data = bytes(data)
        with tempfile.NamedTemporaryFile() as original:
            original.write(data)
            original.flush()
            plan = json.loads(subprocess.check_output([str(args.builder.resolve()), original.name, 'speed-policy']))
        cases, clamp_cases, coverage, pools = execute(data, plan)
        if not args.inventory:
            assert plan == row['plan']
            assert cases == row['cases']
        record = dict(sha256=row['sha256'], identity=row['identity'], plan=plan, cases=cases, clamp_cases=clamp_cases)
        if args.inventory:
            assert sha(path.read_bytes()) == row['sha256']
            record['path'] = str(path.relative_to(args.hoard))
        records.append(record)
        if args.write_fixtures:
            # Each distinct default grammar / C7 policy / clamp grammar gets a witness.
            start, end = plan['clamp']['entry'], plan['clamp']['after_clamp']
            words = struct.unpack('<' + 'H' * ((end - start) // 2), data[start:end])
            normalized = tuple(v & 0xff00 if v & 0xf800 == 0x4800 else v for v in words)
            key = (plan['variant'], cases[0]['maximum'], normalized)
            witnesses.setdefault(key, record | {'parts': excerpts(data, coverage, pools, plan)})
        print(f"{row['sha256'][:12]} {plan['variant']}: native defaults + {clamp_cases} clamp cases passed", flush=True)
    counts = collections.Counter((r['identity']['chip'], r['cases'][0]['maximum']) for r in records)
    result = dict(scope='read-only native maximum/optimum stores and requested-rate clamps; physical speeds unmeasured',
                  builder_sha256=sha(args.builder.read_bytes()), script_sha256=sha(Path(__file__).read_bytes()),
                  inventory_sha256=sha(args.inventory.read_bytes()) if args.inventory else None,
                  images=records, native_default_cases=sum(len(r['cases']) for r in records),
                  native_clamp_cases=sum(r['clamp_cases'] for r in records),
                  c7_default_counts=[dict(chip=chip, rate=rate, images=n) for (chip, rate), n in sorted(counts.items())])
    if args.catalog:
        catalog = json.loads(args.catalog.read_text())
        final, intermediate = set(), set()
        for identity in catalog['identities']:
            if identity.get('family') != 'mediatek' or 'MT1959' not in identity.get('platforms', []):
                continue
            for revision in identity.get('revisions', []):
                for package in revision.get('packages', []):
                    if package.get('image_sha256'):
                        final.add(package['image_sha256'])
                    if package.get('intermediate_sha256'):
                        intermediate.add(package['intermediate_sha256'])
        covered = {r['sha256'] for r in records}
        missing = (final | intermediate) - covered
        assert not missing, missing
        result['catalog_coverage'] = dict(catalog_sha256=sha(args.catalog.read_bytes()), final_hashes=sorted(final),
                                          intermediate_hashes=sorted(intermediate), missing=[])
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    if args.write_fixtures:
        args.write_fixtures.mkdir(parents=True, exist_ok=True)
        (args.write_fixtures / 'sources.json').write_text(json.dumps(list(witnesses.values()), indent=2) + '\n')
    print(f"PASS {len(records)} images, {result['native_default_cases']} native default cases, {result['native_clamp_cases']} clamp cases", flush=True)


if __name__ == '__main__':
    main()
