"""Execute native classic selectors against the production tail detour.

Uses held originals when --sources is provided; never writes those files.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn import arm_const as reg


def execute(image, plan, media, maximum, mode, setting, patched):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    # Exercise the legacy instruction set; Unicorn's default accepts Thumb-2.
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(0x01ff0000, 0x20000)
    cpu.mem_map(0x03000000, 0x10000)
    stub = 0x1ff000
    cpu.mem_write(stub, bytes(plan['stub']))
    if patched:
        cpu.mem_write(plan['site'], bytes(plan['branch']))
    # Every native byte cell read by these selectors is explicitly initialized.
    # Vary all other RAM bytes as well as the separately bound media/RMAX cells.
    cpu.mem_write(0x01ff0000, bytes([mode]) * 0x20000)
    cpu.mem_write(plan['media_cell'], bytes([media]))
    cpu.mem_write(plan['maximum_cell'], bytes([maximum]))
    cpu.mem_write(plan['flag_base'] + 1, bytes([setting]))
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
    regs = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
    for i, r in enumerate(regs):
        cpu.reg_write(r, 0x12340000 + i * 0x101)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR, 0x1fe001)
    try:
        cpu.emu_start(plan['entry'] | 1, 0x1fe000, count=256)
    except Exception as error:
        raise RuntimeError((hex(cpu.reg_read(reg.UC_ARM_REG_PC)), plan, media, maximum, mode, setting, patched)) from error
    assert cpu.reg_read(reg.UC_ARM_REG_PC) == 0x1fe000
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
    assert cpu.reg_read(reg.UC_ARM_REG_LR) == 0x1fe001
    return [cpu.reg_read(r) for r in regs], cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--hoard', type=Path)
    args = parser.parse_args()
    if args.sources:
        sources = json.loads(args.sources.read_text())
        images = [(r['sha256'], (args.hoard / r['path']).read_bytes()) for r in sources]
    else:
        # Small real excerpts plus original offsets; synthetic gaps are analysis only.
        root = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/classic-speed'
        images = []
        for r in json.loads((root / 'sources.json').read_text()):
            data = bytearray(b'\xff' * 0x200000)
            for part in r['segments']:
                blob = (root / part['file']).read_bytes()
                assert hashlib.sha256(blob).hexdigest() == part['excerpt_sha256']
                data[part['source_offset']:part['source_offset'] + len(blob)] = blob
            images.append((r['source_sha256'], bytes(data)))
    cases = 0
    import tempfile
    for sha, image in images:
        if args.sources:
            assert hashlib.sha256(image).hexdigest() == sha
        with tempfile.NamedTemporaryFile() as source:
            source.write(image)
            source.flush()
            plan = json.loads(subprocess.check_output([str(args.builder.resolve()), source.name, 'classic-speed-candidate']))
        for media in (0, 0x40, 0x80, 0xc0, 0xc7, 0xc8, 0xd0, 0xff):
            for maximum in (0, 1, 4, 6, 8, 12, 24, 48, 49, 255):
                for mode in (0, 0xc0, 0xff):
                    for setting in (0, 1, 2, 255):
                        old, old_flags = execute(image, plan, media, maximum, mode, setting, False)
                        new, flags = execute(image, plan, media, maximum, mode, setting, True)
                        expected = maximum if setting == 1 and 0 < maximum <= 48 else old[0]
                        assert new[0] == expected, (sha, media, maximum, mode, setting, old, new)
                        assert new[1:] == old[1:], (sha, 'live register changed')
                        if expected == old[0]:
                            assert flags == old_flags, (sha, 'OEM flags changed')
                        else:
                            assert flags == 0, (sha, 'unexpected normalized flags')
                        cases += 1
        print(f'{sha[:12]}: selector/tail/RMAX contract passed', flush=True)
    print(f'{len(images)} native selectors; {cases} execution comparisons passed')


if __name__ == '__main__':
    main()
