"""Execute native and emitted RPC response tails, including FIFO bytes and return frames."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
FIFO, STACK, RETURN = 0x04209000, 0x03008000, 0x1fe000


class RegionCpu:
    def __init__(self, data):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for start, size in ((0, 0x200000), (0x01ff0000, 0x20000),
                            (0x03000000, 0x10000), (0x04200000, 0x10000)):
            self.cpu.mem_map(start, size)
        self.cpu.mem_write(0, data)
        self.cpu.hook_add(UC_HOOK_CODE, self.visit)
        self.cpu.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.bytes = []
        self.returned = False

    def visit(self, cpu, address, _size, _user):
        if address == RETURN:
            self.returned = True
            cpu.emu_stop()

    def write(self, _cpu, _access, address, size, value, _user):
        if address == FIFO + 8:
            assert size == 1
            self.bytes.append(value)

    def execute(self, entry, slot, flag, type_code, counter, mask):
        cpu = self.cpu
        self.bytes, self.returned = [], False
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
        before = [0x76540000 + i * 0x101 for i in range(13)]
        before[0], before[1], before[2], before[4] = FIFO, 0, type_code, 1
        for register, value in zip(REGISTERS, before):
            cpu.reg_write(register, value)
        cpu.reg_write(reg.UC_ARM_REG_SP, STACK)
        cpu.reg_write(reg.UC_ARM_REG_LR, 0x12345)
        word = (mask << 24) | (counter << 16) | 0x2211
        cpu.mem_write(STACK, struct.pack('<III', word, 0xcafebabe, RETURN | 1))
        cpu.mem_write(slot, bytes([flag]))
        cpu.emu_start(entry | 1, 0x200000, count=200)
        assert self.returned and len(self.bytes) == 4
        after = [cpu.reg_read(r) for r in REGISTERS]
        assert after[0] == FIFO and after[1] == 0
        assert after[3] == word and after[4] == 0xcafebabe
        assert after[5:] == before[5:]
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == STACK + 12
        return self.bytes


def review(builder, original, modified, report_path):
    data, patched = original.read_bytes(), modified.read_bytes()
    evidence = json.loads(subprocess.check_output([str(builder.resolve()), str(original),
        'installed-region', str(report_path), str(modified)]))
    native, changed = RegionCpu(data), RegionCpu(patched)
    cases = 0
    for type_code in (0, 0x40, 0x80, 0xc0):
        for counter in (0, 1, 7):
            for mask in (0, 1, 0x7f, 0xfe, 0xff):
                expected_oem = [(type_code + counter) & 255, mask, 1, 0]
                for flag in (255, 1, 0, 2):
                    old = native.execute(evidence['entry'], evidence['flag_slot'], flag,
                                         type_code, counter, mask)
                    new = changed.execute(evidence['entry'], evidence['flag_slot'], flag,
                                          type_code, counter, mask)
                    assert old == expected_oem
                    expected = ([0, 0, 0, 0] if flag == 1 else
                                [expected_oem[0], 255, 1, 0] if flag == 0 else old)
                    assert new == expected, (flag, type_code, counter, mask, new, expected)
                    cases += 1
    return {'input_sha256': hashlib.sha256(data).hexdigest(),
            'output_sha256': hashlib.sha256(patched).hexdigest(), 'cases': cases,
            'fifo_bytes': 'passed', 'native_return_frame': 'passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--fw', type=Path)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--hoard', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    records = []
    if args.corpus:
        assert args.hoard and args.artifacts
        for row in json.loads(args.corpus.read_text())['images']:
            if (row.get('capability') or {}).get('status') != 'supported':
                continue
            folder = args.artifacts / row['sha256']
            report = json.loads((folder / 'modify.json').read_text())
            if not report['boot_settings']['region']['supported']:
                continue
            record = review(args.builder, args.hoard / row['path'], folder / 'modified.bin',
                            folder / 'modify.json')
            assert record['input_sha256'] == row['sha256']
            assert record['output_sha256'] == row['capability']['output_sha256']
            records.append(record)
            if len(records) % 25 == 0:
                print(f'{len(records)} Region inputs passed', flush=True)
    else:
        assert args.fw
        fixtures = ROOT / 'crates/freemkv-fw/tests/fixtures'
        with tempfile.TemporaryDirectory(prefix='freemkv-region-cpu-') as temp:
            for name in ('BU40N_OEM_1.00.bin', 'BE14NU40_MT1939_JB7_1.01.bin'):
                original, modified = fixtures / name, Path(temp) / name
                result = subprocess.run([str(args.fw.resolve()), 'modify', str(original),
                    str(modified), '--json', '--audit'], capture_output=True, text=True, check=True)
                report = Path(temp) / f'{name}.json'
                report.write_text(result.stdout)
                records.append(review(args.builder, original, modified, report))
    if args.output:
        args.output.write_text(json.dumps({'images': records}, indent=2) + '\n')
    print(f"PASS: {len(records)} inputs; {sum(r['cases'] for r in records)} Region FIFO/return comparisons")


if __name__ == '__main__':
    main()
