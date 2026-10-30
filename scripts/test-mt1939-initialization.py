"""Compare the actual post-DI mode function on ARM926, with no drive access.

The complete native function and installed selector execute. Only logging is
stubbed. This establishes mode selection and OEM preservation, not hardware
acquisition, controller readiness, capacity, or sector readability.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn import arm_const as reg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('detection', Path(__file__).with_name('test-mt1939-detection.py'))
    detection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detection)
    detection.HELPERS.add(0xabadc)  # logging only, on this provenance-bound fixture
    receipt = json.loads(args.receipt.read_text())
    original, baseline, candidate = (p.read_bytes() for p in (args.original, args.baseline, args.candidate))
    assert hashlib.sha256(original).hexdigest() == receipt['source_sha256'] == detection.OEM_HASH
    assert hashlib.sha256(candidate).hexdigest() == receipt['output_sha256']
    baseline_receipt = json.loads(args.baseline.with_suffix('.json').read_text())
    assert hashlib.sha256(baseline).hexdigest() == baseline_receipt['output_sha256']
    assert baseline_receipt['source_sha256'] == receipt['source_sha256']
    assert baseline_receipt['flag_base'] == receipt['flag_base']
    assert baseline_receipt['mode_entry'] == receipt['mode_entry']
    machines = {name: detection.machine(data, receipt) for name, data in (
        ('oem', original), ('baseline', baseline), ('candidate', candidate))}
    mode_cell = 0x01ffa20d  # bound literal in the held BH16NS48 mode function
    rows = []
    reference = args.reference.read_bytes()
    reference_sha = hashlib.sha256(reference).hexdigest()
    assert reference_sha == '221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4'
    reference_cpu, _ = detection.machine(reference, receipt)
    native_reference = {}
    for state in (0xc7, 0xc8):
        reference_cpu.mem_write(0x01ff0000, bytes(0x20000))
        reference_cpu.mem_write(0x01ff9e04, bytes([state]))
        reference_cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        reference_cpu.reg_write(reg.UC_ARM_REG_LR, detection.DONE | 1)
        reference_cpu.emu_start(0xdae01, detection.DONE, count=10000)
        assert reference_cpu.reg_read(reg.UC_ARM_REG_PC) == detection.DONE
        assert reference_cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        native_reference[state] = reference_cpu.mem_read(0x01ffa395, 1)[0]
    assert native_reference == {0xc7: 0x1c, 0xc8: 0x1c}

    def execute(name, state, flag, nzcv):
        cpu, trace = machines[name]
        cpu.mem_write(0x01ff0000, bytes(0x20000))
        cpu.mem_write(0x03000000, bytes(0x10000))
        cpu.mem_write(receipt['state'], bytes([state]))
        cpu.mem_write(receipt['flag_base'] + 3, bytes([flag]))
        for index, register in enumerate(detection.REGISTERS):
            cpu.reg_write(register, 0x12000000 + index * 0x101)
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30 | (nzcv << 28))
        cpu.reg_write(reg.UC_ARM_REG_SP, 0x03008000)
        cpu.reg_write(reg.UC_ARM_REG_LR, detection.DONE | 1)
        before = [cpu.reg_read(r) for r in detection.REGISTERS[4:8]]
        cpu.emu_start(receipt['mode_entry'] | 1, detection.DONE, count=10000)
        assert cpu.reg_read(reg.UC_ARM_REG_PC) == detection.DONE
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == 0x03008000
        assert [cpu.reg_read(r) for r in detection.REGISTERS[4:8]] == before
        return bytes(cpu.mem_read(0x01ff0000, 0x20000)), cpu.mem_read(mode_cell, 1)[0]

    cases = 0
    for state in range(256):
        for flag in (0, 1, 255, 2):
            for nzcv in range(16):
                oem, old_mode = execute('oem', state, flag, nzcv)
                previous, baseline_mode = execute('baseline', state, flag, nzcv)
                changed, mode = execute('candidate', state, flag, nzcv)
                assert previous == oem, (state, flag, 'baseline changed native mode function')
                if state == 0xc7 and flag == 1:
                    _, native_dense_mode = execute('oem', 0xc8, flag, nzcv)
                    assert mode == native_dense_mode == 0x1c
                    assert old_mode == baseline_mode == 7
                    deltas = [i + 0x01ff0000 for i, (a, b) in enumerate(zip(oem, changed)) if a != b]
                    assert deltas == [mode_cell], deltas
                    rows.append({'state':state, 'flag':flag, 'nzcv':nzcv, 'native_mode':old_mode, 'research_mode':mode, 'changed_cells':deltas})
                else:
                    assert changed == oem, (state, flag, 'unrelated native RAM changed')
                cases += 1
    args.output.write_text(json.dumps({'scope':__doc__, 'source_sha256':receipt['source_sha256'],
        'candidate_sha256':receipt['output_sha256'], 'reference_sha256':reference_sha,
        'native_bu40n_mode':native_reference, 'cases':cases, 'changed_cases':rows}, indent=2) + '\n')
    print(f'PASS: {cases} complete post-DI initialization-mode comparisons; only C7/On changes one mode byte, to native C8 value; registers and stack preserved')


if __name__ == '__main__':
    main()
