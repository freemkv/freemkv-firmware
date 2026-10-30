"""Execute native saved-state pairing and frame returns using planner evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

ROOT = Path(__file__).resolve().parents[1] / 'crates/freemkv-fw/tests/fixtures/cmac-research'
FRAME = 0x03008000
RETURN = 0x0300F000
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--candidate-builder', type=Path, required=True)
args = parser.parse_args()


def execute(record, frame, selection, cookie, wrong_slot=False):
    data = (ROOT / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['excerpt_sha256']
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.mem_write(record['source_offset'], data)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP, FRAME)
    # Native prologue/epilogue binding says these five words were pushed before
    # the local frame was allocated. The actual epilogue must restore them.
    saved = [0x11223344, 0x22334455, 0x33445566, 0x44556677]
    cpu.mem_write(FRAME + frame['stack_bytes'], struct.pack('<5I', *saved, RETURN | 1))
    restored = []
    reached = []

    def visit(machine, address, _size, _data):
        if address == selection:
            reached.append('saved')
            machine.emu_stop()
        elif address == RETURN:
            reached.append('returned')
            machine.emu_stop()
        elif address == 0x2D4:
            assert machine.reg_read(reg.UC_ARM_REG_R0) == 0xC0
            machine.reg_write(reg.UC_ARM_REG_R0, cookie)
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))
        elif address == 0x2CC:
            restored.append(machine.reg_read(reg.UC_ARM_REG_R0))
            machine.reg_write(reg.UC_ARM_REG_PC, machine.reg_read(reg.UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.emu_start((frame['save_call'] - 2) | 1, 0x200000, count=20)
    assert reached == ['saved']
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == FRAME
    assert struct.unpack('<I', cpu.mem_read(FRAME + frame['slot'], 4))[0] == cookie
    continuation = frame['restore_call'] - 2
    if wrong_slot:
        instruction = struct.unpack('<H', cpu.mem_read(continuation, 2))[0]
        cpu.mem_write(continuation, struct.pack('<H', instruction ^ 1))
    cpu.reg_write(reg.UC_ARM_REG_R0, 0xBAD0BAD0)
    cpu.emu_start(continuation | 1, 0x200000, count=40)
    assert reached == ['saved', 'returned']
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == FRAME + frame['stack_bytes'] + 20
    assert [cpu.reg_read(getattr(reg, f'UC_ARM_REG_R{i}')) for i in range(4, 8)] == saved
    if wrong_slot:
        assert restored != [cookie], 'wrong slot unexpectedly recovered original state'
    else:
        assert restored == [cookie]


records = json.loads((ROOT / 'sources.json').read_text())
for name in ('uh12-application.bin', 'wp50-application.bin',
             'bu40-a103-application.bin', 'be16-application.bin'):
    record = next(r for r in records if r['file'] == name)
    result = subprocess.run([str(args.candidate_builder.resolve()), str(ROOT / name),
                             'application-evidence', f"{record['source_offset']:x}"],
                            check=True, capture_output=True, text=True)
    evidence = json.loads(result.stdout)
    candidates = [r for r in evidence['ranges'] if r['state_slot'] is not None]
    assert len(candidates) == 1
    selected = candidates[0]
    for cookie in (0, 0xC0FFEE, 0xFEDCBA98):
        execute(record, selected['state_slot'], selected['selection'], cookie)
    execute(record, selected['state_slot'], selected['selection'], 0xC0FFEE, wrong_slot=True)
print('PASS: 12 native state-save/restore frame returns and 4 wrong-slot counterexamples (state helpers stubbed)')
