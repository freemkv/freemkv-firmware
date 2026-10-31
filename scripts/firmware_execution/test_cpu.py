import sys
from pathlib import Path
import struct
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cpu import Execution, thumb1_instruction
from unicorn import arm_const as reg


class CpuTests(unittest.TestCase):
    def test_thumb1_allows_native_bl_and_rejects_thumb2(self):
        self.assertTrue(thumb1_instruction(bytes.fromhex('00f000f8')))
        self.assertTrue(thumb1_instruction(bytes.fromhex('7047')))
        for code in ('00f000b8', '40f20000', '00b1', '08bf', '00b2', '00ba'):
            self.assertFalse(thumb1_instruction(bytes.fromhex(code)), code)

    def test_thumb2_is_rejected_during_legacy_execution(self):
        execution = Execution('MT1959','arm926')
        image = bytearray(0x200000)
        image[0x1000:0x1004] = bytes.fromhex('00f000b8')
        cpu = execution.machine(bytes(image))
        with self.assertRaisesRegex(AssertionError, 'ARMv5 Thumb'):
            cpu.emu_start(0x1001, 0x1010, count=1)

    def test_native_thumb_bl_split_at_translation_boundary_is_legal(self):
        execution = Execution('MT1959','arm926')
        image = bytearray(0x200000)
        image[0x13fe:0x1402] = bytes.fromhex('00f000f8')
        cpu = execution.machine(bytes(image))
        cpu.emu_start(0x13ff, 0x1402, count=4)
        self.assertIn(0x1400, execution.instructions)

    def test_orphan_thumb_bl_suffix_remains_illegal(self):
        execution = Execution('MT1939')
        image = bytearray(0x200000)
        image[0x1400:0x1402] = bytes.fromhex('00f8')
        cpu = execution.machine(bytes(image))
        with self.assertRaisesRegex(AssertionError, 'ARMv5 Thumb'):
            cpu.emu_start(0x1401, 0x1410, count=1)

    def test_mt1959_native_thumb2_executes_on_user_selected_armv7(self):
        execution=Execution('MT1959')
        self.assertEqual(execution.cpu_model,'Cortex-A8')
        image=bytearray(0x200000);image[0x1000:0x1004]=bytes.fromhex('00f000b8')
        cpu=execution.machine(bytes(image));cpu.emu_start(0x1001,0x1010,count=1)
        self.assertEqual(cpu.reg_read(reg.UC_ARM_REG_PC),0x1004)

    def test_unknown_engine_cannot_default_to_a_permissive_cpu(self):
        with self.assertRaises(ValueError):
            Execution('unknown')

    def test_unexecuted_branch_is_a_coverage_gap(self):
        execution = Execution('MT1939-classic')
        image = bytearray(0x200000)
        image[0x1000:0x100c] = struct.pack('<6H', 0x2800, 0xd001, 0x2101, 0x4770, 0x2102, 0x4770)
        cpu = execution.machine(bytes(image))
        for value in (0, 1):
            cpu.reg_write(reg.UC_ARM_REG_R0, value)
            cpu.reg_write(reg.UC_ARM_REG_LR, 0x0300f001)
            cpu.emu_start(0x1001, 0x0300f000, count=10)
            coverage = execution.missing(bytes(image), [0x1000])
            self.assertEqual(len(coverage['uncovered']), 1 if value == 0 else 0)


if __name__ == '__main__':
    unittest.main()
