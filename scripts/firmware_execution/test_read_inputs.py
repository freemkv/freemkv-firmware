"""Reject implicit zero RAM as a native getter/controller input oracle."""
import unittest
from stages import STOP, run


class ExplicitNativeInputs(unittest.TestCase):
    def test_unprovided_ram_read_is_rejected(self):
        with self.assertRaisesRegex(AssertionError,'unprovided native memory input'):
            run(bytes.fromhex('08687047'),'MT1939',0,{STOP},0x02001000,
                registers={1:0x02003000},strict_reads=True)

    def test_explicit_input_is_read_and_returned(self):
        r=run(bytes.fromhex('08687047'),'MT1939',0,{STOP},0x02001000,
            registers={1:0x02003000},memory=[(0x02003000,b'\x78\x56\x34\x12')],strict_reads=True)
        self.assertEqual(r['registers'][0],0x12345678)


if __name__=='__main__':unittest.main()
