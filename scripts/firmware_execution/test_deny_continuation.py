"""Actual generated reset continuation: sense replay and caller-frame mutations."""
import json
import os
from pathlib import Path
import unittest
from stages import DECODER, compare_hook


class DenyContinuation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder=Path(os.environ['MT_CPU_FIXTURE_DIR'])
        doc=json.loads((folder/'modify.json').read_text())
        cls.original=(folder/'original.bin').read_bytes()
        cls.modified=(folder/'modified.bin').read_bytes()
        cls.engine=doc['engine'];cls.contracts=doc['execution_contracts']
        root=cls.contracts['facts']['deny_stub_va']
        cls.continuation=next(i.address+i.size for i in DECODER.disasm(
            cls.modified[root:root+16],root) if i.mnemonic=='blx')

    def audit(self, data):
        return compare_hook('deny-reset',self.original,bytes(data),self.engine,self.contracts)

    def test_real_continuation_replays_native_sense_and_restores_frame(self):
        result=self.audit(self.modified)
        self.assertEqual(result['status'],'passed',result.get('failures'))
        self.assertEqual(result['cases'],13)

    def test_wrong_sense_and_wrong_frame_are_detected(self):
        for offset,opcode in ((0,'0322'),(2,'6e21'),(4,'00bd')):
            with self.subTest(offset=offset):
                data=bytearray(self.modified)
                data[self.continuation+offset:self.continuation+offset+2]=bytes.fromhex(opcode)
                result=self.audit(data)
                self.assertEqual(result['status'],'failed')
                self.assertTrue(result['failures'])


if __name__=='__main__':unittest.main()
