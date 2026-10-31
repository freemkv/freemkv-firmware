"""Mutation-check independent contracts against real source-bound production output.

MT_CPU_FIXTURE_DIR must name a builder output directory with an auth_cell hook.
Tests fail closed when the required production artifact is missing.
"""
import json
import os
import struct
from pathlib import Path
import unittest
from stages import compare_hook


class ProductionContractMutations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=Path(os.environ['MT_CPU_FIXTURE_DIR'])
        cls.original=(p/'original.bin').read_bytes()
        cls.modified=(p/'modified.bin').read_bytes()
        doc=json.loads((p/'modify.json').read_text())
        cls.contracts=doc['execution_contracts'];cls.engine=doc['engine']
        cls.site=cls.contracts['auth_cell']['site']
        cls.stub=cls.contracts['facts']['auth_cell_stub_va']

    def audit(self,data):
        return compare_hook('auth_cell',self.original,bytes(data),self.engine,self.contracts)

    def test_real_production_auth_contract_passes(self):
        result=self.audit(self.modified)
        self.assertEqual(result['status'],'passed',result.get('failures'))
        self.assertGreater(result['cases'],0)

    def test_noop_intended_patch_is_caught(self):
        data=bytearray(self.modified);data[self.site:self.site+4]=self.original[self.site:self.site+4]
        self.assertEqual(self.audit(data)['status'],'failed')

    def test_unconditional_auth_bypass_is_caught(self):
        data=bytearray(self.modified);data[self.stub:self.stub+2]=bytes.fromhex('7047')
        self.assertEqual(self.audit(data)['status'],'failed')

    def test_unintended_live_register_change_is_caught(self):
        data=bytearray(self.modified);data[self.stub:self.stub+2]=bytes.fromhex('0124')
        self.assertEqual(self.audit(data)['status'],'failed')

    def test_unintended_arm_mode_continuation_is_caught(self):
        data=bytearray(self.modified)
        deny=self.contracts['auth_cell']['deny']
        position=data.find(struct.pack('<I',deny|1),self.stub,self.stub+128)
        self.assertGreaterEqual(position,self.stub,'source-bound denial target literal missing')
        data[position:position+4]=struct.pack('<I',deny)
        result=self.audit(data)
        self.assertEqual(result['status'],'failed')
        self.assertTrue(any('CPU control/Thumb state' in f['error'] for f in result['failures']))

    def test_thumb2_injection_is_caught(self):
        data=bytearray(self.modified);data[self.site:self.site+4]=bytes.fromhex('40f20000')
        result=self.audit(data)
        self.assertEqual(result['status'],'failed')
        self.assertTrue(any('ARMv5 Thumb' in f['error'] for f in result['failures']))

if __name__=='__main__':unittest.main()
