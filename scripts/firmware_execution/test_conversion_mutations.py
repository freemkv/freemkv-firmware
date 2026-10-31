"""Mutation sensitivity against actual installed classic UHD firmware output."""
import json
import os
from pathlib import Path
import struct
import unittest
from stages import compare_hook


class InstalledConversionMutations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=Path(os.environ['MT_UHD_CPU_FIXTURE_DIR'])
        cls.original=(p/'original.bin').read_bytes();cls.modified=(p/'modified.bin').read_bytes()
        d=json.loads((p/'modify.json').read_text());cls.engine=d['engine'];cls.contracts=d['execution_contracts']
        cls.contracts['_hoard']=os.environ['MT_CPU_HOARD']
        helpers=cls.contracts['media_conversion_helpers']
        cls.di=next(c for c in helpers if c['role']=='DiscInformation')
        cls.math=next(c for c in helpers if c['role']=='ForwardCalculation')
        cls.selection=next(c for c in helpers if c['role']=='ParameterClass')

    def audit(self,data,helper):
        return compare_hook('conversion:'+str(helper['site']),self.original,bytes(data),self.engine,self.contracts)

    def test_actual_installed_di_contract_passes(self):
        r=self.audit(self.modified,self.di)
        self.assertEqual(r['status'],'passed',r.get('failures',[None])[:1])
        self.assertEqual(r['generated_branch_coverage']['uncovered'],[])

    def test_actual_installed_native_math_contract_passes(self):
        r=self.audit(self.modified,self.math)
        self.assertEqual(r['status'],'passed',r.get('failures',[None])[:1])

    def test_noop_di_extension_is_caught(self):
        data=bytearray(self.modified);c=self.di
        data[c['site']:c['site']+len(c['original_bytes'])]=bytes(c['original_bytes'])
        self.assertEqual(self.audit(data,c)['status'],'failed')

    def test_wrong_uhd_identity_is_caught(self):
        data=bytearray(self.modified);c=self.di
        at=data.find(bytes.fromhex('c720'),c['target'],c['target']+c['helper_len'])
        self.assertGreaterEqual(at,c['target'])
        data[at:at+2]=bytes.fromhex('c620')
        self.assertEqual(self.audit(data,c)['status'],'failed')

    def test_noop_routing_extension_is_caught(self):
        data=bytearray(self.modified);c=self.selection
        data[c['site']:c['site']+len(c['original_bytes'])]=bytes(c['original_bytes'])
        self.assertEqual(self.audit(data,c)['status'],'failed')

    def test_wrong_native_continuation_is_caught(self):
        data=bytearray(self.modified);c=self.selection;contract=c['contract']
        at=data.find(struct.pack('<I',contract['accept']|1),c['target'],c['target']+c['helper_len'])
        self.assertGreaterEqual(at,c['target'])
        data[at:at+4]=struct.pack('<I',contract['reject']|1)
        self.assertEqual(self.audit(data,c)['status'],'failed')

    def test_unintended_native_coefficient_change_is_caught(self):
        data=bytearray(self.modified);c=self.math;contract=c['contract']
        at=data.find(bytes.fromhex('0c23'),contract['accept'],contract['calculation_end'])
        self.assertGreaterEqual(at,contract['accept'])
        data[at:at+2]=bytes.fromhex('1323')
        self.assertEqual(self.audit(data,c)['status'],'failed')

    def test_thumb2_conversion_injection_is_caught(self):
        data=bytearray(self.modified);c=self.selection
        data[c['target']:c['target']+4]=bytes.fromhex('40f20000')
        r=self.audit(data,c)
        self.assertEqual(r['status'],'failed')
        self.assertTrue(any('ARMv5 Thumb' in f['error'] for f in r.get('failures',[])))

if __name__=='__main__':unittest.main()
