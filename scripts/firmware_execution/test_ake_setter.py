"""Actual production-BIN AKE setter closure and sensitivity tests."""
import json
import os
from pathlib import Path
import unittest
from unicorn import UcError, UC_ERR_WRITE_UNMAPPED

from ake_setter import compare_closed_setter, execute_setter, setter_contract
from stages import Stage


class ActualAkeSetter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=Path(os.environ['MT_UHD_CPU_FIXTURE_DIR'])
        cls.original=(p/'original.bin').read_bytes()
        cls.modified=(p/'modified.bin').read_bytes()
        d=json.loads((p/'modify.json').read_text())
        cls.engine=d['engine'];cls.contracts=d['execution_contracts']
        cls.base=cls.contracts['base'];cls.facts=cls.contracts['facts']
        cls.c=setter_contract(cls.original,cls.facts)

    def test_actual_setter_and_installed_nonoff_paths_complete(self):
        s=Stage('closed-setter',self.original,self.modified,self.engine,self.base)
        compare_closed_setter(s,self.facts,self.base)
        self.assertEqual(s.result.get('failures',[]),[])
        self.assertEqual(s.result['coverage_gaps'],[])
        self.assertEqual(s.result['cases'],62 if self.c['classic'] else 60)

    def test_native_agid_bound_mutant_is_detected(self):
        data=bytearray(self.original)
        data[self.c['setter']:self.c['setter']+2]=bytes.fromhex('0428')
        with self.assertRaisesRegex(AssertionError,'wrong state, address or AGID bound'):
            execute_setter(bytes(data),self.engine,self.base['flags'],self.c,2,6)

    def test_native_store_state_mutant_is_detected(self):
        data=bytearray(self.original)
        at=self.c['setter']+self.c['length']-4
        # STRB r2,[r0] replaces STRB r1,[r0]. Real runtime input gives
        # r2 an unrelated relocated base, so this cannot accidentally alias6.
        data[at:at+2]=bytes.fromhex('0270')
        with self.assertRaisesRegex(AssertionError,'wrong state, address or AGID bound'):
            execute_setter(bytes(data),self.engine,self.base['flags'],self.c,0,6)

    def test_native_relocation_shift_mutant_is_detected(self):
        data=bytearray(self.original)
        at=self.c['setter']+{'common':20,'short':16,'adjusted':18,'adjusted_common':22}[self.c['shape']]
        # Erase the low24 truncation's first shift. Strict input accounting
        # rejects any unowned resultant address rather than silently mapping it.
        data[at:at+2]=bytes.fromhex('c046')
        execute_setter(self.original,self.engine,self.base['flags'],self.c,0,6)
        with self.assertRaises(UcError) as failure:
            execute_setter(bytes(data),self.engine,self.base['flags'],self.c,0,6)
        self.assertEqual(failure.exception.errno,UC_ERR_WRITE_UNMAPPED)

    def test_installed_wrong_native_join_is_detected(self):
        if self.c['join']==self.c['site']:
            self.skipTest('NB replaces nativeBL; desktop nativejoin mutation only')
        data=bytearray(self.modified)
        # Actual native call changed to branch over the store-producing setter.
        data[self.c['join']:self.c['join']+4]=bytes.fromhex('00e0c046')
        s=Stage('closed-setter-mutant',self.original,bytes(data),self.engine,self.base)
        compare_closed_setter(s,self.facts,self.base)
        self.assertEqual(s.result['status'],'failed')
        self.assertGreater(len(s.result.get('failures',[])),0)

    def test_actual_off_reset_prefix_matches_native_invocation(self):
        from ake_setter import compare_reset_prefix
        if self.c['classic']:
            self.skipTest('classic AKE Off goes directly to native setter')
        s=Stage('reset-prefix',self.original,self.modified,self.engine,self.base)
        compare_reset_prefix(s,self.facts,self.base)
        self.assertEqual(s.result.get('failures',[]),[])
        self.assertEqual(s.result['coverage_gaps'],[])
        self.assertEqual(s.result['cases'],15)

    def test_off_reset_wrong_saved_agid_mutant_is_detected(self):
        from ake_setter import compare_reset_prefix
        if self.c['classic']:
            self.skipTest('classic AKE Off goes directly to native setter')
        root=self.facts['ake_stub_va']
        at=self.modified.find(bytes.fromhex('01b5'),root,root+80)
        self.assertNotEqual(at,-1,'actual Off stub PUSH{r0,lr} not found')
        data=bytearray(self.modified)
        data[at:at+2]=bytes.fromhex('02b5')  # save r1 instead of live AGID r0
        control=Stage('reset-control',self.original,self.modified,self.engine,self.base)
        compare_reset_prefix(control,self.facts,self.base)
        self.assertEqual(control.result['cases'],15)
        self.assertEqual(control.result.get('failures',[]),[])
        s=Stage('reset-mutant',self.original,bytes(data),self.engine,self.base)
        compare_reset_prefix(s,self.facts,self.base)
        self.assertEqual(s.result['status'],'failed')
        self.assertTrue(any(f['error']=='Off reset lost saved AGID'
                            for f in s.result.get('failures',[])))
