"""ReadControl operand provenance and actual native store-path sensitivity.

Uses a real production output directory via MT_UHD_CPU_FIXTURE_DIR. Executes
actual native prelude/body bytes through their common join, with declared MMIO
words and no service return or controller-completion model.
"""
import json
import os
from pathlib import Path
import struct
import unittest

from cpu import Execution
from conversion import source_inputs
from stages import DECODER, compare_hook, run, unchanged


class ReadControlInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ['MT_UHD_CPU_FIXTURE_DIR'])
        cls.original=(root/'original.bin').read_bytes()
        cls.modified=(root/'modified.bin').read_bytes()
        doc=json.loads((root/'modify.json').read_text())
        cls.engine=doc['engine'];cls.contracts=doc['execution_contracts']
        cls.contracts['_hoard']=os.environ['MT_CPU_HOARD']
        cls.helper=next(c for c in cls.contracts['media_conversion_helpers']
                        if c['role']=='ReadControl')
        cls.contract=cls.helper['contract']
        cls.entry=cls.contract['region_start']-10
        branch=next(DECODER.disasm(cls.original[cls.contract['reject']-2:cls.contract['reject']],
                                  cls.contract['reject']-2,count=1))
        assert branch.mnemonic=='b','ReadControl common join not independently bound'
        cls.join=int(branch.op_str.lstrip('#'),0)
        assert cls.contract['reject']<cls.join<cls.contract['reject']+0x100
        load=int.from_bytes(cls.original[cls.entry:cls.entry+2],'little')
        cls.base_register=(load>>8)&7
        pool=((cls.entry+4)&~3)+(load&255)*4
        cls.controller=int.from_bytes(cls.original[pool:pool+4],'little')
        assert cls.controller==0x042080c0

    def test_controller_and_request_are_source_owned_non_aliasing_operands(self):
        registers,_=source_inputs(self.original,self.helper,0xc8)
        self.assertEqual(registers[self.base_register],self.controller)
        self.assertNotEqual(registers[4],self.controller)
        # The source-owned request comes from a native immediate comparison,
        # not a synthetic writable pointer or the controller address.
        self.assertLessEqual(registers[4],255)
        self.assertNotEqual(registers[5],registers[6])

    def test_actual_prelude_and_bodies_preserve_native_controller_transactions(self):
        flags=self.contracts['base']['flags']
        controller=self.controller;state_cell=self.contract['state']
        for setting in (0,1,2,255):
            # Include declared CD/DVD as well as BD/UHD media-state inputs.
            # These exercise the actual controller store path, not acquisition.
            for state in (0,0x40,0x44,0xc0,0xc4,0xc7,0xc8,0xcc,0xf8):
                for seed in (0,0xffffffff,0xa55a3cc3,0x12345678):
                    active=setting==1 and state==0xc7
                    old_state=0xc8 if active else state
                    words=b''.join(struct.pack('<I',(seed^(i*0x01010101))&0xffffffff)
                                   for i in range(0,0x40,4))
                    def execute(data,media):
                        registers,_=source_inputs(self.original,self.helper,media)
                        return run(data,self.engine,self.entry,{self.join},flags,
                            settings={3:setting},registers=registers,
                            memory=[(state_cell,bytes([media])),(controller,words)],
                            allow_writes=[(controller,controller+len(words))],
                            observe_memory=[(controller,len(words))],strict_reads=True)
                    with self.subTest(setting=setting,state=state,seed=seed):
                        old=execute(self.original,old_state)
                        new=execute(self.modified,state)
                        self.assertEqual(old['target'],self.join)
                        self.assertEqual(new['target'],self.join)
                        unchanged(old,new)
                        self.assertEqual(old['memory'],new['memory'])
                        stores=lambda result:[w for w in result['writes']
                                               if controller<=w[0]<controller+len(words)]
                        self.assertEqual(stores(old),stores(new))
                        self.assertGreater(len(stores(new)),0)

    def test_actual_installed_selector_passes_complete_coverage(self):
        result=compare_hook('conversion:'+str(self.helper['site']),self.original,
                            self.modified,self.engine,self.contracts)
        self.assertEqual(result['status'],'passed',result.get('failures',[])[:1])
        self.assertEqual(result['generated_branch_coverage']['uncovered'],[])
        self.assertEqual(result['generated_branch_coverage']['unvisited_instructions'],[])

    def test_wrong_replay_base_is_rejected_on_actual_bin(self):
        c=self.helper;mutated=bytearray(self.modified)
        replay=int.from_bytes(bytes(c['original_bytes'])[2:4],'little')
        self.assertEqual((replay>>3)&7,self.base_register)
        wrong=(replay&~0x38)|(4<<3)
        self.assertNotEqual(wrong,replay)
        execution=Execution(self.engine)
        execution.branch_requirements(mutated,c['target'])
        sites=[at for at in execution.static_instructions
               if int.from_bytes(mutated[at:at+2],'little')==replay]
        self.assertGreater(len(sites),0)
        for at in sites:mutated[at:at+2]=wrong.to_bytes(2,'little')
        result=compare_hook('conversion:'+str(c['site']),self.original,bytes(mutated),
                            self.engine,self.contracts)
        self.assertEqual(result['status'],'failed')
        self.assertGreater(len(result.get('failures',[])),0)

    def test_changed_controller_literal_is_refused(self):
        changed=bytearray(self.original)
        op=int.from_bytes(changed[self.entry:self.entry+2],'little')
        pool=((self.entry+4)&~3)+(op&255)*4
        changed[pool:pool+4]=struct.pack('<I',self.controller+4)
        with self.assertRaisesRegex(AssertionError,'source controller identity'):
            source_inputs(bytes(changed),self.helper,0xc8)


if __name__=='__main__':unittest.main()
