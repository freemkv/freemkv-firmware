"""Execute the source-bound private identity reset on ARM926.

This verifies the actual emitted helper and the native initializer's CPU effects.
Native callees are stubbed with explicit AAPCS volatile clobbers; no hardware,
boot ordering, SRAM ownership, DI producer or optical readiness is established.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

SP=0x03008000
RETURN=0x003f0000
REGS=[getattr(reg,f'UC_ARM_REG_R{i}') for i in range(13)]
NZCV=tuple(n << 28 for n in range(16))


class Machine:
    def __init__(self,data,contract,candidate,base,patched,whole,mutation=None):
        self.contract,self.base,self.whole=contract,base,whole
        self.marker,self.mode=contract['marker'],contract['mode']
        self.continuation=contract['continuation']
        assert self.marker not in (self.mode,contract['density_class'],contract['state'])
        self.stub=bytearray(candidate['bytes'])
        if mutation=='marker_store':self.stub[2:4]=b'\xc0\x46'
        if mutation=='mode_store':self.stub[6:8]=b'\xc0\x46'
        if mutation=='flags':self.stub[2:4]=b'\x00\x21'  # MOVS R1,#0: value unchanged, NZ changes
        if mutation=='return':
            op=int.from_bytes(self.stub[10:12],'little');assert op&0xff00==0x4b00
            pool=((10+4)&~3)+(op&255)*4
            self.stub[pool:pool+4]=struct.pack('<I',(self.continuation+2)|1)
        code=bytearray(data)
        assert code[contract['site']:contract['site']+4]==bytes(candidate['original'])==bytes(contract['original'])
        if patched:
            delta=(base-contract['site']-4)>>1
            assert -(1<<21)<=delta<(1<<21)
            code[contract['site']:contract['site']+4]=struct.pack('<HH',0xf000|((delta>>11)&0x7ff),0xf800|(delta&0x7ff))
        self.cpu=c=Uc(UC_ARCH_ARM,UC_MODE_THUMB);c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for at,size in ((0,0x400000),(0x01ff0000,0x40000),(0x03000000,0x10000),(0x04000000,0x400000)):
            c.mem_map(at,size)
        c.mem_write(0,bytes(code));c.mem_write(base,bytes(self.stub))
        self.initial=c.context_save();self.decode=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
        self.calls={};self.writes=[];self.exit=None
        self.patched=patched
        self.stack_depth=contract['stack_bytes']
        def hook(cpu,at,size,user):
            if at==(RETURN if whole else self.continuation):self.exit=at;cpu.emu_stop();return
            in_stub=patched and base<=at<base+16
            in_native=(contract['entry']<=at<=max(contract['returns']) if whole else contract['site']<=at<contract['site']+4)
            if not (in_stub or in_native):self.exit=at;cpu.emu_stop();return
            if whole and not in_stub and not (patched and at==contract['site']):
                if at not in self.calls:
                    ins=next(self.decode.disasm(bytes(cpu.mem_read(at,size)),at),None)
                    self.calls[at]=bool(ins and ins.mnemonic in ('bl','blx'))
                if self.calls[at]:
                    # Both runs execute the same native call boundary. These
                    # stand-ins preserve only AAPCS nonvolatile state.
                    for r in (0,1,2,3,12):cpu.reg_write(REGS[r],0)
                    cpu.reg_write(reg.UC_ARM_REG_LR,(at+size)|1)
                    cpu.reg_write(reg.UC_ARM_REG_PC,(at+size)|1)
        def write(cpu,access,at,size,value,user):
            self.writes.append((at,size,value))
        c.hook_add(UC_HOOK_CODE,hook);c.hook_add(UC_HOOK_MEM_WRITE,write)

    def run(self,nzcv,marker,mode,salt=0):
        c=self.cpu;c.context_restore(self.initial);self.writes=[];self.exit=None
        if self.whole:
            c.mem_write(0x01ff0000,bytes(0x40000));c.mem_write(0x04000000,bytes(0x400000))
        c.mem_write(SP-0x100,b'\xa5'*0x180)
        for i,r in enumerate(REGS):c.reg_write(r,(0x10203040*(i+1)+salt)&0xffffffff)
        c.reg_write(reg.UC_ARM_REG_R1,0)  # partial-run precondition, whole run defines it natively
        c.reg_write(reg.UC_ARM_REG_LR,RETURN|1);c.reg_write(reg.UC_ARM_REG_SP,SP)
        c.reg_write(reg.UC_ARM_REG_CPSR,0x20|nzcv|(0x08000000 if salt else 0))
        flags=self.contract['flags'];canary=bytes((0x81+i*7)&255 for i in range(32))
        c.mem_write(flags-4,canary);c.mem_write(self.marker,bytes([marker]));c.mem_write(self.mode,bytes([mode]))
        start=self.contract['entry'] if self.whole else (self.base if self.patched else self.contract['site'])
        c.emu_start(start|1,0,count=30000)
        assert self.exit is not None,'native execution did not terminate'
        bottom=SP-self.stack_depth-8 if self.whole else SP-8
        assert bytes(c.mem_read(SP-0x100,bottom-(SP-0x100)))==b'\xa5'*(bottom-(SP-0x100)),'lower stack canary'
        assert bytes(c.mem_read(SP,0x80))==b'\xa5'*0x80,'upper stack canary'
        nonstack=[w for w in self.writes if not SP-0x100<=w[0]<SP+0x80]
        return {'exit':self.exit,'registers':[c.reg_read(r) for r in REGS],
            'lr':c.reg_read(reg.UC_ARM_REG_LR),'sp':c.reg_read(reg.UC_ARM_REG_SP),
            'flags':c.reg_read(reg.UC_ARM_REG_CPSR)&0xf8000000,
            'workspace':bytes(c.mem_read(flags-4,32)),'mode':c.mem_read(self.mode,1)[0],
            'marker':c.mem_read(self.marker,1)[0],'writes':nonstack}


def compare(before,after,contract,whole):
    marker=contract['marker'];expected=RETURN if whole else contract['continuation']
    assert before['exit']==after['exit']==expected,(before,after)
    for key in ('registers','lr','sp','flags','mode'):assert before[key]==after[key],(key,before,after)
    assert after['sp']==SP and after['mode']==0 and after['marker']==0
    expected_workspace=bytearray(before['workspace']);expected_workspace[marker-(contract['flags']-4)]=0
    assert after['workspace']==bytes(expected_workspace),'feature/scratch/guard byte changed'
    assert all(not (a<=marker<a+n) for a,n,v in before['writes']),'native initializer already writes private marker'
    expected_writes=[w for w in after['writes'] if w[0]!=marker]
    assert expected_writes==before['writes'],'native mode/controller effects changed'
    assert [w for w in after['writes'] if w[0]==marker]==[(marker,1,0)]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--plans',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();scans={r['sha256']:r for r in json.loads(args.scan.read_text())['images']}
    helpers=[];counts={'partial':0,'initializer':0,'mutations':0};prepared=0
    for row in json.loads(args.plans.read_text()):
        contract=row['plan'].get('identity_contract')
        if not contract:continue
        candidate=next(c for c in row['plan']['candidates'] if c['site']==contract['site'])
        assert candidate['gap']=='G01' and len(candidate['original'])==4
        assert contract['source_sha256']==row['sha256'] and contract['zero_register']==1
        assert contract['boot_clear_required'] is True
        data=(args.hoard/scans[row['sha256']]['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        helper={'source_sha256':row['sha256'],'gap':candidate['gap'],'site':candidate['site'],
            'original_sha256':hashlib.sha256(bytes(candidate['original'])).hexdigest(),
            'helper_sha256':hashlib.sha256(bytes(candidate['bytes'])).hexdigest(),
            'bytes_sha256':hashlib.sha256(bytes(candidate['bytes'])).hexdigest()}
        for base in (0x280000,0x300000):
            before=Machine(data,contract,candidate,base,False,False)
            after=Machine(data,contract,candidate,base,True,False)
            for flags in NZCV:
                for marker in (0,1,255):
                    for mode in (0,1,255):
                        for salt in (0,0xa5a55a5a):
                            compare(before.run(flags,marker,mode,salt),after.run(flags,marker,mode,salt),contract,False)
                            counts['partial']+=1
        before=Machine(data,contract,candidate,0x300000,False,True)
        after=Machine(data,contract,candidate,0x300000,True,True)
        for flags in NZCV:
            for marker in (0,1,255):
                compare(before.run(flags,marker,255),after.run(flags,marker,255),contract,True)
                counts['initializer']+=1
        reference=Machine(data,contract,candidate,0x300000,False,False).run(0x80000000,0,255)
        for mutation in ('marker_store','mode_store','flags','return'):
            bad=Machine(data,contract,candidate,0x300000,True,False,mutation)
            initial_marker=0xa5 if mutation=='marker_store' else 0
            original=Machine(data,contract,candidate,0x300000,False,False).run(0x80000000,initial_marker,255)
            try:changed=bad.run(0x80000000,initial_marker,255)
            except UcError:
                assert mutation!='flags';counts['mutations']+=1;continue
            if mutation=='flags':
                assert changed['flags']!=reference['flags'] and changed['marker']==0 and changed['mode']==0
            try:compare(original,changed,contract,False)
            except AssertionError:counts['mutations']+=1
            else:raise AssertionError(('mutation survived',mutation,row['sha256']))
        helpers.append(helper);prepared+=1
    assert prepared,'no identity helpers tested'
    receipt={'scope':__doc__,'cpu':'ARM926','result':'pass','cases':sum(counts.values()),'case_counts':counts,
        'scan_input_sha256':hashlib.sha256(args.scan.read_bytes()).hexdigest(),
        'candidate_input_sha256':hashlib.sha256(args.plans.read_bytes()).hexdigest(),
        'plans_sha256':hashlib.sha256(args.plans.read_bytes()).hexdigest(),
        'scan_sha256':hashlib.sha256(args.scan.read_bytes()).hexdigest(),
        'suite_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'helpers':helpers,'boot_ordering':'requires separate boot clear; not established by CPU suite'}
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(f"PASS: {receipt['cases']} identity reset cases across {prepared} helpers; {counts}")


if __name__=='__main__':main()
