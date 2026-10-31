"""Execute prepared conversion stubs on ARM926. No firmware file is written.

Candidate-only checks do not authorize partial installation or establish optical
readiness, numerical worker correctness, certificates or authentication success.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from functools import lru_cache
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

BASE=0x1e0000
FLAGS=0x02000e43
SP=0x03008000


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


consumers=module('audit-mtk-uhd-consumers')


class Patched(consumers.Runner):
    def __init__(self,data,area,state,candidate,feature):
        code=bytearray(data);site=candidate['site'];delta=(BASE-(site+4))>>1
        assert -(1<<21)<=delta<(1<<21)
        branch=struct.pack('<HH',0xf000|((delta>>11)&0x7ff),0xf800|(delta&0x7ff))
        code[BASE:BASE+len(candidate['bytes'])]=bytes(candidate['bytes'])
        assert code[site:site+len(candidate['original'])]==bytes(candidate['original'])
        code[site:site+4]=branch
        for at in range(site+4,site+len(candidate['original']),2):code[at:at+2]=b'\xc0\x46'
        self.candidate,self.feature=candidate,feature
        super().__init__(bytes(code),area,state)

    def code(self,c,at,size,user):
        if at==self.area['site']:c.mem_write(FLAGS,bytes([self.feature]))
        if at==self.candidate['site'] or BASE<=at<BASE+len(self.candidate['bytes']):
            self.trace.append(at);return
        super().code(c,at,size,user)


def observations(result):
    return {k:v for k,v in result.items() if k not in ('trace','site','exit')}


@lru_cache(maxsize=2)
def isolated_cpu(data,stub,site,width,patched):
    # Reuse immutable flash mappings, restoring the full CPU context for each
    # case. Checked memory writes below limit side effects to scratch stack.
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB);cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base,size in ((0,0x200000),(0x01ff0000,0x40000),(0x03000000,0x10000)):cpu.mem_map(base,size)
    cpu.mem_write(0,data);cpu.mem_write(BASE,stub)
    result={};allowed=set(range(site,site+width,2))
    def code(c,at,size,_user):
        if at not in allowed and not (patched and BASE<=at<BASE+len(stub)):
            result.update(exit=at,registers=[c.reg_read(getattr(reg,f'UC_ARM_REG_R{i}')) for i in range(13)],
                flags=c.reg_read(reg.UC_ARM_REG_CPSR)&0xf0000000,sp=c.reg_read(reg.UC_ARM_REG_SP));c.emu_stop()
    def write(c,_access,at,size,value,_user):
        assert SP-64<=at and at+size<=SP,('unexpected isolated write',hex(at),size,value)
    cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_WRITE,write)
    return cpu,result,cpu.context_save()


def di_run(data,candidate,di,feature,identifier,density,layers,attr,vflag,patched):
    site=candidate['site']
    cpu,result,initial=isolated_cpu(data,bytes(candidate['bytes']),site,len(candidate['original']),patched)
    cpu.context_restore(initial);result.clear();cpu.mem_write(SP-64,bytes(64))
    cpu.mem_write(FLAGS,bytes([feature]));cpu.reg_write(reg.UC_ARM_REG_SP,SP)
    for i in range(13):cpu.reg_write(getattr(reg,f'UC_ARM_REG_R{i}'),0x11111111*(i+1)&0xffffffff)
    cpu.reg_write(reg.UC_ARM_REG_R7,di['state']);cpu.mem_write(di['state'],b'\0')
    cpu.reg_write(reg.UC_ARM_REG_CPSR,0x20|vflag)
    block=SP+di['stack_block'];offset=di['identifier_offset']
    cpu.mem_write(block+offset-4,b'BD');cpu.mem_write(block+offset,bytes([ord(identifier),attr<<4,layers<<4,density]))
    cpu.emu_start((BASE if patched else site)|1,0x200000,count=256)
    assert result and result['sp']==SP,result
    return dict(result)


def key_run(data,candidate,feature,key_class,patched):
    site=candidate['site']
    cpu,result,initial=isolated_cpu(data,bytes(candidate['bytes']),site,4,patched)
    cpu.context_restore(initial);result.clear();cpu.mem_write(SP-64,bytes(64));cpu.mem_write(FLAGS,bytes([feature]))
    for i in range(13):cpu.reg_write(getattr(reg,f'UC_ARM_REG_R{i}'),0x12340000+i)
    cpu.reg_write(reg.UC_ARM_REG_R0,key_class);cpu.reg_write(reg.UC_ARM_REG_SP,SP)
    cpu.emu_start((BASE if patched else site)|1,0x200000,count=128)
    assert result and result['sp']==SP,result
    return dict(result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--candidates',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True);p.add_argument('--output',type=Path)
    args=p.parse_args();scans={r['sha256']:r for r in json.loads(args.scan.read_text())['images']}
    cases=0;tested=[]
    roles={'G02':'ControlBit','G03':'ControlField','G04':'ForwardCalculation','G06':'ParameterNibble'}
    for row in json.loads(args.candidates.read_text()):
        assert 'error' not in row['plan'],row
        source=scans[row['sha256']];data=(args.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        for candidate in row['plan']['candidates']:
            gap=candidate['gap']
            if gap=='G07':
                for feature in (0,1,255):
                    for key_class in range(256):
                        before=key_run(data,candidate,feature,key_class,False)
                        after=key_run(data,candidate,feature,key_class,True)
                        if feature==1 and key_class==3:
                            assert after['exit']==candidate['site']+4 and after['registers']==before['registers'],after
                        else:assert before==after,(feature,key_class,before,after)
                        cases+=1
                tested.append((row['sha256'][:12],gap));continue
            if gap=='G01':
                di=row['di_contract'];assert di is not None
                layer_hook=candidate['site']==di['layers']
                for feature in (0,1,255):
                    for identity in ('U','O','W','R','?'):
                        for density in (1,5,6):
                            for layers in (1,2,3,4):
                                for attr in (0,1,2,3):
                                    for v in (0,0x10000000):
                                        before=di_run(data,candidate,di,feature,identity,density,layers,attr,v,False)
                                        after=di_run(data,candidate,di,feature,identity,density,layers,attr,v,True)
                                        if feature==1 and identity=='U' and density==5 and layers in (2,3) and attr in (0,3):
                                            assert after['exit']==di['layer_store' if layer_hook else 'format'],after
                                            if layer_hook:assert after['registers'][0]=={2:0xc7,3:0xc8}[layers],after
                                        else:assert before==after,(feature,identity,density,layers,attr,v,before,after)
                                        cases+=1
                tested.append((row['sha256'][:12],gap));continue
            if gap not in roles:continue
            area=next(r for r in source['uhd_code']['areas'] if r['role']==roles[gap])
            original=consumers.Runner(data,area,source['uhd_code']['state_cell'])
            for feature in (0,1,255):
                modified=Patched(data,area,source['uhd_code']['state_cell'],candidate,feature)
                for state in consumers.STATES:
                    for flag in (0,32):
                        for word in (0,0xa5a5a5a5):
                            for index in (range(13) if gap=='G06' else (0,)):
                                before=original.run(state,word,flag,index);after=modified.run(state,word,flag,index)
                                if feature!=1 or state!=0xc7:
                                    assert observations(before)==observations(after),(row['sha256'],gap,feature,state,before,after)
                                elif gap=='G02':assert after['value']==word|0x80000000,after
                                elif gap=='G03':assert after['value']==word&~0xf0,after
                                elif gap=='G04':assert after['status']=='worker_call' and after['arguments']==[0x1234,10],after
                                elif gap=='G06':
                                    if flag:assert after['value']==(word&~15)|2,after
                                    else:assert observations(before)==observations(after),(before,after)
                                cases+=1
            tested.append((row['sha256'][:12],gap))
    if args.output:
        args.output.write_text(json.dumps({'scope':__doc__,'cpu':'ARM926','cases':cases,
            'candidate_input_sha256':hashlib.sha256(args.candidates.read_bytes()).hexdigest(),
            'scan_input_sha256':hashlib.sha256(args.scan.read_bytes()).hexdigest(),
            'tested':tested,'result':'pass'},indent=2)+'\n')
    print(f'PASS: {cases} ARM926 selector cases, {len(tested)} candidates; OEM/Off and other-state preservation checked')


if __name__=='__main__':main()
