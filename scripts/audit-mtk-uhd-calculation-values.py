"""Run native calculation workers and prepared G04 stubs on ARM926.

Pure numerical-stage evidence. Native division workers execute; no arithmetic
call is replaced with a supplied success/result. Stops before the caller's
input-restoration store and records R6. No optical or authentication proof.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

BASE=0x1e0000
INPUT=0x03002000
SP=0x03008000
FLAG=0x02000e43
VALUES=(0,1,8,9,10,11,19,20,21,99,100,101,32767,32768,50719,50720,50729,50730,50739,50740,65525,65526,65529,65530,65534,65535)


class Calculation:
    def __init__(self,data,area,state,candidate=None):
        self.area,self.state=area,state
        self.cpu=c=Uc(UC_ARCH_ARM,UC_MODE_THUMB);c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for at,size in ((0,0x200000),(0x01ff0000,0x40000),(0x03000000,0x10000)):c.mem_map(at,size)
        code=bytearray(data)
        if candidate:
            site=candidate['site'];assert code[site:site+len(candidate['original'])]==bytes(candidate['original'])
            delta=(BASE-site-4)>>1
            code[site:site+4]=struct.pack('<HH',0xf000|((delta>>11)&0x7ff),0xf800|(delta&0x7ff))
            for at in range(site+4,site+len(candidate['original']),2):code[at:at+2]=b'\xc0\x46'
            code[BASE:BASE+len(candidate['bytes'])]=bytes(candidate['bytes'])
        c.mem_write(0,bytes(code));self.result={};self.count=0
        c.hook_add(UC_HOOK_CODE,self.step);c.hook_add(UC_HOOK_MEM_WRITE,self.write)
        self.initial=c.context_save()

    def step(self,c,at,size,_user):
        self.count+=1
        if c.reg_read(reg.UC_ARM_REG_CPSR)&0x20 and bytes(c.mem_read(at,2))==b'\x20\x80' and c.reg_read(reg.UC_ARM_REG_R4)==INPUT:
            self.result={'value':c.reg_read(reg.UC_ARM_REG_R6),'sp':c.reg_read(reg.UC_ARM_REG_SP),'instructions':self.count,'restoration':at}
            c.emu_stop()

    def write(self,c,_access,at,size,value,_user):
        assert SP-256<=at and at+size<=SP+256,('non-stack write',hex(at),size,value)

    def run(self,value,base,feature,mode_cell=None,mode=0,base5=0):
        c=self.cpu;c.context_restore(self.initial);self.result={};self.count=0
        c.mem_write(0x01ff0000,bytes(0x40000));c.mem_write(SP-256,bytes(512))
        c.mem_write(self.state,b'\xc7');c.mem_write(FLAG,bytes([feature]));c.mem_write(INPUT,value.to_bytes(2,'little'))
        if mode_cell is not None:c.mem_write(mode_cell,bytes([mode]))
        for i in range(13):c.reg_write(getattr(reg,f'UC_ARM_REG_R{i}'),0)
        c.reg_write(reg.UC_ARM_REG_R0,value);c.reg_write(reg.UC_ARM_REG_R4,INPUT)
        c.reg_write(reg.UC_ARM_REG_R5,base5);c.reg_write(reg.UC_ARM_REG_R6,value<<16);c.reg_write(reg.UC_ARM_REG_R7,base)
        c.reg_write(reg.UC_ARM_REG_SP,SP);c.mem_write(SP,struct.pack('<I',value)*64)
        c.emu_start(self.area['site']|1,0x200000,count=2000)
        assert self.result,('numerical stage did not reach restoration',value,base,feature,self.count)
        assert self.result['sp']==SP,self.result
        return self.result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--plans',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--direction',choices=['forward','reverse'],default='forward')
    a=p.parse_args();plans={r['sha256']:r for r in json.loads(a.plans.read_text())};rows=[];count=0
    for source in json.loads(a.scan.read_text())['images']:
        data=(a.hoard/source['path']).read_bytes();assert hashlib.sha256(data).hexdigest()==source['sha256']
        area=next(x for x in source['uhd_code']['areas'] if x['role']==('ForwardCalculation' if a.direction=='forward' else 'ReverseCalculation'))
        candidates=[c for c in plans[source['sha256']]['plan']['candidates'] if c['gap']=='G04'] if a.direction=='forward' else [];assert len(candidates)<=1
        original=Calculation(data,area,source['uhd_code']['state_cell'])
        modified=Calculation(data,area,source['uhd_code']['state_cell'],candidates[0]) if candidates else None
        cases=[]
        mode_cells=[v['value'] for v in area['literals'] if 0x01ff0000<=v['value']<0x02010000 and v['value']!=source['uhd_code']['state_cell']]
        assert len(mode_cells)<=1,mode_cells
        modes=(0,1,255) if a.direction=='reverse' and mode_cells else (0,)
        for value in VALUES:
            for base,base5 in ((0,0),(0x1234,0x4321),(0xffff,0x1234)):
                for mode in modes:
                    cell=mode_cells[0] if a.direction=='reverse' and mode_cells else None
                    native=original.run(value,base,1,cell,mode,base5)
                    actual=modified.run(value,base,1,cell,mode,base5) if modified else native
                    if a.direction=='forward':expected=(base+12*(value//10))&0xffff
                    elif cell is None:expected=value
                    elif mode==0:expected=(base-12*(value//10))&0xffff
                    else:expected=(base5-9*(value//10))&0xffff
                    assert actual['value']==expected,(source['sha256'],value,base,base5,mode,actual,expected)
                    if modified:
                        for feature in (0,255):
                            preserved=modified.run(value,base,feature)
                            assert preserved['value']==native['value'],(source['sha256'],feature,preserved,native)
                            count+=1
                    cases.append({'input':value,'base7':base,'base5':base5,'mode':mode,'expected':expected,'actual':actual['value'],'instructions':actual['instructions']});count+=1
        rows.append({'sha256':source['sha256'],'candidate_applied_in_memory':bool(modified),'mode_cell':mode_cells[0] if a.direction=='reverse' and mode_cells else None,'cases':cases})
    a.output.write_text(json.dumps({'scope':__doc__,'cpu':'ARM926','direction':a.direction,'executions':count,'images':rows},indent=2)+'\n')
    print(f'PASS: {count} native numerical executions across {len(rows)} images; no division-worker substitution')


if __name__=='__main__':main()
