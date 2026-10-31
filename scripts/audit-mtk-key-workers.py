"""Execute the source-bound REPORT KEY worker's format/mode dispatch stage.

The registered wrapper's class-2 worker is taken from the prior routing receipt.
For the extended layout execution starts after its setup call with explicit mode
inputs; that call and its arguments are recorded, never simulated as successful.
The test stops at the next call or native return. No crypto, physical media,
certificate exchange or device initialization is treated as successful.
Certificate sizing enters after assumed successful AGID/session validation and
stops at the response-length store. It produces no certificate/nonce contents.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

DONE = 0x0300f000
FORMATS = (0, 1, 2, 4, 0x20, 0x21, 0x38, 0x39, 0x3f)


def half(data, at):
    return struct.unpack_from('<H', data, at)[0]


def literal(data, at, register):
    op = half(data, at)
    assert op & 0xff00 == 0x4800 | register << 8, (at, register)
    return struct.unpack_from('<I', data, ((at+4)&~3)+(op&255)*4)[0]


def bind(data, entry, cdb):
    assert [half(data, entry+i) for i in (2, 4, 6)] == [0x2000, 0xb510, 0x8008]
    response_length = literal(data, entry, 1)
    setup = None
    io = entry+8
    if half(data, entry+8) == 0x2101 and half(data, entry+10) == 0x2003:
        ins = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[entry+12:entry+16], entry+12))
        assert ins.mnemonic == 'bl'
        setup = {'site':entry+12,'target':int(ins.op_str.removeprefix('#'),0),'arguments':[3,1]}
        io = entry+16
    assert [half(data,io+i) for i in (0,2,4,6,8,10)] == [0x2201,0x0692,0x6810,0x2110,0x4388,0x6010]
    if half(data, io+12) & 0xff00 == 0x4900:
        mode = literal(data, io+12, 1)
        assert literal(data, io+16, 2) == cdb
        expected = {14:0x7808,18:0x2801,22:0x79d0,24:0x2803,
                    28:0x7808,30:0x2800,34:0x79d0,36:0x2802}
        assert all(half(data, io+k)==v for k,v in expected.items())
        assert 0x01ff0000 <= mode < 0x02010000
        return {'variant':'mode_and_class_dispatch', 'start':io if setup else entry, 'mode_cell':mode,
            'excluded_setup_call':setup,
            'response_length_cell':response_length}
    assert literal(data, io+12, 0)==cdb
    return {'variant':'single_mode_dispatch', 'start':io if setup else entry,'mode_cell':None,'excluded_setup_call':setup,
        'response_length_cell':response_length}


def execute(data, entry, binding, cdb, sense, key_class, mode, fmt):
    c = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for at,size in ((0,0x200000),(0x01ff0000,0x40000),(0x03000000,0x10000),(0x04000000,0x10000)):
        c.mem_map(at,size)
    c.mem_write(0,data)
    packet=bytearray(12); packet[0]=0xa4;packet[7]=key_class;packet[10]=fmt;packet[8:10]=b'\x04\x00'
    c.mem_write(cdb,bytes(packet))
    if binding['mode_cell'] is not None:c.mem_write(binding['mode_cell'],bytes([mode]))
    c.reg_write(reg.UC_ARM_REG_SP,0x03008000)
    c.reg_write(reg.UC_ARM_REG_LR,DONE|1)
    if binding['start']!=entry:
        c.mem_write(0x03008000,struct.pack('<II',0,DONE|1))
    result={'status':'instruction_limit','writes':[]}
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)

    def code(cpu,at,size,_user):
        if at==DONE:
            result['status']='native_return'
            cpu.emu_stop();return
        op=int.from_bytes(cpu.mem_read(at,2),'little')
        if op&0xf800==0xf000:
            ins=next(decoder.disasm(bytes(cpu.mem_read(at,4)),at,count=1))
            if ins.mnemonic in ('bl','blx'):
                target=int(ins.op_str.removeprefix('#'),0)
                result.update(status='sense_call' if target==sense else 'worker_call',site=at,target=target,
                    arguments=[cpu.reg_read(getattr(reg,f'UC_ARM_REG_R{i}')) for i in range(3)])
                cpu.emu_stop()

    def write(cpu,_access,at,size,value,_user):
        if 0x01ff0000<=at<0x02030000:
            result['writes'].append({'site':cpu.reg_read(reg.UC_ARM_REG_PC),'address':at,'size':size,'value':value})

    c.hook_add(UC_HOOK_CODE,code);c.hook_add(UC_HOOK_MEM_WRITE,write)
    c.emu_start(binding['start']|1,DONE+4,count=256)
    assert result['status']!='instruction_limit',(entry,key_class,mode,fmt,result)
    return result


def certificate_allocation(data, entry, binding, cdb, mode, allocation):
    # Enter only after the native AGID/session-state validation. The incoming
    # CDB base is independently bound to this format-1 worker's first literal.
    candidates=[]
    for at in range(entry,entry+256,2):
        if (half(data,at)&0xff00==0x4f00 and
            [half(data,at+i) for i in (2,4,6,12,14,16,18)] ==
                [0x7839,0x2901,0x7a21,0x7a62,0x0209,0x1889,0x29b4] and
                half(data,at+10)&0xff00==0xd100):
            assert literal(data,entry+2,4)==cdb
            mode_cell=literal(data,at,7)
            assert mode_cell==binding['mode_cell']
            assert literal(data,at+8,0)==binding['response_length_cell']
            candidates.append((at,'mode_selected_116_or_180',mode_cell))
        for base in (4,6):
            if [half(data,at+i) for i in (0,2,4,6,8)] == [0x7a00|(base<<3),0x7a41|(base<<3),0x0200,0x1840,0x2874]:
                assert literal(data,entry+2,base)==cdb
                assert binding['mode_cell'] is None
                candidates.append((at,'fixed_116',None))
    assert len(candidates)==1,(entry,candidates)
    start,variant,mode_cell=candidates[0]
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    cpu.mem_map(0,0x200000);cpu.mem_map(0x01ff0000,0x40000)
    cpu.mem_write(0,data)
    packet=bytearray(12);packet[0]=0xa4;packet[7]=3 if mode else 2;packet[10]=1
    packet[8:10]=allocation.to_bytes(2,'big')
    cpu.mem_write(cdb,bytes(packet))
    if mode_cell is not None:cpu.mem_write(mode_cell,bytes([mode]))
    for r in (4,6):cpu.reg_write(getattr(reg,f'UC_ARM_REG_R{r}'),cdb)
    result={'status':'instruction_limit','variant':variant,'start':start}

    def write(c,_access,at,size,value,_user):
        assert at==binding['response_length_cell'] and size==2,(at,size)
        result.update(status='response_length_assigned',value=value,site=c.reg_read(reg.UC_ARM_REG_PC))
        c.emu_stop()

    cpu.hook_add(UC_HOOK_MEM_WRITE,write)
    cpu.emu_start(start|1,0x200000,count=128)
    assert result['status']=='response_length_assigned',result
    cap=180 if mode_cell is not None and mode==1 else 116
    assert result['value']==min(allocation,cap),result
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True)
    p.add_argument('--routing',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    routes={r['sha256']:r for r in json.loads(a.routing.read_text())['images']}
    rows=[]
    for source in json.loads(a.scan.read_text())['images']:
        data=(a.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==source['sha256'] and len(data)==2097152
        route=next(c['classes']['2'] for c in routes[source['sha256']]['cases'] if c['opcode']==0xa4 and c['key_format']==0x38 and c['media_state']==0xc7)
        entry,cdb=route['target'],route['CDB']
        binding=bind(data,entry,cdb)
        cases=[]
        for mode in (0,1):
            for key_class in (2,3):
                for fmt in FORMATS:
                    result=execute(data,entry,binding,cdb,source['uhd_code']['sense_setter'],key_class,mode,fmt)
                    cases.append({'mode':mode,'key_class':key_class,'format':fmt,**result})
        format39=next(c for c in cases if c['mode']==1 and c['key_class']==3 and c['format']==0x39)
        invalid=next(c for c in cases if c['mode']==1 and c['key_class']==3 and c['format']==4)
        if binding['mode_cell'] is None:
            assert format39['status']==invalid['status']=='native_return'
            assert format39['writes']==invalid['writes']
            assert format39['writes'][-1]['size']==1 and format39['writes'][-1]['value']==1
        else:
            assert format39['status']=='worker_call' and invalid['status']=='native_return'
        certificate_entry=next(c['target'] for c in cases if c['mode']==0 and c['key_class']==2 and c['format']==1)
        certificate_cases=[]
        for mode in (0,1):
            for allocation in (0,1,115,116,117,179,180,181,1024):
                certificate_cases.append({'mode':mode,'allocation':allocation,
                    **certificate_allocation(data,certificate_entry,binding,cdb,mode,allocation)})
        rows.append({'sha256':source['sha256'],'entry':entry,**binding,'cases':cases,
            'certificate_entry':certificate_entry,'certificate_allocation_cases':certificate_cases})
    a.output.write_text('{"scope":'+json.dumps(__doc__)+',"images":[\n'+',\n'.join(json.dumps(r,separators=(',',':')) for r in rows)+'\n]}\n')
    print(f'PASS: {len(rows)*len(FORMATS)*4} REPORT KEY dispatch and {len(rows)*18} certificate-allocation executions across {len(rows)} payloads')


if __name__=='__main__':main()
