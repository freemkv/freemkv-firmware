"""Compare native REPORT/SEND KEY class routing against OEM UHD references.

Native registered handlers execute on ARM926 until their first key-worker call.
Only a positively matched MOV r0,1 / call / CMP r0,0 guard is supplied success;
the guard is recorded. No optical acquisition, crypto worker or host exchange
is simulated as successful. Class-3 routing parity is one requirement, not proof
of complete OEM UHD operation.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

DONE = 0x0300f000


def run(data, entry, state_cell, sense_setter, opcode, key_class, key_format, state):
    # The native wrapper's first literal defines its registered CDB buffer.
    push, load = struct.unpack_from('<HH', data, entry)
    if push != 0xb510 or load & 0xff00 != 0x4c00:
        return {'status':'unhandled_wrapper', 'entry':entry}
    pool = ((entry+6)&~3)+(load&255)*4
    cdb = struct.unpack_from('<I',data,pool)[0]
    if not 0x02000000 <= cdb < 0x02020000:
        return {'status':'unhandled_CDB_binding','entry':entry,'CDB':cdb}
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    cpu.mem_map(0, (len(data)+4095)&~4095)
    cpu.mem_map(0x01ff0000,0x40000)
    cpu.mem_map(0x03000000,0x10000)
    cpu.mem_write(0,data)
    packet = bytearray(12)
    packet[0],packet[7],packet[10]=opcode,key_class,key_format
    packet[8:10]=b'\x04\x00'
    cpu.mem_write(cdb,bytes(packet))
    cpu.mem_write(state_cell,bytes([state]))
    cpu.reg_write(reg.UC_ARM_REG_SP,0x03008000)
    cpu.reg_write(reg.UC_ARM_REG_LR,DONE|1)
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    result={'status':'unresolved','CDB':cdb,'guard_calls':[]}

    def literal(at, register):
        op=int.from_bytes(data[at:at+2],'little')
        if op&0xff00 != 0x4800|(register<<8):
            return None
        pool=((at+4)&~3)+(op&255)*4
        return int.from_bytes(data[pool:pool+4],'little')

    def legacy_refusal_worker(at):
        expected={0:0xb5f8,4:0x2000,6:0x8008,0x2e:0x7800,0x30:0x0980,
            0x32:0x2801,0x36:0x2202,0x38:0x2130,0x3a:0x2005}
        return (all(int.from_bytes(data[at+i:at+i+2],'little')==op for i,op in expected.items())
            and literal(at+8,6)==cdb and literal(at+0x2c,0)==state_cell)

    def code(c,at,size,_user):
        if at==DONE:
            result.update(status='native_return',returned=c.reg_read(reg.UC_ARM_REG_R0))
            c.emu_stop()
            return
        ins=next(decoder.disasm(bytes(c.mem_read(at,size)),at,count=1))
        if ins.mnemonic in ('bl','blx'):
            target=int(ins.op_str.removeprefix('#'),0)
            if result.get('legacy_worker') is not None:
                result.update(status='worker_refusal',target=result['legacy_worker'],
                    refusal_call=target,refusal_args=[c.reg_read(getattr(reg,f'UC_ARM_REG_R{i}')) for i in range(3)],
                    matches_sense_setter=target==sense_setter)
                assert result['matches_sense_setter'] and result['refusal_args']==[5,0x30,2], result
                c.emu_stop()
                return
            previous=int.from_bytes(data[at-2:at],'little')
            after=int.from_bytes(data[at+size:at+size+2],'little')
            branch=int.from_bytes(data[at+size+2:at+size+4],'little')
            if previous==0x2001 and after==0x2800 and branch&0xff00==0xd000:
                result['guard_calls'].append({'site':at,'target':target,'supplied_return':1})
                c.reg_write(reg.UC_ARM_REG_R0,1)
                c.reg_write(reg.UC_ARM_REG_LR,(at+size)|1)
                c.reg_write(reg.UC_ARM_REG_PC,(at+size)|1)
            else:
                if opcode==0xa4 and legacy_refusal_worker(target):
                    result.update(legacy_worker=target,call_site=at)
                else:
                    result.update(status='worker_call',call_site=at,target=target)
                    c.emu_stop()

    cpu.hook_add(UC_HOOK_CODE,code)
    cpu.emu_start(entry|1,DONE,count=1000)
    assert result['status']!='unresolved',(entry,opcode,key_class,key_format,state)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--hoard',type=Path,default=Path('.'),help='Root for relative source paths')
    args=p.parse_args()
    rows=[]
    for row in json.loads(args.scan.read_text())['images']:
        data=(args.hoard / row['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        code=row['uhd_code']
        cases=[]
        for opcode in (0xa4,0xa3):
            records=[r for r in code.get('native_commands') or [] if r['opcode']==opcode and r['handler']&1]
            if len(records)!=1:
                cases.append({'opcode':opcode,'status':'unresolved_registered_handler','matches':len(records)})
                continue
            entry=records[0]['handler']&~1
            for key_format in (0,1,2,0x38,0x3f):
                for state in (0xc0,0xc7,0xc8):
                    results={str(k):run(data,entry,code['state_cell'],code['sense_setter'],opcode,k,key_format,state) for k in (2,3)}
                    targets=[results[str(k)].get('target') for k in (2,3)]
                    cases.append({'opcode':opcode,'key_format':key_format,'media_state':state,'classes':results,
                        'same_worker':targets[0] is not None and targets[0]==targets[1]})
        comparable=[c for c in cases if 'same_worker' in c]
        rows.append({'sha256':row['sha256'],'model':row['model'],
            'identity':(row.get('provenance') or {}).get('identity'),'cases':cases,
            'same_class2_class3_workers':sum(c['same_worker'] for c in comparable),
            'compared_cases':len(comparable)})
    args.output.write_text(json.dumps({'scope':__doc__,'images':rows},indent=2)+'\n')
    print(f'PASS: native key routing audited for {len(rows)} images')


if __name__=='__main__':
    main()
