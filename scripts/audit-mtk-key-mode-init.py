"""Trace the native key-mode selector bound to the extended REPORT KEY worker.

Execution starts with a supplied, already-read header word. Media acquisition,
header reads, session preparation and any recorded auxiliary call are excluded.
Only the matched selector and its bound zero-store branch execute. This proves
conditional mode assignment, not successful initialization or device provisioning.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg


def half(data, at):return struct.unpack_from('<H', data, at)[0]


def literal(data, at, register):
    h=half(data,at)
    if h&0xff00 != 0x4800|register<<8:return None
    pool=((at+4)&~3)+(h&255)*4
    return struct.unpack_from('<I',data,pool)[0] if pool+4<=len(data) else None


def conditional(data,at,condition):
    h=half(data,at)
    assert h&0xff00==condition
    off=h&255
    return at+4+(off if off<128 else off-256)*2


def locate(data, mode):
    found=[]
    for at in range(0,len(data)-64,2):
        if half(data,at)&0xff00!=0x4d00 or half(data,at+2)!=0x60a8:continue
        if literal(data,at,5)!=mode-1:continue
        pc=at+4
        clear_first=half(data,pc)==0x2000 and half(data,pc+2)==0x7068
        if clear_first:pc+=4
        if half(data,pc)!=0x68a8 or literal(data,pc+2,1)!=0x10030000:continue
        if half(data,pc+4)!=0x0400 or half(data,pc+6)!=0x4288:continue
        if half(data,pc+8)&0xff00!=0xd100:continue
        reject=conditional(data,pc+8,0xd100);pc+=10
        excluded=[]
        if half(data,pc)==0x68a9 and half(data,pc+2)&0xff00==0x4800:
            ins=next(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(data[pc+4:pc+8],pc+4),None)
            if ins is None or ins.mnemonic!='bl':continue
            excluded.append({'site':pc+4,'target':int(ins.op_str.removeprefix('#'),0),
                'argument0_literal':literal(data,pc+2,0),'supplied_result':'not consumed before native header reload'})
            pc+=8
        if [half(data,pc+i) for i in (0,2,4,8,10)] != [0x68a8,0x0200,0x0f00,0x2001,0x7068]:continue
        if half(data,pc+6)&0xff00!=0xd000:continue
        zero=conditional(data,pc+6,0xd000)
        if clear_first:
            if zero!=reject:continue
        elif not (pc<zero<pc+256 and zero+4<=len(data) and
                  [half(data,zero),half(data,zero+2)]==[0x2000,0x7068]):continue
        found.append({'entry':at,'end':pc+12,'zero_branch':zero,'invalid_header_exit':reject,
            'variant':'header_nibble','invalid_header_policy':'clear_first' if clear_first else 'preserve_supplied',
            'clears_mode_before_validation':clear_first,'excluded_auxiliary_calls':excluded})
    # Older implementations compare two specific type words after dropping the
    # high byte. They keep the header on the stack and carry the struct base in
    # R5 across the preceding header-read call, rather than reloading it here.
    for at in range(64,len(data)-24,2):
        if literal(data,at,1)!=0x14100300 or literal(data,at+10,1)!=0x15100300:continue
        if [half(data,at+i) for i in (2,4,6,12,16,18)] != [0x9000,0x0200,0x4288,0x4288,0x2001,0x7068]:continue
        if half(data,at+8)&0xff00!=0xd000 or half(data,at+14)&0xff00!=0xd100:continue
        if conditional(data,at+8,0xd000)!=at+16:continue
        zero=conditional(data,at+14,0xd100)
        if not (at+20<=zero<at+256 and [half(data,zero),half(data,zero+2)]==[0x2000,0x7068]):continue
        roots=[p for p in range(at-64,at,2) if literal(data,p,5)==mode-1]
        if len(roots)!=1:continue
        found.append({'entry':at,'end':at+20,'zero_branch':zero,'invalid_header_exit':zero,
            'variant':'exact_header_types','accepted_low24_types':[0x141003,0x151003],
            'invalid_header_policy':'clear_on_other_type','mode_base_literal_site':roots[0],
            'initial_registers':{'5':mode-1},'clears_mode_before_validation':False,'excluded_auxiliary_calls':[]})
    return found


def execute(data,binding,mode,word,initial):
    c=Uc(UC_ARCH_ARM,UC_MODE_THUMB);c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    c.mem_map(0,0x200000);c.mem_map(0x01ff0000,0x40000);c.mem_map(0x03000000,0x10000)
    c.mem_write(0,data);c.mem_write(mode,bytes([initial]));c.reg_write(reg.UC_ARM_REG_R0,word)
    c.reg_write(reg.UC_ARM_REG_SP,0x03008000)
    for register,value in binding.get('initial_registers',{}).items():
        c.reg_write(getattr(reg,f'UC_ARM_REG_R{register}'),value)
    result={'status':'instruction_limit','mode_writes':[]}
    excluded={x['site'] for x in binding['excluded_auxiliary_calls']}

    def code(cpu,at,size,_user):
        if at in excluded:
            cpu.reg_write(reg.UC_ARM_REG_LR,(at+4)|1);cpu.reg_write(reg.UC_ARM_REG_PC,(at+4)|1)
            return
        in_main=binding['entry']<=at<binding['end']
        in_zero=not binding['clears_mode_before_validation'] and binding['zero_branch']<=at<binding['zero_branch']+4
        if not in_main and not in_zero:
            result.update(status='selector_exit',exit=at);cpu.emu_stop()

    def write(cpu,_access,at,size,value,_user):
        if at==mode:
            assert size==1
            result['mode_writes'].append({'site':cpu.reg_read(reg.UC_ARM_REG_PC),'value':value})

    c.hook_add(UC_HOOK_CODE,code);c.hook_add(UC_HOOK_MEM_WRITE,write)
    c.emu_start(binding['entry']|1,0x200000,count=100)
    assert result['status']=='selector_exit',result
    final=c.mem_read(mode,1)[0]
    if binding['variant']=='exact_header_types':
        expected=int(word&0xffffff in binding['accepted_low24_types'])
    else:
        expected=int(bool((word>>20)&15)) if word&0xffff==0x1003 else (0 if binding['clears_mode_before_validation'] else initial)
    assert final==expected,(word,initial,result,final,expected)
    result['mode']=final
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--workers',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sources={r['sha256']:r for r in json.loads(a.scan.read_text())['images']}
    rows=[];total=0;bound=0
    words=[(n<<20)|0x1003 for n in range(16)]+[0x00031003,0x48141003,0x48151003,0x00031002,0x48141002,0,
        0x00141003,0x00151003,0xff141003,0xff151003,0x48161003,0x48041003]
    for worker in json.loads(a.workers.read_text())['images']:
        mode=worker['mode_cell']
        if mode is None:
            rows.append({'sha256':worker['sha256'],'status':'no_extended_worker_binding','cases':[]});continue
        source=sources[worker['sha256']];data=(a.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==worker['sha256']
        matches=locate(data,mode)
        if len(matches)!=1:
            rows.append({'sha256':worker['sha256'],'status':'unresolved_selector_layout','matches':len(matches),'cases':[]});continue
        binding=matches[0];cases=[];bound+=1
        for word in words:
            for initial in (0,1,255):
                cases.append({'header_word':word,'initial_mode':initial,**execute(data,binding,mode,word,initial)});total+=1
        rows.append({'sha256':worker['sha256'],'status':'bound_header_selector','mode_cell':mode,**binding,'cases':cases})
    a.output.write_text('{"scope":'+json.dumps(__doc__)+',"executions":'+str(total)+',"images":[\n'+',\n'.join(json.dumps(r,separators=(',',':')) for r in rows)+'\n]}\n')
    print(f'PASS: {total} header-selector cases; {bound} bound of {sum(w["status"]!="no_extended_worker_binding" for w in rows)} extended-worker images. Unmatched selectors remain unresolved.')


if __name__=='__main__':main()
