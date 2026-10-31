"""Bind certificate worker calls into the native authentication service.

Read-only code evidence. This follows source-bound direct calls, records packet
and service-selector differences, and executes no crypto or device service.
Absence of a selector in the reviewed prefix is not absence of every backend.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB


def half(d,at):return struct.unpack_from('<H',d,at)[0]


def branch(d,at,mnemonic):
    i=next(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(d[at:at+4],at,count=1),None)
    assert i is not None and i.mnemonic==mnemonic,(at,i)
    return int(i.op_str.removeprefix('#'),0)


def bind(d,worker,extended):
    found=[]
    for at in range(worker,worker+0x180,2):
        if extended and half(d,at)==0x20b3 and half(d,at+2)==0xa901 and half(d,at+4)&0xf800==0xe000:
            site=branch(d,at+4,'b');found.append({'argument_site':at,'call_site':site,
                'service':branch(d,site,'bl'),'operation':0xb3,'packet_stack_offset':4})
        if not extended and half(d,at)==0x2012 and (half(d,at+2)==0x4669 or half(d,at+2)&0xff00==0xa900):
            found.append({'argument_site':at,'call_site':at+4,'service':branch(d,at+4,'bl'),
                'operation':0x12,'packet_stack_offset':0 if half(d,at+2)==0x4669 else (half(d,at+2)&255)*4})
    assert len(found)==1,(worker,found)
    result=found[0];entry=result['service']
    # Both prefixes call the same ARM kernel service with argument C0 before
    # their MMIO setup. Its behavior is outside this read-only survey.
    calls=[]
    for at in range(entry,entry+24,2):
        if half(d,at)==0x20c0:
            calls.append({'site':at+2 if half(d,at+2)&0xf800==0xf000 else at+4,
                'argument0':0xc0})
    assert len(calls)==1,calls
    call=calls[0];call['target']=branch(d,call['site'],'blx')
    result['kernel_service_call']=call
    # Review only the connected immediate-operation dispatch prefix. The
    # extended service has a separate family of B0..C3 selectors; report it.
    selectors=[]
    for at in range(entry,entry+0x110,2):
        if half(d,at)&0xff00!=0x2c00:continue
        value=half(d,at)&255
        if 0xb0<=value<=0xc3:
            op=half(d,at+2)
            if op&0xff00 in (0xd000,0xd100):
                offset=op&255;offset=offset if offset<128 else offset-256
                selectors.append({'site':at,'operation':value,'condition':'eq' if op&0xff00==0xd000 else 'ne',
                    'target':at+6+offset*2})
    result['reviewed_extended_operation_selectors']=selectors
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--workers',type=Path,required=True)
    p.add_argument('--hoard',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sources={r['sha256']:r for r in json.loads(a.scan.read_text())['images']};rows=[]
    for worker in json.loads(a.workers.read_text())['images']:
        source=sources[worker['sha256']];d=(a.hoard/source['path']).read_bytes()
        assert hashlib.sha256(d).hexdigest()==worker['sha256']
        rows.append({'sha256':worker['sha256'],'extended_worker':worker['mode_cell'] is not None,
            **bind(d,worker['certificate_entry'],worker['mode_cell'] is not None)})
    a.output.write_text(json.dumps({'scope':__doc__,'images':rows},indent=2)+'\n')
    print(f'PASS: {len(rows)} source-bound certificate/service call chains; read-only evidence')


if __name__=='__main__':main()
