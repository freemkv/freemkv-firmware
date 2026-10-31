#!/usr/bin/env python3
"""Execute the exact native inner W-family recovery guard, not its callees."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import unicorn
from stages import run

SOURCE='40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a'
EARLIEST='c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    data=a.source.read_bytes();digest=hashlib.sha256(data).hexdigest();assert digest in (SOURCE,EARLIEST)
    early=digest==EARLIEST
    def literal(at):
        h=struct.unpack_from('<H',data,at)[0];assert h&0xf800==0x4800
        return struct.unpack_from('<I',data,((at+4)&~3)+(h&255)*4)[0]
    entry,flag_load,reload,body,bypass=(0x11aa38,0x11aa48,0x11aae0,0x11aa52,0x11ac9a) if early else (0x15304e,0x153062,0x1530f8,0x15306a,0x153146)
    state,flag=literal(entry),literal(flag_load)
    assert literal(reload)==state
    if early:
        assert data[0x11aa3a:0x11aa52]==bytes.fromhex('107800090f2801d1012000e000205c49097808426ed07fe0')
        assert state==0x01ff9def and flag==0x02000c8c
        assert data[0x11ab52:0x11ab58]==bytes.fromhex('b44200d27ce7')
    else:assert data[0x153054:0x15306a]==bytes.fromhex('107800090f2801d1012000e00020ad49097808426dd0')
    active=0;instructions=set();edges=set();trace_path=a.output.with_suffix('.traces.jsonl.gz')
    with gzip.open(trace_path,'wt') as log:
        for value in range(256):
            for context in range(256):
                r=run(data,'MT1959' if early else 'MT1939',entry,{body,bypass},0x0200fe00,
                    registers={0:0x12345678,4:0,6:1},memory=[(state,bytes([value])),(flag,bytes([context]))],allow_stack_delta=32,strict_reads=True)
                expected=body if value>>4==15 and context&1 else bypass
                assert r['target']==expected,(value,context,r['target'])
                active+=int(r['target']==body);instructions.update(r['instructions']);edges.update(r['edges'])
                log.write(json.dumps({'state':value,'flag':context,'target':r['target'],'trace':r['trace'],'cpsr':r['cpsr'],'writes':r['writes']})+'\n')
        if early:
            for value in (0xc7,0xf7):
                for start,end in ((0,1),(0,0),(1,0),(0xffffffff,1)):
                    r=run(data,'MT1959',entry,{body,bypass,0x11ab58},0x0200fe00,
                        registers={4:start,6:end},memory=[(state,bytes([value])),(flag,b'\x01')],strict_reads=True)
                    expected=bypass if value==0xc7 else body if start<end else 0x11ab58
                    assert r['target']==expected
                    instructions.update(r['instructions']);edges.update(r['edges'])
                    log.write(json.dumps({'state':value,'flag':1,'r4':start,'r6':end,'target':r['target'],'trace':r['trace'],'cpsr':r['cpsr'],'writes':r['writes']})+'\n')
    receipt={'schema':'native-inner-w-recovery-guard-v2','status':'passed','source_sha256':digest,
        'cpu':'ARM926','unicorn':unicorn.__version__,'entry':entry,'state_cell':state,'flag_cell':flag,
        'cases':65536,'enter_recovery_loop':active,'bypass_recovery_loop':65536-active,
        'c7_c8_enter_loop':False,'source_same_cell_reload_at':reload,
        'explicit_iteration_bounds':{'r4':0,'r6':1} if early else None,'additional_bounds_cases':8 if early else 0,
        'instructions':sorted(instructions),'edges':sorted(edges),'trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        'suite_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'limits':['Only native inner guard is executed','No calls are replaced or returned as success',
                  'State mutations after this guard, indirect callbacks, full request lifecycle and hardware remain unresolved']}
    a.output.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
