"""Execute the missing legacy G03 owner through both stores against native owners.

Bounded passive-MMIO regression, not optical/controller qualification. References
are hash-bound test evidence; production patch selection remains structural.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import __version__ as unicorn_version
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as r

BANK = 0x04200000
TARGET = BANK + 0x8270
FLAGS = 0x02000e43
SP = 0x0200e000
REGS = [getattr(r, f'UC_ARM_REG_R{i}') for i in range(13)]
OWNERS = {'c88a6901': (0x3392c, 0x33ba0), '1bbeb535': (0x3535a, 0x355ee),
          '5c01c1fd': (0x35336, 0x355ca)}
SOURCE_HASHES = {'c88a6901': 'c88a69013d557b9c4cf1a4d603c314585f51a258b9747c345184e866eef36306', '1bbeb535': '1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396', '5c01c1fd': '5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95'}
WORDS = (0, 0xffffffff, 0xa5a5a5a5, 0x400, 0xf0)
STATES = (0, 0x40, 0x80, 0xc0, 0xc4, 0xc7, 0xc8, 0xcc)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def install(data, candidates):
    image = bytearray(data)
    for index, candidate in enumerate(candidates):
        site = candidate['site']; original = bytes(candidate['original'])
        assert image[site:site+len(original)] == original, ('source mismatch', site)
        dest = 0x1e0000 + index*0x1000
        stub = bytes(candidate['bytes']); assert len(stub) <= 0x1000
        # Isolated private CPU scratch: not an installer/free-space qualification.
        delta = (dest-site-4)//2
        image[dest:dest+len(stub)] = stub
        image[site:site+4] = struct.pack('<HH', 0xf000|((delta>>11)&0x7ff), 0xf800|(delta&0x7ff))
        image[site+4:site+len(original)] = b'\xc0\x46'*((len(original)-4)//2)
    return bytes(image)

def execute(data, row, start, stop, state, feature, caller, word):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB); cpu.ctl_set_cpu_model(r.UC_CPU_ARM_926)
    for address, size in ((0,0x300000),(0x01ff0000,0x20000),(BANK,0x10000),(0x04000000,0x1000)):
        cpu.mem_map(address,size)
    cpu.mem_write(0,data); cpu.mem_write(row['uhd_code']['state_cell'],bytes([state]))
    cpu.mem_write(FLAGS,bytes([feature])); cpu.mem_write(TARGET,struct.pack('<I',word))
    cpu.reg_write(r.UC_ARM_REG_R0,caller); cpu.reg_write(r.UC_ARM_REG_R1,0x0200d000)
    cpu.reg_write(r.UC_ARM_REG_R3,BANK+0x8c00); cpu.reg_write(r.UC_ARM_REG_SP,SP)
    writes=[]; trace=[]; reached=False
    def step(c,at,size,_):
        nonlocal reached
        if at==stop:
            reached=True; c.emu_stop(); return
        trace.append(at)
    def write(c,access,at,size,value,_):
        assert (BANK<=at and at+size<=BANK+0x10000) or (SP-256<=at and at+size<=SP) or at in (0x02000b6c,0x02000b74) or (at==0x04000004 and size==4), ('undeclared write',hex(at),size)
        writes.append((at,size,value))
    cpu.hook_add(UC_HOOK_CODE,step); cpu.hook_add(UC_HOOK_MEM_WRITE,write)
    try:
        cpu.emu_start(start|1,0x300000,count=3000)
    except UcError as error:
        raise UcError(error.errno) from RuntimeError(('trace tail', [hex(x) for x in trace[-12:]]))
    assert reached, ('owner did not reach continuation',hex(cpu.reg_read(r.UC_ARM_REG_PC)))
    return {'registers':[cpu.reg_read(x) for x in REGS], 'sp':cpu.reg_read(r.UC_ARM_REG_SP),
            'live_stack':bytes(cpu.mem_read(SP-20,20)).hex(),
            'nzcv':cpu.reg_read(r.UC_ARM_REG_CPSR)&0xf0000000,'writes':writes,
            'mmio':[(a,s,v) for a,s,v in writes if BANK<=a<BANK+0x10000 or a==0x04000004],
            'target':int.from_bytes(cpu.mem_read(TARGET,4),'little'),'trace':trace}

def stable(result):
    observed = {k:v for k,v in result.items() if k not in ('trace','writes')}
    observed['writes'] = [(a,s,v) for a,s,v in result['writes'] if not SP-256<=a<SP-20]
    return observed

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('scan','plans','hoard','output'): parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(); rows=json.loads(args.scan.read_text())['images']; plans=json.loads(args.plans.read_text())
    selected={prefix:next(x for x in rows if x['sha256']==SOURCE_HASHES[prefix]) for prefix in OWNERS}
    data={prefix:(args.hoard/row['path']).read_bytes() for prefix,row in selected.items()}
    for prefix,row in selected.items(): assert sha(data[prefix])==row['sha256']
    old='c88a6901'; plan=next(x for x in plans if x['sha256']==selected[old]['sha256'])
    candidates=[c for c in plan['plan']['candidates'] if c['gap']=='G03']
    assert len(candidates)==2, ('two source-bound G03 helpers required',len(candidates))
    image=install(data[old],candidates); count=0
    for feature in (0,1,2,255):
        for state in STATES:
            for caller in (0,1):
                for word in WORDS:
                    actual=execute(image,selected[old],*OWNERS[old],state,feature,caller,word)
                    if feature!=1 or state!=0xc7 or caller!=0:
                        native=execute(data[old],selected[old],*OWNERS[old],state,feature,caller,word)
                        assert stable(actual)==stable(native), ('preservation',feature,state,caller,word)
                    else:
                        assert actual['target']&0x4f0==0, ('G03 field/bit10',caller,hex(word),hex(actual['target']))
                        for prefix in ('1bbeb535','5c01c1fd'):
                            native=execute(data[prefix],selected[prefix],*OWNERS[prefix],state,feature,caller,word)
                            assert actual['mmio']==native['mmio'], ('native MMIO parity',prefix,caller,hex(word),actual['mmio'],native['mmio'])
                        assert all(any(0x1e0000+i*0x1000<=at<0x1e0000+(i+1)*0x1000 for at in actual['trace']) for i in range(2)), 'both helpers must execute'
                    count+=1
    killed=[]
    for removed in range(2):
        mutant=install(data[old],[c for i,c in enumerate(candidates) if i!=removed])
        observed=execute(mutant,selected[old],*OWNERS[old],0xc7,1,0,0xffffffff)
        assert observed['target']&0x4f0!=0, ('surviving removed-helper mutant',removed)
        killed.append({'mutation':'remove-helper','site':candidates[removed]['site'],'observed_mask':observed['target']&0x4f0})
    wrong_admission = json.loads(json.dumps(candidates))
    mutations = 0
    for candidate in wrong_admission:
        stub = bytes(candidate['bytes'])
        mutations += stub.count(bytes.fromhex('c72b'))
        candidate['bytes'] = list(stub.replace(bytes.fromhex('c72b'), bytes.fromhex('c62b')))
    assert mutations, 'no C7 admission comparator bound for negative control'
    observed = execute(install(data[old],wrong_admission),selected[old],*OWNERS[old],0xc7,1,0,0xffffffff)
    assert observed['target']&0x4f0!=0, 'wrong C7 admission mutant survived'
    killed.append({'mutation':'C7 comparator changed to C6','comparators':mutations,'observed_mask':observed['target']&0x4f0})
    # Thumb2 negative control uses the same CPU model as the contract.
    bad=bytearray(data[old]); bad[OWNERS[old][0]:OWNERS[old][0]+4]=bytes.fromhex('40f20100')
    try: execute(bytes(bad),selected[old],*OWNERS[old],0xc7,1,0,0xffffffff)
    except UcError: killed.append({'mutation':'Thumb2 MOVW','result':'ARM926 rejected'})
    else: raise AssertionError('Thumb2 negative control survived')
    receipt={'scope':__doc__,'result':'pass','cpu':'ARM926','qualified_missing_images':1,
             'native_reference_images':2,'cases':count,'enabled_c7_native_parity_cases':5,
             'preservation_cases':315,'unicorn_version':unicorn_version,'suite_sha256':sha(Path(__file__).read_bytes()),
             'scratch_policy':'Private CPU slots; helper stack writes below SP-20 excluded from persistent-write parity; live owner stack checked',
             'scan_sha256':sha(args.scan.read_bytes()),
             'plans_sha256':sha(args.plans.read_bytes()),'private_patched_sha256':sha(image),
             'sources':{p:row['sha256'] for p,row in selected.items()},
             'helpers':[{'source_sha256':selected[old]['sha256'],'gap':'G03','site':c['site'],'bytes_sha256':sha(bytes(c['bytes'])),'original_sha256':sha(bytes(c['original']))} for c in candidates],
             'kill_controls':killed}
    args.output.write_text(json.dumps(receipt,indent=2)+'\n'); print(f'PASS: {count} downstream cases; 1 missing G03 image, 2 native references; {len(killed)} kill controls')

if __name__=='__main__': main()
