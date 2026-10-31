"""Execute prepared conversion stubs on ARM926. No firmware file is written.

Candidate-only checks do not authorize partial installation or establish optical
readiness, numerical worker correctness, certificates or authentication success.
"""
import subprocess
import tempfile
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


def di_run(data,candidate,di,feature,identifier,density,layers,attr,vflag,patched,initial_state=0):
    site=candidate['site']
    cpu,result,initial=isolated_cpu(data,bytes(candidate['bytes']),site,len(candidate['original']),patched)
    cpu.context_restore(initial);result.clear();cpu.mem_write(SP-64,bytes(64))
    cpu.mem_write(FLAGS,bytes([feature]));cpu.reg_write(reg.UC_ARM_REG_SP,SP)
    for i in range(13):cpu.reg_write(getattr(reg,f'UC_ARM_REG_R{i}'),0x11111111*(i+1)&0xffffffff)
    cpu.reg_write(reg.UC_ARM_REG_R7,di['state']);cpu.mem_write(di['state'],bytes([initial_state]))
    cpu.reg_write(reg.UC_ARM_REG_CPSR,0x20|vflag)
    block=SP+di['stack_block'];offset=di['identifier_offset']
    cpu.mem_write(block+offset-4,b'BD');cpu.mem_write(block+offset,bytes([ord(identifier),attr<<4,layers<<4,density]))
    cpu.emu_start((BASE if patched else site)|1,0x200000,count=256)
    assert result and result['sp']==SP,result
    return dict(result)



NATIVE_DI_SHA='1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396'
DI_STATES=(0,0xc0,0xc4,0xc7,0xc8,0xe0,0xe8,0xf8,0xcc,0xd8)


def native_di_oracle(path):
    """Execute stock raw-buffer parser, not a Python copy of its predicate.

    Hardware acquisition is bypassed and logging stubbed; actual prologue,
    raw-buffer copies, state definitions and ARM switch/normalization execute.
    This oracle covers classification, not readiness or the separate U marker.
    """
    data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==NATIVE_DI_SHA
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB);cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base,size in ((0,0x200000),(0x01ff0000,0x20000),(0x02100000,0x1000)):
        cpu.mem_map(base,size)
    cpu.mem_write(0,data);initial=cpu.context_save();result={};table={}
    def hook(c,at,size,user):
        if at==0xe099a:c.reg_write(reg.UC_ARM_REG_PC,0xe0a31)
        elif at==0xcb1bc:c.reg_write(reg.UC_ARM_REG_PC,c.reg_read(reg.UC_ARM_REG_LR))
        elif at in (0xe0d42,0xe0a00):result['exit']=at;c.emu_stop()
    cpu.hook_add(UC_HOOK_CODE,hook)
    for state in DI_STATES:
        for attr in range(4):
            for layers in (2,3):
                cpu.context_restore(initial);result.clear();cpu.mem_write(0x01ff0000,bytes(0x20000))
                cpu.reg_write(reg.UC_ARM_REG_SP,0x0200e000);cpu.reg_write(reg.UC_ARM_REG_LR,0x1001)
                cpu.mem_write(0x01ff9e04,bytes([state]))
                cpu.mem_write(0x02000c78,struct.pack('<I',0x02100000))
                raw=bytearray(64);raw[8:14]=bytes([66,68,85,attr<<4,layers<<4,5])
                cpu.mem_write(0x02100000,bytes(raw));cpu.emu_start(0xe0971,0,count=10000)
                assert result,(state,attr,layers)
                accepted=result['exit']==0xe0d42
                value=cpu.mem_read(0x01ff9e04,1)[0]
                assert value==({2:0xc7,3:0xc8}[layers] if accepted else 0)
                assert cpu.mem_read(0x02000b19,1)[0]==int(accepted)
                table[state,attr,layers]=accepted
    return table


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
    p.add_argument('--native-di-reference',type=Path,help='stock BU40N1.02 payload with pinned SHA256')
    args=p.parse_args();scans={r['sha256']:r for r in json.loads(args.scan.read_text())['images']}
    reference=args.native_di_reference or next((args.hoard/'originals'/NATIVE_DI_SHA).glob('*.bin'))
    di_oracle=native_di_oracle(reference)
    plans=json.loads(args.candidates.read_text())
    assert len({row['sha256'] for row in plans})==len(plans), 'duplicate plan source'
    assert {row['sha256'] for row in plans}==set(scans), 'scan/plan inventory mismatch'
    plan_hash=hashlib.sha256(args.candidates.read_bytes()).hexdigest()
    scan_hash=hashlib.sha256(args.scan.read_bytes()).hexdigest()
    children={}; delegated={}
    with tempfile.TemporaryDirectory(prefix='freemkv-conversion-cpu-') as temporary:
        for gap,script in (('G03','test-mt1959-control-field-downstream.py'),('G05','test-mt1959-reverse-downstream.py')):
            receipt_path=Path(temporary)/(gap+'.json')
            script_path=Path(__file__).with_name(script)
            subprocess.run([sys.executable,str(script_path),'--scan',str(args.scan),'--plans',str(args.candidates),
                            '--hoard',str(args.hoard),'--output',str(receipt_path)],check=True)
            receipt=json.loads(receipt_path.read_text())
            assert receipt['result']=='pass' and receipt['plans_sha256']==plan_hash and receipt['scan_sha256']==scan_hash
            assert receipt['suite_sha256']==hashlib.sha256(script_path.read_bytes()).hexdigest()
            children[gap]=receipt
            for helper in receipt['helpers']:
                assert helper['gap']==gap, ('unexpected child gap',gap,helper)
                key=(helper['source_sha256'],helper['gap'],helper['site'])
                assert key not in delegated, ('duplicate child helper',key)
                delegated[key]=helper
    cases=0;tested=[];coverage=[];expected=set();child_claims=set();role_cases={}
    def record(row,candidate,kind):
        key=(row['sha256'],candidate['gap'],candidate['site'])
        assert key not in {(x['source_sha256'],x['gap'],x['site']) for x in coverage}, ('duplicate coverage',key)
        coverage.append({'source_sha256':key[0],'gap':key[1],'site':key[2], 'suite':kind,
                         'bytes_sha256':hashlib.sha256(bytes(candidate['bytes'])).hexdigest(),
                         'original_sha256':hashlib.sha256(bytes(candidate['original'])).hexdigest()})

    roles={'G02':'ControlBit','G04':'ForwardCalculation','G06':'ParameterNibble'}
    for row in plans:
        assert 'error' not in row['plan'],row
        source=scans[row['sha256']];data=(args.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        for candidate in row['plan']['candidates']:
            gap=candidate['gap']
            key=(row['sha256'],gap,candidate['site'])
            assert key not in expected, ('duplicate plan helper',key)
            expected.add(key)
            if gap in ('G03','G05'):
                assert key in delegated, ('missing downstream helper coverage',key)
                bound=delegated[key]
                assert bound['bytes_sha256']==hashlib.sha256(bytes(candidate['bytes'])).hexdigest()
                assert bound['original_sha256']==hashlib.sha256(bytes(candidate['original'])).hexdigest()
                child_claims.add(key);record(row,candidate,'downstream-'+gap)
                tested.append((row['sha256'][:12],gap));continue
            before_cases=cases

            if gap=='G07':
                for feature in (0,1,255):
                    for key_class in range(256):
                        before=key_run(data,candidate,feature,key_class,False)
                        after=key_run(data,candidate,feature,key_class,True)
                        if feature==1 and key_class==3:
                            assert after['exit']==candidate['site']+4 and after['registers']==before['registers'],after
                        else:assert before==after,(feature,key_class,before,after)
                        cases+=1
                role_cases[gap]=role_cases.get(gap,0)+cases-before_cases
                record(row,candidate,'isolated-selector')
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
                                        if feature==1 and identity=='U' and density==5 and layers in (2,3) and di_oracle[0,attr,layers]:
                                            assert after['exit']==di['layer_store' if layer_hook else 'format'],after
                                            if layer_hook:assert after['registers'][0]=={2:0xc7,3:0xc8}[layers],after
                                        else:assert before==after,(feature,identity,density,layers,attr,v,before,after)
                                        cases+=1
                # Exercise both detours against actual native parser outcomes
                # for prior states beyond the broad conservation matrix above.
                for state in DI_STATES[1:]:
                    for layers in (2,3):
                        for attr in range(4):
                            for v in (0,0x10000000):
                                before=di_run(data,candidate,di,1,'U',5,layers,attr,v,False,state)
                                after=di_run(data,candidate,di,1,'U',5,layers,attr,v,True,state)
                                if di_oracle[state,attr,layers]:
                                    assert after['exit']==di['layer_store' if layer_hook else 'format'],after
                                    if layer_hook:assert after['registers'][0]=={2:0xc7,3:0xc8}[layers],after
                                else:assert before==after,(state,layers,attr,v,before,after)
                                cases+=1
                role_cases[gap]=role_cases.get(gap,0)+cases-before_cases
                record(row,candidate,'isolated-selector')
                tested.append((row['sha256'][:12],gap));continue
            assert gap in roles, ('unhandled candidate gap',gap,key)
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
                                elif gap=='G04':assert after['status']=='worker_call' and after['arguments']==[0x1234,10],after
                                elif gap=='G06':
                                    if flag:assert after['value']==(word&~15)|2,after
                                    else:assert observations(before)==observations(after),(before,after)
                                cases+=1
            role_cases[gap]=role_cases.get(gap,0)+cases-before_cases
            record(row,candidate,'isolated-selector')
            tested.append((row['sha256'][:12],gap))
    assert child_claims==set(delegated), ('unclaimed child helpers',set(delegated)-child_claims)
    assert len(coverage)==len(expected)
    if args.output:
        args.output.write_text(json.dumps({'scope':__doc__,'cpu':'ARM926','cases':cases,
            'candidate_input_sha256':hashlib.sha256(args.candidates.read_bytes()).hexdigest(),
            'scan_input_sha256':hashlib.sha256(args.scan.read_bytes()).hexdigest(),
            'native_di_oracle_sha256':NATIVE_DI_SHA,'native_di_oracle_cases':len(di_oracle),
            'tested':tested,'result':'pass','coverage':coverage,'helper_count':len(coverage),
            'suite_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'full_conversion_qualified':False,
            'helper_count_by_gap':{gap:sum(x['gap']==gap for x in coverage) for gap in sorted({x['gap'] for x in coverage})},
            'selector_cases_by_gap':role_cases,'downstream_receipts':children,
            'total_contract_cases':cases+sum(x['cases'] for x in children.values()),
            'limits':'Prepared private CPU patches and bounded native stages; no full installed BIN or QA qualification. Every pending plan remains unqualified.',
            'unresolved_reverse_bindings':children['G05']['unqualified'],
            'unqualified':[{'sha256':row['sha256'],'pending':row['plan']['pending']} for row in plans if row['plan'].get('pending')]},indent=2)+'\n')
    print(f'PASS: {cases} ARM926 selector cases, {len(tested)} candidates; OEM/Off and other-state preservation checked')


if __name__=='__main__':main()
