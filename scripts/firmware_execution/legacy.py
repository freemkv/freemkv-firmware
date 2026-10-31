"""Actual installed older MT1959 helpers, not relocated prepared candidates."""
import struct
from functools import lru_cache
from pathlib import Path
from stages import DECODER, STACK, require, unchanged, branch
from position import literal

CV=(0,0x10000000,0x20000000,0x30000000)
INPUT=0x02003000


def mode_flow(stage,c,d):
    region=d['region_start'];cell=literal(stage.original,region+6,0)
    call=next(DECODER.disasm(stage.original[region+26:region+30],region+26,count=1))
    require(call.mnemonic in ('bl','blx'),'native DI-mode programming call not bound')
    target=int(call.op_str.lstrip('#'),0)
    require(stage.original[region:region+2]==bytes.fromhex('3878'),'native DI-mode R7 state load differs')
    for setting in (0,1,2,255):
        for state in range(256):
            def case():
                active=setting==1 and state==0xc7
                common=dict(settings={3:setting},registers={7:d['state']},
                    allow_writes=[(cell,cell+1)],observe_memory=[(cell,1)],strict_reads=True,stop_thumb=call.mnemonic!='blx')
                old=stage.execute(False,region,{target},memory=[(d['state'],bytes([0xc8 if active else state])),(cell,b'\xa5')],**common)
                new=stage.execute(True,region,{target},memory=[(d['state'],bytes([state])),(cell,b'\xa5')],**common)
                require(old['memory']==new['memory'],'native DI-mode byte differs from own dense/OEM path')
                if active:
                    require(new['memory'][str(cell)]=='1c','C7 initialization did not select native UHD dense mode1c')
                    require(old['registers'][2]==0xc8 and new['registers'][2]==0xc7,'native DI-mode raw identity operand changed')
                unchanged(old,new,dead=(2,) if active else ())
                return old,new
            stage.case(['native-mode-programming-prefix',setting,state],case)
    stage.result['native_mode_flow']={'mode_cell':cell,'programming_call':call.address,'stop_at_actual_callee':target,
        'native_uhd_reference':'BU40N1.02 source1bbe e09c6..e0a06 explicit C7 uses mode1c through shared C8 arm',
        'limit':'Actual programming call entry/order reached; callee completion/acquisition not invented'}


def identity_reset(stage,c,d):
    marker=d['identity_marker'];mode=d['mode'];density=d['density_class'];end=d['continuation']
    for setting in (0,1,2,255):
        for previous in (0,1,2,255):
            for old_mode in (0,1,255):
                def case():
                    common=dict(settings={3:setting},registers={d['zero_register']:0},memory=[(marker,bytes([previous])),
                        (mode,bytes([old_mode])),(density,b'\x5a')],allow_writes=[(marker,marker+1),(mode,mode+1)],
                        observe_memory=[(marker,1),(mode,1),(density,1)],strict_reads=True)
                    old=stage.execute(False,c['site'],{end},**common);new=stage.execute(True,c['site'],{end},**common)
                    unchanged(old,new)
                    require(new['memory'][str(marker)]=='00' and old['memory'][str(marker)]==bytes([previous]).hex(),'private per-disc identity not reset')
                    require(old['memory'][str(mode)]==new['memory'][str(mode)]=='00','native mode clear changed')
                    require(old['memory'][str(density)]==new['memory'][str(density)]=='5a','density class changed during unrelated clear')
                    return old,new
                stage.case([setting,previous,old_mode],case)
    stage.result['coverage_gaps'].append('Source-bound local reset and boot clear are separate from complete per-disc insertion/rearm ordering')


def density(stage,c,d):
    # Independent source policy: immutable native BU40N getter/startup profile,
    # already executed in the native policy receipts; no emitter table import.
    from conversion import NATIVE_SHA
    paths=list(Path(stage.hoard).rglob(NATIVE_SHA+'.bin'));require(bool(paths),'native density reference missing')
    reference=paths[0].read_bytes();high=tuple(int.from_bytes(reference[0x150de6+i:0x150de8+i],'little') for i in range(0,8,2))
    require(high==(1860,2547,3745,4869),'native UHD density reference profile changed')
    if d['lookup_displaced']:
        flags=tuple(n|v for n in (0,0x40000000,0x80000000) for v in CV)
    else:flags=CV
    for setting in (0,1,2,255):
        for state in range(256):
            for index in range(4):
                for nzcv in flags:
                    def case():
                        common=dict(settings={3:setting},registers={6:index*2},memory=[(d['state'],bytes([state]))],initial_nzcv=nzcv,strict_reads=True)
                        old=stage.execute(False,c['site'],{d['continuation']},**common);new=stage.execute(True,c['site'],{d['continuation']},**common)
                        active=setting==1 and (state==0xc7 or state>>2==0x32)
                        if d['lookup_displaced']:
                            require(new['registers'][0]==(high[index] if active else old['registers'][0]),'source/native UHD density halfword differs')
                        else:
                            require(new['registers'][0]==d['normal_table'] or active,'ordinary native density pointer changed')
                            if active:
                                address=new['registers'][0]+index*2
                                require(int.from_bytes(stage.modified[address:address+2],'little')==high[index],'actual installed density table differs from native source policy')
                        unchanged(old,new,dead=(0,) if active else ())
                        return old,new
                    stage.case([setting,state,index,nzcv],case)
    stage.result['density_policy_reference']={'source_sha256':NATIVE_SHA,'held_profile':0x150de6,'values':list(high)}
    stage.result['coverage_gaps'].append('Density selection/flags only; no measurement return, arithmetic MMIO or controller completion is manufactured')


def reverse(stage,c,d):
    reject=d['reject'];seen=set()
    while reject not in seen:
        seen.add(reject)
        ins=next(DECODER.disasm(stage.original[reject:reject+4],reject,count=1))
        if ins.mnemonic!='bne':break
        reject=int(ins.op_str.lstrip('#'),0)
    # First establish all ordinary gate routes with exact replay operands.
    for setting in (0,1,2,255):
        for state in range(256):
            if setting==1 and state==0xc7:continue
            for cv in CV:
                def case():
                    common=dict(settings={3:setting},registers={0:state,1:d['state'],2:0xc8},
                        memory=[(d['state'],bytes([state])),(d['mode'],b'\x02')],initial_nzcv=cv,strict_reads=True)
                    stops={d['accept'],reject}
                    old=stage.execute(False,c['site'],stops,**common);new=stage.execute(True,c['site'],stops,**common)
                    require(new['target']==old['target'],'ordinary G05 gate changed');unchanged(old,new);return old,new
                stage.case(['gate',setting,state,cv],case)
    # Exercise the installed gate with each supported incoming C/V pair.
    # Full-prelude tests below separately establish the native caller path.
    for cv in CV:
        for mode in (0,1,2,255):
            for value in (0,19,65535):
                def active_gate():
                    r5,r7=0x4321,0x1234
                    result=stage.execute(True,c['site'],{d['normalize']+4},
                        settings={3:1},registers={0:0xc7,1:d['state'],2:0xc8,4:INPUT,5:r5,6:value,7:r7},
                        memory=[(d['state'],b'\xc7'),(d['mode'],bytes([mode])),(INPUT,struct.pack('<H',value))],
                        initial_nzcv=cv,strict_reads=True)
                    expected=(r7-12*(value//10) if mode==0 else r5-9*(value//10))&0xffff
                    require(result['registers'][6]==expected,'C7 G05 gate mode arithmetic differs across incoming C/V')
                    require(result['sp']==STACK,'C7 G05 gate stack changed')
                    return None,result
                stage.case(['active-gate-cv',cv,mode,value],active_gate)
    for value in (0,1,9,10,11,19,20,1000,32768,65535):
        for r7,r5 in ((0,0),(0x1234,0x4321),(0xffff,0x1234),(0x5534,0x3fd2)):
            for mode in (0,1,2,255):
                def case():
                    # Enter the real source prelude; native ARM unsigned divide
                    # and low-halfword normalization execute from the final BIN.
                    common=dict(settings={3:1},registers={0:value,1:d['state'],4:INPUT,5:r5,6:value,7:r7},
                        memory=[(d['state'],b'\xc7'),(d['mode'],bytes([mode])),(INPUT,struct.pack('<H',value))],strict_reads=True)
                    end=d['normalize']+4
                    new=stage.execute(True,d['region_start'],{end},**common)
                    require(new['registers'][6]==((r7-12*(value//10)) if mode==0 else (r5-9*(value//10)))&0xffff,'actual G05 native UHD mode arithmetic differs')
                    require(new['registers'][4]==INPUT and new['registers'][5]==r5 and new['registers'][7]==r7,'native G05 inherited operands changed')
                    require(new['sp']==STACK,'native G05 stack changed')
                    # Ordinary source C8 is independently exercised for mode0;
                    # mode1 intentionally follows the native UHD C7 policy.
                    old=None
                    if mode==0:
                        common['memory'][0]=(d['state'],b'\xc8')
                        old=stage.execute(False,d['region_start'],{end},**common)
                        require(old['registers'][6]==new['registers'][6],'mode0 native C8 result differs')
                    return old,new
                stage.case(['native-mode-arithmetic',value,r7,r5,mode],case)
    stage.result['coverage_gaps'].append('Actual final-BIN/held ARM divide/normalization only; phase producer/lifetime and controller sink remain separate requirements')


def forward(stage,c,d):
    end=d['legacy_forward_end'];r5,r7=0x3fd2,0x5534
    for setting in (0,1,2,255):
        for value in (0,1,9,10,11,19,20,1000,65535):
            def case():
                active=setting==1;state=0xc7 if active else 0xc8
                common=dict(settings={3:setting},registers={0:value,4:INPUT,5:r5,6:value<<16,7:r7},
                    memory=[(d['state'],b'\xc8'),(INPUT,struct.pack('<H',value))],strict_reads=True)
                old=stage.execute(False,d['region_start'],{end},**common)
                common['memory'][0]=(d['state'],bytes([state]));new=stage.execute(True,d['region_start'],{end},**common)
                unchanged(old,new);require(new['registers'][0]==12*(value//10)+r7,'native G04 C7 coefficient policy differs');return old,new
            stage.case(['full-native-G04',setting,value],case)
