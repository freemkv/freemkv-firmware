"""Full source getter tests with an independently executed coefficient oracle.

C7 retains its OEM rate list and count. Only its final coefficient selection
joins this image's native exact-C8 selection. Opaque logging calls are stops.
"""
from stages import DECODER, STOP, require, unchanged
import struct


def runtime_inputs(stage,g,pattern):
    """Supply labeled test parameters only at actual native literal pointers."""
    count=g['rate_count'];require(count==4,'unknown runtime getter table width')
    inputs={};rates=[]
    for at in range(g['entry'],g['lookup'],2):
        op=int.from_bytes(stage.original[at:at+2],'little')
        if op&0xf800!=0x4800:continue
        literal=((at+4)&~3)+(op&255)*4
        pointer=int.from_bytes(stage.original[literal:literal+4],'little')
        register=(op>>8)&7
        if not 0x01ff0000<=pointer<0x02030000 or pointer==g['state']:continue
        if register==6:
            rates=[2,5,9,17] if pattern==0 else [1,6,8,12]
            data=bytes(rates)
        else:
            require(register==1,'unknown native runtime getter input register')
            values=(0x1111,0x2468,0x3579,0x4567) if pattern==0 else (0,0xffff,0x8000,1)
            # Distinguish the CC profile from the exact-C8 profile.
            if pointer!=g['coefficients']:values=tuple(v^0x5555 for v in values)
            data=struct.pack('<4H',*values)
        require(pointer not in inputs or inputs[pointer]==data,'aliased runtime getter input')
        inputs[pointer]=data
    require(g['coefficients'] in inputs and rates,'runtime source profile/rates not bound')
    return list(inputs.items()),rates


def full_getter(stage, helper, contracts):
    g=contracts['native_parameter_getter']
    require(g['variant']=='MediaSelected','full selector oracle requires MediaSelected source')
    calls=[i for i in DECODER.disasm(stage.original[g['entry']:g['lookup']],g['entry'])
           if i.mnemonic in ('bl','blx')]
    require(len(calls)==1,'full getter logger call binding ambiguous')
    logger=int(calls[0].op_str.lstrip('#'),16)
    runtime=g.get('coefficients_are_runtime',False)
    for pattern in ((0,1) if runtime else (None,)):
        memory,extra_rates=runtime_inputs(stage,g,pattern) if runtime else ([],[])
        _full_getter_profile(stage,helper,g,logger,memory,extra_rates,pattern)
    stage.result['full_parameter_getter_valid_request_domain_qualified']=stage.result['status']=='passed'
    stage.result['full_parameter_getter_qualified']=False
    stage.result['coverage_gaps'].append('Out-of-range getter requests stop at real OEM logging call; logger/resident return and subsequent clamp remain unexecuted')
    if runtime:
        stage.result['runtime_calibration_profile_qualified']=False
        stage.result['coverage_gaps'].append('Parameterized synthetic runtime table inputs prove selection/index behavior; actual initialized calibration values/producer remain unknown')


def _full_getter_profile(stage,helper,g,logger,memory,extra_rates,pattern):
    stops={STOP,logger}
    def args(setting,state,request):
        return dict(settings={3:setting},registers={0:request},
                    memory=[(g['state'],bytes([state])),*memory],strict_reads=True)
    # The real OEM loop establishes the native count and exhaustion boundary.
    stage.case_executions=[]
    limit=stage.execute(False,g['entry'],stops,**args(255,0xc7,255))
    count=limit['registers'][4]
    require(limit['target']==logger and count in (4,6),'native C7 rate limit not bound')
    require(g.get('rate_count',count)==count,'typed source rate count differs from native full getter')
    rates=list(stage.original[g['rates']:g['rates']+count])
    require(rates==sorted(set(rates)) and rates[-1]<255,'native C7 rates not ordered')
    coefficients=[];native_flags=[]
    for index in range(count):
        stage.case_executions=[]
        require(helper['original_bytes'][:2]==[0xc8,0x28],'native final CMP R0,C8 binding changed')
        native=stage.execute(False,helper['site'],{g['lookup']+2},
            registers={0:0xc8,2:index},memory=[(g['state'],b'\xc8'),*memory],strict_reads=True)
        require(native['registers'][1]==g['coefficients'],
                'exact-C8 source coefficient address differs from declared table')
        coefficients.append(native['registers'][0])
        native_flags.append(native['nzcv'])
    policy={
        'entry':g['entry'],'logger_stop':logger,'native_c7_rates':rates,
        'native_exact_c8_coefficients':coefficients,
        'coefficient_source':'Actual OEM final CMP R0,C8 and accepted branch to source LDRH',
        'request_domain':'All 256 request bytes for C7; all states at representative request boundaries',
        'strict_memory_inputs':True,'synthetic_runtime_pattern':pattern,
        'runtime_inputs':[{'address':a,'bytes':b.hex(),'provenance':'Synthetic declared software test input; not captured NV/calibration'} for a,b in memory]}
    stage.result.setdefault('full_getter_policy_profiles',[]).append(policy)
    states=range(256)
    for state in states:
        requests=range(256) if state==0xc7 else sorted({0,3,8,12,16,255,*rates,*extra_rates})
        for request in requests:
            for setting in (0,1,2,255):
                def case():
                    kw=args(setting,state,request)
                    old=stage.execute(False,g['entry'],stops,**kw)
                    new=stage.execute(True,g['entry'],stops,**kw)
                    require(old['target']==new['target'],'getter return/log boundary changed')
                    active=state==0xc7 and setting==1 and old['target']==STOP
                    if state==0xc7:
                        index=next((i for i,rate in enumerate(rates) if rate>=request),count)
                        require(old['registers'][2]==new['registers'][2]==index,
                                'C7 native rate index/count changed')
                        require((new['target']==logger)==(index==count),'C7 limit/log boundary changed')
                    if active:
                        require(new['registers'][0]==coefficients[new['registers'][2]],
                                'full C7 getter did not select own native exact-C8 coefficient')
                        require(new['registers'][1]==g['coefficients'],'full C7 getter selected wrong table')
                        require(new['nzcv']==native_flags[new['registers'][2]],
                                'full getter flags differ from own native exact-C8 coefficient path')
                    # At the function return, the selected C8 path's native
                    # LSLS replaces the default path's ADD-immediate flags.
                    # Preserve control state; arithmetic flags are volatile
                    # for the explicitly changed coefficient return path.
                    unchanged(old,new,dead=(0,1) if active else (),flags=not active)
                    return old,new
                stage.case(['full-getter',state,request,setting,pattern],case)
