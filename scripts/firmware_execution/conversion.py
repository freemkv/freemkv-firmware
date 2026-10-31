"""Independent production-site classic UHD contracts; no service success stubs."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import struct
from capstone import CS_OP_REG, CS_OP_IMM
import stages
from stages import REGS, STACK, DECODER, require, unchanged, run

NATIVE_SHA='1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396'
STATES=(0,0x40,0x44,0xc0,0xc4,0xc7,0xc8,0xcc,0xe0,0xe8,0xf8,255)
CV=(0,0x20000000,0x10000000,0x30000000)
RAM=0x02003000


def regno(operand):
    name=operand.strip()
    require(name.startswith('r') and name[1:].isdigit(),'unbound source register '+name)
    return int(name[1:])


def source_inputs(data,c,state):
    ins=next(DECODER.disasm(data[c['site']:c['site']+4],c['site'],count=1))
    registers={i:RAM for i in range(13)}
    parts=[p.strip() for p in ins.op_str.split(',')]
    if ins.mnemonic=='bics':
        registers[regno(parts[0])]=0xc8;registers[regno(parts[1])]=state
    elif ins.mnemonic=='cmp':
        immediate=int(parts[1].lstrip('#'),0)
        require(immediate in (0,0xc8),'unknown native selector immediate')
        registers[regno(parts[0])]=(0xc8&~state) if immediate==0 else state
    else:raise AssertionError('unknown native selector: '+ins.mnemonic+' '+ins.op_str)
    return registers,ins.mnemonic


@lru_cache(maxsize=1)
def native_attribute_oracle(hoard):
    paths=list(Path(hoard).rglob(NATIVE_SHA+'.bin'));require(bool(paths),'native DI oracle source missing')
    data=paths[0].read_bytes();require(hashlib.sha256(data).hexdigest()==NATIVE_SHA,'native DI oracle digest mismatch')
    # Enter after native BD-prefix validation and diagnostic calls. Execute only
    # the actual OEM attribute predicate, stopping before identifier routing.
    require(data[0xe0bd2:0xe0bd4]==bytes.fromhex('eb4f'),'native attribute entry signature changed')
    table,records={},[]
    for state in range(256):
        for attribute in range(4):
            result=run(data,'MT1959',0xe0bd2,{0xe0c26,0xe0c2a},0x02000e40,
                memory=[(0x01ff9e04,bytes([state])),(STACK+0x49,bytes([attribute<<4]))])
            table[state,attribute]=result['target']==0xe0c2a
            record={'stage':'native-DI-attribute-oracle','source_sha256':NATIVE_SHA,
                    'state':state,'attribute':attribute,'target':result['target'],'trace':result['trace']}
            records.append(record)
            if stages.TRACE_SINK:stages.TRACE_SINK.write(json.dumps(record)+'\n')
    return table,hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest()


def selection(stage,c,contract):
    site=c['site'];stops={contract['accept'],contract['reject']}
    instructions=list(DECODER.disasm(bytes(c['original_bytes']),site))
    native=instructions[-1]
    require(native.mnemonic in ('beq','bne'),'native selector conditional branch missing')
    target=int(native.op_str.lstrip('#'),0)
    accept=target if native.mnemonic=='beq' else native.address+native.size
    reject=native.address+native.size if native.mnemonic=='beq' else target
    seen=set()
    while reject not in seen:
        seen.add(reject)
        following=next(DECODER.disasm(stage.original[reject:reject+4],reject,count=1))
        if following.mnemonic!='bne':break
        reject=int(following.op_str.lstrip('#'),0)
    require(accept==contract['accept'] and reject==contract['reject'],'exported C8 continuations disagree with independent source branch decoding')
    for setting in (0,1,2,255):
        for state in range(256):
            registers,mnemonic=source_inputs(stage.original,c,state)
            for cv in CV if mnemonic=='bics' else (0,):
                def case():
                    kw={'settings':{3:setting},'registers':registers,'initial_nzcv':cv,
                        'memory':[(contract['state'],bytes([state])),(RAM,bytes(range(128)))]}
                    old=stage.execute(False,site,stops,**kw);new=stage.execute(True,site,stops,**kw)
                    expected=contract['accept'] if setting==1 and state==0xc7 else old['target']
                    require(new['target']==expected,'C7/On native C8 selection contract')
                    unchanged(old,new)
                    return old,new
                stage.case([setting,state,cv],case)
    stage.result['scope']='Every state byte; isolated native selector operands; exact live GPR/NZCV/SP comparison'
    if contract.get('calculation_end') is not None:
        stage.result['coverage_gaps'].append('Selector qualified; downstream arithmetic gets a separate native-worker boundary test')
        arithmetic(stage,c,contract)


def arithmetic(stage,c,contract):
    end=contract['calculation_end'];site=c['site'];state_cell=contract['state']
    # The source-bound native C8 calculation, including its in-image ARM divide
    # worker, is the independent numerical oracle. No division-call stub exists.
    for setting,state in ((1,0xc7),(0,0xc8),(1,0xc8),(255,0xc8),(2,0xc8)):
        for value in (0,1,9,10,11,99,100,1000,65535):
            def case():
                registers,_=source_inputs(stage.original,c,0xc8)
                registers.update({1:state_cell,4:RAM,5:0x100000,7:0x200000})
                oldkw={'settings':{3:setting},'registers':registers,
                       'memory':[(state_cell,b'\xc8'),(RAM,struct.pack('<H',value))],
                       'strict_reads':True}
                old=stage.execute(False,site,{end,contract['reject']},**oldkw)
                registers,_=source_inputs(stage.original,c,state)
                registers.update({1:state_cell,4:RAM,5:0x100000,7:0x200000})
                new=stage.execute(True,site,{end,contract['reject']},settings={3:setting},registers=registers,
                    memory=[(state_cell,bytes([state])),(RAM,struct.pack('<H',value))],strict_reads=True)
                require(old['target']==new['target']==end,'native C8 calculation join not reached')
                unchanged(old,new)
                return old,new
            stage.case(['native-C8-arithmetic',setting,state,value],case)


def di(stage,c,contract,contracts):
    oracle,oracle_sha=native_attribute_oracle(contracts['_hoard'])
    stage.result['native_reference_sha256']=NATIVE_SHA
    stage.result['native_reference_trace_sha256']=oracle_sha
    stage.result['native_attribute_oracle_table_cases']=1024
    state_cell=contract['state'];site=c['site'];fmt=contract['format'];replay=contract['replay_continuation']
    def inputs(setting,state,identifier,density,layers,attribute,v,prefix=b'BD'):
        raw=bytearray(32);raw[12:14]=prefix;raw[16:20]=bytes([identifier,attribute<<4,layers<<4,density])
        return {'settings':{3:setting},'registers':{4:state_cell},'initial_nzcv':v,
            'memory':[(state_cell,bytes([state])),(STACK,bytes(raw))],
            'allow_writes':[(state_cell,state_cell+1)],'observe_memory':[(state_cell,1)]}
    for setting in (0,1,2,255):
        for state in STATES:
            for attribute in range(4):
                for identifier in b'UOW?':
                    for density in (1,5,255):
                        for layers in (1,2,3,4):
                            for v in (0,0x10000000):
                                def case():
                                    kw=inputs(setting,state,identifier,density,layers,attribute,v)
                                    old=stage.execute(False,site,{replay},**kw)
                                    new=stage.execute(True,site,{replay,fmt},**kw)
                                    accepted=setting==1 and identifier==ord('U') and density==5 and layers in (2,3) and oracle[state,attribute]
                                    require(new['target']==(fmt if accepted else replay),'DI admission disagrees with native attribute oracle/media grammar')
                                    if accepted:
                                        expected={2:0xc7,3:0xc8}[layers]
                                        require(new['memory'][str(state_cell)]==bytes([expected]).hex(),'DI layer identity assignment')
                                        require(new['registers'][2]==expected,'DI state argument changed')
                                        require(new['registers'][contract['one_register']]==1,'DI native format argument not one')
                                        for index in range(4,13):
                                            require(new['registers'][index]==new['before'][index],'DI live register changed')
                                        require(new['registers'][3]==STACK,'DI native stack scratch changed')
                                        require(new['sp']==STACK,'DI frame unbalanced')
                                    else:
                                        unchanged(old,new)
                                        require(new['memory']==old['memory'],'ordinary/Off/OEM DI state changed')
                                    return old,new
                                stage.case([setting,state,attribute,identifier,density,layers,v],case)
    # Exercise every native attribute-oracle state/class pair on the installed
    # U/5 extension, separately from the ordinary-media cross product above.
    for state in range(256):
        for attribute in range(4):
            def case():
                kw=inputs(1,state,ord('U'),5,2,attribute,0)
                old=stage.execute(False,site,{replay},**kw)
                new=stage.execute(True,site,{replay,fmt},**kw)
                require(new['target']==(fmt if oracle[state,attribute] else replay),'complete native DI attribute truth table mismatch')
                if not oracle[state,attribute]:unchanged(old,new)
                return old,new
            stage.case(['native-attribute-table',state,attribute],case)
    for prefix in (b'??',b'B?',b'?D'):
        def case():
            kw=inputs(1,0xc7,ord('U'),5,2,0,0,prefix)
            old=stage.execute(False,site,{replay},**kw);new=stage.execute(True,site,{replay,fmt},**kw)
            require(new['target']==replay,'malformed BD prefix accepted');unchanged(old,new)
            return old,new
        stage.case(['invalid-prefix',prefix.hex()],case)
    def wrong_state_pointer():
        kw=inputs(1,0xc7,ord('U'),5,2,0,0)
        kw['registers'][4]=state_cell+4
        old=stage.execute(False,site,{replay},**kw);new=stage.execute(True,site,{replay,fmt},**kw)
        require(new['target']==replay,'DI state-pointer guard bypassed');unchanged(old,new)
        return old,new
    stage.case('wrong-native-state-pointer',wrong_state_pointer)
    # Continue genuine accepted inputs through the installed entry, native format
    # dispatcher and native layer store. This does not enter acquisition services.
    for state in STATES:
        for attribute in range(4):
            if not oracle[state,attribute]:continue
            for layers in (2,3):
                def case():
                    kw=inputs(1,state,ord('U'),5,layers,attribute,0)
                    kw['allow_writes'].append((contract['format_flag'],contract['format_flag']+1))
                    kw['observe_memory'].append((contract['format_flag'],1))
                    expected={2:0xc7,3:0xc8}[layers]
                    oldkw=inputs(1,expected,ord('U'),5,layers,attribute,0)
                    oldkw['registers'].update({2:expected,3:STACK,contract['one_register']:1})
                    oldkw['allow_writes'].append((contract['format_flag'],contract['format_flag']+1))
                    oldkw['observe_memory'].append((contract['format_flag'],1))
                    old=stage.execute(False,fmt,{contract['layer_store']+2,contract['epilogue']},**oldkw)
                    new=stage.execute(True,site,{contract['layer_store']+2,contract['epilogue']},**kw)
                    require(old['target']==new['target']==contract['layer_store']+2,'native DI layer store was not reached')
                    require(new['memory'][str(state_cell)]==bytes([expected]).hex(),'native layer normalization changed UHD identity')
                    require(new['memory'][str(contract['format_flag'])]=='20','native format-five flag changed')
                    require(new['memory']==old['memory'],'OEM shared format/layer state differs')
                    unchanged(old,new)
                    return old,new
                stage.case(['native-format-and-layers',state,attribute,layers],case)
    stage.result['coverage_gaps'].append('DI entered after acquisition/BD-prefix validation; no acquisition, ready flag or native return/hardware completion qualified')


def read_position(stage,c,contract):
    site=c['site'];stops={contract[k] for k in ('accept','reject','layer_one','layer_zero')}
    for setting in (0,1,2,255):
        for state in range(256):
            for native_value in (0,1,2,255):
                for layer in range(4):
                    def case():
                        kw={'settings':{3:setting},'registers':{1:native_value,contract.get('position_register',4):RAM},
                            'memory':[(contract['state'],bytes([state])),(RAM+2,bytes([layer<<6]))]}
                        old=stage.execute(False,site,{contract['accept'],contract['reject']},**kw)
                        new=stage.execute(True,site,stops,**kw)
                        active=setting==1 and state==0xc7
                        expected=contract['layer_one'] if layer==1 else contract['layer_zero']
                        require(new['target']==(expected if active else old['target']),'C7 position layer decode contract')
                        unchanged(old,new,dead=(1,) if active else (),flags=not active)
                        if active:require(new['registers'][1]==layer,'position layer byte extraction changed')
                        return old,new
                    stage.case([setting,state,native_value,layer],case)
    stage.result['coverage_gaps'].append('Native position reflection/range worker bodies remain outside this decode boundary')


def calibration(stage,c,contract):
    site=c['site'];end=contract['continuation']
    runtime=contract.get('coefficients_are_runtime',False)
    count=contract.get('rate_count',6)
    tables=((0x1234,0x4321,0x7fff,0xffff),(0,1,0x8000,0xabcd)) if runtime else (None,)
    for table in tables:
        _calibration_table(stage,c,contract,table,count,site,end)
    if runtime:
        stage.result['coverage_gaps'].append('Startup coefficient values supplied as labeled synthetic runtime table inputs; actual initialized NV profile/producer remains unknown')
        stage.result['runtime_calibration_profile_qualified']=False


def _calibration_table(stage,c,contract,table,count,site,end):
    runtime=table is not None
    if runtime:require(count==len(table),'runtime coefficient fixture count differs from native count')
    data=struct.pack('<'+'H'*count,*table) if runtime else b''
    for setting in (0,1,2,255):
        for state in range(256):
            for index in range(0,count*2,2):
                def case():
                    memory=[(contract['state'],bytes([state]))]
                    if runtime:memory.append((contract['c8_coefficients'],data))
                    kw={'settings':{3:setting},'registers':{6:index},'memory':memory,'strict_reads':True}
                    old=stage.execute(False,site,{end},**kw);new=stage.execute(True,site,{end},**kw)
                    active=setting==1 and state==0xc7
                    address=contract['c8_coefficients']+index if active else contract['original_base']+contract.get('base_adjustment',0x58)+index
                    expected=table[index//2] if active and runtime else int.from_bytes(stage.original[address:address+2],'little')
                    require(new['registers'][0]==expected,'startup calibration not selected from this OEM image')
                    unchanged(old,new,dead=(0,) if active else ())
                    return old,new
                stage.case([setting,state,index,table],case)


def compare(stage,c,contracts):
    contract=c.get('contract')
    if not contract:
        stage.result['status']='unqualified';stage.result['coverage_gaps'].append('Missing independent installed conversion contract');return
    fn={'selection':selection,'di':di,'legacy_di_admission':legacy_di,'legacy_di_layers':legacy_di,'read_position_decode':read_position,'calibration':calibration}[contract['kind']]
    stage.result['source_bound_helper']=c
    if fn in (di,legacy_di):fn(stage,c,contract,contracts)
    else:fn(stage,c,contract)
    if c.get('role')=='MediaSelected':
        from getters import full_getter
        full_getter(stage,c,contracts)


def legacy_di(stage,c,contract,contracts):
    """Coordinated stack-buffer parser, executed from installed production sites."""
    oracle,oracle_sha=native_attribute_oracle(contracts['_hoard'])
    stage.result.update(native_reference_sha256=NATIVE_SHA,native_reference_trace_sha256=oracle_sha,
        native_attribute_oracle_table_cases=1024,
        preconditions='Native BD-prefix validation completed; source-bound saved frame and nonvolatile state pointer supplied')
    site=c['site'];is_layers=contract['kind']=='legacy_di_layers'
    active_target=contract['layer_store'] if is_layers else contract['format'];fallback=site+len(c['original_bytes'])
    block=contract['stack_block'];offset=contract['identifier_offset'];state_cell=contract['state']
    state_register=contract['state_register']
    store=int.from_bytes(stage.original[contract['layer_store']:contract['layer_store']+2],'little')
    store_base=(store>>3)&7
    def inputs(setting,state,identifier,density,layers,attribute,v,prefix=b'BD'):
        raw=bytearray(offset+4);raw[offset-4:offset-2]=prefix
        raw[offset:offset+4]=bytes([identifier,attribute<<4,layers<<4,density])
        registers={} if state_register is None else {state_register:state_cell}
        return {'settings':{3:setting},'registers':registers,'initial_nzcv':v,
            'memory':[(state_cell,bytes([state])),(STACK+block,bytes(raw))],
            'observe_memory':[(state_cell,1)]}
    def one_case(setting,state,identifier,density,layers,attribute,v):
        kw=inputs(setting,state,identifier,density,layers,attribute,v)
        old=stage.execute(False,site,{fallback},**kw)
        new=stage.execute(True,site,{fallback,active_target},**kw)
        accepted=setting==1 and identifier==ord('U') and density==5 and layers in (2,3) and oracle[state,attribute]
        require(new['target']==(active_target if accepted else fallback),'stack DI admission differs from native attribute oracle/media grammar')
        if not accepted:unchanged(old,new)
        elif not is_layers:
            require(new['registers']==new['before'],'stack DI admission changed live native arguments')
            require(new['sp']==STACK,'stack DI admission frame changed')
        else:
            expected=list(new['before']);expected[0]={2:0xc7,3:0xc8}[layers];expected[1]=0xf3;expected[3]=STACK+block
            if state_register is None:expected[store_base]=state_cell
            require(new['registers']==expected,'stack DI layer-store arguments/live registers changed')
            require(new['sp']==STACK,'stack DI layer frame changed')
        require(new['memory']==old['memory'],'stack DI helper wrote media state before native store')
        return old,new
    for setting in (0,1,2,255):
        for state in STATES:
            for attribute in range(4):
                for identifier in b'UOW?':
                    for density in (1,5,255):
                        for layers in (1,2,3,4):
                            for v in (0,0x10000000):
                                stage.case([setting,state,attribute,identifier,density,layers,v],lambda:one_case(setting,state,identifier,density,layers,attribute,v))
    for state in range(256):
        for attribute in range(4):
            stage.case(['native-attribute-table',state,attribute],lambda:one_case(1,state,ord('U'),5,2,attribute,0))
    if not is_layers:
        # Independently locate the native prefix branch, then prove malformed
        # prefix inputs stop before reaching either installed DI detour.
        stack_op=0xab00|(block//4);load=0x7800|((offset-4)<<6)|(3<<3)
        signature=struct.pack('<3H',stack_op,load,0x2842)
        matches=[at for at in range(max(0,site-0x80),site,2) if stage.original[at:at+6]==signature]
        require(len(matches)==1,'native BD-prefix source binding ambiguous')
        prefix=matches[0];failure=stages.branch(stage.original,prefix+6)
        for value in (b'BD',b'B?',b'?D',b'??'):
            def case():
                kw=inputs(1,0xc7,ord('U'),5,2,0,0,value)
                old=stage.execute(False,prefix,{site,failure},**kw);new=stage.execute(True,prefix,{site,failure},**kw)
                require(new['target']==old['target']==(site if value==b'BD' else failure),'native BD-prefix path changed')
                unchanged(old,new);return old,new
            stage.case(['native-prefix',value.hex()],case)
        # Both installed hooks participate. Compare to the unchanged native
        # shared format/layer routine with an independently supplied identity.
        for state in STATES:
            for attribute in range(4):
                if not oracle[state,attribute]:continue
                for layers in (2,3):
                    def case():
                        expected={2:0xc7,3:0xc8}[layers]
                        kw=inputs(1,state,ord('U'),5,layers,attribute,0)
                        kw['allow_writes']=[(state_cell,state_cell+1),(contract['format_flag'],contract['format_flag']+1)]
                        kw['observe_memory'].append((contract['format_flag'],1))
                        oldkw=inputs(1,expected,ord('U'),5,layers,attribute,0)
                        oldkw['allow_writes']=kw['allow_writes'];oldkw['observe_memory']=kw['observe_memory']
                        stops={contract['layer_store']+2}
                        old=stage.execute(False,contract['format'],stops,**oldkw)
                        new=stage.execute(True,contract['prevalidation'],stops,**kw)
                        require(new['memory'][str(state_cell)]==bytes([expected]).hex(),'coordinated DI hooks lost C7/C8 identity')
                        require(new['memory'][str(contract['format_flag'])]=='20','native format-five flag changed')
                        require(old['memory']==new['memory'],'native shared format/layer output differs')
                        unchanged(old,new);return old,new
                    stage.case(['coordinated-native-format-layers',state,attribute,layers],case)
    stage.result['coverage_gaps'].append('Source-bound post-acquisition parser context only; no full acquisition, ready/controller completion or physical read qualification')
