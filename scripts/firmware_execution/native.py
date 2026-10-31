"""Native G01-G06 local software contracts with actual held code and data.

Declared inputs are not evidence of acquisition/geometry/phase producers.
No call, arithmetic device, or controller completion is replaced by success.
"""
import struct
from stages import Stage, DECODER, STACK, require, unchanged, branch
from position import literal
from cpu import CONDITIONAL

INPUT=0x02003000


def pair(stage,site,stops,**kw):
    old=stage.execute(False,site,stops,**kw)
    new=stage.execute(True,site,stops,**kw) if stage.actual_final_bin else None
    if new is not None:unchanged(old,new);require(old['memory']==new['memory'] and old['target']==new['target'],'native original/final role effect changed')
    return old,new


def control_bit(stage,c,state_cell):
    site=c['site'];end=site+c['length'];base=literal(stage.original,site+8,0)
    op=int.from_bytes(stage.original[site+10:site+12],'little')
    require(op&0xff00==0x3800 and (op&255) in (64,128),'native controller base adjustment differs')
    address=base-(op&255)+0x3c
    for state in range(256):
        for word in (0,0xffffffff,0x12345678,0xa55a9669):
            def case():
                old,new=pair(stage,site,{end},memory=[(state_cell,bytes([state])),(address,struct.pack('<I',word))],
                    allow_writes=[(address,address+4)],observe_memory=[(address,4)],strict_reads=True)
                expected=(word|0x80000000) if state&0xc8==0xc8 or state==0xc7 else word&0x7fffffff
                require(old['memory'][str(address)]==struct.pack('<I',expected).hex(),'native G02 bit31 policy differs')
                require(old['writes']==[(address,4,expected)],'native G02 write destination/order differs')
                return old,new
            stage.case([state,word],case)
    stage.result['declared_controller_word']=address


def field_store(data,c):
    pc=c['edges'][-1]['target']
    for _ in range(4):
        op=int.from_bytes(data[pc:pc+2],'little')
        if op==0x6308:return pc
        if op==0x43b8:pc+=2
        else:pc=branch(data,pc)
    raise AssertionError('native G03 common STR R0,[R1,#30] not bound')


def control_field(stage,c,state_cell):
    site=c['site'];store=field_store(stage.original,c);address=0x04209030
    for state in range(256):
        for word in (0,0xffffffff,0x12345678,0xa55a9669):
            def case():
                old,new=pair(stage,site,{store+2},registers={1:address-0x30},memory=[(state_cell,bytes([state])),(address,struct.pack('<I',word))],
                    allow_writes=[(address,address+4)],observe_memory=[(address,4)],strict_reads=True)
                field=0 if state&0xc8==0xc8 or state==0xc7 or state>>6==1 else 0x30 if state>>6==3 else 0xc0
                expected=(word&~0xf0)|field
                require(old['memory'][str(address)]==struct.pack('<I',expected).hex(),'native G03 field policy differs')
                require(old['writes']==[(address,4,expected)],'native G03 write destination/order differs')
                return old,new
            stage.case([state,word],case)
    stage.result['native_store_join']=store;stage.result['preconditions']='R1 is a declared controller pointer; its caller producer is outside this local contract'


def arithmetic(stage,c,state_cell):
    site=c['site'];reverse=c['role']=='ReverseCalculation';coefficient=c['coefficient_continuation']
    join=branch(stage.original,coefficient+2)
    require(stage.original[join:join+4]==bytes.fromhex('0604360c'),'native low16 arithmetic join differs')
    literal_base=c['literals'][-1]['value'];mode=c['literals'][1]['value'] if reverse else None
    r5,r7=0x13579bdf,0x2468ace0
    for state in range(256):
        accepted=state&0xc8==0xc8 or state==0xc7
        values=(0,1,9,10,11,19,20,1000,65535) if accepted else (100,)
        for phase in (0,1,2,255) if reverse else (0,):
            for value in values:
                def case():
                    memory=[(state_cell,bytes([state])),(INPUT,struct.pack('<H',value))]
                    if mode is not None:memory.append((mode,bytes([phase])))
                    old,new=pair(stage,site,{join+4},registers={0:0x1357,4:INPUT,5:r5,6:0x12340000,7:r7},
                        memory=memory,strict_reads=True)
                    require(old['target']==join+4,'native arithmetic boundary differs')
                    if accepted:
                        if state&0xcc==0xcc:amount=23*(value//20);base=literal_base
                        elif reverse and (state==0xc7 and phase!=0 or state>>2==0x32 and phase==1):amount=9*(value//10);base=r5
                        else:amount=12*(value//10);base=r7
                        expected=(base-amount if reverse else base+amount)&0xffff
                        require(old['registers'][6]==expected,'native G04/G05 integer/low16 policy differs')
                    return old,new
                # Non-high-layer states leave via the restoring epilogue; do
                # not execute it with an invented enclosing caller frame.
                if not accepted:
                    # The unconditional branch immediately after low16 join
                    # is shared by the native rejection route.
                    def fallback():
                        memory=[(state_cell,bytes([state])),(INPUT,struct.pack('<H',value))]
                        if mode is not None:memory.append((mode,bytes([phase])))
                        target=branch(stage.original,join+4)
                        return pair(stage,site,{join+4,target},registers={0:0x1357,4:INPUT,5:r5,6:0x12340000,7:r7},memory=memory,strict_reads=True)
                    stage.case([state,phase,value,'native-fallback'],fallback)
                else:stage.case([state,phase,value],case)
    stage.result['declared_operands']={'input_halfword':INPUT,'r5':r5,'r7':r7,'mode_cell':mode,'mode_values':[0,1,2,255] if reverse else []}
    stage.result['coverage_gaps'].append('Arithmetic entered with declared inherited bases/measurement and phase byte; enclosing producers, phase transitions and final controller sink remain unexecuted')


def parameter(stage,c,state_cell):
    site=c['site'];end=site+c['length'];register_variant=c['variant']=='modern_register_variant'
    controller=c['literals'][1]['value'];flag=c['literals'][2]['value'];table=c['literals'][3]['value']
    store=int.from_bytes(stage.original[end-2:end],'little')
    require(store&0xf800==0x6000 and store&7==0,'native G06 final word-store ABI differs')
    address=controller+((store>>6)&31)*4
    require(table+16<=len(stage.original),'native G06 lookup table out of held image')
    fallback=c['edges'][0]['target']
    for state in range(256):
        arguments=(0,0x10,0xc0,0xd0,0xff0,0x1000) if state in (0xc0,0xc7,0xc8,0xcc) else (0x10,)
        for flag_value,word,argument in [(f,w,a) for f in (0,0x1f,0x20,0xdf,255)
                                       for w in (0,0xffffffff,0x12345678,0xa55a9669) for a in arguments]:
                def case():
                    old,new=pair(stage,site,{end,fallback},registers={0:argument},memory=[(state_cell,bytes([state])),
                        (flag,bytes([flag_value])),(address,struct.pack('<I',word))],allow_writes=[(address,address+4)],observe_memory=[(address,4)],strict_reads=True)
                    if state>>6==3:
                        special=(state&0xc8==0xc8 or state==0xc7) and bool(flag_value&0x20)
                        nibble=2 if special else stage.original[table+min((argument>>4)&255,12)]&15
                        expected=(word&~15)|nibble
                        require(old['target']==end and old['writes']==[(address,4,expected)],'native G06 nibble/store policy differs')
                    else:require(old['target']==fallback and not old['writes'],'native G06 non-media fallback changed')
                    return old,new
                stage.case([state,flag_value,word,argument],case)
    stage.result['native_input_cells']={'controller_word':address,'flag':flag,'held_table':table,
        'index_policy':'min((argument>>4)&255,12)','special_low_nibble':2}


def disc_information(stage,c,state_cell):
    site=c['site'];end=site+c['length'];variant=c['variant'];flagged=variant!='modern';flag=c['literals'][0]['value'] if flagged else None
    # The source grammar owns SP+40h; these are post-acquisition parser bytes.
    for identifier in b'UOW?':
        for density in (0,1,5,255):
            for layers in (1,2,3,4):
                def case():
                    raw=bytearray(16);raw[8]=identifier;raw[10]=layers<<4;raw[11]=density
                    memory=[(STACK+0x40,bytes(raw)),(state_cell,b'\xc0')]
                    if flag is not None:memory.append((flag,b'\x00'))
                    allowed=[(state_cell,state_cell+1)]+([(flag,flag+1)] if flag is not None else [])
                    stops={e['target'] for e in c['edges'] if not site<=e['target']<end}|{end}
                    old,new=pair(stage,site,stops,registers={5:state_cell},memory=memory,allow_writes=allowed,
                        observe_memory=[(state_cell,1)]+([(flag,1)] if flag is not None else []),strict_reads=True)
                    if flag is not None:require(old['memory'][str(flag)]==('01' if identifier==ord('U') else '00'),'native U-marker producer order differs')
                    if identifier==ord('U') and density==5 and layers in (2,3):
                        expected=0xc7 if layers==2 else 0xc8
                        actual=int(old['memory'][str(state_cell)],16)
                        require(old['registers'][0]==expected or actual==expected,'native U/5 layer classification differs')
                    return old,new
                stage.case([identifier,density,layers],case)
    stage.result['coverage_gaps'].append('Native identifier/format/layer admission slice after attribute/acquisition predicates; later shared format/layer stores and complete parser caller are outside this stage')


def compare(role,original,modified,engine,base,contracts):
    c=next(x for x in contracts['roles'] if x['role']==role)
    stage=Stage('native:'+role,original,modified or original,engine,base);stage.actual_final_bin=modified is not None
    stage.result['final_bin_compared']=stage.actual_final_bin
    require(c['status']=='source-bound' and c['selects_c7'] is True,'native role is not independently bound with C7')
    require(contracts['state'] is not None,'native media-state roles disagree')
    fn={'DiscInformation':disc_information,'ControlBit':control_bit,'ControlField':control_field,
        'ForwardCalculation':arithmetic,'ReverseCalculation':arithmetic,'ParameterNibble':parameter}[role]
    fn(stage,c,contracts['state'])
    stage.result['source_contract']=c
    result=stage.finish();required=set()
    for e in c['edges']:
        ins=next(DECODER.disasm(original[e['instruction']:e['instruction']+4],e['instruction'],count=1))
        if ins.mnemonic in CONDITIONAL:required.update(((ins.address,e['target']),(ins.address,ins.address+ins.size)))
    observed=set(map(tuple,result['original_edges']))
    result['bound_region_conditional_edges']={'required':sorted(required),'unvisited':sorted(required-observed)}
    result['full_native_role_workflow_qualified']=False
    return result
