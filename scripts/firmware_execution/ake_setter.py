"""Source-bound native AKE setter execution; no native service return is mocked.

The two runtime relocation cells are explicit input variables, not inferred from
patched output. We exercise both arithmetic wrap forms in the OEM setter and
compare exact permitted byte stores. This closes setter completion, not the
separate session-reset service used by Encryption Off.
"""
import struct

from stages import STACK, branch, require, run, unchanged


def half(data, at):
    return int.from_bytes(data[at:at+2], 'little')


def literal(data, at):
    op=half(data,at)
    require(op & 0xf800 == 0x4800, f'expected native literal load at {at:#x}')
    pool=((at+4)&~3)+(op&255)*4
    require(pool+4<=len(data),'native setter literal outside source image')
    return int.from_bytes(data[pool:pool+4],'little')


def setter_contract(original, facts):
    site=facts['ake_site']
    classic=half(original,site)==0x0980
    if classic:
        require(half(original,site+2)==0x2101,'classic AKE LSRS lacks native state writer')
        join=site+4
    elif half(original,site)==0x2101:
        join=branch(original,site+2)
        require(branch(original,site-6)==join,'AKE success and failure native joins differ')
    else:
        join=site
    require(half(original,join)&0xf800==0xf000 and
            half(original,join+2)&0xf800==0xf800,'AKE native join is not Thumb BL')
    setter=branch(original,join)
    common=[0x2802,0xd20c,None,0x1880,None,0x0400,0x6812,0x0c00,
            0x1810,None,0x0200,0x6812,0x0a00,0x1880,0x7001,0x4770]
    short=[0x2802,0xd20a,None,0x1880,None,0x6812,0x1810,None,
           0x0200,0x6812,0x0a00,0x1880,0x7001,0x4770]
    adjusted=[0x2802,0xd20b,None,0x3a3c,0x1880,None,0x6812,0x1810,
              None,0x0200,0x6812,0x0a00,0x1880,0x7001,0x4770]
    adjusted_common=[0x2802,0xd20d,None,0x3a3c,0x1880,None,0x0400,
                     0x6812,0x0c00,0x1810,None,0x0200,0x6812,0x0a00,
                     0x1880,0x7001,0x4770]
    shape=None
    for name,grammar in [('common',common),('short',short),('adjusted',adjusted),('adjusted_common',adjusted_common)]:
        if all(half(original,setter+2*i)==op if op is not None else
               half(original,setter+2*i)&0xff00==0x4a00
               for i,op in enumerate(grammar)):
            shape=name;break
    require(shape is not None,'unqualified native AKE setter operand grammar')
    offset=literal(original,setter+4)-(0x3c if shape in ('adjusted','adjusted_common') else 0)
    first=literal(original,setter+(10 if shape in ('adjusted','adjusted_common') else 8))
    second=literal(original,setter+{'common':18,'short':14,'adjusted':16,'adjusted_common':20}[shape])
    require(first!=second and all(0x01ff0000<=a<0x02040000 and a%4==0
                                 for a in (first,second)),
            'AKE relocation cells lack independent aligned RAM ownership')
    return {'site':site,'classic':classic,'join':join,'setter':setter,'shape':shape,
            'length':{'common':32,'short':28,'adjusted':30,'adjusted_common':34}[shape],
            'offset':offset,'first_cell':first,'second_cell':second}


def inputs(contract, agid, first=0xab00fffd, second=0x02003000, sentinel=0xa5):
    # The source performs these truncations before pointer addition. Choose
    # upper-bit and carry-sensitive inputs so removing either shift is visible.
    base_offset=contract['offset'] & (0xffff if contract['shape'] in ('common','adjusted_common') else 0xffffffff)
    first=(first-base_offset)&0xffffffff
    value=agid+contract['offset']
    if contract['shape'] in ('common','adjusted_common'):value &= 0xffff
    destination=((value+first)&0xffffff)+second
    require(0x01ff0000<=destination<0x02040000,
            'test relocation vector outside independently mapped RAM')
    memory=[(contract['first_cell'],struct.pack('<I',first)),
            (contract['second_cell'],struct.pack('<I',second)),
            (destination-2,bytes([sentinel]*5))]
    return destination,memory


def execute_setter(data, engine, flags, contract, agid, state, first=0xab00fffd):
    destination,memory=inputs(contract,agid,first)
    result=run(data,engine,contract['join'],{contract['join']+4},flags,
               registers={0:agid,1:state},memory=memory,
               allow_writes=[(destination,destination+1)],
               observe_memory=[(destination-2,5)],strict_reads=True)
    expected=[(destination,1,state)] if agid<2 else []
    stores=[w for w in result['writes'] if not STACK-0x100<=w[0]<STACK]
    require(stores==expected,'native AKE setter wrote wrong state, address or AGID bound')
    require(result['lr']==(contract['join']+4)|1,'native setter did not preserve BL return LR')
    require(result['sp']==STACK,'native AKE setter changed caller stack')
    expected_memory=bytes([0xa5,0xa5,state if agid<2 else 0xa5,0xa5,0xa5]).hex()
    require(result['memory'][str(destination-2)]==expected_memory,'native AKE setter changed adjacent state bytes')
    require(contract['setter'] in result['trace'],'native setter body was not executed')
    return result


def compare_closed_setter(stage, facts, base):
    """Append actual native-setter cases to an existing AKE Stage.

    Unknown source forms are reported as explicit gaps rather than succeeding
    by copying a patched contract. Native reset completion remains separate.
    """
    try:c=setter_contract(stage.original,facts)
    except AssertionError as error:
        stage.result['coverage_gaps'].append('Closed AKE setter source qualification: '+str(error))
        return
    stage.result['closed_ake_setter_contract']=c
    for agid in (0,1,2,3,255):
        for state in (0,1,6):
            for first in (0xab00fffd,0xcd000001):
                def case(agid=agid,state=state,first=first):
                    old=execute_setter(stage.original,stage.engine,base['flags'],c,agid,state,first)
                    # The NB hook replaces the native BL itself. Enter the held
                    # setter there via a source-owned BL in a scratch-free OEM
                    # desktop join only; NB is tested from its real hook below.
                    if c['join']==c['site']:
                        return old,None
                    new=execute_setter(stage.modified,stage.engine,base['flags'],c,agid,state,first)
                    unchanged(old,new);require(old['writes']==new['writes'],'held native AKE state writes changed')
                    return old,new
                stage.case(['native-setter',agid,state,first],case)
    # Actual installed detour, actual native BL and actual setter. NB uses the
    # original caller's existing LR and enters the leaf setter from its stub.
    for setting in ((0,1,2,255) if c['classic'] else (1,2,255)):
        for agid in ((0,1,2,3) if c['classic'] else (0,1,2,3,255)):
            for incoming in (1,6):
                def case(setting=setting,agid=agid,incoming=incoming):
                    dest,memory=inputs(c,agid)
                    stop=c['join']+4
                    kw=dict(registers={0:agid,1:incoming},memory=memory,
                            allow_writes=[(dest,dest+1)],observe_memory=[(dest-2,5)],strict_reads=True)
                    if c['classic']:
                        old=execute_setter(stage.original,stage.engine,base['flags'],c,agid,6 if setting==0 else 1)
                        kw['registers']={0:(agid<<6)|0x3f,1:incoming}
                    else:
                        old=stage.execute(False,c['site'],{stop},settings={6:setting},**kw)
                    new=stage.execute(True,c['site'],{stop},settings={6:setting},**kw)
                    unchanged(old,new,dead=(2,),flags=True)
                    native_stores=lambda result:[w for w in result['writes'] if not STACK-0x100<=w[0]<STACK]
                    require(native_stores(old)==native_stores(new),'installed AKE changed native state write')
                    require(old['memory']==new['memory'],'installed AKE changed state or neighbors')
                    require(new['lr']==stop|1,'installed AKE did not return through native BL continuation')
                    require(c['setter'] in new['trace'],'installed AKE skipped native setter body')
                    return old,new
                stage.case(['installed-native-setter',setting,agid,incoming],case)


def reset_prefix_contract(original, base):
    from stages import DECODER
    reset=base['native_reset']
    decoded=list(DECODER.disasm(original[reset:reset+0x100],reset))
    call=next((i for i in decoded if i.mnemonic=='bl'),None)
    require(call is not None,'reset lacks source-owned initial mailbox call')
    prefix=[i for i in decoded if i.address<call.address]
    require(all(i.mnemonic not in ('b','blx','bx','beq','bne','bhs','blo','bhi','bls')
                for i in prefix),'reset prefix contains unqualified branch')
    require(any(i.mnemonic=='lsls' and i.op_str=='r2, r2, #0x1a' for i in prefix),
            'reset MMIO base not source-owned MOV1/LSL26')
    callee=branch(original,call.address)
    body=list(DECODER.disasm(original[callee:callee+0x30],callee))
    linked=next((i for i in body if i.mnemonic=='blx'),None)
    require(linked is not None and 0< int(linked.op_str.lstrip('#'),0)<0x20000,
            'reset mailbox has no bounded linked-boot service call')
    before=[i for i in body if i.address<linked.address]
    require(all(i.mnemonic in ('push','movs','sub') for i in before),
            'mailbox pre-service instructions exceed qualified stack/argument setup')
    require(any(i.mnemonic=='movs' and i.op_str=='r0, #0xc0' for i in before),
            'mailbox service input selector not independently source-bound')
    addresses=[]
    for i in prefix:
        if half(original,i.address)&0xf800==0x4800:
            value=literal(original,i.address)
            if 0x01ff0000<=value<0x02040000:addresses.append(value)
    require(len(addresses)>=3,'reset RAM owners unqualified')
    # Merge literal-owned cells/structs explicitly. This is a variable input
    # state, not an arbitrary zero-page allowance or a mocked MMIO response.
    cells={a:0 for address in addresses for a in range(address,address+16)}
    memory=[]
    for address in sorted(cells):
        if memory and memory[-1][0]+len(memory[-1][1])==address:
            at,value=memory[-1];memory[-1]=(at,value+b'\x00')
        else:memory.append((address,b'\x00'))
    memory.append((0x04000000,bytes.fromhex('ffffffff')))
    return {'entry':reset,'mailbox':callee,'stop':linked.address,
            'linked_boot_service':int(linked.op_str.lstrip('#'),0),
            'memory':memory,'prefix_end':call.address+4}


def compare_reset_prefix(stage, facts, base):
    """Execute the real reset prefix from native and installed Off invocation.

    Stops before the real linked boot service instruction; no service result is
    substituted. The hook's saved AGID/LR frame and alignment are also checked.
    """
    try:c=reset_prefix_contract(stage.original,base)
    except AssertionError as error:
        stage.result['coverage_gaps'].append('AKE reset-prefix source qualification: '+str(error))
        return
    require(stage.original[c['entry']:c['prefix_end']]==stage.modified[c['entry']:c['prefix_end']],
            'installed output changed held reset prefix')
    require(stage.original[c['mailbox']:c['stop']+4]==stage.modified[c['mailbox']:c['stop']+4],
            'installed output changed held mailbox service prefix')
    stage.result['reset_prefix_contract']={k:v for k,v in c.items() if k!='memory'}
    allow=[(a,a+len(b)) for a,b in c['memory']]
    for agid in (0,1,2,3,255):
        for seed in (0,0x10,0xffffffff):
            def case(agid=agid,seed=seed):
                memory=[(a,struct.pack('<I',seed) if a==0x04000000 else b)
                        for a,b in c['memory']]
                kw=dict(settings={6:0},registers={0:agid,1:1},memory=memory,
                        allow_writes=allow,strict_reads=True)
                old=stage.execute(False,c['entry'],{c['stop']},**kw)
                new=stage.execute(True,facts['ake_site'],{c['stop']},
                    observe_memory=[(STACK-8,8)],**kw)
                unchanged(old,new,dead=(2,),stack=False)
                require(old['lr']==new['lr'],'Off reset native nested call LR changed')
                require(new['sp']==old['sp']-8 and new['sp']%8==0,
                        'Off reset nested frame or ABI alignment changed')
                saved=bytes.fromhex(new['memory'][str(STACK-8)])
                require(int.from_bytes(saved[:4],'little')==agid,'Off reset lost saved AGID')
                require(int.from_bytes(saved[4:],'little')==facts['ake_site']+5,
                        'Off reset did not save installed call LR')
                native=lambda result:[w for w in result['writes'] if not STACK-0x100<=w[0]<STACK]
                require(native(old)==native(new),'Off reset altered native RAM/MMIO prefix transactions')
                require(c['entry'] in new['trace'] and c['mailbox'] in new['trace'],
                        'Off path did not execute actual reset and mailbox prefix')
                return old,new
            stage.case(['actual-Off-reset-prefix',agid,seed],case)
