"""Actual held three-boundary normalization worker and caller/store checks."""
import struct
from position import literal
from stages import DECODER, require, unchanged, branch


def normalize(value,e0,e1,e2):
    u=lambda x:x&0xffffffff
    if value<=e0:return value
    value=u(value-e0-1);base=u(0x03ffffff-e0);size=u(e1-base+1)
    if value<size:return u(value+base)
    value=u(value-size);base=u(0x07ffffff-e1);size=u(e2-base+1)
    if value<size:return u(value+base)
    return u(u(value-size)+u(0x0bffffff-e2))


def full_worker(stage,helper,contract):
    accept=contract['accept'];site=helper['site']
    state=literal(stage.original,contract['region_start'],1)
    word=literal(stage.original,accept,1)
    require(state==contract['state'] and literal(stage.original,accept+8,1)==word,
            'ReadValue caller state/working-word provenance differs')
    require(stage.original[accept+2:accept+4]==bytes.fromhex('0868') and
            stage.original[accept+10:accept+12]==bytes.fromhex('0860'),
            'ReadValue load/store source operands differ')
    call=next(DECODER.disasm(stage.original[accept+4:accept+8],accept+4,count=1))
    require(call.mnemonic in ('bl','blx'),'ReadValue held worker call missing')
    worker=int(call.op_str.lstrip('#'),0)
    if call.mnemonic=='blx':
        require(stage.original[worker:worker+4]==bytes.fromhex('04f01fe5'),'ReadValue ARM veneer not bound')
        target=int.from_bytes(stage.original[worker+4:worker+8],'little')
        require(target&1==1,'ReadValue worker is not held Thumb code');worker=target&~1
    e0=literal(stage.original,worker,2);e1=literal(stage.original,worker+0x12,3);e2=literal(stage.original,worker+0x26,3)
    require(e1==e0+4 and e2==e1+4,'ReadValue boundary source cells differ')
    require([literal(stage.original,worker+off,2) for off in (0x10,0x24,0x38)]==[0x03ffffff,0x07ffffff,0x0bffffff],
            'ReadValue native three-boundary masks changed')
    require(stage.original[worker+0x3e:worker+0x40]==bytes.fromhex('7047'),'ReadValue native worker return changed')
    end=branch(stage.original,accept+12);thresholds=(0x1000000,0x4000000,0x8000000)
    for state_value in (0xc7,0xc8,0xc4,0):
        for setting in (0,1,2,255):
            for value in (0,0xffffff,0x1000000,0x1000001,0x2000002,0x2000003,0x6000004,0x6000005,0xffffffff):
                def case():
                    active=state_value==0xc7 and setting==1
                    old_state=0xc8 if active else state_value
                    kw=dict(settings={3:setting},memory=[(state,bytes([old_state])),(word,struct.pack('<I',value)),
                        (e0,struct.pack('<3I',*thresholds))],registers={0:0xc8,1:old_state},
                        allow_writes=[(word,word+4)],observe_memory=[(word,4)],strict_reads=True)
                    old=stage.execute(False,site,{end},**kw)
                    kw['memory'][0]=(state,bytes([state_value]));kw['registers'][1]=state_value
                    new=stage.execute(True,site,{end},**kw)
                    require(old['memory']==new['memory'],'native ReadValue caller store changed')
                    unchanged(old,new)
                    if active or state_value==0xc8:
                        require(int.from_bytes(bytes.fromhex(new['memory'][str(word)]),'little')==normalize(value,*thresholds),
                                'ReadValue differs from independently reviewed native high-density normalization')
                    return old,new
                stage.case(['native-ReadValue-worker',state_value,setting,value],case)
    stage.result['full_ReadValue_source']={'worker':worker,'store_join':end,'word_cell':word,'boundary_cells':[e0,e1,e2],
        'declared_boundaries':list(thresholds),'native_c7_policy_reference':'648a16d0 native explicit C7 high-density path142826 calls14bbcc and branches around C4 leg',
        'limits':'Held worker/caller/store executes; acquisition and geometry producer/lifetime not established by declared boundaries'}
