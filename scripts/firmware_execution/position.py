"""Full native layer decoder oracle; no logging/controller service returns."""
from functools import lru_cache
import hashlib
from pathlib import Path
import struct
from stages import run, require, unchanged, DECODER

REFERENCE='1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396'


def literal(data,at,register):
    op=int.from_bytes(data[at:at+2],'little')
    require(op&0xf800==0x4800 and (op>>8)&7==register,'native position literal/register not bound')
    slot=((at+4)&~3)+(op&255)*4
    return int.from_bytes(data[slot:slot+4],'little')


@lru_cache(maxsize=1)
def native_oracle(hoard):
    paths=list(Path(hoard).rglob(REFERENCE+'.bin'));require(bool(paths),'native full-position oracle missing')
    data=paths[0].read_bytes();require(hashlib.sha256(data).hexdigest()==REFERENCE,'native position oracle source changed')
    require(data[0x848e4:0x848ee]==bytes.fromhex('002902d03978c72940d1'),'native C7 position admission changed')
    results={}
    for layer in range(4):
        for low in (0,0x1234,0x3fffff):
            value=(layer<<22)|low
            r=run(data,'MT1959',0x848e4,{0x849d0},0x0200fe00,
                registers={0:0x02000b04,1:8,4:0x02000b03,5:0x02000b40,6:0,7:0x01ff9e04},
                memory=[(0x02000b40,struct.pack('<I',value)),(0x02000b04,bytes([layer])),
                        (0x02000b03,bytes([layer])),(0x01ff9e04,b'\xc7')],
                allow_writes=[(0x02000b40,0x02000b44),(0x02000b03,0x02000b05)],
                observe_memory=[(0x02000b40,4),(0x02000b03,1),(0x02000b04,1)],strict_reads=True)
            results[layer,low]={'position':r['memory'][str(0x02000b40)],
                'decoded':r['memory'][str(0x02000b03)],'peer':r['memory'][str(0x02000b04)],
                'nzcv':r['nzcv'],'trace':r['trace']}
    return results


def full_decoder(stage,helper,contract,contracts):
    """Compare actual installed detour plus complete held native store suffix."""
    oracle=native_oracle(contracts['_hoard'])
    position_register=contract.get('position_register',4)
    require(position_register==4,'full position ABI variant not independently reviewed')
    entry=contract['site'] if 'site' in contract else helper['site']
    caller=entry-0x40
    peer=literal(stage.original,caller+0x3c,0)
    decoded=literal(stage.original,caller+0x3e,7)
    state=literal(stage.original,caller+0x32,6)
    position=literal(stage.original,caller+0x18,4)
    require(position==contract['position'] and state==contract['state'],'position source operand provenance differs')
    require(stage.original[caller+0x3a:caller+0x3c]==bytes.fromhex('0025'),'native zero-register definition changed')
    end=caller+0x124
    # The reviewed common join starts the next state-dependent range phase.
    require(stage.original[end:end+2]==bytes.fromhex('3078'),'native decoder/range join changed')
    calls={int(i.op_str.lstrip('#'),0) for i in DECODER.disasm(stage.original[helper['site']:end],helper['site'])
           if i.mnemonic in ('bl','blx')}
    for setting in (0,1,2,255):
        for layer in range(4):
            for low in (0,0x1234,0x3fffff):
                def case():
                    active=setting==1
                    value=(layer<<22)|low
                    common=dict(settings={3:setting},registers={0:peer,1:0,4:position,5:0,6:state,7:decoded},
                        allow_writes=[(position,position+4),(peer,peer+1),(decoded,decoded+1)],
                        observe_memory=[(position,4),(peer,1),(decoded,1)],strict_reads=True,
                        boundary=lambda at:at in calls)
                    old_memory=[(state,b'\xc8' if active else b'\xc7'),(position,struct.pack('<I',value)),
                                (peer,bytes([layer])),(decoded,bytes([layer]))]
                    old_common=dict(common);old_common['registers']=dict(common['registers']);old_common['registers'][1]=0 if active else 8
                    old=stage.execute(False,helper['site'],{end},memory=old_memory,**old_common)
                    common['registers'][1]=8
                    new=stage.execute(True,helper['site'],{end},memory=[(state,b'\xc7'),*old_memory[1:]],**common)
                    require(new['memory']==old['memory'],'full C7 decoder stores differ from OEM native C8/OEM-off path')
                    require(new['target']==old['target'],'decoder/logging boundary changed')
                    unchanged(old,new)
                    if active:
                        require(new['target']==end,'active native decoder unexpectedly called an opaque logger')
                        expected=oracle[layer,low]
                        require(new['memory'][str(position)]==expected['position'] and
                                new['memory'][str(decoded)]==expected['decoded'] and
                                new['memory'][str(peer)]==expected['peer'],
                                'decoder differs from independent native UHD C7 position/layer oracle')
                        require(new['nzcv']==expected['nzcv'],'decoder NZCV differs from native UHD C7 oracle')
                    return old,new
                stage.case(['full-native-position-decoder',setting,layer,low],case)
    stage.result['full_native_position_oracle']={'source_sha256':REFERENCE,'entry':0x848e4,'stop':0x849d0,
        'source_decoder_join':end,'peer_layer_cell':peer,'decoded_layer_cell':decoded,
        'preconditions':'Both layer cells equal requested decoded layer; avoids genuine logging calls, no manufactured return',
        'reference_cases':[{'layer':layer,'low':low,**value} for (layer,low),value in oracle.items()]}
    stage.result['coverage_gaps'].append('Full native layer decode/store suffix only; subsequent range/controller lifecycle remains unexecuted')
