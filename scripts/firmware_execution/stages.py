"""Reviewed bounded hook contracts. Native calls are observed, never replaced.

These contracts cover software decisions and argument/state at the next native
boundary. They do not assert what an opaque service or physical device does.
"""
import struct
import json
import hashlib
from functools import lru_cache

TRACE_SINK = None
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn import arm_const as reg
from cpu import Execution

REGS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
STOP, STACK = 0x0300f000, 0x03008000
DECODER = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
SETTINGS = (0, 1, 2, 255)


def require(value, text):
    if not value:
        raise AssertionError(text)


def branch(data, address):
    ins = next(DECODER.disasm(data[address:address+4], address, count=1))
    require(ins.mnemonic.startswith('b'), f'expected source branch at {address:#x}')
    return int(ins.op_str.lstrip('#'), 16)


@lru_cache(maxsize=2)
def machine_cache(data, engine, profile=None):
    execution=Execution(engine,profile);cpu=execution.machine(data)
    return execution,cpu,cpu.context_save(),[]


def run(data, engine, site, stops, flags, settings=None, registers=None,
        memory=(), allow_writes=(), boundary=None, allow_stack_delta=0,
        observe_memory=(), initial_nzcv=0xa0000000, strict_reads=False,cpu_profile=None,stop_thumb=True):
    execution,cpu,initial_context,dirty=machine_cache(data,engine,cpu_profile)
    # Restore each memory change, including seeded inputs and aborted writes.
    # No hardware service is replaced. Flash remains the actual supplied BIN.
    for address,previous in reversed(dirty):cpu.mem_write(address,previous)
    dirty.clear();cpu.context_restore(initial_context)
    execution.instructions.clear();execution.edges.clear()
    initial=[0x76540000+i*0x101 for i in range(13)]
    for number,value in (registers or {}).items():initial[number]=value
    for register,value in zip(REGS,initial):cpu.reg_write(register,value)
    cpu.reg_write(reg.UC_ARM_REG_CPSR,initial_nzcv|0x30)
    cpu.reg_write(reg.UC_ARM_REG_SP,STACK);cpu.reg_write(reg.UC_ARM_REG_LR,STOP|1)
    def seed(address,value):
        dirty.append((address,bytes(cpu.mem_read(address,len(value)))))
        cpu.mem_write(address,value)
    seed(flags,bytes([255]*7))
    for offset,setting in (settings or {}).items():seed(flags+offset,bytes([setting]))
    for address,value in memory:seed(address,value)
    reached,writes,trace=[],[],[]
    def visit(c,at,size,unused):
        trace.append(at)
        if at in stops or boundary is not None and boundary(at):reached.append(at);c.emu_stop()
    def write(c,access,address,size,value,unused):
        dirty.append((address,bytes(c.mem_read(address,size))))
        writes.append((address,size,value))
        require(STACK-0x100<=address and address+size<=STACK+allow_stack_delta
                or any(a<=address and address+size<=b for a,b in allow_writes),
                f'unintended memory write {address:#x}/{size}/{value:#x}')
    def read(c,access,address,size,value,unused):
        require(0<=address and address+size<=len(data)
                or STACK-0x100<=address and address+size<=STACK
                or flags<=address and address+size<=flags+7
                or any(a<=address and address+size<=a+len(b) for a,b in memory),
                f'unprovided native memory input {address:#x}/{size}')
    visit_hook=cpu.hook_add(UC_HOOK_CODE,visit);write_hook=cpu.hook_add(UC_HOOK_MEM_WRITE,write)
    read_hook=cpu.hook_add(UC_HOOK_MEM_READ,read) if strict_reads else None
    try:
        cpu.emu_start(site|1,STOP+2,count=2000)
        require(len(reached)==1,'instruction budget exhausted without proven boundary')
        require(cpu.reg_read(reg.UC_ARM_REG_CPSR)&0x00ffffff==(0x30 if stop_thumb else 0x10),'unexpected CPU control/Thumb state change at continuation')
    except Exception as error:
        error.execution_evidence={'trace':trace,'writes':writes,
            'cpu_profile':execution.cpu_model,
            'instructions':sorted(execution.instructions),'edges':sorted(execution.edges),
            'pc':cpu.reg_read(reg.UC_ARM_REG_PC),'cpsr':cpu.reg_read(reg.UC_ARM_REG_CPSR)}
        raise
    finally:
        cpu.hook_del(visit_hook);cpu.hook_del(write_hook)
        if read_hook is not None:cpu.hook_del(read_hook)
    return {'target':reached[0],'cpu_profile':execution.cpu_model,'registers':[cpu.reg_read(r) for r in REGS],
            'sp':cpu.reg_read(reg.UC_ARM_REG_SP),'lr':cpu.reg_read(reg.UC_ARM_REG_LR),
            'cpsr':cpu.reg_read(reg.UC_ARM_REG_CPSR),'nzcv':cpu.reg_read(reg.UC_ARM_REG_CPSR)&0xf0000000,
            'before':initial,'writes':writes,'trace':trace,
            'memory':{str(a):bytes(cpu.mem_read(a,n)).hex() for a,n in observe_memory},
            'instructions':set(execution.instructions),'edges':set(execution.edges)}


def unchanged(old, new, dead=(), flags=True, stack=True):
    for index in range(13):
        if index not in dead:
            require(old['registers'][index] == new['registers'][index], f'live r{index} changed')
    if flags:
        require(old['nzcv'] == new['nzcv'], 'native NZCV changed')
    if stack:
        require(old['sp'] == new['sp'], 'native SP changed')


class Stage:
    def __init__(self, name, original, modified, engine, base, root=None):
        self.name, self.original, self.modified = name, original, modified
        self.engine, self.base, self.root = engine, base, root
        self.result = {'stage':name, 'status':'passed', 'cases':0,
                       'original_instructions':set(), 'modified_instructions':set(),
                       'original_edges':set(), 'modified_edges':set(), 'coverage_gaps':[]}

    def case(self, key, function):
        self.case_executions=[]
        try:
            old, new = function()
            for prefix, execution in [('original',old),('modified',new)]:
                if execution:
                    self.result[prefix+'_instructions'].update(execution['instructions'])
                    self.result[prefix+'_edges'].update(execution['edges'])
            self.result['cases'] += 1
            if TRACE_SINK:
                evidence={'stage':self.name,'input':key,'status':'passed'}
                for name,item in [('original',old),('modified',new)]:
                    evidence[name]=None if item is None else {k:v for k,v in item.items() if k not in ('instructions','edges')}
                TRACE_SINK.write(json.dumps(evidence)+'\n')
        except Exception as error:
            self.result['status'] = 'failed'
            failure={'input':key,'error':str(error)}
            evidence=getattr(error,'execution_evidence',None)
            if evidence:
                failure['execution']=evidence
                prefix=evidence.get('image','modified')
                self.result[prefix+'_instructions'].update(evidence['instructions'])
                self.result[prefix+'_edges'].update(map(tuple,evidence['edges']))
            self.result.setdefault('failures',[]).append(failure)
            if TRACE_SINK: TRACE_SINK.write(json.dumps({'stage':self.name,'status':'failed','executions':self.case_executions,**failure})+'\n')

    def finish(self):
        for key, value in list(self.result.items()):
            if isinstance(value,set):
                self.result[key] = sorted(value)
        if self.root:
            try:
                execution = Execution(self.engine)
                execution.edges = set(map(tuple,self.result['modified_edges']))
                execution.instructions = set(self.result['modified_instructions'])
                self.result['generated_branch_coverage'] = execution.missing(self.modified,[self.root])
            except Exception as error:
                self.result['coverage_gaps'].append('generated CFG unresolved: '+str(error))
                if 'unsupported generated instruction' in str(error):
                    self.result['status']='failed'
                    self.result['generated_code_error']=str(error)
        for name,data in [('original',self.original),('modified',self.modified)]:
            windows={str(a):data[a:a+4].hex() for a in self.result[name+'_instructions']}
            self.result[name+'_fetched_instruction_windows_sha256']=hashlib.sha256(json.dumps(windows,sort_keys=True).encode()).hexdigest()
        return self.result

    def execute(self, patched, site, stops, **kwargs):
        try:
            result=run(self.modified if patched else self.original, self.engine, site,
                       stops, self.base['flags'], **kwargs)
            self.case_executions.append({'image':'modified' if patched else 'original',
                **{k:v for k,v in result.items() if k not in ('instructions','edges')}})
            return result
        except Exception as error:
            evidence=getattr(error,'execution_evidence',{})
            evidence['image']='modified' if patched else 'original'
            self.case_executions.append(evidence)
            raise


def compare_hook(name, original, modified, engine, contracts):
    facts, base = contracts['facts'], contracts['base']
    root = facts.get({'speed':'speed_stub_va','hrl':'hrl_stub_va','vid':'gatea_stub_va',
                      'boot':'boot_stub_va','ake':'ake_stub_va','deny-reset':'deny_stub_va',
                      'region':'region_stub_va','auth_cell':'auth_cell_stub_va'}.get(name,''))
    stage = Stage(name,original,modified,engine,base,root)
    if name.startswith('conversion:'):
        from conversion import compare
        c=next(c for c in contracts['media_conversion_helpers'] if c['site']==int(name.split(':')[1]))
        stage.root=c['target']
        compare(stage,c,contracts)
    elif name=='vendor-handler':
        root=base['handler'];site=root;stage.root=root
        end=root+base['handler_len'];native=base['original_handler'];writer=base['writer']
        stage.result['coverage_gaps'].append('Vendor tests stop at OEM handler/first response-writer call; later reply loops, commit, reset/save/flash/debug dispatch and opaque services remain unqualified')
        for mode in range(256):
            if mode==14:continue
            def case():
                memory=[(base['cdb'],bytes([0x3c,mode,0xc0,0xde,2,1,0,0,0,0]))]
                old=stage.execute(False,native,{native},memory=memory)
                new=stage.execute(True,site,{native},memory=memory)
                require(new['target']==native,'ordinary READ BUFFER fallback changed')
                unchanged(old,new,dead=(0,3),flags=False)
                require(new['lr']==old['lr'],'fallback LR changed')
                return old,new
            stage.case(['ordinary-mode',mode],case)
        for verb in (1,2,3,0,255):
            for feature in (0,1,2,3,4,5,6,7,255):
                for setting in SETTINGS if verb==2 else (255,):
                    def case():
                        cdb=bytes([0x3c,14,0xc0,0xde,verb,feature,setting,0,0,0])
                        old=stage.execute(False,native,{native},memory=[(base['cdb'],cdb)])
                        boundary=lambda at: not root<=at<end
                        new=stage.execute(True,site,{writer},memory=[(base['cdb'],cdb)],
                            allow_writes=[(base['flags'],base['flags']+7)],boundary=boundary)
                        require(new['target']==writer,'safe vendor prefix bypassed first native response writer')
                        writes=[(a,n,v) for a,n,v in new['writes'] if base['flags']<=a<base['flags']+7]
                        expected=[(base['flags']+feature,1,setting)] if verb==2 and 1<=feature<=6 else []
                        require(writes==expected,'safe SET bounds/state or non-SET state changed')
                        require(new['registers'][:2]==[0,0],'first native response writer arguments changed')
                        return old,new
                    stage.case(['safe-prefix',verb,feature,setting],case)
    elif name == 'auth_cell':
        c=contracts[name]; site=c['site']; stops={site+4,c['deny']}
        if c.get('native_refusal') is not None: stops.add(c['native_refusal'])
        for setting in SETTINGS:
            for band in tuple(range(16))+(255,):
                def case():
                    kw={'settings':{3:setting},'registers':{c['value_register']:band}}
                    old=stage.execute(False,site,{site+4,c['deny']},**kw)
                    new=stage.execute(True,site,stops,**kw)
                    if c.get('native_refusal') is not None:
                        expected=c['native_refusal'] if setting==0 and band==12 else old['target']
                    else: expected=c['deny'] if setting==0 else site+4 if setting==1 else old['target']
                    require(new['target']==expected,'authentication acceptance/refusal contract')
                    unchanged(old,new)
                    return old,new
                stage.case([setting,band],case)
    elif name in ('bd_site','uhd_site'):
        site=facts[name]
        stage.root=facts[name.replace('site','stub_va')]
        for setting in SETTINGS:
            for command_class in (0,1,2,3,4,12,255):
                for retired in (0,1,255):
                    def case():
                        kw={'settings':{3:setting,4:retired},'registers':{2:0x02001000},
                            'memory':[(0x02001007,bytes([command_class]))]}
                        old=stage.execute(False,site,{site+4},**kw)
                        new=stage.execute(True,site,{site+4},**kw)
                        unchanged(old,new,dead=(3,),flags=setting!=0)
                        require(old['registers'][0]==new['registers'][0]==command_class,'native CDB byte changed')
                        if setting==0: require(new['nzcv']&0x40000000==0,'Off accepted CDB class')
                        return old,new
                    stage.case([setting,command_class,retired],case)
        stage.result['scope']='CDB command class gate; not physical optical media classification'
    elif name == 'hrl':
        sites=[facts[k] for k in ('hrl_site','hrl_site2','hrl_site3') if facts.get(k)]
        for site in sites:
            deny=branch(original,site+2)
            for setting in SETTINGS:
                for value in (0,1,2,255,0xffffffff):
                    def case():
                        kw={'settings':{5:setting},'registers':{0:value}}
                        old=stage.execute(False,site,{site+4,deny},**kw)
                        new=stage.execute(True,site,{site+4,deny},**kw)
                        require(new['target']==(site+4 if setting==0 else old['target']),'HRL decision contract')
                        unchanged(old,new,flags=setting!=0)
                        return old,new
                    stage.case([site,setting,value],case)
    elif name=='speed':
        c=contracts['speed'];site=c['site']
        for setting in SETTINGS+(50,254):
            for value in (0,1,2,48,49,50,51,254,255,256,0xffffffff):
                for maximum in ((0,1,48,49,255) if c['variant']=='classic' else (0,)):
                    def case():
                        kw={'settings':{1:setting}}
                        if c['variant']=='classic':
                            kw.update(registers={0:value},memory=[(c['maximum_cell'],bytes([maximum]))])
                            old=stage.execute(False,site,{STOP},**kw)
                            new=stage.execute(True,site,{STOP},**kw)
                            expected=maximum if setting==1 and 0<maximum<=48 else value&255
                            require(new['registers'][0]==expected,'classic maximum selector contract')
                            unchanged(old,new,dead=(0,),flags=False)
                            require(new['lr']==old['lr'],'classic LR changed')
                        else:
                            kw['registers']={c['index']:value}; stops={c['fallthrough'],c['exit']}
                            old=stage.execute(False,site,stops,**kw);new=stage.execute(True,site,stops,**kw)
                            cap=255 if setting==1 else 50 if setting==255 else setting
                            require(new['target']==(c['exit'] if value>cap else c['fallthrough']),'ramp ceiling contract')
                            unchanged(old,new,dead=(c['index'],),flags=False)
                        return old,new
                    stage.case([setting,value,maximum],case)
    elif name=='region':
        site=facts['region_emitter']+6
        stage.result['scope']='Advertised OEM/free FIFO contract; other raw bytes are unsupported/experimental software diagnostics, not hardware region qualification'
        stage.result['advertised_choices']=contracts.get('advertised_boot_choices',{}).get('region',[])
        stage.result['advertised_settings']=[choice[2] for choice in stage.result['advertised_choices']]
        require(set(stage.result['advertised_settings'])=={1,255},'advertised region choices require a new independent contract')
        stage.result['experimental_contract_conflicts']=[]
        stage.result['coverage_gaps'].append('Forced-region contract conflict: ABI BD states 0x0a..0x0c are routed to OEM by the emitted <0x11 guard; source comments name 0x2a..0x2c instead. BootSettings exposes only OEM/free.')
        for setting in range(256):
            for mask in (0,0x55,255):
                def case():
                    frame=bytes([0,0,0,mask])+struct.pack('<II',0x12345678,STOP|1)
                    kw={'settings':{2:setting},'registers':{0:0x04001000,1:0,2:0xa5,4:1},
                        'memory':[(STACK,frame)],'allow_writes':[(0x04001008,0x04001009)],
                        'allow_stack_delta':12}
                    old=stage.execute(False,site,{STOP},**kw)
                    new=stage.execute(True,site,{STOP},**kw)
                    native=[v for a,n,v in old['writes'] if a==0x04001008]
                    actual=[v for a,n,v in new['writes'] if a==0x04001008]
                    if setting==1:expected=[0,0,0,0]
                    elif setting==0:expected=[0xa5,255,1,0]
                    elif 0x11<=setting<=0x18:expected=[0xa5,255^(1<<(setting-0x11)),1,0]
                    else:expected=native
                    if 0x0a<=setting<=0x0c:
                        legacy=[0xa5,1<<(setting-0x0a),1,0]
                        if actual!=legacy:stage.result['experimental_contract_conflicts'].append({'setting':setting,'native_mask':mask,'legacy_abi_expected':legacy,'actual':actual,'advertised':False})
                    require(actual==expected,'region response FIFO store sequence contract')
                    unchanged(old,new,dead=(2,),flags=False)
                    require(new['sp']==STACK+12,'region epilogue frame changed')
                    return old,new
                stage.case([setting,mask],case)
    elif name=='vid':
        site=facts['gatea_gate'];deny=branch(original,site+2)
        stage.result['coverage_gaps'].append('Encryption Off reaches native reset; reset effects and return path unqualified')
        for setting in SETTINGS:
            for value in (0,1,5,6,7,255):
                def case():
                    kw={'settings':{6:setting},'registers':{0:value}}
                    old=stage.execute(False,site,{site+4,deny},**kw)
                    # Observe the actual indirect call target; do not execute it
                    # against invented MMIO or manufacture its return.
                    boundary=lambda at: at not in (site,) and not root<=at<root+256 and at not in (site+4,deny)
                    new=stage.execute(True,site,{site+4,deny},boundary=boundary,**kw)
                    if setting!=0:
                        require(new['target']==old['target'],'VID OEM native decision changed');unchanged(old,new)
                    else:
                        require(base.get('native_reset') is not None and new['target']==base['native_reset'],'VID forced arm bypassed source-resolved native reset')
                        require(new['sp']==STACK-32,'VID reset stack alignment/frame')
                        require(new['sp']%8==0,'VID reset SP unaligned')
                    return old,new
                stage.case([setting,value],case)
    elif name=='boot':
        site=base['boot_site'];target=base['boot_target']
        stage.result['coverage_gaps'].append('Native initialization call and its return remain unexecuted; hardware/resident effects unknown')
        for seed in (0,0xffffffff,0x31415926):
            def case():
                kw={'registers':{i:seed+i for i in range(5)}}
                old=stage.execute(False,site,{target},**kw)
                marker=contracts.get('legacy_uhd_identity',{}).get('marker')
                allowed=[(base['flags'],base['flags']+7)]+([(marker,marker+1)] if marker is not None else [])
                if marker is not None:kw['memory']=[(marker,b'\xa5')];kw['observe_memory']=[(marker,1)]
                new=stage.execute(True,site,{target},allow_writes=allowed,**kw)
                if marker is not None:require(new['memory'][str(marker)]=='00','private U identity not cleared before native boot call')
                require(new['target']==old['target'],'native initialization target changed')
                unchanged(old,new,dead=(12,),flags=False,stack=False)
                require(new['sp']==STACK-8 and new['sp']%8==0,'boot native call frame')
                actual=[v for a,s,v in new['writes'] if base['flags']<=a<base['flags']+7]
                require(actual==base['defaults'],'boot settings differ from selected production defaults')
                return old,new
            stage.case(seed,case)
    elif name=='ake':
        site=facts['ake_site'];classic=original[site:site+2]==bytes.fromhex('8009')
        native=site+4 if classic else branch(original,site) if original[site:site+2]!=bytes.fromhex('0121') else branch(original,site+2)
        stage.result['initial_gate_scope']='Initial gate checks stop at native joins; appended setter/reset-prefix cases execute their independently qualified bodies'
        for setting in SETTINGS:
            for value,incoming in [(v,r) for v in (0,64,128,192,255)
                                   for r in ((1,) if classic else (1,6))]:
                def case():
                    kw={'settings':{6:setting},'registers':{0:value,1:incoming}}
                    old=stage.execute(False,site,{native},**kw)
                    boundary=lambda at: at!=site and not root<=at<root+256 and at!=native
                    new=stage.execute(True,site,{native},boundary=boundary,**kw)
                    if classic:
                        require(new['target']==native,'classic AKE native join')
                        require(new['registers'][0]==value>>6,'classic AKE AGID changed')
                        require(new['registers'][1]==(6 if setting==0 else 1),'classic AKE state contract')
                        unchanged(old,new,dead=(1,2),flags=False)
                    elif setting!=0:
                        require(new['target']==native,'AKE native setter changed')
                        unchanged(old,new,dead=(2,),flags=False)
                    else:
                        require(base.get('native_reset') is not None and new['target']==base['native_reset'],'AKE Off bypassed source-resolved native reset')
                    return old,new
                stage.case([setting,value,incoming],case)
        from ake_setter import compare_closed_setter,compare_reset_prefix
        compare_closed_setter(stage,facts,base)
        if original[site:site+2]!=bytes.fromhex('8009'):compare_reset_prefix(stage,facts,base)
    elif name=='deny-reset':
        site=facts['deny_site']
        def case():
            old=stage.execute(False,site,{site+4})
            boundary=lambda at: at!=site and not root<=at<root+128
            new=stage.execute(True,site,set(),boundary=boundary)
            require(base.get('native_reset') is not None and new['target']==base['native_reset'],'deny path bypassed source-resolved native reset')
            require(new['sp']==STACK-8,'deny reset call frame')
            return old,new
        stage.case('reset-boundary',case)
        # Independently enter the real post-call continuation with an explicit
        # ABI return-state input. This proves replay/pop, not service completion.
        continuation=next(i.address+i.size for i in DECODER.disasm(
            modified[root:root+16],root) if i.mnemonic=='blx')
        for seed in (0,0xffffffff,0x31415926):
            for cv in (0,0x10000000,0x20000000,0x30000000):
                def continuation_case():
                    registers={i:(seed+i)&0xffffffff for i in range(13)}
                    old=stage.execute(False,site,{site+4},registers=registers,initial_nzcv=cv)
                    frame=struct.pack('<II',registers[4],(site+4)|1)
                    new=stage.execute(True,continuation,{site+4},registers=registers,
                        initial_nzcv=cv,memory=[(STACK,frame)],allow_stack_delta=8,strict_reads=True)
                    unchanged(old,new,stack=False)
                    require(new['sp']==STACK+8,'deny continuation failed to restore saved frame')
                    require(new['registers'][1:3]==[0x6f,2],'deny sense arguments differ from OEM')
                    return old,new
                stage.case(['post-reset-ABI-continuation',seed,cv],continuation_case)
        stage.result['coverage_gaps'].append('Native reset completion remains external; post-call replay/return tested independently with declared ABI return-state inputs')
    else:
        stage.result['status']='unqualified'
        stage.result['coverage_gaps'].append('Installed hook lacks a qualified complete CPU contract')
    return stage.finish()
