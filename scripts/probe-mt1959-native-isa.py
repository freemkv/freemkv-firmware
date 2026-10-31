import json,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg
import sys
sys.path.insert(0,'scripts/firmware_execution')
from cpu import thumb1_instruction
ROOT=Path(sys.argv[1]);OUTPUT=Path(sys.argv[2])
allrows=[]
for prefix in ('1bbe','5c01'):
 p=next(p for p in ROOT.iterdir() if p.is_dir() and p.name.startswith(prefix));data=(p/'original.bin').read_bytes();doc=json.loads((p/'modify.json').read_text());base=doc['execution_contracts']['base'];source=hashlib.sha256(data).hexdigest();record=doc['execution_contracts']['facts']['record_off'];assert data[record]==0x3c and struct.unpack_from('<I',data,record+4)[0]==base['original_handler']|1
 cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB);cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
 for a,n in ((0,0x200000),(0x01ff0000,0x40000),(0x03000000,0x10000)):cpu.mem_map(a,n)
 cpu.mem_write(0,data);initial=cpu.context_save();thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB);arm=Cs(CS_ARCH_ARM,CS_MODE_ARM)
 state={}
 def code(c,at,size,_):
  if at<0x10000:
   state['trace'].append({'at':at,'boundary':'opaque-resident-service'});state['stop']='opaque-resident-service';c.emu_stop();return
  thumb_mode=bool(c.reg_read(reg.UC_ARM_REG_CPSR)&32);opcode=bytes(c.mem_read(at,max(size,4)));ins=next((thumb if thumb_mode else arm).disasm(opcode,at,count=1),None)
  state['trace'].append({'at':at,'size':size,'thumb':thumb_mode,'bytes':opcode[:size].hex(),'mnemonic':None if ins is None else ins.mnemonic})
  if thumb_mode:
   prior=state.get('previous');suffix=(int.from_bytes(opcode[:2],'little')&0xf800 in (0xe800,0xf800) and prior==at-2 and int.from_bytes(c.mem_read(at-2,2),'little')&0xf800==0xf000)
   if not thumb1_instruction(opcode) and not suffix:state['isa_events'].append(state['trace'][-1].copy());state['stop']='native-instruction-exceeds-ARM926-Thumb-profile';c.emu_stop()
  state['previous']=at
 def read(c,access,at,size,value,_):
  if 0x10000<=at and at+size<=len(data):return
  if all(a in state['known'] for a in range(at,at+size)):return
  state.update(stop='unseeded-native-data-read',address=at,size=size,pc=c.reg_read(reg.UC_ARM_REG_PC));c.emu_stop()
 def write(c,access,at,size,value,_):
  if not (0x03007000<=at and at+size<=0x03009000):state.update(stop='non-stack-native-write',address=at,size=size);c.emu_stop()
  state['known'].update(range(at,at+size))
 cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_READ,read);cpu.hook_add(UC_HOOK_MEM_WRITE,write)
 for mode in range(32):
  for buffer_id in (0,1,15,32,128,255):
   cpu.context_restore(initial);cpu.mem_write(0x01ff0000,bytes(0x40000));cpu.mem_write(0x03000000,bytes(0x10000));cdb=bytes([0x3c,mode,buffer_id,0,0,0,0,0,64,0,0,0]);cpu.mem_write(base['cdb'],cdb)
   for i in range(13):cpu.reg_write(getattr(reg,f'UC_ARM_REG_R{i}'),0)
   cpu.reg_write(reg.UC_ARM_REG_CPSR,0x30);cpu.reg_write(reg.UC_ARM_REG_SP,0x03008000);cpu.reg_write(reg.UC_ARM_REG_LR,0x0300f001)
   state.clear();state.update(known=set(range(base['cdb'],base['cdb']+len(cdb))),trace=[],isa_events=[],stop='instruction-budget')
   try:cpu.emu_start(base['original_handler']|1,0x0300f000,count=10000)
   except Exception as error:state.update(stop='CPU-error',error=str(error))
   allrows.append({'source_sha256':source,'source_modify_report_sha256':hashlib.sha256((p/'modify.json').read_bytes()).hexdigest(),'registered_record':record,'registered_flags':data[record+1],'entry':base['original_handler'],'cdb':cdb.hex(),'model':'ARM926','arguments':'r0-r12 zero, supplied transport preconditions only','stop':state['stop'],'unmodeled_address':state.get('address'),'isa_events':state['isa_events'],'trace':state['trace']})
receipt={'schema':'source-native-mt1959-ordinary-isa-v1',
 'scope':'Unmodified registered READ BUFFER handler; stop before opaque resident service/unseeded RAM reads/global writes; no service-success replacement; supplied transport arguments only',
 'native_thumb2_support_proven':False,'native_armv6_instruction_proven':False,
 'physical_core_identity_qualified':False,
 'conclusion':'Bounded native prefixes supplied no higher-ISA evidence; this does not prove the silicon lacks Thumb2',
 'suite_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'thumb_guard_sha256':hashlib.sha256(Path('scripts/firmware_execution/cpu.py').read_bytes()).hexdigest(),
 'raw_decoder_counterexamples':{'0x5ca98':'word01ffb2ce looks like UXTB under linear Thumb decode','0x103140':'same pointer word01ffb2ce; not an executed-ISA proof'},
 'cases':allrows}
OUTPUT.write_text(json.dumps(receipt,indent=2))
from collections import Counter
print('cases',len(allrows),'stops',Counter(r['stop'] for r in allrows),'ISA events',sum(len(r['isa_events']) for r in allrows),'fetched',len({(r['source_sha256'],i['at']) for r in allrows for i in r['trace']}))
for r in allrows:
 if r['isa_events']:print(r['source_sha256'][:12],r['cdb'],r['isa_events'])
