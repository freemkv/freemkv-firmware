#!/usr/bin/env python3
"""Replay WH 1.V9's actual Thumb integrity gate; model only AES-CMAC hardware.

Requires unicorn==2.1.4 and pycryptodome. No device I/O.
Usage: python3 wh_v9_integrity_repro.py ORIGINAL.bin TARGET.bin [TARGET.bin ...]
This proves the integrity branch only, not successful physical programming.
"""
import sys, struct, json, hashlib
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
if len(sys.argv) < 3:
 raise SystemExit(__doc__)
rom=Path(sys.argv[1]).read_bytes()
if hashlib.sha256(rom).hexdigest() != '97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061':
 raise SystemExit('ROM must be the exact original WH16NS58 1.V9 image')
KEY=bytes.fromhex('BD209408E35E526A36235234434FE8AB')
STAGE=0x03000000

def run(path):
 image=Path(path).read_bytes();u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 for base,size in [(0,0x200000),(0x02000000,0x100000),(STAGE,0x300000),(0x04000000,0x100000)]:u.mem_map(base,size)
 u.mem_write(0,rom);u.mem_write(STAGE,image)
 u.mem_write(0x02000c34,struct.pack('<I',STAGE));u.mem_write(0x04002058,struct.pack('<I',1))
 u.reg_write(UC_ARM_REG_SP,0x02080000);u.reg_write(UC_ARM_REG_LR,0x101)
 result={'file':Path(path).name,'checks':[]}
 active={}
 def hook(uc,address,size,user):
  if address==0xcbb44: # Firmware logging only: no validation result is synthesized here.
   uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  if address==0x143dc0:
   active.clear();active.update(start=uc.reg_read(UC_ARM_REG_R0)-STAGE,end=uc.reg_read(UC_ARM_REG_R1)-STAGE,stored=uc.reg_read(UC_ARM_REG_R2)-STAGE)
  if address==0x143de0:
   # Real helper's alignment/range/overlap checks have already executed.
   start=active['start'];end=active['end'];stored=active['stored']
   data=bytes(uc.mem_read(STAGE+start,end-start+1));data=b''.join(data[i:i+16][::-1] for i in range(0,len(data),16))
   mac=CMAC.new(KEY,ciphermod=AES);mac.update(data)
   valid=mac.digest()[::-1]==bytes(uc.mem_read(STAGE+stored,16))
   result['checks'].append(dict(active,result=valid))
   # Substitute only the AES-CMAC hardware primitive, then restore its stack frame.
   sp=uc.reg_read(UC_ARM_REG_SP);saved=struct.unpack('<6I',uc.mem_read(sp,24))
   for reg,value in zip([UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7],saved[:5]):uc.reg_write(reg,value)
   uc.reg_write(UC_ARM_REG_SP,sp+24);uc.reg_write(UC_ARM_REG_R0,int(valid));uc.reg_write(UC_ARM_REG_PC,saved[5]);return
  if address==0x143eaa:
   result['rejected_check']=dict(active,pc=hex(address))
  if address==0x9d35a:
   result['sense']=[uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)];uc.emu_stop()
  if address==0x9d9a6:
   result['integrity_gate']='passed';uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook)
 u.emu_start(0x9d982|1,0x200000,count=100000)
 return result
for name in sys.argv[2:]:print(json.dumps(run(name),indent=2))
