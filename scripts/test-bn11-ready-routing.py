"""Bounded stock BN11 ready-store and READ-table tests; not an acquisition trace."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as r

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('source', type=Path)
p.add_argument('output', type=Path)
a = p.parse_args()
b = a.source.read_bytes()
sha = hashlib.sha256(b).hexdigest()
assert sha == '5c01c1fda59f3db130bd14aa64fe97d4010376798716b16792dbffd59c488a95'
c = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
c.ctl_set_cpu_model(r.UC_CPU_ARM_926)
c.mem_map(0, 0x200000)
c.mem_map(0x01ff0000, 0x20000)
c.mem_write(0, b)
stops = set()
seen = []
def hook(cpu, address, size, user):
    if address in stops:
        seen.append(address)
        cpu.emu_stop()
c.hook_add(UC_HOOK_CODE, hook)
initial = c.context_save()
state_cell, ready_cell = 0x01ff9e04, 0x01ffbd2a
for state in range(256):
    c.context_restore(initial)
    c.mem_write(0x01ff0000, bytes(0x20000))
    c.mem_write(state_cell, bytes([state]))
    c.reg_write(r.UC_ARM_REG_R4, state_cell)
    stops = {0x9e418, 0x9e422}
    seen.clear()
    c.emu_start(0x9e3f3, 0, count=100)
    accepted = state >> 4 in (0xc, 0xf)
    assert seen == [0x9e418 if accepted else 0x9e422], (state, seen)
    assert c.mem_read(ready_cell, 1)[0] == int(accepted), state

for state in range(256):
    for ready in (0, 1):
        c.context_restore(initial)
        c.mem_write(state_cell, bytes([state]))
        c.mem_write(ready_cell, bytes([ready]))
        stops = {0xa3f52, 0xa406c}
        seen.clear()
        c.emu_start(0xa3ff5, 0, count=100)
        assert len(seen) == 1, (state, ready)
        table = c.reg_read(r.UC_ARM_REG_R0)
        if not ready:
            assert table == 0x14ebdc and seen == [0xa3f52]
        elif state >> 6 == 3 and state >> 4 != 0xe:
            assert table == 0x14f184 and seen == [0xa3f52]
            opcode, handler = struct.unpack_from('<II', b, table)
            assert opcode & 255 == 0x28 and handler == 0xaddc1

result = dict(source_sha256=sha, cpu='ARM926', result='pass', cases=768,
    ready_store=hex(0x9e410), ready_cell=hex(ready_cell), read_handler=hex(0xaddc0),
    limits='Two independently entered stock blocks; no parser-to-ready call chain, resident bodies, final patched BIN, hardware or sector transfer proven.',
    preceding_resident_calls=[dict(site='0x9e2d6', veneer='0x147f3c', target='0x01f95864', state='Thumb'),
                              dict(site='0x9e2fa', veneer='0x147f44', target='0x01f9400c', state='Thumb')])
a.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
