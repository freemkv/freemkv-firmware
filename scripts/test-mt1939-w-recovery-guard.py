#!/usr/bin/env python3
"""Execute the reference OEM guard, stopping before either native continuation."""
import argparse
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_CPSR, UC_CPU_ARM_926


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--hoard', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source_hash = '40eb760e23f100d55e86e9c061c73428d4087ef712294e4dbfcefa3093837a1a'
    rows = json.loads(args.inventory.read_text())['images']
    row = next(row for row in rows if row['sha256'] == source_hash)
    source = (args.hoard / row['path']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == source_hash
    start, call, bypass = 0x14D7B6, 0x14D7C8, 0x14D7CE
    assert source[start:call] == bytes.fromhex(
        '7d480078002807d18448007800090f2802d1'
    )
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, len(source))
    cpu.mem_write(0, source)
    cpu.mem_map(0x01FF0000, 0x20000)
    trace = []

    def stop(machine, address, size, data):
        trace.append(address)
        if address in (call, bypass):
            machine.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, stop)
    counts = {'call': 0, 'bypass': 0}
    digest = hashlib.sha256()
    for state in range(256):
        for context in range(256):
            trace.clear()
            cpu.mem_write(0x01FF9DD3, bytes([state]))
            cpu.mem_write(0x02000DDC, bytes([context]))
            cpu.reg_write(UC_ARM_REG_R0, 0xDEADBEEF)
            cpu.reg_write(UC_ARM_REG_CPSR, 0x20)
            cpu.emu_start(start | 1, 0, count=16)
            wanted = call if context == 0 and state >> 4 == 15 else bypass
            assert trace[-1] == wanted, (state, context, trace)
            counts['call' if wanted == call else 'bypass'] += 1
            digest.update(bytes([state, context]))
            digest.update(b''.join(at.to_bytes(4, 'little') for at in trace))
    receipt = {
        'scope': 'actual OEM guard only; stops before native recovery call or '
                 'bypass; no callee/optical qualification',
        'input_sha256': source_hash,
        'entry': start,
        'call_site': call,
        'bypass': bypass,
        'cases': 65536,
        'counts': counts,
        'trace_sha256': digest.hexdigest(),
        'c7_c8_enter_recovery': False,
        'all_cases_pass': True,
    }
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
