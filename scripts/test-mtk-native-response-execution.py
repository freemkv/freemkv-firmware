"""Execute selected native response writers/committers; do not stub their bodies.

Input contracts come from native_response_contract_corpus. This checks native
instruction execution and the host's selected buffer/ABI against an independent
CPU. It does not emulate a physical DMA controller or prove drive behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--contracts', type=Path, required=True)
parser.add_argument('--inventory', type=Path, required=True)
parser.add_argument('--hoard', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
inputs = {row['sha256']: row for row in json.loads(args.inventory.read_text())}
paths = {sha: row['path'] for sha, row in inputs.items()}
contracts = json.loads(args.contracts.read_text())
STACK = 0x03008000
RETURN = 0x0300F000
VIRTUAL = 0x00300000
SOURCE = 0x040300E8
LENGTH = 0x04042154
registers = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
results = []

for contract in contracts:
    assert contract['status'] == 'matched', contract
    for key, expected in inputs[contract['sha256']].get('expected', {}).items():
        assert contract[key] == expected, ('selected wrong native role', key, contract)
    source = args.hoard / paths[contract['sha256']]
    image = source.read_bytes()
    assert hashlib.sha256(image).hexdigest() == contract['sha256']
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, 0x200000)
    cpu.mem_write(0, image)
    cpu.mem_map(VIRTUAL, 0x400000)
    cpu.mem_map(0x02000000, 0x2000)
    cpu.mem_map(0x03000000, 0x10000)
    cpu.mem_map(0x04000000, 0x1000000)
    reached = []
    writes = []

    def visit(machine, address, _size, _data):
        if address == RETURN:
            reached.append(address)
            machine.emu_stop()

    def write(_machine, _access, address, size, value, _data):
        writes.append((address, size, value))

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)

    def execute(entry, arg0, arg1=0):
        reached.clear()
        writes.clear()
        before = [0x76540000 + i * 0x101 for i in range(13)]
        before[0], before[1] = arg0, arg1
        for register, value in zip(registers, before):
            cpu.reg_write(register, value)
        cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xA0000030)
        cpu.reg_write(reg.UC_ARM_REG_SP, STACK)
        cpu.reg_write(reg.UC_ARM_REG_LR, RETURN | 1)
        cpu.emu_start(entry | 1, 0x200000, count=512)
        assert reached == [RETURN], ('no native return', contract)
        assert cpu.reg_read(reg.UC_ARM_REG_SP) == STACK, ('unbalanced native stack', contract)
        assert [cpu.reg_read(r) for r in registers[4:12]] == before[4:12], ('native saved registers', contract)

    writer_cases = commit_cases = 0
    for physical in (0x00100000, 0x01000000):
        cpu.mem_write(contract['source_cell'], struct.pack('<I', physical))
        cpu.mem_write(contract['source_cell'] - 4, struct.pack('<I', VIRTUAL))
        for offset in (0, 1, 15, 31):
            for value in (0, 1, 0x80, 0xFF):
                address = VIRTUAL + ((physical + contract['buffer'] + offset) & 0xFFFFFF)
                cpu.mem_write(address - 1, b'\xA5\xA5\xA5')
                execute(contract['writer'], offset, value)
                assert cpu.mem_read(address - 1, 3) == bytes((0xA5, value, 0xA5)), ('wrong writer/buffer/width', contract, physical, offset, value, writes)
                writer_cases += 1
        for length in (0, 1, 15, 16, 0xFFFE, 0xFFFF):
            cpu.mem_write(contract['length_cell'], struct.pack('<H', length))
            cpu.mem_write(contract['ready_cell'], b'\x00')
            execute(contract['commit'], contract['buffer'])
            normalized = 0xFFFE if length == 0xFFFF else (length + 1) & ~1
            actual_source = struct.unpack('<I', cpu.mem_read(SOURCE, 4))[0]
            actual_length = struct.unpack('<I', cpu.mem_read(LENGTH, 4))[0]
            assert actual_source == physical + contract['buffer'], ('wrong DMA source', contract, physical, length, actual_source)
            assert actual_length == normalized, ('wrong DMA count', contract, physical, length, actual_length, normalized)
            assert cpu.mem_read(contract['ready_cell'], 1) == b'\x01', ('response not queued', contract)
            ordered = [address for address, _size, _value in writes if address in (SOURCE, LENGTH, contract['ready_cell'])]
            assert ordered[-1] == contract['ready_cell'] and SOURCE in ordered and LENGTH in ordered, ('queue-before-DMA', contract, ordered)
            commit_cases += 1
    results.append({'sha256': contract['sha256'], 'writer': contract['writer'], 'commit': contract['commit'],
                    'buffer': contract['buffer'], 'writer_cases': writer_cases, 'commit_cases': commit_cases,
                    'native_execution': 'passed'})

args.output.write_text(json.dumps({'scope': __doc__, 'inputs': results}, indent=2) + '\n')
print(f'PASS: {len(results)} native writer/committer pairs, {sum(r["writer_cases"] for r in results)} byte writes and {sum(r["commit_cases"] for r in results)} DMA queue cases')
