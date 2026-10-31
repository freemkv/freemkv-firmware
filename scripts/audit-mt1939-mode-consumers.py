"""Audit the held C7 mode selector's consumers without drive access.

Execute actual classic and BU40N position functions. Controller busy bits are
idle and arithmetic results are fixed synthetic values: operand programming,
branch choices and output scaling are verified, not hardware mathematics or
physical disc detection. Exact-literal inventory is not a complete alias proof.
"""
import argparse
import importlib.util
import sys
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm_const as r

DONE = 0x1fe000
SYNTHETIC_RESULT = 0x12345670
sys.dont_write_bytecode = True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def literal_refs(data, value):
    result = []
    for at in range(0, len(data) - 2, 2):
        op = struct.unpack_from('<H', data, at)[0]
        if op & 0xf800 != 0x4800:
            continue
        pool = ((at + 4) & ~3) + (op & 255) * 4
        if pool + 4 <= len(data) and struct.unpack_from('<I', data, pool)[0] == value:
            result.append({'instruction': at, 'literal_pool': pool, 'register': (op >> 8) & 7})
    return result


def position(data, entry, state_cell, mode_cell, state, mode, value):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(r.UC_CPU_ARM_926)
    for base, length in ((0, 0x200000), (0x01ff0000, 0x20000), (0x03000000, 0x10000), (0x04042000, 0x1000)):
        cpu.mem_map(base, length)
    cpu.mem_write(0, data)
    cpu.mem_write(state_cell, bytes([state]))
    cpu.mem_write(mode_cell, bytes([mode]))
    cpu.mem_write(0x02000b40, struct.pack('<I', value))
    cpu.mem_write(0x02000b30, struct.pack('<I', value))
    for index in range(13):
        cpu.reg_write(getattr(r, f'UC_ARM_REG_R{index}'), 0x76540000 + index * 0x101)
    cpu.reg_write(r.UC_ARM_REG_R0, value)
    cpu.reg_write(r.UC_ARM_REG_SP, 0x03008000)
    cpu.reg_write(r.UC_ARM_REG_LR, DONE | 1)
    saved = [cpu.reg_read(getattr(r, f'UC_ARM_REG_R{i}')) for i in range(4, 8)]
    writes = []

    def read(c, _access, at, size, _value, _user):
        if at == 0x04042018:
            c.mem_write(at, bytes(size))
        elif at == 0x04042010:
            c.mem_write(at, struct.pack('<I', SYNTHETIC_RESULT))

    def write(_c, _access, at, size, value, _user):
        if at in (0x04042010, 0x04042014, 0x04042018):
            writes.append({'address': at, 'bytes': size, 'value': value})

    cpu.hook_add(UC_HOOK_MEM_READ, read)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user: c.emu_stop() if at == DONE else None)
    cpu.emu_start(entry | 1, DONE, count=10000)
    assert cpu.reg_read(r.UC_ARM_REG_PC) == DONE
    assert cpu.reg_read(r.UC_ARM_REG_SP) == 0x03008000
    assert [cpu.reg_read(getattr(r, f'UC_ARM_REG_R{i}')) for i in range(4, 8)] == saved
    return {'writes': writes, 'returned': cpu.reg_read(r.UC_ARM_REG_R0)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    original, candidate, reference = (f.read_bytes() for f in (args.original, args.candidate, args.reference))
    assert digest(original) == '43c484dccc37ccb36183e970c5a4f28e90d6ccb530c0efd3bd8f96943ba7dfe3'
    assert digest(candidate) == '618ebd55cd109ba37188ab0d4e294c66d73d51f3eb5ee43fb64a1b972616285a'
    assert digest(reference) == '221ad35b7edd402353e125841893ce651064e8fc6b90368fe84ff19a85a506f4'
    # Held-image landmarks, independently pinned above; no patch is selected here.
    assert candidate[0xfcc30:0xfccca] == original[0xfcc30:0xfccca]
    table = 0x1a7934
    rows = []
    for mode in (0, 7, 14, 21, 28):
        row = original[table + mode:table + mode + 7]
        assert len(row) == 7
        rows.append({'offset':mode, 'record':row.hex(),
            'first_u24_be':int.from_bytes(row[:3], 'big'),
            'second_u24_be':int.from_bytes(row[3:6], 'big'), 'last_byte':row[6]})
    cases = []
    for mode in (7, 28):
        for value in (0, 1, 255, 0x1000, 0x12345, 0x1b0000, 0x800000, 0xffffff):
            outputs = {}
            for name, data, entry, state_cell, mode_cell in (
                ('classic_oem', original, 0xfcc30, 0x01ff9dd3, 0x01ffa20d),
                ('mode_candidate', candidate, 0xfcc30, 0x01ff9dd3, 0x01ffa20d),
                ('bu40n_oem', reference, 0xd8022, 0x01ff9e04, 0x01ffa395)):
                outputs[name] = {str(state):position(data, entry, state_cell, mode_cell, state, mode, value)
                    for state in (0xc7, 0xc8)}
            assert outputs['mode_candidate'] == outputs['classic_oem']
            assert outputs['bu40n_oem']['199'] == outputs['bu40n_oem']['200']
            c7, c8 = (outputs['mode_candidate'][str(s)] for s in (0xc7, 0xc8))
            coefficient = next(x['second_u24_be'] for x in rows if x['offset'] == mode)
            assert c7['writes'][0]['value'] == coefficient
            assert c8['writes'][0]['value'] == coefficient >> 2
            assert c7['writes'][1]['value'] == (value << 3) & 0xffffffff
            assert c8['writes'][1]['value'] == ((value << 3) & 0xffffffff) >> 2
            assert c7['returned'] == SYNTHETIC_RESULT >> 4
            assert c8['returned'] == ((SYNTHETIC_RESULT << 1) & 0xffffffff) >> 4
            cases.append({'mode':mode, 'input':value, 'outputs':outputs})
    # Re-enter the real DI parent with a previously selected dense profile.
    # This isolates the pre-acquisition mode store; DI/hardware readiness is supplied.
    proof = json.loads(Path('internal/docs/audits/mt1939-initialization-mode-20261030.json').read_text())['candidate']
    spec = importlib.util.spec_from_file_location('detection', Path(__file__).with_name('test-mt1939-detection.py'))
    detection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detection)
    di_reentry = []
    for state, layers in ((0xc7, 2), (0xc8, 3)):
        machine = detection.machine(candidate, proof)
        cpu, _ = machine
        stores = []
        cpu.hook_add(UC_HOOK_CODE, lambda c, at, _size, _user:
            c.mem_write(0x01ffa20d, b'\x1c') if at == proof['entry'] else None)
        cpu.hook_add(UC_HOOK_MEM_WRITE, lambda c, _access, at, _size, value, _user:
            stores.append({'instruction':c.reg_read(r.UC_ARM_REG_PC), 'value':value}) if at == 0x01ffa20d else None)
        status, assigned, _ = detection.execute(machine, proof, ord('U'), 5, layers, 0, state, 1)
        final_mode = cpu.mem_read(0x01ffa20d, 1)[0]
        assert status == 0 and assigned == state
        assert final_mode == (7 if state == 0xc7 else 28)
        di_reentry.append({'initial_state':state, 'initial_mode':28, 'DI_status':status,
            'final_state':assigned, 'final_mode':final_mode, 'mode_stores':stores,
            'limit':'DI acquisition and readiness supplied; not a physical retry trace'})
    setup_cases = []
    for mode in (7, 28):
        for value in (0, 1, 255, 0x1000, 0x12345, 0x1b0000, 0x800000, 0xffffff):
            outputs = {}
            for name, data, entry, state_cell, mode_cell in (
                    ('classic_oem', original, 0xfcb24, 0x01ff9dd3, 0x01ffa20d),
                    ('mode_candidate', candidate, 0xfcb24, 0x01ff9dd3, 0x01ffa20d),
                    ('bu40n_oem', reference, 0xd7f04, 0x01ff9e04, 0x01ffa395)):
                outputs[name] = {str(state):position(data, entry, state_cell, mode_cell, state, mode, value)
                    for state in (0xc7, 0xc8)}
            assert outputs['mode_candidate'] == outputs['classic_oem']
            assert outputs['bu40n_oem']['199'] == outputs['bu40n_oem']['200']
            c7, c8 = (outputs['mode_candidate'][str(s)] for s in (0xc7, 0xc8))
            assert c8['writes'][0]['value'] == c7['writes'][0]['value'] >> 2
            assert c7['writes'][1]['value'] == value
            assert c8['writes'][1]['value'] == value >> 2
            # The third coefficient write supplies a later controller operation.
            terms = lambda out: [w['value'] for w in out['writes'] if w['address'] == 0x04042014]
            assert terms(c7)[2] == 10 and terms(c8)[2] == 20
            setup_cases.append({'mode':mode, 'input':value, 'outputs':outputs})
    result = {'scope':__doc__, 'source_sha256':digest(original), 'candidate_sha256':digest(candidate),
        'reference_sha256':digest(reference), 'mode_cell':0x01ffa20d,
        'exact_literal_references':literal_refs(original,0x01ffa20d),
        'table':table, 'record_bytes':7, 'mode_0x1c_row_index':4, 'records':rows,
        'position_cases':cases, 'position_setup_cases':setup_cases,
        'executions':(len(cases)+len(setup_cases))*6, 'di_reentry':di_reentry,
        'finding':'The current mode-only candidate still uses classic C7 input/output scaling; native BU40N treats C7 and C8 alike here. Selecting row0x1c alone does not establish equivalent downstream parameter use.'}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f'PASS: {(len(cases)+len(setup_cases))*6} native position/setup executions; confirmed unadapted classic C7 scaling and native BU40N C7/C8 parity; controller arithmetic simulated')


if __name__ == '__main__':
    main()
