"""Execute positively matched stock DI identifier gates, without a drive.

Input is mtk_uhd_scan JSON. The native BD prefix/attribute checks are assumed
complete. Stop at the first media-state store or the gate's outgoing edge.
This isolates identifier/density admission; it is not complete DI parsing,
acquisition, readiness, authentication or sector-reading evidence.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg


def execute(data, area, state_cell, identifier, density, layers):
    start, end = area['site'], area['site'] + area['length']
    first, load = struct.unpack_from('<HH', data, start)
    # Reviewed layouts bind ADD r3,SP,#imm (or MOV r3,SP) followed
    # by a byte load from the native DI identifier offset.
    if (first & 0xff00 != 0xab00 and first != 0x466b) or load & 0xf838 != 0x7818:
        return {'status':'unhandled_test_layout'}
    stack_block = 0 if first == 0x466b else (first & 255) * 4
    identity_offset = (load >> 6) & 31
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
    for base, size in ((0, 0x200000), (0x01ff0000, 0x30000), (0x03000000, 0x10000)):
        cpu.mem_map(base, size)
    cpu.mem_write(0, data)
    cpu.mem_write(state_cell, b'\xc0')
    sp = 0x03008000
    cpu.mem_write(sp + stack_block + identity_offset - 4, b'BD')
    cpu.mem_write(sp + stack_block + identity_offset,
        bytes([identifier, 0, layers << 4, density]))
    # Only a region is executed. Supply its established state-pointer register;
    # scratch registers are overwritten by native gate instructions.
    for index in range(13):
        cpu.reg_write(getattr(reg, f'UC_ARM_REG_R{index}'), state_cell)
    cpu.reg_write(reg.UC_ARM_REG_SP, sp)
    result = {'status':'outgoing_edge', 'state_store':None, 'exit':None}

    def code(c, at, size, _user):
        if not start <= at < end:
            op = int.from_bytes(data[at:at+2], 'little')
            # The reviewed U/C7 edge can join a nearby shared native STRB.
            # Execute only that store if its runtime address agrees.
            is_state_store = (op & 0xf800 == 0x7000 and
                c.reg_read(getattr(reg, f'UC_ARM_REG_R{(op >> 3) & 7}')) + ((op >> 6) & 31) == state_cell)
            if not is_state_store or not start - 32 <= at < end + 128:
                result['exit'] = at
                c.emu_stop()

    def write(c, _access, at, size, value, _user):
        if at == state_cell:
            assert size == 1
            result.update(status='state_assigned', state_store=value,
                exit=c.reg_read(reg.UC_ARM_REG_PC))
            c.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    cpu.emu_start(start | 1, 0x200000, count=1000)
    assert result['exit'] is not None
    assert cpu.reg_read(reg.UC_ARM_REG_SP) == sp
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for row in json.loads(args.scan.read_text())['images']:
        area = next(a for a in row['uhd_code']['areas'] if a['role'] == 'DiscInformation')
        if area['evidence'] == 'unknown':
            continue
        data = Path(row['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        cases = []
        for identity, density, layers in ((ord('U'),5,2),(ord('U'),5,3),
                (ord('U'),5,1),(ord('U'),5,4),(ord('O'),1,2),(ord('?'),5,2)):
            actual = execute(data, area, row['uhd_code']['state_cell'], identity, density, layers)
            if actual['status'] == 'unhandled_test_layout':
                break
            if identity == ord('U') and density == 5 and layers in (2,3):
                if area['evidence'] == 'explicit_u_or_c7':
                    assert actual['state_store'] == {2:0xc7,3:0xc8}[layers], (row['sha256'], actual)
                else:
                    assert actual['state_store'] is None, (row['sha256'], actual)
            cases.append({'identifier':chr(identity),'density':density,'layers':layers,**actual})
        rows.append({'source_sha256':row['sha256'],'model':row['model'],
            'gate_variant':area['variant'],'site':area['site'],'cases':cases})
    args.output.write_text(json.dumps({'scope':__doc__,'cpu':'ARM926','images':rows},indent=2)+'\n')
    handled = sum(bool(r['cases']) for r in rows)
    print(f'PASS: {sum(len(r["cases"]) for r in rows)} native DI-gate cases across {handled} images; {len(rows)-handled} unhandled layouts; stage-only evidence')


if __name__ == '__main__':
    main()
