"""Trace a bound native operation-stage mode transition without running hardware.

The caller's R5 structure and R7 media-state pointer are supplied explicitly.
Stops at the selected native callee before executing it. This establishes stage
dispatch, not the units of the coordinate, full caller reachability or reading.
The enclosing caller is also checked for its actual R5 base and coordinate
fields. The native phase field must alias the numerical mode byte. Local flow
overapproximates branches and assumes calls preserve callee-saved R5. Unmatched
compiler layouts remain unresolved, never classified as absent.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP
from capstone.arm_const import ARM_REG_R5, ARM_OP_IMM
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg

STATE, FRAME, SP = 0x02001000, 0x03003000, 0x03008000


def half(data, at):
    return struct.unpack_from('<H', data, at)[0]


def target(data, at, mnemonic):
    i = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[at:at+4], at, count=1), None)
    assert i and i.mnemonic == mnemonic, (hex(at), i)
    return int(i.op_str.removeprefix('#'), 0)


def literal(data, at):
    op = half(data, at)
    assert op & 0xf800 == 0x4800
    return struct.unpack_from('<I', data, ((at+4)&~3)+(op&255)*4)[0]


def bind(data):
    found = []
    prefix = bytes.fromhex('0f00097849090729')
    at = data.find(prefix)
    while at >= 0:
        if at % 2 == 0 and half(data, at+8)&0xff00 == 0xd100:
            site = target(data, at+8, 'bne')
            if data[site:site+4] == bytes.fromhex('e87aac73'):
                found.append(site)
        at = data.find(prefix, at+1)
    if len(found) != 1:
        return None
    site = found[0]
    if half(data, site+4)&0xf800 == 0xf000:
        return {'site': site, 'variant': 'direct_driver',
                'driver': target(data, site+4, 'blx')}
    if data[site+4:site+18] != bytes.fromhex('38788008322802d03878c7280fd1'):
        return None
    coordinate_op = half(data, site+18)
    if coordinate_op&0xf83f != 0x682c or half(data, site+20) != coordinate_op-4:
        return None
    coordinate_offset = ((coordinate_op>>6)&31)*4
    phase_op = half(data, site+26)
    if phase_op&0xf83f != 0x7828:
        return None
    phase_offset = (phase_op>>6)&31
    assert half(data, site+22)&0xff00 == 0x4900
    assert half(data, site+24) == 0x4288
    assert data[site+30:site+34] == bytes.fromhex('002806d1')
    assert data[site+40:site+44] == bytes.fromhex('012801d1')
    assert half(data, site+48) == coordinate_op-0x800
    assert target(data, site+28, 'bhs') == site+40
    assert target(data, site+38, 'b') == site+48
    return {'site': site, 'variant': 'coordinate_phase_transition',
            'threshold': literal(data, site+22),
            'coordinate_offset': coordinate_offset, 'phase_offset': phase_offset,
            'enter': target(data, site+34, 'bl'),
            'leave': target(data, site+44, 'bl'),
            'driver': target(data, site+50, 'blx')}


def frame_flow(data, entry, site, expected):
    """Overapproximate native local branches; calls preserve callee-saved R5."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    pending, visited, bases = [(entry, None)], set(), set()
    while pending:
        pc, base = pending.pop()
        if (pc, base) in visited:
            continue
        visited.add((pc, base))
        assert len(visited) <= 4096, 'unbounded frame flow'
        if not entry <= pc < entry+0x2000:
            continue  # Native tail transfer outside this enclosing routine.
        if pc == site:
            bases.add(base)
        instruction = next(decoder.disasm(data[pc:pc+4], pc, count=1), None)
        assert instruction is not None, hex(pc)
        if instruction.mnemonic == 'pop' and 'pc' in instruction.op_str:
            continue
        if instruction.mnemonic == 'bx' and instruction.op_str == 'lr':
            continue
        if ARM_REG_R5 in instruction.regs_access()[1]:
            if instruction.size == 2 and half(data, pc)&0xff00 == 0x4d00:
                base = literal(data, pc)
            else:
                raise AssertionError(('unbound R5 definition', hex(pc), instruction.mnemonic, instruction.op_str))
        if instruction.group(CS_GRP_CALL):
            pending.append((pc+instruction.size, base))
        elif instruction.group(CS_GRP_JUMP):
            operands = [operand for operand in instruction.operands if operand.type == ARM_OP_IMM]
            assert len(operands) == 1, ('indirect local flow', hex(pc), instruction.op_str)
            pending.append((operands[0].imm, base))
            if instruction.mnemonic != 'b':
                pending.append((pc+instruction.size, base))
        else:
            pending.append((pc+instruction.size, base))
    assert bases == {expected}, bases
    return {'cfg_states': len(visited), 'stage_base': expected,
            'call_assumption': 'AAPCS callee-saved R5'}


def bind_frame(data, contract):
    # Bind the enclosing operation routine's actual R5 base, rather than
    # treating the phase byte as an unrelated caller-supplied structure.
    entries = []
    for entry in range(max(0, contract['site']-0x1000), contract['site'], 2):
        if data[entry:entry+4] != bytes.fromhex('f8b50700'):
            continue
        if half(data, entry+4)&0xff00 != 0x4800:
            continue
        at = entry+6
        if half(data, at)&0xff00 == 0x3800 or half(data, at)&0xfe3f == 0x1e00:
            at += 2
        if half(data, at)&0xf83f != 0x7800:
            continue
        if half(data, at+2) != 0x2401 or half(data, at+4)&0xff00 != 0x4d00:
            continue
        if half(data, at+6) != 0x2802:
            continue
        entries.append((entry, at+4))
    if not entries:
        contract['frame'] = None
        return
    assert len(entries) == 1, (contract['site'], entries)
    entry, base_load = entries[0]
    base = literal(data, base_load)
    assert 0x01ff0000 <= base < 0x02010000
    # Both lineages compare the returned/current coordinate pair. R2 is an
    # explicit alias of R5; infer the offsets from that downstream use.
    coordinate = []
    for at in range(contract['site'], contract['site']+0x200, 2):
        if data[at:at+4] != bytes.fromhex('2a000028'):
            continue
        if half(data, at+4)&0xff00 != 0xd100:
            continue
        if data[at+6:at+10] != bytes.fromhex('d078c007'):
            continue
        returned, requested = half(data, at+10), half(data, at+14)
        if returned&0xf83f != 0x6810 or requested&0xf83f != 0x6811:
            continue
        if half(data, at+12)&0xff00 != 0xd000:
            continue
        returned_offset = ((returned>>6)&31)*4
        requested_offset = ((requested>>6)&31)*4
        assert returned_offset == requested_offset+4
        coordinate.append((at, requested_offset, returned_offset))
    if not coordinate:
        contract['frame'] = None
        return
    assert len(coordinate) == 1, (contract, coordinate)
    use, requested, returned = coordinate[0]
    contract['frame'] = {'entry': entry, 'base_load': base_load, 'base': base, 'coordinate_use': use,
                         'requested_coordinate_offset': requested,
                         'returned_coordinate_offset': returned}
    contract['frame']['flow'] = frame_flow(data, entry, contract['site'], base)
    if contract['variant'] == 'coordinate_phase_transition':
        assert requested == contract['coordinate_offset']
        contract['frame']['phase_address'] = base+contract['phase_offset']


def bind_mode_producer(data, contract, areas, state):
    if contract['variant'] != 'coordinate_phase_transition':
        return
    reverse = next(a for a in areas if a['role'] == 'ReverseCalculation')
    cells = [v['value'] for v in reverse['literals']
             if 0x01ff0000 <= v['value'] < 0x02010000 and v['value'] != state]
    assert len(cells) == 1, cells
    # The reverse role also carries its media-state literal. The setter's
    # independently derived literal must select the other cell.
    pairs = []
    for at in range(contract['enter'], contract['enter']+0x180, 2):
        if data[at:at+2] != bytes.fromhex('1020') or data[at+6:at+10] != bytes.fromhex('05001120'):
            continue
        if half(data, at+2)&0xf800 != 0xf000 or half(data, at+10)&0xf800 != 0xf000:
            continue
        if data[at-2:at] != bytes.fromhex('0670') or half(data, at-4)&0xff00 != 0x4800:
            continue
        assert target(data, at+2, 'bl') == target(data, at+10, 'bl')
        cell = literal(data, at-4)
        assert cell in cells
        pairs.append({'store_site': at-2, 'mode_cell': cell,
                      'parameter_getter': target(data, at+2, 'bl')})
    assert len(pairs) == 1, (contract, pairs)
    contract['mode_producer'] = pairs[0]
    if contract['frame'] is not None:
        assert contract['frame']['phase_address'] == pairs[0]['mode_cell'], (contract, pairs)
    clears = []
    for at in range(contract['leave'], contract['leave']+0x100, 2):
        if half(data, at)&0xff00 == 0x4900 and data[at+2:at+6] == bytes.fromhex('00200870'):
            if literal(data, at) == pairs[0]['mode_cell']:
                clears.append(at+4)
    assert len(clears) == 1, (contract, clears)
    contract['mode_clear_store'] = clears[0]


class Stage:
    def __init__(self, data, contract):
        self.contract = contract
        self.result = None
        c = self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        c.ctl_set_cpu_model(reg.UC_CPU_ARM_926)
        for at, size in ((0, 0x200000), (0x02000000, 0x2000), (0x03000000, 0x10000)):
            c.mem_map(at, size)
        c.mem_write(0, data)
        self.stops = {contract[k]: k for k in ('enter', 'leave', 'driver') if k in contract}
        c.hook_add(UC_HOOK_CODE, self.step)
        c.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.initial = c.context_save()

    def step(self, c, at, size, user):
        if at in self.stops:
            self.result = self.stops[at]
            c.emu_stop()

    def write(self, c, access, at, size, value, user):
        assert (at, size) in ((FRAME+0xe, 1), (FRAME+self.contract.get('coordinate_offset', 0x3c), 4)), (at, size)

    def run(self, state, coordinate, phase):
        c = self.cpu
        c.context_restore(self.initial)
        self.result = None
        c.mem_write(FRAME, bytes(0x80))
        c.mem_write(STATE, bytes([state]))
        coordinate_offset = self.contract.get('coordinate_offset',
            self.contract['frame']['requested_coordinate_offset'] if self.contract.get('frame') else 0x3c)
        c.mem_write(FRAME+coordinate_offset, struct.pack('<I', coordinate))
        c.mem_write(FRAME+self.contract.get('phase_offset', 0x1a), bytes([phase]))
        c.reg_write(reg.UC_ARM_REG_R4, 0x12345678)
        c.reg_write(reg.UC_ARM_REG_R5, FRAME)
        c.reg_write(reg.UC_ARM_REG_R7, STATE)
        c.reg_write(reg.UC_ARM_REG_SP, SP)
        c.emu_start(self.contract['site']|1, 0x200000, count=64)
        assert self.result is not None
        return self.result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scan', type=Path, required=True)
    p.add_argument('--hoard', type=Path, required=True)
    p.add_argument('--scope', type=Path, help='explicit image inventory; select its full source rows')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    rows, count = [], 0
    sources = json.loads(a.scan.read_text())['images']
    if a.scope:
        scope = {row['sha256'] for row in json.loads(a.scope.read_text())['images']
                 if row.get('payload', 'full source') == 'full source'}
        sources = [row for row in sources if row['sha256'] in scope]
        assert len(sources) == len(scope) and {row['sha256'] for row in sources} == scope
    for source in sources:
        data = (a.hoard/source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == source['sha256']
        contract = bind(data)
        row = {'sha256': source['sha256'], 'contract': contract}
        if contract:
            bind_frame(data, contract)
            bind_mode_producer(data, contract, source['uhd_code']['areas'], source['uhd_code']['state_cell'])
            cpu = Stage(data, contract)
            threshold = contract.get('threshold', 0x1b640)
            cases = []
            for state in (0xc0, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xff):
                for coordinate in (0, threshold-1, threshold, threshold+1, 0xffffffff):
                    for phase in (0, 1, 255):
                        actual = cpu.run(state, coordinate, phase)
                        expected = 'driver'
                        if contract['variant'] == 'coordinate_phase_transition' and (state == 0xc7 or state>>2 == 0x32):
                            if coordinate < threshold and phase == 0:
                                expected = 'enter'
                            elif coordinate >= threshold and phase == 1:
                                expected = 'leave'
                        assert actual == expected, (source['sha256'], state, coordinate, phase, actual, expected)
                        cases.append({'state': state, 'coordinate': coordinate, 'phase': phase, 'callee': actual})
                        count += 1
            row['cases'] = cases
        rows.append(row)
    a.output.write_text(json.dumps({'scope': __doc__, 'cpu': 'ARM926', 'cases': count,
        'scan_sha256': hashlib.sha256(a.scan.read_bytes()).hexdigest(), 'images': rows}, indent=2)+'\n')
    print(f'PASS: {count} operation-stage cases; {sum(r["contract"] is not None for r in rows)} bound layouts; '
          f'{sum(r["contract"] is None for r in rows)} compiler layouts unresolved')


if __name__ == '__main__':
    main()
