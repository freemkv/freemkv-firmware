"""CPU-specific instruction checks and measured generated-code branch coverage."""
from collections import deque
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import arm_const as reg

CONDITIONAL = {'beq', 'bne', 'bhs', 'blo', 'bmi', 'bpl', 'bvs', 'bvc',
               'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz'}


def thumb1_instruction(data):
    first = int.from_bytes(data[:2], 'little')
    if first & 0xf800 in (0xe800, 0xf000, 0xf800):
        # ARMv5 Thumb BL/BLX are legal two-halfword instructions.
        return (len(data) >= 4 and first & 0xf800 == 0xf000
                and int.from_bytes(data[2:4], 'little') & 0xf800 in (0xe800, 0xf800))
    if first & 0xf000 == 0xb000:
        return first & 0xff00 in (0xb000, 0xb400, 0xb500, 0xbc00, 0xbd00, 0xbe00)
    return first & 0xff00 not in (0xde00, 0xdf00)


class Execution:
    def __init__(self, engine, profile=None):
        self.engine = engine
        if not engine.startswith(('MT1939', 'MT1959')):
            raise ValueError(f'no qualified CPU model for {engine}')
        self.thumb1 = engine.startswith('MT1939') if profile is None else profile=='arm926'
        if profile not in (None,'arm926','cortex-a8'):raise ValueError('unknown CPU profile '+profile)
        self.cpu_model = 'ARM926' if self.thumb1 else 'Cortex-A8'
        self.generated_thumb1 = True
        self.edges, self.instructions = set(), set()
        self.decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.decoder.detail = True

    def factory(self, *args, **kwargs):
        cpu = Uc(*args, **kwargs)
        cpu.ctl_set_cpu_model(reg.UC_CPU_ARM_926 if self.thumb1 else reg.UC_CPU_ARM_CORTEX_A8)
        previous = [None]
        original_start = cpu.emu_start

        def start(*args, **kwargs):
            previous[0] = None
            return original_start(*args, **kwargs)

        cpu.emu_start = start

        def step(c, at, size, user):
            prior = previous[0]
            if prior is not None:
                self.edges.add((prior, at))
            previous[0] = at
            self.instructions.add(at)
            if self.thumb1 and c.reg_read(reg.UC_ARM_REG_CPSR) & 0x20:
                opcode = bytes(c.mem_read(at, max(4, size)))
                # ARM926 can report the two halves of a legal Thumb BL/BLX
                # separately at a translation boundary. Accept a suffix only
                # after its immediately executed, already validated first half.
                suffix = (int.from_bytes(opcode[:2], 'little') & 0xf800 in (0xe800,0xf800)
                          and prior == at-2
                          and int.from_bytes(c.mem_read(at-2,2),'little') & 0xf800 == 0xf000)
                if not thumb1_instruction(opcode) and not suffix:
                    raise AssertionError(f'unsupported ARMv5 Thumb instruction at {at:#x}')
        cpu.hook_add(UC_HOOK_CODE, step)
        return cpu

    def machine(self, data):
        cpu = self.factory(UC_ARCH_ARM, UC_MODE_THUMB)
        for base, size in ((0, 0x200000), (0x00300000, 0x400000),
                           (0x01ff0000, 0x40000), (0x03000000, 0x10000),
                           (0x04000000, 0x1000000)):
            cpu.mem_map(base, size)
        cpu.mem_write(0, data)
        return cpu

    def branch_requirements(self, data, root):
        """Walk generated instructions only, stopping at calls' return and exits.

        Literal pools are never walked linearly. Unknown indirect control flow
        is an exit from the generated function, not a fabricated native success.
        """
        queue, seen, required = deque([root]), set(), set()
        while queue:
            at = queue.popleft()
            if at in seen:
                continue
            if not root <= at < min(len(data), root+0x2000):
                raise AssertionError('generated CFG leaves its bounded function')
            seen.add(at)
            ins = next(self.decoder.disasm(data[at:at+4], at, count=1), None)
            if ins is None:
                raise AssertionError(f'unbound generated instruction at {at:#x}')
            if self.generated_thumb1 and not thumb1_instruction(data[at:at+4]):
                raise AssertionError(f'unsupported generated instruction at {at:#x}')
            end, name = at+ins.size, ins.mnemonic
            if name in CONDITIONAL:
                target = ins.operands[-1].imm
                required.update(((at, target), (at, end)))
                queue.extend((target, end))
            elif name in ('b', 'b.w'):
                queue.append(ins.operands[-1].imm)
            elif name == 'bx' or name == 'pop' and 'pc' in ins.op_str:
                continue
            else:
                if name in ('udf', 'svc', 'bkpt'):
                    raise AssertionError(f'trap in generated function at {at:#x}')
                queue.append(end)
        self.static_instructions = seen
        return required

    def missing(self, data, roots):
        required, instructions = set(), set()
        for root in roots:
            required.update(self.branch_requirements(data,root))
            instructions.update(self.static_instructions)
        missing = required-self.edges
        return {'conditional_edges': len(required), 'covered_edges': len(required & self.edges),
                'uncovered': [[a, b] for a, b in sorted(missing)],
                'reachable_generated_instructions':len(instructions),
                'covered_generated_instructions':len(instructions & self.instructions),
                'unvisited_instructions':sorted(instructions-self.instructions)}
