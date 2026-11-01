"""Synthetic invalid/boundary inputs for installed classic geometry guards.

These cases prove guard selection, preservation and bounded writes. Captured
disc tests separately establish real geometry/capacity/address agreement.
"""
import hashlib
import itertools
import struct

from classic_mapping import bind
from stages import STOP, STACK, require, unchanged


def compare(stage, helper, contract, contracts):
    require(hashlib.sha256(stage.original).hexdigest() == contract['source_sha256'], 'geometry source binding changed')
    operands = contract['operands']
    copy = helper['role'] == 'DiRecordLifetime'
    route = next(h for h in contracts['media_conversion_helpers'] if h['role'] == 'ReadValue')
    native = bind(stage.original, route)
    base, source, dest = 0x02010000, 0x1000, 0x2000
    variants = [(f'layers-{layers}-state-{state}', layers, state, None, 0, 2)
                for layers, state in itertools.product((1, 2, 3, 4), (0xc0, 0xc7, 0xc8))]
    variants += [(f'bad-byte-{offset}', 3, 0xc8, offset, 0, 2) for offset in (0, 1, 8, 9, 10, 13)]
    variants += [('bypass', 3, 0xc8, None, 1, 2), ('not-ready', 3, 0xc8, None, 0, 0),
                 ('wrong-ready-bit', 3, 0xc8, None, 0, 1)]
    for setting, cv, variant in itertools.product((0, 1, 2, 255), range(4), variants):
        label, layers, state, bad, bypass, ready = variant
        def case():
            records = bytearray((i * 7 + 3) & 255 for i in range(0x150))
            records[0:2] = b'DI'; records[8:11] = b'BDU'
            records[12] = layers << 4; records[13] = 5
            records[0x14:0x18] = (0x1000ff).to_bytes(4, 'big')
            records[0x8c:0x90] = (0x10007f).to_bytes(4, 'big')
            records[0xf8:0xfc] = (0x100080).to_bytes(4, 'big')
            if bad is not None: records[bad] ^= 1
            eligible = setting == 1 and bad is None and layers in (2, 3)
            if not copy:
                eligible &= bypass == 0 and ready & 2 != 0 and (state, layers) in ((0xc7, 2), (0xc8, 3))
            memory = [(operands['translation'], struct.pack('<I', base)),
                      (operands['di'], struct.pack('<I', dest)), (operands['state'], bytes([state]))]
            if copy:
                memory += [(base + source, bytes(records)), (base + dest, bytes([0xa5]) * 0x150),
                           (0x04050010, bytes(4))]
                observed = [(base + dest, 0x150)]
                writes = [(base + dest + 0xe0, base + dest + 0x120), (0x04050010, 0x04050014)] if eligible else []
                registers, stops, delta = {4:source, 5:operands['di']}, {helper['site'] + 4}, 0
            else:
                frame = struct.pack('<6I', *[0x76540303 + i * 0x101 for i in range(5)], STOP | 1)
                observed = [(operands['descriptor'], 16), (operands['last_physical'], 4),
                            (operands['layer_one_end'], 4), (operands['end_cell'], 4)]
                memory += [(a, bytes(n)) for a,n in observed]
                memory += [(base + dest, bytes(records)), (operands['bypass'], bytes([bypass])),
                           (operands['status'], bytes([ready])), (STACK, frame),
                           (native['boundary0'], struct.pack('<I', 0x10003f)),
                           (native['cache'], bytes(16))]
                writes = [(a, a+n) for a,n in observed] if eligible else []
                registers, stops, delta = {}, {STOP}, 24
            kwargs = dict(settings={3:setting}, registers=registers, memory=memory,
                          observe_memory=observed, strict_reads=True, initial_nzcv=cv << 28,
                          allow_stack_delta=delta)
            old = stage.execute(False, helper['site'], stops, **kwargs)
            new = stage.execute(True, helper['site'], stops, allow_writes=writes, **kwargs)
            unchanged(old, new)
            if copy:
                expected = bytearray([0xa5] * 0x150)
                if eligible: expected[0xe0:0x120] = records[0x80:0xc0] if layers == 3 else bytes(64)
                require(new['memory'][str(base + dest)] == expected.hex(), 'DI guard copy/clear mismatch')
            elif eligible:
                descriptor = bytes.fromhex(new['memory'][str(operands['descriptor'])])
                require(descriptor[1] == 0x20, 'geometry descriptor format mismatch')
                require(int.from_bytes(bytes.fromhex(new['memory'][str(operands['last_physical'])]), 'little') == 0x1000ff, 'last physical guard mismatch')
                require(int.from_bytes(bytes.fromhex(new['memory'][str(operands['layer_one_end'])]), 'little') == 0x100080, 'layer boundary guard mismatch')
                require(int.from_bytes(descriptor[12:16], 'little') == (0x100080 >> 3 if layers == 3 else 0), 'third layer descriptor guard mismatch')
            else:
                require(new['memory'] == old['memory'], 'guard rejection changed OEM memory')
            return old, new
        stage.case(['synthetic-guard', setting, cv, label], case)
    stage.result['coverage_gaps'].append('Synthetic guard inputs; captured-disc capacity/address regression is a separate required stage. No optical acquisition or MMIO completion is simulated.')
