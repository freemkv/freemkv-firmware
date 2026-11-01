"""Bind both complete classic native address leaves from source instructions."""
import json
from pathlib import Path
import struct

from stages import branch, DECODER


def literal(data, pc):
    half = int.from_bytes(data[pc:pc + 2], 'little')
    assert half & 0xf800 == 0x4800
    return struct.unpack_from('<I', data, ((pc + 4) & ~3) + 4 * (half & 255))[0]


def bind(data, helper):
    accept = helper['contract']['accept']
    assert data[accept + 2:accept + 4] == bytes.fromhex('0868')
    inverse = branch(data, accept + 4)
    mapping = bind_leaves(data, inverse, inverse + 0x40)['ram_mapping']
    assert branch(data, accept + 12) > accept
    return dict(inverse=inverse, forward=inverse + 0x40,
        boundary0=mapping[0x02000f4c], boundary1=mapping[0x02000f50],
        boundary2=mapping[0x02000f54], cache=mapping[0x02000f84],
        read_value=literal(data, accept), read_stop=branch(data, accept + 12))


def bind_leaves(data, inverse, forward):
    """Match both complete arithmetic CFGs; literal pools may split blocks.

    Branch conditions, arithmetic and literal roles must all agree. A template
    block cannot map to multiple source blocks, nor may distinct blocks alias.
    """
    template_path = Path(__file__).with_name('classic_mapping_template.json')
    template = json.loads(template_path.read_text())
    items = {item['offset']: item for item in template['instructions']}
    mapping, visited, reverse = {}, {}, {}
    queue = [(0, inverse), (0x40, forward)]
    while queue:
        offset, pc = queue.pop()
        if offset in visited:
            assert visited[offset] == pc, 'inconsistent mapper control-flow join'
            continue
        assert pc not in reverse, 'aliased mapper instructions'
        assert offset in items and 0 <= pc < len(data), 'mapper control-flow bounds'
        visited[offset], reverse[pc] = pc, offset
        item = items[offset]
        expected = bytes.fromhex(item['bytes'])
        actual = next(DECODER.disasm(data[pc:pc + 4], pc, count=1))
        reference = next(DECODER.disasm(expected, template['entry'] + offset, count=1))
        assert actual.mnemonic == reference.mnemonic and actual.size == reference.size
        if 'literal' in item:
            assert bytes(actual.bytes)[1:] == expected[1:]
            old, new = item['literal'], literal(data, pc)
            if 0x01ff0000 <= old < 0x02030000:
                assert 0x01ff0000 <= new < 0x02030000
                assert old not in mapping or mapping[old] == new
                mapping[old] = new
            else:
                assert new == old
        elif actual.mnemonic.startswith('b') and actual.mnemonic != 'bx':
            queue.append((int(reference.op_str.lstrip('#'), 16) - template['entry'],
                          int(actual.op_str.lstrip('#'), 16)))
            if actual.mnemonic == 'b':
                continue
        else:
            assert bytes(actual.bytes) == expected
        if actual.mnemonic == 'bx' or actual.mnemonic == 'pop' and 'pc' in actual.op_str:
            continue
        queue.append((offset + reference.size, pc + actual.size))
    assert set(visited) == set(items), 'unbound native mapper instructions'
    assert len(set(mapping.values())) == len(mapping), 'aliased mapper RAM roles'
    return dict(inverse=inverse, forward=forward, ram_mapping=mapping,
                instruction_mapping=visited)
