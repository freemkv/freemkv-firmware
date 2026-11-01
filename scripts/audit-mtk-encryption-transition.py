#!/usr/bin/env python3
"""Trace native authentication bytes through runtime Encryption SET and VID.

Classic inputs execute the installed AKE bypass and native setter. Other inputs
execute the native setter with an explicit state-6 input: their reset service
completion is NOT fabricated. SET executes all actual response-writer calls and
stops at the independently source-bound response commit. The following VID
state-load/gate is entered with the resulting RAM, not an invented auth result.
This stitches bounded software stages; it does not claim SCSI completion or
complete authentication/data reads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / 'firmware_execution'))
from stages import run as cpu_run, machine_cache, branch, DECODER, STACK
from ake_setter import literal, half, setter_contract


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(data, engine, *args, **kwargs):
    # Some native setters use a >64-KiB untruncated offset. Map only declared
    # synthetic input pages beyond the harness's small default RAM window.
    # Strict reads still reject every unprovided byte; this is not an inferred
    # physical RAM map or a zero-filled substitute for an unknown input.
    _, cpu, _, _ = machine_cache(data, engine, None)
    regions = list(cpu.mem_regions())
    for address, value in kwargs.get('memory', ()):
        for page in range(address & ~0xfff, (address + len(value) + 0xfff) & ~0xfff, 0x1000):
            if not any(lo <= page and page + 0xfff <= hi for lo, hi, _ in regions):
                assert 0x02030000 <= page < 0x03000000
                cpu.mem_map(page, 0x1000)
                regions.append((page, page + 0xfff, 7))
    return cpu_run(data, engine, *args, **kwargs)


def writer_contract(data, at):
    if half(data, at) & 0xff00 == 0x4a00:
        offset = literal(data, at)
        shift = 0
    else:
        assert data[at:at + 4] == bytes.fromhex('6d225202')
        offset = 0x6d << 9
        shift = 2
    grammar = [0x1880, None, 0x6812, 0x1810, None, 0x0200, 0x6812,
               0x0a00, 0x1880, 0x7001, 0x4770]
    for i, op in enumerate(grammar):
        actual = half(data, at + 2 + shift + i * 2)
        assert actual == op if op is not None else actual & 0xff00 == 0x4a00
    return dict(offset=offset, first_cell=literal(data, at + 4 + shift),
                second_cell=literal(data, at + 10 + shift), length=24 + shift)


def state_reader(data, gate, setter):
    candidates = [at for at in range(gate - 40, gate, 2)
                  if half(data, at) & 0xffc7 == 0x7a80]
    assert candidates
    entry = candidates[-1]
    instructions = list(DECODER.disasm(data[entry:gate], entry))
    assert instructions[-1].mnemonic == 'ldrb' and instructions[-1].op_str == 'r0, [r0]'
    assert all(i.mnemonic in ('ldrb', 'ldr', 'lsls', 'lsrs', 'adds', 'subs') for i in instructions)
    pools = [literal(data, i.address) for i in instructions if half(data, i.address) & 0xf800 == 0x4800]
    assert len(pools) == 3
    assert setter['first_cell'] in pools and setter['second_cell'] in pools
    assert setter['offset'] in pools or setter['offset'] + 0x3c in pools
    return dict(entry=entry, cdb_register=(half(data, entry) >> 3) & 7)


def inspect(folder, native_folder, source_hash):
    original = (folder / 'original.bin').read_bytes()
    modified = (folder / 'modified.bin').read_bytes()
    assert sha(original) == source_hash
    assert (native_folder / 'original.bin').read_bytes() == original
    report = json.loads((folder / 'modify.json').read_text())
    c = report['execution_contracts']; base = c['base']; facts = c['facts']
    response = json.loads((native_folder / 'native.json').read_text())['response']
    assert response['status'] == 'source-bound' and response['writer'] == base['writer']
    writer = writer_contract(original, base['writer'])
    assert original[base['writer']:base['writer'] + writer['length']] == modified[base['writer']:base['writer'] + writer['length']]
    setter = setter_contract(original, facts)
    reader = state_reader(original, facts['gatea_gate'], setter)
    # Native writer and setter share the same two relocation owners.
    assert (writer['first_cell'], writer['second_cell']) == (setter['first_cell'], setter['second_cell'])
    native_base = 0x02010000
    auth = native_base + (setter['offset'] & (0xffff if setter['shape'] in ('common', 'adjusted_common') else 0xffffff))
    output = native_base + writer['offset']
    assert not auth <= output < auth + 2
    relocation = [(setter['first_cell'], bytes(4)), (setter['second_cell'], struct.pack('<I', native_base))]
    result = dict(source_sha256=source_hash, output_sha256=sha(modified),
        setter=setter, reader=reader, response=response, writer=writer, cases=[],
        provenance='installed classic bypass' if setter['classic'] else 'explicit native state-6 setter input; reset completion unqualified')
    for agid in (0, 1):
        input_registers = {0:(agid << 6) | 0x3f, 1:1} if setter['classic'] else {0:agid, 1:6}
        # Directly enter the native leaf on modern variants; this is a state
        # producer input contract, not a substituted reset return.
        entry = setter['site'] if setter['classic'] else setter['setter']
        from stages import STOP
        stop = setter['join'] + 4 if setter['classic'] else STOP
        produced = run(modified, report['engine'], entry, {stop}, base['flags'],
            settings={6:0}, registers=input_registers,
            memory=relocation + [(auth, b'\x01\x01')], allow_writes=[(auth, auth + 2)],
            observe_memory=[(auth, 2)], strict_reads=True)
        states = bytes.fromhex(produced['memory'][str(auth)])
        assert states[agid] == 6 and states[1 - agid] == 1
        native_reject = run(original, report['engine'], setter['site'], {setter['join'] + 4}, base['flags'],
            registers={0:(agid << 6) | 0x3f, 1:1} if setter['classic'] else {0:agid, 1:1},
            memory=relocation + [(auth, b'\x01\x01')], allow_writes=[(auth, auth + 2)],
            observe_memory=[(auth, 2)], strict_reads=True)
        reject_states = bytes.fromhex(native_reject['memory'][str(auth)])
        assert reject_states[agid] == 1
        for setting in (1, 255):
            flags = bytes([255, 255, 255, 1, 1, 255, 0])
            command = bytes([0x3c, 14, 0xc0, 0xde, 2, 6, setting, 0, 0, 0, 0, 0])
            observed = [(base['flags'], 7), (auth, 2), (output, 64), (response['length_cell'], 2)]
            set_result = run(modified, report['engine'], base['handler'], {response['commit']}, base['flags'],
                memory=relocation + [(base['flags'], flags), (base['cdb'], command), (auth, states),
                    (output, bytes([0xa5] * 64)), (response['length_cell'], b'\xa5\xa5')],
                allow_writes=[(a, a + n) for a, n in observed], observe_memory=observed, strict_reads=True)
            assert set_result['registers'][0] == response['buffer_offset']
            assert set_result['memory'][str(output)] == bytes(64).hex()
            assert set_result['memory'][str(response['length_cell'])] == '4000'
            new_flags = bytes.fromhex(set_result['memory'][str(base['flags'])])
            assert new_flags == flags[:6] + bytes([setting])
            next_states = bytes.fromhex(set_result['memory'][str(auth)])
            gate = facts['gatea_gate']; deny = branch(original, gate + 2)
            vid_command = bytes(10) + bytes([agid << 6]) + b'\x00'
            checked = run(modified, report['engine'], reader['entry'], {gate + 4, deny}, base['flags'],
                memory=relocation + [(base['flags'], new_flags), (base['cdb'], vid_command), (auth, next_states)],
                registers={reader['cdb_register']:base['cdb']}, strict_reads=True)
            native_checked = run(original, report['engine'], reader['entry'], {gate + 4, deny}, base['flags'],
                memory=relocation + [(base['cdb'], vid_command), (auth, reject_states)],
                registers={reader['cdb_register']:base['cdb']}, strict_reads=True)
            assert native_checked['target'] == deny and native_checked['registers'][0] == 1
            result['cases'].append(dict(agid=agid, requested_setting=setting,
                before_auth=states.hex(), after_auth=next_states.hex(),
                observed_state=checked['registers'][0], vid_accept=checked['target'] == gate + 4,
                native_failed_ake_state=reject_states.hex(), native_vid_accept=False,
                setter_trace=produced['trace'], set_trace=set_result['trace'], vid_trace=checked['trace']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--require-invalidated', action='store_true')
    args = parser.parse_args()
    rows = []
    for source in json.loads(args.inventory.read_text())['images']:
        try:
            rows.append(inspect(args.outputs / source['sha256'], args.native / source['sha256'], source['sha256']))
        except Exception:
            print('FAILED', source['sha256'], flush=True)
            raise
    receipt = dict(scope=__doc__, script_sha256=sha(Path(__file__).read_bytes()),
        inventory_sha256=sha(args.inventory.read_bytes()), images=rows,
        cases=sum(len(r['cases']) for r in rows),
        retained_accepts=sum(c['vid_accept'] for r in rows for c in r['cases']),
        classic_retained_accepts=sum(c['vid_accept'] for r in rows if r['setter']['classic'] for c in r['cases']))
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k:receipt[k] for k in ('cases', 'retained_accepts', 'classic_retained_accepts')}))
    if args.require_invalidated and receipt['retained_accepts']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
