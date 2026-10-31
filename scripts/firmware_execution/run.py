#!/usr/bin/env python3
"""Fail-closed, bounded ARM926 checks of actual production Modify outputs.

An inventory is {"images":[{"path":"...","sha256":"..."}, ...]}.
Every listed input and every fixed profile receives a result, including failures.
This is not whole-firmware, optical, READ-transfer, or AACS qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import unicorn
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm_const as reg
from cpu import Execution

PROFILES = {'cd', 'dvd_single_layer', 'dvd_dual_layer', 'bd_single_layer',
            'bd_dual_layer', 'bdxl_three_layer', 'uhd_dual_layer',
            'uhd_three_layer', 'invalid_state'}
REGS = [getattr(reg, f'UC_ARM_REG_R{i}') for i in range(13)]
SETTINGS = (0, 1, 2, 255)
STOP = 0x0300f000
STACK = 0x03008000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load_profiles(path):
    document = json.loads(path.read_text())
    profiles = document['profiles']
    ids = [p['id'] for p in profiles]
    require(len(ids) == len(set(ids)), 'duplicate profile')
    require(set(ids) == PROFILES, f'missing/extra profiles: {PROFILES ^ set(ids)}')
    for p in profiles:
        for key in ('media_state', 'auth_band'):
            require(type(p[key]) is int and 0 <= p[key] <= 255, f'invalid {key}')
    return profiles


def execute(data, engine, site, stops, flags, setting, inputs):
    execution = Execution(engine)
    cpu = execution.machine(data)
    cpu.reg_write(reg.UC_ARM_REG_CPSR, 0xa0000030)
    before = [0x76540000 + i * 0x101 for i in range(13)]
    for number, value in inputs.get('registers', {}).items():
        before[number] = value
    for r, value in zip(REGS, before):
        cpu.reg_write(r, value)
    cpu.reg_write(reg.UC_ARM_REG_SP, STACK)
    cpu.reg_write(reg.UC_ARM_REG_LR, STOP | 1)
    cpu.mem_write(flags, bytes([255] * 7))
    cpu.mem_write(flags + 3, bytes([setting]))
    for address, content in inputs.get('memory', []):
        cpu.mem_write(address, content)
    reached, writes = [], []

    def visit(c, address, size, user):
        if address in stops:
            reached.append(address)
            c.emu_stop()

    def write(c, access, address, size, value, user):
        writes.append([address, size, value])

    cpu.hook_add(UC_HOOK_CODE, visit)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    try:
        cpu.emu_start(site | 1, STOP, count=1000)
    except Exception as error:
        pc = cpu.reg_read(reg.UC_ARM_REG_PC)
        raise AssertionError(f'CPU failure at {pc:#x}: {error}') from error
    require(len(reached) == 1, 'missing continuation or instruction budget exhausted')
    require(cpu.reg_read(reg.UC_ARM_REG_SP) == STACK, 'unbalanced stack')
    # Only stack scratch may be written by these decision hooks. No MMIO model
    # or external software-call success hook exists in these tests.
    require(all(STACK - 0x100 <= a < STACK for a, _, _ in writes),
            f'unexpected non-stack write: {writes}')
    return {'target': reached[0], 'registers': [cpu.reg_read(r) for r in REGS],
            'nzcv': cpu.reg_read(reg.UC_ARM_REG_CPSR) & 0xf0000000,
            'before': before, 'writes': writes,
            'instructions': execution.instructions, 'edges': execution.edges}


def compare_auth(original, modified, engine, base, contract, profile):
    site, deny = contract['site'], contract['deny']
    refusal = contract.get('native_refusal')
    stops = {site + 4, deny} | ({refusal} if refusal is not None else set())
    runs, instructions, edges = [], set(), set()
    for setting in SETTINGS:
        inputs = {'registers': {contract['value_register']: profile['auth_band']}}
        old = execute(original, engine, site, {site+4, deny}, base['flags'], setting, inputs)
        new = execute(modified, engine, site, stops, base['flags'], setting, inputs)
        if refusal is not None:
            expected = refusal if setting == 0 and profile['auth_band'] == 12 else old['target']
        else:
            expected = deny if setting == 0 else site+4 if setting == 1 else old['target']
        require(new['target'] == expected, f'auth continuation {new["target"]:#x} != {expected:#x}')
        require(new['registers'] == old['registers'] == new['before'], 'auth live register changed')
        require(new['nzcv'] == old['nzcv'], 'auth CMP flags changed')
        instructions |= new['instructions']; edges |= new['edges']
        runs.append({'setting': setting, 'original_target': old['target'],
                     'modified_target': new['target'], 'nzcv': new['nzcv']})
    return {'cases': runs, 'consumed_profile_fields': ['auth_band'],
            'not_consumed': ['media_state'], 'stop_boundary': 'before native continuation',
            'fetched_instructions': sorted(instructions), 'observed_edges': sorted(edges)}


def compare_media(original, modified, engine, base, contracts, profile):
    require(len(contracts) == 2, 'both registered media gates required')
    runs, instructions, edges = [], set(), set()
    for contract in contracts:
        site = contract['site']
        for setting in SETTINGS:
            for command_class in (0, 2, 3, 255):
                for retired in (0, 1, 255):
                    inputs = {'registers': {2: 0x02001000}, 'memory': [
                        (0x02001007, bytes([command_class])),
                        (base['flags']+4, bytes([retired]))]}
                    old = execute(original, engine, site, {site+4}, base['flags'], setting, inputs)
                    new = execute(modified, engine, site, {site+4}, base['flags'], setting, inputs)
                    require(new['registers'][0] == old['registers'][0] == command_class,
                            'CDB class load changed')
                    for i in range(13):
                        if i not in (0, 3):
                            require(new['registers'][i] == old['registers'][i] == new['before'][i],
                                    f'media live r{i} changed')
                    if setting == 0:
                        require(new['nzcv'] & 0x40000000 == 0, 'Off accepted')
                    else:
                        require(new['nzcv'] == old['nzcv'], 'native class comparison flags changed')
                    instructions |= new['instructions']; edges |= new['edges']
                    runs.append({'role': contract['role'], 'setting': setting,
                                 'command_class': command_class, 'retired': retired,
                                 'original_nzcv': old['nzcv'], 'modified_nzcv': new['nzcv']})
    return {'cases': runs, 'consumed_profile_fields': [],
            'not_consumed': ['media_state', 'auth_band'],
            'scope': 'CDB class gates repeated per profile; not profile-specific optical coverage',
            'stop_boundary': 'before native continuation',
            'fetched_instructions': sorted(instructions), 'observed_edges': sorted(edges)}


def command(args, timeout=600):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f'command failed ({result.returncode}): {result.stderr[-3000:]}')
    return json.loads(result.stdout)


def image_result(row, args, profiles):
    result = {'input_sha256': row['sha256'], 'path': row['path'], 'profiles': [], 'status': 'failed'}
    try:
        source = (args.hoard / row['path']).resolve()
        require(sha(source.read_bytes()) == row['sha256'], 'input hash mismatch')
        folder = args.output / row['sha256']; folder.mkdir(parents=True, exist_ok=True)
        built = command([args.builder, source, folder])
        result['build'] = built
        require(built['status'] in ('supported', 'unchanged'), f'production builder: {built}')
        cli_path = folder / 'production.bin'
        cli_report = command([args.fw, 'modify', source, cli_path, '--json'])
        (folder / 'production.json').write_text(json.dumps(cli_report, indent=2)+'\n')
        original = (folder/'original.bin').read_bytes()
        modified = cli_path.read_bytes()
        require(sha(original) == built['canonical_sha256'], 'canonical input hash mismatch')
        require(sha(modified) == built['output_sha256'], 'CLI/API output mismatch')
        require(modified == (folder/'modified.bin').read_bytes(), 'CLI/API bytes differ')
        result.update(canonical_sha256=sha(original), output_sha256=sha(modified))
        document = json.loads((folder/'modify.json').read_text())
        contracts = document['execution_contracts']
        result['contracts_sha256'] = sha(json.dumps(contracts, sort_keys=True).encode())
        for profile in profiles:
            record = {'id': profile['id'], 'inputs': profile, 'stages': [], 'status': 'passed'}
            for stage in args.stages:
                item = {'stage': stage, 'status': 'failed'}
                try:
                    require(stage in contracts, f'missing requested contract: {stage}')
                    require('base' in contracts, 'missing base contract')
                    fn = {'auth_cell': compare_auth, 'media_gates': compare_media}[stage]
                    item.update(fn(original, modified, built['engine'], contracts['base'],
                                   contracts[stage], profile))
                    item['status'] = 'passed'
                except Exception as error:
                    item['error'] = str(error); record['status'] = 'failed'
                record['stages'].append(item)
            result['profiles'].append(record)
        result['status'] = 'passed' if all(r['status']=='passed' for r in result['profiles']) else 'failed'
    except Exception as error:
        result['error'] = str(error)
        result['profiles'] = [{'id': p['id'], 'inputs': p, 'status': 'failed',
            'error': 'image construction/provenance failed before execution'} for p in profiles]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--hoard', type=Path, required=True)
    parser.add_argument('--builder', type=Path, required=True)
    parser.add_argument('--fw', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiles', type=Path, default=Path(__file__).with_name('profiles.json'))
    parser.add_argument('--stages', nargs='+', choices=('auth_cell', 'media_gates'),
                        default=['auth_cell', 'media_gates'])
    args = parser.parse_args()
    args.builder = args.builder.resolve(); args.fw = args.fw.resolve()
    profiles = load_profiles(args.profiles)
    inventory = json.loads(args.inventory.read_text())['images']
    require(inventory, 'empty inventory')
    hashes = [r['sha256'] for r in inventory]
    require(len(hashes) == len(set(hashes)), 'duplicate inventory hashes')
    args.output.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[2]
    suite = [Path(__file__), Path(__file__).with_name('cpu.py'), args.profiles,
             repo/'crates/freemkv-fw/examples/firmware_execution_evidence.rs']
    lock = (repo/'Cargo.lock').read_text()
    expected_pin = '45e5a98b6085e938986456b098434720dd8ae368'
    require(f'#{expected_pin}' in lock, 'unexpected mediatek-optical source pin')
    receipt = {'schema': 'firmware-bounded-execution-v1', 'status': 'failed',
        'scope': 'explicit supplied-input decision stages only; not full conversion or READ/optical success',
        'cpu': 'ARM926', 'unicorn': unicorn.__version__,
        'hardware_model': 'RAM only; no hardware/service return interception; no modeled successful acquisition',
        'source_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        'dependency_commit': expected_pin, 'working_tree_diff_sha256': sha(subprocess.check_output(['git','diff','--binary'],cwd=repo)),
        'shipping_binary_sha256': sha(args.fw.read_bytes()), 'builder_sha256': sha(args.builder.read_bytes()),
        'inventory_sha256': sha(args.inventory.read_bytes()), 'profiles_sha256': sha(args.profiles.read_bytes()),
        'suite_files': {str(p.relative_to(repo)) if p.is_relative_to(repo) else str(p):sha(p.read_bytes()) for p in suite},
        'requested_stages': args.stages, 'expected_images': len(inventory), 'images': []}
    for row in inventory:
        result = image_result(row, args, profiles); receipt['images'].append(result)
        print(f'{row["sha256"][:12]}: {result["status"]}', flush=True)
        (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    require(sha(args.fw.read_bytes()) == receipt['shipping_binary_sha256'], 'shipping executable changed during run')
    require(sha(args.builder.read_bytes()) == receipt['builder_sha256'], 'builder changed during run')
    receipt['status'] = 'passed' if all(r['status']=='passed' for r in receipt['images']) else 'failed'
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 0 if receipt['status']=='passed' else 1


if __name__ == '__main__':
    sys.exit(main())
