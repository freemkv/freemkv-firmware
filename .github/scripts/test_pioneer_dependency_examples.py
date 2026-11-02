"""Execute Rust examples and native-code KATs from the application's exact locked Pioneer git revision."""
import json
import os
from pathlib import Path
import re
import subprocess

EXAMPLES = {
    'pioneer_startup_checks': ('public_startup_api_known_answers',),
    'bank_transaction_contract': (
        'tests::source_selection_obeys_unsigned_sequence_and_b_wins_ties',
        'tests::every_phase_refusal_preserves_selected_authoritative_source',
        'tests::partial_programs_and_commits_preserve_selected_authoritative_source',
        'tests::extended_target_collision_refuses_before_any_mutation',
        'tests::skipping_old_staging_invalidation_can_select_corrupted_tied_bank',
        'tests::erased_or_unknown_maintenance_state_refuses_before_any_mutation',
        'tests::absent_authority_refuses_before_any_mutation',
    ),
}


NATIVE_TESTS = {
    'native_bridge_cpu': ('ccr_capture_mask_restore_preserves_incoming_interrupt_state',),
    'native_sha256': (
        'native_sha256_empty_abc_and_block_boundaries',
        'native_sha256_source_and_target_bank_lengths',
    ),
}


NATIVE_LIB_TESTS = tuple('startup::bank::bridge::execution_tests::' + name for name in (
    'native_payload_preserves_all_geometry_and_active_bank_cases',
    'native_payload_stops_after_partial_erase_program_and_footer',
    'native_payload_clone_failure_retains_valid_source_and_runtime_pointer',
    'installed_bridge_is_independent_of_fresh_bank_capture',
    'native_payload_restore_tag_and_unknown_tags_do_not_mutate_banks',
    'native_payload_refuses_changed_runtime_vectors_before_flash',
    'native_payload_extended_geometry_faults_preserve_source',
    'extended_competing_target_header_is_checked_after_clone_mapping',
    'native_payload_refuses_tampered_footer_before_flash',
))


def run(command, env):
    result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end='', flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
    return result.stdout


def main():
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--format-version', '1'], text=True))
    packages = [p for p in metadata['packages'] if p['name'] == 'pioneer-optical']
    if len(packages) != 1:
        raise SystemExit('Expected exactly one resolved pioneer-optical dependency')
    package = packages[0]
    # Refuse a local patch or mutable branch/tag. The source must resolve the
    # full revision requested by the application's committed dependency pin.
    match = re.fullmatch(
        r'git\+https://github\.com/MattJackson/pioneer-optical\?rev=([0-9a-f]{40})#([0-9a-f]{40})',
        package['source'] or '')
    if not match or match[1] != match[2]:
        raise SystemExit('Pioneer examples require an immutable, matching git revision')
    targets = {t['name'] for t in package['targets'] if 'example' in t['kind']}
    if not EXAMPLES.keys() <= targets:
        raise SystemExit('Pinned Pioneer dependency is missing mandatory Rust examples')
    native_targets = {t['name'] for t in package['targets'] if 'test' in t['kind']}
    if not NATIVE_TESTS.keys() <= native_targets:
        raise SystemExit('Pinned Pioneer dependency is missing mandatory native-code Rust tests')
    print(f"Pioneer example/native KAT source: {package['source']}", flush=True)
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(Path(metadata['target_directory']).resolve()))
    manifest = package['manifest_path']
    for example, tests in EXAMPLES.items():
        common = ['--locked', '--manifest-path', manifest, '--features', 'image',
                  '--example', example]
        for test in tests:
            output = run(['cargo', 'test', *common, test, '--', '--exact'], env)
            if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in output:
                raise SystemExit(f'Mandatory Rust example KAT did not execute: {example}::{test}')
        run(['cargo', 'run', *common], env)
    for target, tests in NATIVE_TESTS.items():
        common = ['--locked', '--manifest-path', manifest,
                  '--features', 'image,envelope,drive', '--test', target]
        for test in tests:
            output = run(['cargo', 'test', *common, test, '--', '--exact'], env)
            if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in output:
                raise SystemExit(f'Mandatory native Rust KAT did not execute: {target}::{test}')
    for test in NATIVE_LIB_TESTS:
        output = run(['cargo', 'test', '--locked', '--manifest-path', manifest,
                      '--features', 'image,envelope,drive', '--lib', test,
                      '--', '--exact'], env)
        if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in output:
            raise SystemExit(f'Mandatory generated-payload Rust KAT did not execute: {test}')


if __name__ == '__main__':
    main()
