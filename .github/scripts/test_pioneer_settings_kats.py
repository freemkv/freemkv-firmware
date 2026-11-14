"""Run mandatory Pioneer Rust KATs; missing or unexecuted tests fail this gate."""
import sys

TESTS = (
    'backends::pioneer::recovery::tests::pioneer_212u_213u_bank_contract_regression',
    *('backends::pioneer::prepared_tests::bypass_transaction_tests::' + name for name in (
        'differing_startup_words_are_set_by_the_flash_transaction',
        'proven_startup_word_is_neither_read_nor_written_in_flash_and_recovery',
        'unresolved_source_sets_the_target_word_and_recovery_refuses_before_firmware',
        'firmware_failures_never_write_persistent_startup_parameters',
        'offline_routes_admit_a_proven_startup_word_without_requirements',
    )),
)


def main():
    """Check the workspace test log: each KAT must have run and passed there.

    The KATs are ordinary freemkv-flash unit tests, so `cargo test --tests`
    already executes them; re-running each through `cargo test -p` only
    recompiled the crate under a different feature resolution.
    """
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_pioneer_settings_kats.py <cargo test log>')
    with open(sys.argv[1], encoding='utf-8', errors='replace') as log:
        passed = {line.split()[1] for line in log
                  if line.startswith('test ') and line.rstrip().endswith(' ... ok')}
    missing = [name for name in TESTS if name not in passed]
    if missing:
        raise SystemExit('Mandatory Pioneer Rust KATs did not execute and pass: ' + ', '.join(missing))
    print(f'All {len(TESTS)} mandatory Pioneer Rust KATs executed and passed.')


if __name__ == '__main__':
    main()
