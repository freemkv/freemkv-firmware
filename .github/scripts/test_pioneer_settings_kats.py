"""Run mandatory Pioneer Rust KATs; missing or unexecuted tests fail this gate."""
import subprocess

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
COMMAND = ['cargo', 'test', '--locked', '-p', 'freemkv-flash', '--lib']


def main():
    for name in TESTS:
        options = ['--exact']
        result = subprocess.run(
            [*COMMAND, name, '--', *options],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False,
        )
        print(result.stdout, end='', flush=True)
        if result.returncode or 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in result.stdout:
            raise SystemExit(f'Mandatory Pioneer Rust KAT did not execute and pass: {name}')


if __name__ == '__main__':
    main()
