"""Run mandatory Pioneer Rust KATs; missing or unexecuted tests fail this gate."""
import subprocess

TESTS = (
    'backends::pioneer::recovery::tests::pioneer_212u_213u_bank_contract_regression',
    'backends::pioneer::prepared_tests::pioneer_crossflash_transition_routing_known_answers',
    *('backends::pioneer::prepared_tests::bypass_transaction_tests::' + name for name in (
        'bypass_preserves_verified_startup_transaction',
        'bypass_startup_failures_stop_before_firmware_and_restore_original',
        'bypass_firmware_attempt_failure_never_restores_old_startup_word',
        'bypass_matching_startup_word_never_writes_settings',
    )),
)
NATIVE_BOOT = ('backends::pioneer::prepared_tests::native_startup_tests::'
               'native_212u_unchanged_banks_are_rejected')
COMMAND = ['cargo', 'test', '--locked', '-p', 'freemkv-flash', '--lib']


def main():
    for name in (*TESTS, NATIVE_BOOT):
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
