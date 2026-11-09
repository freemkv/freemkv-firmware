"""Run mandatory Pioneer Rust KATs; missing or unexecuted tests fail this gate."""
import subprocess

TESTS = (
    'backends::pioneer::recovery::tests::pioneer_212u_213u_bank_contract_regression',
    *('backends::pioneer::prepared_tests::bypass_transaction_tests::' + name for name in (
        'startup_comparison_rewrites_are_refused_before_firmware_io',
        'unchanged_native_startup_preserves_live_word_in_flash_and_recovery',
        'unresolved_source_keeps_target_comparison_and_read_only_fallback',
        'read_only_prerequisite_failures_stop_flash_and_bypass_before_firmware',
        'firmware_failures_never_write_persistent_startup_parameters',
        'matching_native_startup_still_requires_read_only_live_word',
        'offline_routes_retain_the_executors_read_only_prerequisites',
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
