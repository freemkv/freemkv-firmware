"""Execute Rust example KATs from the application's exact locked Pioneer git revision."""
import json
import os
from pathlib import Path
import re
import subprocess

EXAMPLES = {
    'pioneer_startup_checks': ('public_startup_api_known_answers',),
}


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
    # Refuse a local patch or mutable branch/tag. The source must be a published
    # crates.io release (immutable, ships its examples) or resolve the full git
    # revision requested by the application's committed dependency pin.
    source = package['source'] or ''
    registry = source == 'registry+https://github.com/rust-lang/crates.io-index'
    match = re.fullmatch(
        r'git\+https://github\.com/MattJackson/pioneer-optical\?rev=([0-9a-f]{40})#([0-9a-f]{40})',
        source)
    if not registry and (not match or match[1] != match[2]):
        raise SystemExit('Pioneer examples require a crates.io release or an immutable, matching git revision')
    targets = {t['name'] for t in package['targets'] if 'example' in t['kind']}
    if not EXAMPLES.keys() <= targets:
        raise SystemExit('Pinned Pioneer dependency is missing mandatory Rust examples')
    print(f"Pioneer example/native KAT source: {package['source']}", flush=True)
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(Path(metadata['target_directory']).resolve()))
    manifest = package['manifest_path']
    for example, tests in EXAMPLES.items():
        common = ['--locked', '--manifest-path', manifest, '--features', 'image,internals',
                  '--example', example]
        for test in tests:
            output = run(['cargo', 'test', *common, test, '--', '--exact'], env)
            if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in output:
                raise SystemExit(f'Mandatory Rust example KAT did not execute: {example}::{test}')
        run(['cargo', 'run', *common], env)


if __name__ == '__main__':
    main()
