"""Choose which workspace packages dev CI tests: the crates the change touches.

dev is the fast gate; qa runs the complete suite on every OS before promotion.
Dependents of a changed crate are compiled by dev's workspace-wide clippy
(all targets, all features) and tested in qa; dev does not re-run their suites.
The base is the last dev commit whose CI succeeded, so a red push followed by an
unrelated one cannot skip re-testing what was red. Anything that is not clearly
confined to one crate (manifests, lockfile, toolchain, CI) tests everything.

Writes to $GITHUB_OUTPUT:
  test          true when any package is tested
  packages      space-separated `-p name` arguments, or empty for the workspace
  all           true when the whole workspace is tested
  gui           true when a GUI crate is tested (needs GTK headers)
  flash         true when freemkv-flash is tested (its mandatory KATs apply)
  deps          true when dependencies or toolchain changed
"""
import json
import os
import subprocess
import sys

# Paths that affect every build; anything under these tests the whole workspace.
GLOBAL = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain', 'rust-toolchain.toml', 'deny.toml',
          '.cargo/', '.github/workflows/ci.yml', '.github/scripts/')
# Paths that never affect a Rust build or test.
INERT = ('.github/', 'internal/', 'docs/', 'scripts/', 'LICENSE')


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True, check=False)


def last_green(repo, branch):
    """Head SHA of the newest successful CI push run on `branch`, if any."""
    result = subprocess.run(
        ['gh', 'api', f'repos/{repo}/actions/workflows/ci.yml/runs?branch={branch}'
         '&event=push&status=success&per_page=1', '--jq', '.workflow_runs[0].head_sha // ""'],
        capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ''


def workspace():
    """Map each workspace package to its manifest directory."""
    meta = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], text=True))
    root = meta['workspace_root'].rstrip('/') + '/'
    return {p['name']: os.path.dirname(p['manifest_path']).replace(root, '', 1) + '/'
            for p in meta['packages']}


def scope(paths, dirs):
    """Return (packages or None for all, deps_changed) for the changed paths."""
    selected, everything, deps = set(), False, False
    for path in paths:
        if path.startswith(GLOBAL) or path in GLOBAL:
            everything = True
            deps = deps or path in ('Cargo.lock', 'Cargo.toml') or path.startswith('rust-toolchain')
            continue
        owner = next((n for n, d in dirs.items() if path.startswith(d)), None)
        if owner:
            selected.add(owner)
        elif not path.startswith(INERT) and not path.endswith('.md'):
            everything = True
    return (None if everything else selected), deps


def main():
    event_name = os.environ.get('GITHUB_EVENT_NAME', '')
    event = json.load(open(os.environ['GITHUB_EVENT_PATH'])) if os.environ.get('GITHUB_EVENT_PATH') else {}
    base = ''
    if event_name == 'pull_request':
        base = event.get('pull_request', {}).get('base', {}).get('sha', '')
    elif event_name == 'push':
        base = last_green(os.environ['GITHUB_REPOSITORY'], os.environ.get('GITHUB_REF_NAME', ''))
    dirs = workspace()
    packages, deps = None, True
    if base and set(base) != {'0'} and git('merge-base', '--is-ancestor', base, 'HEAD').returncode == 0:
        diff = git('diff', '--name-only', base, 'HEAD')
        if diff.returncode == 0:
            packages, deps = scope(diff.stdout.split(), dirs)
    tested = set(dirs) if packages is None else packages
    out = {
        'test': bool(tested),
        'packages': '' if packages is None else ' '.join(f'-p {n}' for n in sorted(packages)),
        'all': packages is None,
        'gui': any(n.endswith('-gui') for n in tested),
        'flash': 'freemkv-flash' in tested,
        'deps': deps,
    }
    print(f'base={base or "(none)"} tested={sorted(tested) if packages is not None else "workspace"}',
          file=sys.stderr)
    with open(os.environ.get('GITHUB_OUTPUT', '/dev/stdout'), 'a') as output:
        for key, value in out.items():
            output.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')


if __name__ == '__main__':
    main()
