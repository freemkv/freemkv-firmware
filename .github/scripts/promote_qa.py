"""Promote complete, source-matched QA artifacts; never compile or replace a release."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

REQUIRED = {
    *('freemkv-' + target for target in ('linux-x86_64', 'linux-aarch64', 'linux-armv7',
      'macos-x86_64', 'macos-aarch64', 'windows-x86_64', 'windows-aarch64')),
    'linux-package-amd64', 'linux-package-arm64', 'linux-package-armhf',
    'windows-installers-x86_64', 'windows-installers-aarch64', 'rpm-package', 'arch-package',
}
QA_ONLY = {
    'crates/freemkv-flash-gui/src/gui_gate.rs',
    'crates/freemkv-flash-gui/src/gui_gate_tests.rs',
    *('crates/freemkv-flash-gui/src/' + os + '/gate.rs' for os in ('mac', 'linux', 'windows')),
}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def same_shipping_source(base, head='HEAD'):
    changed = command('git', 'diff', '--name-only', base, head, '--').splitlines()
    return all(p.startswith('.github/') or p in QA_ONLY for p in changed)


def eligible(run, artifacts):
    return (run.get('conclusion') == 'success'
            and REQUIRED <= {a['name'] for a in artifacts if not a.get('expired')})


def stage_assets(source, destination, tag):
    files = [p for p in source.rglob('*') if p.is_file()]
    checked = 0
    for path in files:
        if path.name.endswith('.sha256'):
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                digest, name = line.split(None, 1)
                target = path.parent / Path(name.lstrip(' *')).name
                if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                    raise ValueError('QA checksum mismatch: ' + str(target))
                checked += 1
    if not checked:
        raise ValueError('QA artifacts contain no checksum evidence')
    destination.mkdir()
    for path in files:
        name = re.sub(r'-dev-[0-9a-f]{7,40}-', '-' + tag + '-', path.name)
        target = destination / name
        data = path.read_bytes()
        if path.name.endswith('.sha256'):
            data = re.sub(rb'-dev-[0-9a-f]{7,40}-', ('-' + tag + '-').encode(), data)
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Different artifacts collide: ' + name)
        target.write_bytes(data)
    return checked


def find_candidate(repo, ref):
    runs = json.loads(command('gh', 'api', f'repos/{repo}/actions/workflows/qa.yml/runs?branch=qa&status=success&per_page=30'))['workflow_runs']
    for run in runs:
        if subprocess.run(['git', 'cat-file', '-e', run['head_sha'] + '^{commit}'], capture_output=True).returncode:
            command('git', 'fetch', '--no-tags', 'origin', run['head_sha'])
        if not same_shipping_source(run['head_sha'], ref):
            continue
        artifacts = json.loads(command('gh', 'api', f'repos/{repo}/actions/runs/{run["id"]}/artifacts?per_page=100'))['artifacts']
        if eligible(run, artifacts):
            return run  # Focused diagnostics lack the required shipping artifacts.
    raise RuntimeError('No successful, complete QA build matches the shipping source')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+', args.tag):
        raise ValueError('Stable semantic version tag required')
    version = next(line.split('"')[1] for line in Path('Cargo.toml').read_text().splitlines() if line.startswith('version = '))
    if args.tag != 'v' + version:
        raise ValueError('Tag does not match Cargo.toml')
    run = find_candidate(args.repo, 'HEAD')
    print(f'Complete QA build {run["id"]}, source {run["head_sha"]}')
    if args.check_only:
        return
    existing = subprocess.run(['gh', 'release', 'view', args.tag, '--repo', args.repo,
                               '--json', 'isDraft,assets'], capture_output=True, text=True)
    release = json.loads(existing.stdout) if existing.returncode == 0 else None
    if release and not release['isDraft']:
        names = {asset['name'] for asset in release['assets']}
        if 'release-provenance.json' not in names or not {'freemkv-flash-x86_64-windows-setup.exe', 'freemkv-flash-gui-macos-aarch64.zip', 'freemkv-flash-gui-amd64.deb'} <= names:
            raise RuntimeError('Published release is incomplete; refusing to replace immutable assets')
        print('Already published; preserving the existing validated assets')
        return
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / 'download'
        for name in sorted(REQUIRED):
            command('gh', 'run', 'download', str(run['id']), '--repo', args.repo,
                    '--name', name, '--dir', str(source / name))
        stage = root / 'assets'
        checked = stage_assets(source, stage, args.tag)
        provenance = {'qa_run': run['id'], 'build_commit': run['head_sha'],
                      'release_commit': command('git', 'rev-parse', 'HEAD'),
                      'checksums_verified': checked,
                      'assets': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.iterdir()}}
        (stage / 'release-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        if not release:
            command('gh', 'release', 'create', args.tag, '--repo', args.repo, '--verify-tag',
                    '--draft', '--title', 'freemkv Firmware Utility ' + version, '--generate-notes')
        existing_assets = {}
        if release:
            metadata = json.loads(command('gh', 'api', f'repos/{args.repo}/releases/tags/{args.tag}'))
            existing_assets = {a['name']: a for a in metadata['assets']}
        assets = []
        for path in sorted(stage.iterdir()):
            previous = existing_assets.get(path.name)
            if previous:
                digest = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                if previous.get('digest') != digest:
                    raise RuntimeError('Draft asset differs; refusing to overwrite ' + path.name)
            else:
                assets.append(path)
        for offset in range(0, len(assets), 30):
            command('gh', 'release', 'upload', args.tag, '--repo', args.repo,
                    *(str(p) for p in assets[offset:offset + 30]))
        command('gh', 'release', 'edit', args.tag, '--repo', args.repo, '--draft=false', '--latest')
        print(f'Published {len(assets)} QA artifacts without compiling')


if __name__ == '__main__':
    main()
