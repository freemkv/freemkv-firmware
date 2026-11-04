import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('promote_qa', Path(__file__).with_name('promote_qa.py'))
promote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(promote)


class PromotionTests(unittest.TestCase):
    def test_failed_or_focused_qa_cannot_release(self):
        complete = [{'name': name, 'expired': False} for name in promote.REQUIRED]
        self.assertTrue(promote.eligible({'conclusion': 'success'}, complete))
        self.assertFalse(promote.eligible({'conclusion': 'failure'}, complete))
        self.assertFalse(promote.eligible({'conclusion': 'success'}, complete[:-1]))
        self.assertFalse(promote.eligible({'conclusion': 'success'}, [{'name': 'gui-gate-windows'}]))
        complete[0]['expired'] = True
        self.assertFalse(promote.eligible({'conclusion': 'success'}, complete))

    def test_shipping_source_changes_block_reuse(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'src/receiver.rs', 'assets/icon.png', 'README.md',
                     'crates/freemkv-flash/src/main.rs', 'crates/freemkv-flash-gui/src/ui.rs']:
            with self.subTest(path=path), patch.object(promote, 'command', return_value=path):
                self.assertFalse(promote.same_shipping_source('qa'))
        for path in ['.github/workflows/qa.yml', 'internal/docs/release.md', 'crates/freemkv-flash-gui/src/windows/gate.rs']:
            with self.subTest(path=path), patch.object(promote, 'command', return_value=path):
                self.assertTrue(promote.same_shipping_source('qa'))

    def artifact(self, root, name='freemkv-flash-dev-abcdef0-linux-x86_64.tar.gz', data=b'validated binary'):
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
        (root / (name + '.sha256')).write_text(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')

    def test_promotes_exact_bytes_and_relabels_only_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.artifact(root / 'download')
            self.assertEqual(promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0'), 1)
            target = root / 'assets/freemkv-flash-v0.15.0-linux-x86_64.tar.gz'
            self.assertEqual(target.read_bytes(), b'validated binary')
            self.assertIn(target.name, target.with_suffix('.gz.sha256').read_text())

    def test_corruption_cannot_be_promoted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.artifact(root / 'download')
            next(p for p in (root / 'download').iterdir() if not p.name.endswith('.sha256')).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0')

    def test_conflicting_artifact_names_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.artifact(root / 'download/a', name='same.tar.gz', data=b'first')
            self.artifact(root / 'download/b', name='same.tar.gz', data=b'second')
            with self.assertRaisesRegex(ValueError, 'collide'):
                promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0')

    def test_unverified_payload_cannot_be_promoted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.artifact(root / 'download/a')
            rpm = root / 'download/rpm-package'
            rpm.mkdir(parents=True)
            (rpm / 'freemkv-flash-x86_64.rpm').write_bytes(b'rpm')
            (rpm / 'freemkv.asc').write_text('key')
            with self.assertRaisesRegex(ValueError, 'lacks checksum evidence'):
                promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0')

    def test_unsigned_linux_packages_cannot_be_promoted(self):
        for name in ('freemkv-flash-x86_64.rpm', 'freemkv-flash-x86_64.pkg.tar.zst'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.artifact(root / 'download/pkg', name=name, data=b'package')
                with self.assertRaisesRegex(ValueError, 'unsigned'):
                    promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0')
                signed = root / 'download/pkg'
                (signed / 'freemkv.asc').write_text('key')
                (signed / (name + '.sig')).write_bytes(b'sig')
                self.assertEqual(promote.stage_assets(root / 'download', root / 'assets', 'v0.15.0'), 1)

    def test_installer_without_release_version_cannot_be_promoted(self):
        name = 'freemkv-flash-x86_64-windows-setup.exe'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.artifact(root / 'download/old', name=name, data=b'MZ' + '0.0.0.0'.encode('utf-16-le'))
            with self.assertRaisesRegex(ValueError, 'not stamped'):
                promote.stage_assets(root / 'download/old', root / 'old-assets', 'v0.15.0')
            self.artifact(root / 'download/new', name=name, data=b'MZ' + '0.15.0.0'.encode('utf-16-le'))
            self.assertEqual(promote.stage_assets(root / 'download/new', root / 'assets', 'v0.15.0'), 1)

    def test_unfetchable_run_is_skipped(self):
        runs = {'workflow_runs': [{'id': 1, 'head_sha': 'a' * 40, 'conclusion': 'success'}, {'id': 2, 'head_sha': 'b' * 40, 'conclusion': 'success'}]}
        def run(args, **kwargs):
            code = 1 if args[1] in ('cat-file', 'fetch') and 'a' * 40 in ' '.join(args) else 0
            return subprocess.CompletedProcess(args, code)
        def command(*args):
            return json.dumps(runs if 'runs?' in args[-1] else {'artifacts': [{'name': n} for n in promote.REQUIRED]})
        with patch.object(promote, 'command', side_effect=command), \
                patch.object(promote.subprocess, 'run', side_effect=run), \
                patch.object(promote, 'same_shipping_source', return_value=True):
            self.assertEqual(promote.find_candidate('o/r', 'HEAD')['id'], 2)

    def test_workflow_has_no_tag_build_path(self):
        text = Path('.github/workflows/release.yml').read_text()
        self.assertTrue('promote-qa:' in text, 'tag artifact-promotion job missing')
        block = text.split('\n  resolve-msrv:\n', 1)[1].split('\n    runs-on:', 1)[0]
        self.assertIn("!startsWith(github.ref, 'refs/tags/')", block)
        self.assertIn('needs: resolve-msrv', text)
        self.assertIn('needs.promote-qa.result', text)


if __name__ == '__main__':
    unittest.main()
