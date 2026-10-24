import hashlib
import importlib.util
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
        for path in ['Cargo.toml', 'Cargo.lock', 'src/receiver.rs', 'assets/icon.png', 'README.md']:
            with self.subTest(path=path), patch.object(promote, 'command', return_value=path):
                self.assertFalse(promote.same_shipping_source('qa'))
        for path in ['.github/workflows/qa.yml', 'crates/freemkv-flash-gui/src/windows/gate.rs']:
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

    def test_workflow_has_no_tag_build_path(self):
        text = Path('.github/workflows/release.yml').read_text()
        self.assertTrue('promote-qa:' in text, 'tag artifact-promotion job missing')
        self.assertIn("!startsWith(github.ref, 'refs/tags/')", text)
        self.assertIn('needs.promote-qa.result', text)


if __name__ == '__main__':
    unittest.main()
