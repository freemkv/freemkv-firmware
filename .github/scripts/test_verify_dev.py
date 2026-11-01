import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('verify_dev', Path(__file__).with_name('verify_dev.py'))
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class DevProofTests(unittest.TestCase):
    def test_only_actual_dev_push_lint_qualifies(self):
        run = {'conclusion': 'success', 'event': 'push', 'head_branch': 'dev'}
        lint = {'name': 'lint', 'conclusion': 'success', 'steps': [{'name': 'Lint Rust targets', 'conclusion': 'success'}]}
        self.assertTrue(proof.eligible(run, [lint]))
        for key, value in [('conclusion', 'failure'), ('event', 'workflow_dispatch'), ('head_branch', 'qa')]:
            self.assertFalse(proof.eligible({**run, key: value}, [lint]))
        for value in ['skipped', 'failure', None]:
            self.assertFalse(proof.eligible(run, [{**lint, 'conclusion': value}]))
            self.assertFalse(proof.eligible(run, [{**lint, 'steps': [{'name': 'Lint Rust targets', 'conclusion': value}]}]))
        self.assertFalse(proof.eligible(run, []))
        self.assertFalse(proof.eligible(run, [{**lint, 'steps': []}]))

    def test_identical_merge_tree_reuses_but_any_changed_file_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            def git(*args):
                return subprocess.check_output(['git', '-C', temp, *args], text=True).strip()
            git('init', '-q'); git('config', 'core.hooksPath', str(Path(temp) / 'empty-hooks')); git('config', 'user.email', 'test@example.com'); git('config', 'user.name', 'Test')
            path = Path(temp) / 'Cargo.lock'; path.write_text('original')
            git('add', '.'); git('commit', '-qm', 'baseline')
            base = git('rev-parse', 'HEAD')
            git('commit', '--allow-empty', '-qm', 'same tree')
            with patch.object(proof, 'command', side_effect=lambda *args: git(*args[1:])):
                self.assertTrue(proof.same_tree(base))
                for name in ['Cargo.lock', 'src/lib.rs', '.github/workflows/ci.yml', '.github/scripts/verify_dev.py']:
                    changed = Path(temp) / name; changed.parent.mkdir(parents=True, exist_ok=True); changed.write_text('changed')
                    git('add', '.'); git('commit', '-qm', 'change')
                    self.assertFalse(proof.same_tree(base))
                    git('reset', '--hard', base)

    def test_paginated_jobs_and_changed_tree_are_checked(self):
        run = {'id': 7, 'head_sha': 'a' * 40, 'conclusion': 'success', 'event': 'push', 'head_branch': 'dev'}
        import json
        queries = []
        def command(*args):
            queries.append(args)
            if args[:2] == ('git', 'fetch'):
                return ''
            if 'jobs?' in args[-1]:
                self.assertIn('--paginate', args)
                return json.dumps([{'jobs': []}, {'jobs': [{'name': 'lint', 'conclusion': 'success', 'steps': [{'name': 'Lint Rust targets', 'conclusion': 'success'}]}]}])
            return json.dumps({'workflow_runs': [run]})
        with patch.object(proof, 'command', side_effect=command), patch.object(proof, 'same_tree', return_value=True):
            self.assertEqual(proof.verify('owner/repo'), 7)
        queries.clear()
        with patch.object(proof, 'command', side_effect=command), patch.object(proof, 'same_tree', return_value=False):
            with self.assertRaises(RuntimeError):
                proof.verify('owner/repo')
        self.assertFalse(any('jobs?' in args[-1] for args in queries))

    def test_missing_matching_proof_fails(self):
        with patch.object(proof, 'command', return_value='{"workflow_runs": []}'):
            with self.assertRaisesRegex(RuntimeError, 'No successful dev push'):
                proof.verify('owner/repo')

    def test_workflow_keeps_release_cpu_suite_and_removes_debug_duplicate(self):
        ci = Path('.github/workflows/ci.yml').read_text()
        qa = Path('.github/workflows/qa.yml').read_text()
        self.assertIn('cargo test --tests', ci)
        self.assertNotIn('unicorn==', ci)
        self.assertNotIn('test-mtk-hook-execution.py', ci)
        self.assertIn('verify_dev.py', qa)
        self.assertNotIn('cargo clippy', qa)
        self.assertIn('cargo test --release --locked --all-targets --all-features', qa)
        for name in ['test-mtk-hook-execution.py', 'test-mtk-native-response-execution.py', 'test-mtk-hrl-execution.py', 'test-mtk-region-execution.py', 'test-mtk-encryption-execution.py', 'test-mtk-classic-speed.py']:
            self.assertIn(name, qa)


if __name__ == '__main__':
    unittest.main()
