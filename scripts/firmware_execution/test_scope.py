import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scope


def stage(name, status='passed'):
    return {'stage': name, 'status': status, 'cases': 1}


class CapabilityMatrixTests(unittest.TestCase):
    def matrix(self, facts, stages):
        doc = {'execution_contracts': {'facts': facts},
               'boot_settings': {'encryption': {'supported': True}, 'unrestricted': {'supported': True}}}
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'modify.json').write_text(json.dumps(doc))
            result = {'_folder': temp, 'output_sha256': 'x', 'status': 'ok', 'stages': stages}
            row = {'sha256': 's', 'path': 'p', 'acceptance_group': 'g', 'provenance_kind': 'k'}
            return {k: v['status'] for k, v in scope.capability_matrix(row, result)['capabilities'].items()}

    def test_failed_vid_fails_encryption_not_unrestricted(self):
        facts = {'gatea_stub_va': 1, 'ake_stub_va': 1, 'deny_stub_va': 1, 'auth_cell_stub_va': 1}
        stages = [stage('boot'), stage('vendor-handler'), stage('ake'), stage('deny-reset'),
                  stage('auth_cell'), stage('vid', 'failed')]
        self.assertEqual(self.matrix(facts, stages), {'encryption': 'failed', 'unrestricted': 'bounded-pass'})

    def test_classic_conversion_unrestricted_without_auth_cell_passes(self):
        facts = {'ake_stub_va': 1, 'deny_stub_va': 1}
        stages = [stage('boot'), stage('vendor-handler'), stage('ake'), stage('deny-reset')]
        self.assertEqual(self.matrix(facts, stages), {'encryption': 'bounded-pass', 'unrestricted': 'bounded-pass'})


if __name__ == '__main__':
    unittest.main()
