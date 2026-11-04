"""Retained membership must fail closed even when aggregate counts still match."""
import copy
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


class RetainedScope(unittest.TestCase):
    def setUp(self):
        inventory=Path(__file__).resolve().parents[2]/'internal/docs/audits/mediatek-oem-only-123-retained-20261031.json'
        self.rows=json.loads(inventory.read_text())['images']

    def test_retained_membership_is_order_independent(self):
        scope.validate_inventory(list(reversed(self.rows)))

    def test_same_size_substitution_is_refused(self):
        changed=copy.deepcopy(self.rows)
        changed[0]['sha256']='0'*64
        with self.assertRaisesRegex(AssertionError,'membership differs'):
            scope.validate_inventory(changed)

    def test_swapped_groups_are_refused_despite_preserved_counts(self):
        changed=copy.deepcopy(self.rows)
        other=next(r for r in changed if r['acceptance_group']!=changed[0]['acceptance_group'])
        other['acceptance_group'],changed[0]['acceptance_group']=changed[0]['acceptance_group'],other['acceptance_group']
        with self.assertRaisesRegex(AssertionError,'membership differs'):
            scope.validate_inventory(changed)

    def test_duplicate_and_missing_inputs_are_refused(self):
        for changed in (self.rows[:-1],self.rows[:-1]+[self.rows[0]]):
            with self.assertRaisesRegex(AssertionError,'exact unique123'):
                scope.validate_inventory(changed)

    def test_modified_input_is_refused(self):
        self.rows[0]['catalogue_patched']=True
        with self.assertRaisesRegex(AssertionError,'modified input'):
            scope.validate_inventory(self.rows)

    def test_native_only_evidence_cannot_replace_production_output(self):
        result=scope.native_row(self.rows[0],{'status':'production-refusal'},'/does/not/exist')
        self.assertEqual(result['status'],'failed')
        self.assertFalse(result['final_bin_compared'])
        self.assertIn('actual production output',result['error'])


if __name__ == '__main__':
    unittest.main()
