"""Actual captured-disc regression and fixture-corruption detection."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import disc


class CapturedDiscTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ('MT_DISC_FIXTURES', 'MT_DISC_OUTPUTS', 'MT_DISC_WORKERS')
        if not all(os.environ.get(key) for key in required):
            raise unittest.SkipTest('real disc fixtures and production outputs required: ' + ', '.join(required))
        cls.directory = Path(os.environ['MT_DISC_FIXTURES'])
        cls.outputs = Path(os.environ['MT_DISC_OUTPUTS'])
        cls.fixtures = disc.load_fixtures(cls.directory)
        cls.workers = {r['source_sha256']:r for r in disc.read_json(os.environ['MT_DISC_WORKERS'])['images']}
        cls.classic, cls.native = disc.geometry_audit.consumer.SOURCES
        cls.classic = os.environ.get('MT_DISC_CLASSIC', cls.classic)

    def test_classic_production_geometry_and_addresses_match(self):
        result = disc.audit_image(self.outputs / self.classic, self.fixtures, self.workers)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['results']), 48)
        self.assertTrue(result['address_results'])
        self.assertTrue(all(r['inverse_trace'] and r['route_trace'] for r in result['address_results']))
        self.assertTrue(any(r['associated_iso_samples'] for r in result['address_results']))
        self.assertTrue(result['capacity_results'])
        self.assertTrue(all(r['status'] == 'passed' for r in result['capacity_results']))

    def test_capture_oracle_exposes_omitted_classic_repairs(self):
        source = self.outputs / self.classic
        report = disc.read_json(source / 'modify.json')
        repairs = [h for h in report['execution_contracts']['media_conversion_helpers']
                   if h['role'] in ('DiRecordLifetime', 'DiscGeometry')]
        self.assertEqual(len(repairs), 2)
        with tempfile.TemporaryDirectory(prefix='mtk-disc-omission-') as temp:
            folder = Path(temp) / self.classic
            folder.mkdir()
            for name in ('original.bin', 'modify.json'):
                (folder / name).write_bytes((source / name).read_bytes())
            original = (folder / 'original.bin').read_bytes()
            changed = bytearray((source / 'modified.bin').read_bytes())
            for repair in repairs:
                site = repair['site']
                changed[site:site + 4] = original[site:site + 4]
            (folder / 'modified.bin').write_bytes(changed)
            result = disc.audit_image(folder, self.fixtures, self.workers)
            self.assertEqual(result['status'], 'failed')
            failures = [r for r in result['results'] if r['status'] == 'failed']
            self.assertEqual(len(failures), 8)
            self.assertTrue(all(r['uhd'] and r['variant'] == 'modified' and r['unrestricted_setting'] == 1 for r in failures))

    def test_native_capacity_and_layer_addresses_match(self):
        result = disc.audit_image(self.outputs / self.native, self.fixtures, self.workers)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['results']), 48)
        self.assertGreaterEqual(len(result['address_results']), 352)
        self.assertTrue(all(r['status'] == 'passed' for r in result['address_results']))
        self.assertTrue(any(r['associated_iso_samples'] for r in result['address_results']))

    def test_corrupted_blob_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='mtk-disc-test-') as temp:
            root = Path(temp)
            (root / 'manifest.json').write_bytes((self.directory / 'manifest.json').read_bytes())
            blob = bytearray((self.directory / 'sectors.bin').read_bytes())
            blob[0] ^= 1
            (root / 'sectors.bin').write_bytes(blob)
            with self.assertRaises(AssertionError):
                disc.load_fixtures(root)

    def test_forged_capture_geometry_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='mtk-disc-test-') as temp:
            root = Path(temp)
            manifest = copy.deepcopy(self.fixtures['manifest'])
            manifest['captures'][0]['geometry']['segments'][1]['first_logical_sector'] += 1
            (root / 'manifest.json').write_text(json.dumps(manifest))
            (root / 'sectors.bin').write_bytes((self.directory / 'sectors.bin').read_bytes())
            with self.assertRaisesRegex(AssertionError, 'geometry differs'):
                disc.load_fixtures(root)

    def test_changed_initializer_opcode_cannot_inherit_binding(self):
        folder = self.outputs / self.classic
        original = (folder / 'original.bin').read_bytes()
        state = disc.read_json(folder / 'modify.json')['execution_contracts']['native_media_roles']['state']
        config, _ = disc.bind_geometry(original, state)
        self.assertIsNotNone(disc.bind_geometry(original, config['state'])[0])
        changed = bytearray(original)
        changed[config['entry'] + 4] ^= 1  # MOVS #0 becomes #1.
        self.assertIsNone(disc.bind_geometry(bytes(changed), config['state'])[0])

    def test_wrong_native_address_arithmetic_is_detected(self):
        source = self.outputs / self.native
        with tempfile.TemporaryDirectory(prefix='mtk-disc-test-') as temp:
            folder = Path(temp) / self.native
            folder.mkdir()
            for name in ('original.bin', 'modify.json'):
                (folder / name).write_bytes((source / name).read_bytes())
            changed = bytearray((source / 'modified.bin').read_bytes())
            # Exact reference leaf: subtracting the physical start becomes addition.
            self.assertEqual(changed[0xbb716:0xbb718], bytes.fromhex('401a'))
            changed[0xbb716:0xbb718] = bytes.fromhex('4018')
            (folder / 'modified.bin').write_bytes(changed)
            result = disc.audit_image(folder, self.fixtures, self.workers)
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(any(r['status'] == 'failed' for r in result['address_results']))

    def test_changed_classic_mapper_cannot_inherit_binding(self):
        from classic_mapping import bind
        source = self.outputs / self.classic
        original = (source / 'original.bin').read_bytes()
        report = disc.read_json(source / 'modify.json')
        helper = next(h for h in report['execution_contracts']['media_conversion_helpers'] if h['role'] == 'ReadValue')
        contract = bind(original, helper)
        changed = bytearray(original)
        changed[contract['inverse']] ^= 1
        with self.assertRaises(AssertionError):
            bind(bytes(changed), helper)

        changed = bytearray(original)
        # BLS into itself violates the native CFG even though it remains BLS.
        changed[contract['inverse'] + 6:contract['inverse'] + 8] = bytes.fromhex('fed9')
        with self.assertRaises(AssertionError):
            bind(bytes(changed), helper)

    def test_wrong_capacity_normalization_is_detected(self):
        from capacity import consumers
        source = self.outputs / self.classic
        report = disc.read_json(source / 'modify.json')
        original = (source / 'original.bin').read_bytes()
        config, _ = disc.bind_geometry(original, report['execution_contracts']['native_media_roles']['state'])
        sites = consumers(original, config['end_cell'])
        self.assertTrue(sites)
        with tempfile.TemporaryDirectory(prefix='mtk-capacity-mutation-') as temp:
            folder = Path(temp) / self.classic
            folder.mkdir()
            for name in ('original.bin', 'modify.json'):
                (folder / name).write_bytes((source / name).read_bytes())
            changed = bytearray((source / 'modified.bin').read_bytes())
            # Replace addition of the negative base with subtraction. The
            # initializer and its outputs stay correct; only the consumer fails.
            pc = sites[0] + 6
            self.assertEqual(changed[pc:pc + 2], bytes.fromhex('4018'))
            changed[pc:pc + 2] = bytes.fromhex('401a')
            (folder / 'modified.bin').write_bytes(changed)
            result = disc.audit_image(folder, self.fixtures, self.workers)
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(all(r['status'] == 'passed' for r in result['results']))
            self.assertTrue(any(r['status'] == 'failed' for r in result['capacity_results']))




if __name__ == '__main__':
    unittest.main()
