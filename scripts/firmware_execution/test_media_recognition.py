"""Mock disc-information inputs against installed code and a native OEM oracle.

MT_UHD_CPU_FIXTURE_DIR supplies original.bin, modified.bin and modify.json.
MT_UHD_TEST_BIN optionally selects the exact binary delivered to a tester.
These tests start after acquisition. They do not emulate an optical pickup.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest

from stages import STACK, branch, run, unchanged


NATIVE_SHA = '1bbeb5351dc0d69feaeefdac9ada7f3f48eed0ca4e2f879d9266679cec133396'


class MediaRecognition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ['MT_UHD_CPU_FIXTURE_DIR'])
        cls.original = (root / 'original.bin').read_bytes()
        cls.modified = Path(os.environ.get('MT_UHD_TEST_BIN', root / 'modified.bin')).read_bytes()
        doc = json.loads((root / 'modify.json').read_text())
        cls.engine = doc['engine']
        cls.contracts = doc['execution_contracts']
        cls.base = cls.contracts['base']
        cls.helper = next(h for h in cls.contracts['media_conversion_helpers']
                          if h['role'] == 'DiscInformation')
        cls.contract = cls.helper['contract']
        if cls.contract['kind'] != 'di':
            raise unittest.SkipTest('This fixture uses a different parser frame')
        # This is a held OEM reference, not a table of expected patched results.
        paths = list(Path(os.environ['MT_CPU_HOARD']).rglob(NATIVE_SHA + '*.bin'))
        if not paths:
            raise RuntimeError('Native BU40N DI reference is required')
        cls.native = paths[0].read_bytes()
        assert hashlib.sha256(cls.native).hexdigest() == NATIVE_SHA
        # Bind the actual native U/1 and U/5 branch and its shared layer suffix.
        assert cls.native[0xe0c6e:0xe0c78] == bytes.fromhex('10ab197ac020552911d1')
        assert cls.native[0xe0c7e:0xe0c88] == bytes.fromhex('d97a012916d005292ad1')
        assert cls.native[0xe0d40:0xe0d42] == bytes.fromhex('3870')
        cls.native_marker = cls.literal(0xe0c78)
        cls.native_format = cls.literal(0xe0ce2)

    @classmethod
    def literal(cls, at):
        op = int.from_bytes(cls.native[at:at + 2], 'little')
        assert op & 0xf800 == 0x4800
        return struct.unpack_from('<I', cls.native, ((at + 4) & ~3) + (op & 255) * 4)[0]

    def inputs(self, identifier, version, layers, setting=1, prefix=b'BD', state=0xc0):
        raw = bytearray(32)
        raw[12:14] = prefix
        raw[16:20] = bytes([identifier, 0, layers << 4, version])
        cell = self.contract['state']
        return dict(settings={3: setting}, registers={4: cell},
                    memory=[(cell, bytes([state])), (STACK, bytes(raw))],
                    allow_writes=[(cell, cell + 1)], observe_memory=[(cell, 1)],
                    strict_reads=True)

    def execute(self, data, stops, **inputs):
        return run(data, self.engine, self.helper['site'], stops,
                   self.base['flags'], **inputs)

    def native_classification(self, version, layers):
        state = 0x02003000
        raw = bytearray(16)
        raw[8:12] = bytes([ord('U'), 0, layers << 4, version])
        cells = (state, self.native_marker, self.native_format)
        out = run(self.native, 'MT1959', 0xe0c6e, {0xe0d42}, self.base['flags'],
                  registers={7: state},
                  memory=[(STACK + 0x40, bytes(raw))] + [(cell, b'\x00') for cell in cells],
                  allow_writes=[(cell, cell + 1) for cell in cells],
                  observe_memory=[(cell, 1) for cell in cells], strict_reads=True)
        self.assertEqual(out['memory'][str(self.native_marker)], '01')
        return out['memory'][str(state)], out['memory'][str(self.native_format)]

    def test_installed_group_is_the_recorded_group(self):
        # A different producer-version string can change CMAC without changing
        # any helper. Check all installed instructions, not whole-image equality.
        for helper in self.contracts['media_conversion_helpers']:
            with self.subTest(role=helper['role']):
                start = helper['target']
                code = self.modified[start:start + helper['helper_len']]
                self.assertEqual(hashlib.sha256(code).hexdigest(), helper['helper_sha256'])
                self.assertEqual(branch(self.modified, helper['site']), start)

    def test_bd_rom_recordable_and_rewritable_keep_oem_parser(self):
        replay = self.contract['replay_continuation']
        for identifier in b'ORW':
            for version in (0, 1, 2, 5, 255):
                for layers in (1, 2, 3, 4):
                    for setting in (0, 1, 2, 255):
                        with self.subTest(identifier=chr(identifier), version=version,
                                          layers=layers, setting=setting):
                            inputs = self.inputs(identifier, version, layers, setting)
                            old = self.execute(self.original, {replay}, **inputs)
                            new = self.execute(self.modified, {replay}, **inputs)
                            unchanged(old, new)
                            self.assertEqual(old['memory'], new['memory'])

    def test_cd_dvd_headers_are_not_reinterpreted_as_bd(self):
        # These are negative BD-parser inputs, not DVD/CD acquisition proofs.
        replay = self.contract['replay_continuation']
        for name, prefix in (('CD', b'CD'), ('DVD', b'DV'), ('bad', b'??')):
            with self.subTest(media=name):
                inputs = self.inputs(ord('U'), 5, 2, prefix=prefix)
                old = self.execute(self.original, {replay}, **inputs)
                new = self.execute(self.modified, {replay}, **inputs)
                unchanged(old, new)
                self.assertEqual(old['memory'], new['memory'])

    def test_uhd_byte13_variants_match_native_oem_classification(self):
        # Required behavior comes from executing the native reference, including
        # its real format dispatcher and layer store. U/1 must not be expected
        # to fail merely because the current emitter only implements U/5.
        for version, layers in ((1, 1), (1, 2), (1, 3), (1, 4), (5, 2), (5, 3)):
            with self.subTest(version=version, layers=layers):
                expected_state, expected_format = self.native_classification(version, layers)
                inputs = self.inputs(ord('U'), version, layers)
                out = self.execute(self.modified,
                                   {self.contract['format'], self.contract['replay_continuation']},
                                   **inputs)
                self.assertEqual(out['target'], self.contract['format'],
                                 'Valid native BDU variant fell back to the rejecting OEM parser')
                inputs['allow_writes'].append((self.contract['format_flag'],
                                               self.contract['format_flag'] + 1))
                inputs['memory'].append((self.contract['format_flag'], b'\x00'))
                inputs['observe_memory'].append((self.contract['format_flag'], 1))
                out = self.execute(self.modified, {self.contract['layer_store'] + 2}, **inputs)
                self.assertEqual(out['memory'][str(self.contract['state'])], expected_state)
                self.assertEqual(out['memory'][str(self.contract['format_flag'])], expected_format)

    def test_oem_off_invalid_settings_and_invalid_uhd_preserve_native(self):
        replay = self.contract['replay_continuation']
        cases = [(setting, version, layers) for setting in (0, 2, 255)
                 for version in (1, 5) for layers in (1, 2, 3)]
        cases += [(1, version, 2) for version in (0, 2, 4, 255)]
        cases += [(1, 5, layers) for layers in (0, 1, 4, 15)]
        for setting, version, layers in cases:
            with self.subTest(setting=setting, version=version, layers=layers):
                inputs = self.inputs(ord('U'), version, layers, setting)
                old = self.execute(self.original, {replay}, **inputs)
                new = self.execute(self.modified, {replay}, **inputs)
                unchanged(old, new)
                self.assertEqual(old['memory'], new['memory'])


if __name__ == '__main__':
    unittest.main()
