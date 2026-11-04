import contextlib
import importlib.util
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pioneer_parity', Path(__file__).with_name('pioneer_parity.py'))
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)

REQ = ('SCSI request: device=d cdb=[12, 00] direction=in requested=36 attempt=1 strict=true\n'
       'SCSI result: status=0x00 transferred=36 sense=[00]\n')


class ParityTests(unittest.TestCase):
    def log(self, root, name, repeats):
        path = Path(root) / name
        path.write_text(REQ * repeats)
        return path

    def test_polling_count_does_not_change_transcript(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(parity.transcript(self.log(temp, 'a', 1)), parity.transcript(self.log(temp, 'b', 3)))

    def test_backup_captured_by_only_one_build_differs(self):
        seq = parity.transcript(self.log(tempfile.gettempdir(), 'parity-seq.log', 1))
        a = {'code': 0, 'seq': seq, 'files': {'x.tar': 'h'}}
        b = {'code': 0, 'seq': seq, 'files': {}}
        self.assertTrue(parity.compare_step('backup', a, b, 'unused'))
        self.assertFalse(parity.compare_step('backup', a, a, 'unused'))

    def test_stale_captures_are_not_attributed_to_this_run(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'x.tar').write_bytes(b'old')
            before = parity.capture_state(temp)
            self.assertEqual(parity.new_captures(temp, before), [])
            (Path(temp) / 'x.tar').write_bytes(b'new run')
            (Path(temp) / 'y.bin').write_bytes(b'z')
            self.assertEqual(parity.new_captures(temp, before), ['x.tar', 'y.bin'])

    def test_relative_binary_and_package_are_resolved_before_changing_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            stub = Path(temp) / 'fake_bin'
            stub.write_text('#!/bin/sh\necho "$@" > argv.txt\n')
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            (Path(temp) / 'pkg.bin').write_bytes(b'p')
            old = os.getcwd()
            os.chdir(temp)
            try:
                with contextlib.redirect_stdout(io.StringIO()), patch('sys.argv', ['p', './fake_bin', './fake_bin', 'dev', 'pkg.bin', 'out']), \
                        self.assertRaises(SystemExit):
                    parity.main()
            finally:
                os.chdir(old)
            argv = (Path(temp) / 'out/old/flash-dry-run/argv.txt').read_text()
            self.assertTrue(os.path.isabs(argv.split()[-1]))


if __name__ == '__main__':
    unittest.main()
