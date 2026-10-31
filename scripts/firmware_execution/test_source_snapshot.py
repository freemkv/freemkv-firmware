"""A frozen source receipt must bind the bytes that actually enter its archive."""
import hashlib
import tarfile
import tempfile
from pathlib import Path
import unittest
from corpus import source_snapshot


class SourceSnapshotBindings(unittest.TestCase):
    def test_project_and_dependency_are_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);project=root/'project';dependency=root/'dependency';output=root/'output'
            for p in (project,dependency,output):p.mkdir()
            (project/'source.rs').write_bytes(b'project source')
            (dependency/'lib.rs').write_bytes(b'dependency source')
            digest=lambda data:hashlib.sha256(data).hexdigest()
            receipt={'source_files':{'source.rs':digest(b'project source')},
                     'dependency_source_files':{'lib.rs':digest(b'dependency source')}}
            result=source_snapshot(project,receipt,output,dependency)
            self.assertEqual(result['sha256'],digest((output/result['file']).read_bytes()))
            with tarfile.open(output/result['file']) as archive:
                self.assertEqual(archive.extractfile('source.rs').read(),b'project source')
                self.assertEqual(archive.extractfile('dependency/mediatek-optical/lib.rs').read(),b'dependency source')

    def test_changed_source_refuses_archive_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'source.rs').write_bytes(b'changed')
            receipt={'source_files':{'source.rs':hashlib.sha256(b'captured').hexdigest()},'dependency_source_files':{}}
            with self.assertRaisesRegex(AssertionError,'source drift'):
                source_snapshot(root,receipt,root,root)


if __name__=='__main__':unittest.main()
