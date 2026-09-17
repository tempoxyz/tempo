import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import phase_archive as archive


class PhaseArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.phase = self.root / 'feature-1'
        self.phase.mkdir()
        (self.phase / 'nested').mkdir()
        (self.phase / 'empty').mkdir()
        self.files = {
            'a.jsonl': b'{"type":"header"}\n' + b'{"type":"end","id":1}\n' * 1000 + b'{"type":"footer","dropped":0}\n',
            'lifecycle.json': b'{"spans":[],"eligible":1}',
            'index.html': b'<a href="nested/block-1.html">p99</a>',
            'nested/block-1.html': b'<a href="../index.html">summary</a>',
            'nested/raw.bin': bytes(range(256)),
        }
        for name, content in self.files.items():
            (self.phase / name).write_bytes(content)

    def pack(self, remove=True):
        receipt = archive.pack(self.phase, remove)
        return self.root / 'feature-1.zip', receipt

    def rewrite(self, mutate):
        path = self.root / 'feature-1.zip'
        with zipfile.ZipFile(path) as z:
            entries = [(i, z.read(i)) for i in z.infolist()]
        entries = mutate(entries)
        with zipfile.ZipFile(path, 'w') as z:
            for info, contents in entries:
                z.writestr(info, contents)
        receipt_path = self.root / 'feature-1.archive.json'
        receipt = json.loads(receipt_path.read_text())
        receipt.update(archive_sha256=archive.digest_file(path), archive_bytes=path.stat().st_size)
        receipt_path.write_text(json.dumps(receipt))

    def test_roundtrip_preserves_every_byte_empty_directory_and_offline_links(self):
        path, receipt = self.pack()
        self.assertFalse(self.phase.exists())
        self.assertLess(path.stat().st_size, sum(map(len, self.files.values())) // 2)
        self.assertEqual(receipt['contents']['total_bytes'], sum(map(len, self.files.values())))
        self.assertTrue((self.root / 'phase_archive.py').exists())
        self.assertIn('feature-1.zip', (self.root / 'index.html').read_text())
        result = archive.unpack(path, self.root, 'feature-1')
        self.assertEqual(result['archive_sha256'], receipt['archive_sha256'])
        actual = {p.relative_to(self.phase).as_posix(): p.read_bytes() for p in self.phase.rglob('*') if p.is_file()}
        self.assertEqual(actual, self.files)
        self.assertTrue((self.phase / 'empty').is_dir())
        self.assertTrue((self.phase / 'nested' / '..' / 'index.html').exists())

    def test_default_keeps_originals_and_existing_names_never_overwrite(self):
        path, _ = self.pack(remove=False)
        self.assertTrue(self.phase.exists())
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            archive.pack(self.phase, True)
        self.assertEqual(path.read_bytes(), original)
        with self.assertRaises(FileExistsError):
            archive.unpack(path, self.root, 'feature-1')
        self.assertEqual((self.phase / 'a.jsonl').read_bytes(), self.files['a.jsonl'])

    def test_failed_verification_does_not_publish_or_remove_sources(self):
        with patch.object(archive, 'inspect_archive', side_effect=ValueError('bad archive')):
            with self.assertRaises(ValueError):
                self.pack()
        self.assertTrue(self.phase.exists())
        self.assertFalse((self.root / 'feature-1.zip').exists())
        self.assertFalse((self.root / 'feature-1.zip.partial').exists())

    def test_preexisting_partial_remains_owned_by_other_operation(self):
        partial = self.root / 'feature-1.zip.partial'
        partial.write_bytes(b'do not touch')
        with self.assertRaises(FileExistsError):
            self.pack()
        self.assertEqual(partial.read_bytes(), b'do not touch')
        self.assertTrue(self.phase.exists())

    def test_changed_source_is_not_deleted(self):
        inspect = archive.inspect_archive
        def changing(*args, **kwargs):
            result = inspect(*args, **kwargs)
            (self.phase / 'a.jsonl').write_bytes(b'new data')
            return result
        with patch.object(archive, 'inspect_archive', side_effect=changing):
            with self.assertRaises(ValueError):
                self.pack()
        self.assertEqual((self.phase / 'a.jsonl').read_bytes(), b'new data')
        self.assertFalse((self.root / 'feature-1.zip').exists())

    def test_source_links_and_special_files_are_rejected(self):
        link = self.phase / 'link'
        link.symlink_to(self.phase / 'a.jsonl')
        with self.assertRaises(ValueError):
            self.pack()
        link.unlink()
        import os
        os.link(self.phase / 'a.jsonl', link)
        with self.assertRaises(ValueError):
            self.pack()
        link.unlink()
        os.mkfifo(link)
        with self.assertRaises(ValueError):
            self.pack()

    def test_archive_and_member_digest_corruption_fail_without_destination(self):
        path, _ = self.pack()
        original = path.read_bytes()
        path.write_bytes(original + b'bad')
        with self.assertRaises(ValueError):
            archive.unpack(path, self.root, 'feature-1')
        path.write_bytes(original)
        self.rewrite(lambda entries: [(i, b'x' * len(b) if i.filename.endswith('raw.bin') else b) for i, b in entries])
        with self.assertRaisesRegex(ValueError, 'member digest'):
            archive.unpack(path, self.root, 'feature-1')
        self.assertFalse(self.phase.exists())
        self.assertFalse(list(self.root.glob('.feature-1.extract-*')))

    def test_archive_symlink_and_duplicate_member_fail(self):
        path, _ = self.pack()
        def symlink(entries):
            entries[0][0].external_attr = (stat.S_IFLNK | 0o777) << 16
            return entries
        self.rewrite(symlink)
        with self.assertRaises(ValueError):
            archive.unpack(path, self.root, 'feature-1')
        self.rewrite(lambda entries: entries + [entries[-1]])
        with self.assertRaises(ValueError):
            archive.unpack(path, self.root, 'feature-1')
        self.assertFalse(self.phase.exists())

    def test_traversal_absolute_alias_and_file_directory_collisions(self):
        _, receipt = self.pack()
        for name in ['../escape', '/escape', 'nested/../escape', 'C:escape', 'a\\b', './a', 'a//b', 'a.', 'CON', 'nested/nul.txt', 'COM1.log']:
            value = json.loads(json.dumps(receipt['contents']))
            value['files'][0]['path'] = name
            with self.assertRaises(ValueError, msg=name):
                archive.validate_contents(value, 'feature-1')
        for names in [('A', 'a'), ('é', 'e\u0301'), ('nested', 'nested/file')]:
            value = json.loads(json.dumps(receipt['contents']))
            for entry, name in zip(value['files'], names):
                entry['path'] = name
            with self.assertRaises(ValueError):
                archive.validate_contents(value, 'feature-1')

    def test_phase_identity_expansion_and_directory_memory_limits(self):
        path, _ = self.pack()
        for phase in ['../feature-1', 'random', 'baseline-0', 'feature-10000']:
            with self.assertRaises(ValueError):
                archive.phase_name(phase)
        for phase in ['feature', 'baseline-2', 'full-feature-4', 'milestones-baseline-1']:
            self.assertEqual(archive.phase_name(phase), phase)
        with self.assertRaises(ValueError):
            archive.unpack(path, self.root, 'baseline-1')
        with self.assertRaises(ValueError):
            archive.unpack(path, self.root, 'feature-1', max_total=1)
        with patch.object(archive, 'MAX_FILES', 1), patch.object(zipfile, 'ZipFile', side_effect=AssertionError('must reject before central-directory allocation')):
            with self.assertRaises(ValueError):
                archive.check_directory_bound(path)
            forged = bytearray(path.read_bytes())
            end = forged.rfind(b'PK\x05\x06')
            struct.pack_into('<2H', forged, end + 8, 1, 1)
            path.write_bytes(forged)
            with self.assertRaisesRegex(ValueError, 'count exceeds'):
                archive.check_directory_bound(path)
        self.assertFalse(self.phase.exists())

    def test_existing_or_redirected_destination_is_not_merged(self):
        path, _ = self.pack()
        other = self.root / 'other'
        other.mkdir()
        self.phase.symlink_to(other, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            archive.unpack(path, self.root, 'feature-1')
        redirect = self.root / 'redirect'
        redirect.symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            archive.unpack(path, redirect, 'feature-1')
        self.assertEqual(list(other.iterdir()), [])

    def test_atomic_directory_publish_refuses_even_empty_collision(self):
        temporary, target = self.root / 'temporary', self.root / 'target'
        temporary.mkdir()
        target.mkdir()
        (temporary / 'data').write_bytes(b'retained')
        with self.assertRaises(FileExistsError):
            archive.publish_directory(temporary, target)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual((temporary / 'data').read_bytes(), b'retained')

    def test_zip64_directory_roundtrip(self):
        with patch.object(zipfile, 'ZIP64_LIMIT', 100):
            path, _ = self.pack()
        # Small data, genuine ZIP64 directory, and standard wide-size sentinels.
        data = bytearray(path.read_bytes())
        end = data.rfind(b'PK\x05\x06')
        struct.pack_into('<2H2L', data, end + 8, 65535, 65535, 0xffffffff, 0xffffffff)
        path.write_bytes(data)
        receipt_path = self.root / 'feature-1.archive.json'
        receipt = json.loads(receipt_path.read_text())
        receipt['archive_sha256'] = archive.digest_file(path)
        receipt_path.write_text(json.dumps(receipt))
        archive.unpack(path, self.root, 'feature-1')
        self.assertEqual((self.phase / 'a.jsonl').read_bytes(), self.files['a.jsonl'])

    def test_cli_expected_set_and_combined_limit_fail_before_extract(self):
        self.pack()
        command = [sys.executable, str(Path(archive.__file__)), 'unpack-all', str(self.root)]
        for extra in [['--expect-phases', 'baseline-1'], ['--max-total-bytes', '1']]:
            result = subprocess.run(command + extra, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.phase.exists())
        result = subprocess.run(command + ['--expect-phases', 'feature-1'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['extracted'][0]['phase'], 'feature-1')

    def test_index_publication_failure_keeps_originals_and_verified_archive(self):
        with patch.object(archive, 'write_index', side_effect=OSError('full device')):
            with self.assertRaises(OSError):
                self.pack()
        self.assertTrue(self.phase.exists())
        receipt = archive.read_json(self.root / 'feature-1.archive.json')
        archive.inspect_archive(self.root / 'feature-1.zip', receipt, 'feature-1')


if __name__ == '__main__':
    unittest.main()
