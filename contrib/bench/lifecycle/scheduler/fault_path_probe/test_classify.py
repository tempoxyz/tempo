import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('fault_classifier',Path(__file__).with_name('classify.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ClassifyTests(unittest.TestCase):
    def test_exact_leaf_to_root_fault_ancestry(self):
        self.assertEqual(m.classify([b'__schedule',b'io_schedule',b'folio_wait_bit_common',b'filemap_fault',b'handle_mm_fault']),(6,1))
    def test_generic_reads_do_not_become_faults(self):
        self.assertEqual(m.classify([b'io_schedule',b'filemap_read',b'vfs_read']),(2,1))
        self.assertEqual(m.classify([b'filemap_fault',b'io_schedule']),(2,1))
        self.assertEqual(m.classify([b'io_schedule',b'filemap_fault.constprop.0']),(2,1))
    def test_ancestry_alone_does_not_prove_io_wait(self):
        self.assertEqual(m.classify([b'filemap_fault',b'handle_mm_fault']),(0,2))
    def test_conflict_unresolved_and_truncated_remain_unknown(self):
        self.assertEqual(m.classify([b'io_schedule',b'filemap_fault',b'futex_wait']),(0,8))
        self.assertEqual(m.classify([b'io_schedule',b'filemap_fault',b'0xffff0000']),(0,7))
        self.assertEqual(m.classify([b'io_schedule',b'filemap_fault'],truncated=True),(0,6))
    def test_old_categories_unchanged(self):
        self.assertEqual(m.classify([b'futex_wait']),(1,1))
        self.assertEqual(m.classify([b'pipe_read']),(4,1))
        self.assertEqual(m.classify([]),(0,3))

if __name__=='__main__':unittest.main()
