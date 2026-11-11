"""Source-only tests for the fail-closed Cargo checkout patcher."""

import difflib
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class PatchSparseTrieTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "patch_sparse_trie", Path(__file__).with_name("patch-sparse-trie.py")
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "checkouts/reth/pinned" / self.module.SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_text("original\n")
        self.module.PRISTINE = hashlib.sha256(b"original\n").hexdigest()
        self.module.PATCHED = hashlib.sha256(b"patched\n").hexdigest()
        self.module.__file__ = str(self.root / "patch-sparse-trie.py")
        (self.root / "sparse-branch.patch").write_text("".join(difflib.unified_diff(
            ["original\n"], ["patched\n"],
            fromfile="a/" + str(self.module.SOURCE),
            tofile="b/" + str(self.module.SOURCE),
        )))
        self.revision = patch.object(
            self.module.subprocess, "check_output", return_value=self.module.REVISION + "\n"
        )
        self.revision.start()
        self.addCleanup(self.revision.stop)

    def test_apply_and_idempotent_cached_checkout(self):
        self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "patched\n")
        self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "patched\n")

    def test_reject_unexpected_source(self):
        self.source.write_text("unexpected\n")
        with self.assertRaisesRegex(RuntimeError, "does not match pinned SHA256"):
            self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "unexpected\n")

    def test_reject_wrong_revision_and_missing_checkout(self):
        with patch.object(self.module.subprocess, "check_output", return_value="wrong\n"):
            with self.assertRaisesRegex(RuntimeError, "found 0"):
                self.module.apply(self.root / "checkouts")
        with self.assertRaisesRegex(RuntimeError, "found 0"):
            self.module.apply(self.root / "missing")

    def test_reject_duplicate_pinned_checkouts(self):
        other = self.root / "checkouts/reth-duplicate/pinned" / self.module.SOURCE
        other.parent.mkdir(parents=True)
        other.write_text("original\n")
        with self.assertRaisesRegex(RuntimeError, "found 2"):
            self.module.apply(self.root / "checkouts")


if __name__ == "__main__":
    unittest.main()
