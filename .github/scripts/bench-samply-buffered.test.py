#!/usr/bin/env python3
"""Focused source-patching tests; synthetic fixtures contain only patch anchors."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "buffered", Path(__file__).with_name("bench-samply-buffered.py")
)
buffered = importlib.util.module_from_spec(spec)
spec.loader.exec_module(buffered)


class BufferedSamplyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="samply-patch-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / "upstream"
        (self.checkout / "samply/src/linux").mkdir(parents=True)
        self.manifest = self.root / "receipt.json"
        # No complete upstream source is copied into the repository or fetched.
        self.sources = {
            "Cargo.lock": b"# synthetic lock fixture\n",
            buffered.PERF_EVENT: (
                b"// fixture before\n" + buffered.COUNT_BEFORE
                + b"// mmap failure returns before the following size calculation\n"
                + buffered.ALLOCATION_ANCHOR + b"// fixture after\n"
            ),
            buffered.PROFILER: (
                b"    perf.flush_events(handle_event);\n\n"
                + buffered.LOSS_BEFORE + b"\n    converter.finish()\n"
            ),
        }
        for relative, data in self.sources.items():
            (self.checkout / relative).write_bytes(data)
        self.expected = {name: buffered.sha256(data) for name, data in self.sources.items()}
        self.addCleanup(patch.stopall)
        patch.dict(buffered.EXPECTED_SHA256, self.expected, clear=True).start()
        self.git = patch.object(buffered, "git_output", side_effect=self.git_output).start()

    def git_output(self, checkout, *args):
        self.assertEqual(checkout, self.checkout)
        return {
            ("rev-parse", "--show-toplevel"): str(self.checkout),
            ("rev-parse", "--verify", "HEAD"): buffered.REVISION,
            ("status", "--porcelain", "--untracked-files=normal"): "",
        }[args]

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def assert_rejected_unchanged(self, message):
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, message):
            buffered.prepare(self.checkout, self.manifest)
        self.assertEqual(self.snapshot(), before)

    def test_success_only_changes_two_sources_and_records_hashes(self):
        receipt = buffered.prepare(self.checkout, self.manifest)
        perf = (self.checkout / buffered.PERF_EVENT).read_bytes()
        profiler = (self.checkout / buffered.PROFILER).read_bytes()
        self.assertEqual(perf.count(buffered.COUNT_AFTER), 1)
        self.assertNotIn(buffered.COUNT_BEFORE, perf)
        self.assertEqual(perf.count(buffered.ALLOCATION_SUMMARY.encode()), 1)
        self.assertGreater(perf.index(buffered.ALLOCATION_SUMMARY.encode()),
                           perf.index(buffered.ALLOCATION_ANCHOR))
        self.assertEqual(profiler.count(buffered.LOSS_SUMMARY.encode()), 1)
        self.assertEqual(profiler.count(buffered.LOSS_BEFORE), 1)
        self.assertIn(buffered.LOSS_AFTER, profiler)
        self.assertLess(profiler.index(buffered.LOSS_SUMMARY.encode()),
                        profiler.index(b"if total_lost_events > 0"))
        self.assertGreater(profiler.index(buffered.LOSS_SUMMARY.encode()),
                           profiler.index(b"perf.flush_events(handle_event)"))
        self.assertEqual((self.checkout / "Cargo.lock").read_bytes(), self.sources["Cargo.lock"])
        self.assertEqual(json.loads(self.manifest.read_text()), receipt)
        self.assertEqual(receipt["revision"], buffered.REVISION)
        self.assertTrue(receipt["diagnostic_only"])
        self.assertEqual(receipt["settings"]["ring_multiplier"], 16)
        self.assertEqual(receipt["cargo_lock"]["sha256"], self.expected["Cargo.lock"])
        self.assertEqual(receipt["patcher_sha256"], buffered.sha256(Path(buffered.__file__).read_bytes()))
        for row in receipt["files"]:
            self.assertEqual(row["upstream_sha256"], self.expected[row["path"]])
            self.assertEqual(row["patched_sha256"],
                             buffered.sha256((self.checkout / row["path"]).read_bytes()))
        self.assertEqual({row["path"]: row["patch_count"] for row in receipt["files"]},
                         {buffered.PERF_EVENT: 2, buffered.PROFILER: 1})
        self.assertEqual(len(self.snapshot()), 4)

    def test_each_bad_hash_rejects_before_any_source_or_manifest_write(self):
        for relative in self.sources:
            with self.subTest(relative=relative):
                source = self.checkout / relative
                source.write_bytes(self.sources[relative] + b"changed\n")
                self.assert_rejected_unchanged("SHA256 mismatch")
                source.write_bytes(self.sources[relative])

    def test_wrong_revision_rejects_without_mutation(self):
        original = self.git_output
        self.git.side_effect = lambda checkout, *args: (
            "0" * 40 if args == ("rev-parse", "--verify", "HEAD")
            else original(checkout, *args)
        )
        self.assert_rejected_unchanged("expected upstream HEAD")

    def test_parent_repository_or_dirty_checkout_rejects_without_mutation(self):
        for args, value, message in (
            (("rev-parse", "--show-toplevel"), str(self.root), "repository root"),
            (("status", "--porcelain", "--untracked-files=normal"), " M other.rs", "must be clean"),
        ):
            with self.subTest(args=args):
                self.git.side_effect = lambda checkout, *actual: (
                    value if actual == args else self.git_output(checkout, *actual)
                )
                self.assert_rejected_unchanged(message)

    def test_existing_output_is_not_overwritten(self):
        self.manifest.write_bytes(b"existing evidence\n")
        self.assert_rejected_unchanged("manifest already exists")
        self.git.assert_not_called()

    def test_dangling_output_symlink_is_not_followed(self):
        target = self.root / "not-created"
        self.manifest.symlink_to(target)
        self.assert_rejected_unchanged("manifest already exists")
        self.assertTrue(self.manifest.is_symlink())
        self.assertFalse(target.exists())

    def test_missing_and_duplicate_anchors_reject_before_mutation(self):
        for relative, anchor in (
            (buffered.PERF_EVENT, buffered.COUNT_BEFORE),
            (buffered.PERF_EVENT, buffered.ALLOCATION_ANCHOR),
            (buffered.PROFILER, buffered.LOSS_BEFORE),
        ):
            for duplicate in (False, True):
                with self.subTest(relative=relative, anchor=anchor, duplicate=duplicate):
                    changed = self.sources[relative].replace(anchor, anchor * 2 if duplicate else b"")
                    (self.checkout / relative).write_bytes(changed)
                    with patch.dict(buffered.EXPECTED_SHA256, {relative: buffered.sha256(changed)}):
                        self.assert_rejected_unchanged("exactly one patch anchor")
                    (self.checkout / relative).write_bytes(self.sources[relative])

    def test_failed_second_install_restores_sources_and_removes_manifest(self):
        real_replace = os.replace
        failed = False

        def fail_once(source, destination):
            nonlocal failed
            if destination == self.checkout / buffered.PROFILER and not failed:
                failed = True
                raise OSError("injected second-file replacement failure")
            return real_replace(source, destination)

        before = self.snapshot()
        with patch.object(buffered.os, "replace", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "injected"):
                buffered.prepare(self.checkout, self.manifest)
        self.assertTrue(failed)
        self.assertEqual(self.snapshot(), before)

    def test_output_race_reservation_fails_before_source_changes(self):
        original_install = buffered.install

        def raced_install(checkout, manifest, *args):
            manifest.write_bytes(b"concurrent evidence\n")
            return original_install(checkout, manifest, *args)

        with patch.object(buffered, "install", side_effect=raced_install):
            with self.assertRaises(FileExistsError):
                buffered.prepare(self.checkout, self.manifest)
        self.assertEqual(self.manifest.read_bytes(), b"concurrent evidence\n")
        for relative, data in self.sources.items():
            self.assertEqual((self.checkout / relative).read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
