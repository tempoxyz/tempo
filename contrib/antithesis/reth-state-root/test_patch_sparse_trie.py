"""Offline pinned-source patch tests and executable Rust observation contract tests."""

import difflib
import gzip
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load_patcher():
    spec = importlib.util.spec_from_file_location("patch_sparse_trie", HERE / "patch-sparse-trie.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PatchSparseTrieTests(unittest.TestCase):
    def setUp(self):
        self.module = load_patcher()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "checkouts/reth/pinned" / self.module.SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_text("original\n")
        self.module.PRISTINE = hashlib.sha256(b"original\n").hexdigest()
        self.module.PATCHED = hashlib.sha256(b"patched\n").hexdigest()
        self.module.LEGACY_PATCHED = hashlib.sha256(b"legacy\n").hexdigest()
        self.module.COMBINED_PATCHED = hashlib.sha256(b"combined\n").hexdigest()
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
        self.source.chmod(0o444)
        self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "patched\n")
        with patch.object(self.module.subprocess, "run") as run:
            self.module.apply(self.root / "checkouts")
            run.assert_not_called()
        self.assertEqual(self.source.read_text(), "patched\n")

    def test_upgrade_both_historical_caches(self):
        for cached in ("legacy\n", "combined\n"):
            with self.subTest(cached=cached):
                self.source.write_text(cached)
                with patch.object(self.module.subprocess, "check_output", side_effect=[
                    self.module.REVISION + "\n", b"original\n",
                ]):
                    self.module.apply(self.root / "checkouts")
                self.assertEqual(self.source.read_text(), "patched\n")

    def test_upgrade_rejects_changed_committed_source(self):
        for cached in ("legacy\n", "combined\n"):
            with self.subTest(cached=cached):
                self.source.write_text(cached)
                with patch.object(self.module.subprocess, "check_output", side_effect=[
                    self.module.REVISION + "\n", b"unexpected\n",
                ]):
                    with self.assertRaisesRegex(RuntimeError, "Committed Reth sparse source"):
                        self.module.apply(self.root / "checkouts")
                self.assertEqual(self.source.read_text(), cached)

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

    def test_reject_bad_patch_without_changing_checkout(self):
        (self.root / "sparse-branch.patch").write_text("not a patch\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "original\n")

    def test_reject_bad_result_digest_without_changing_checkout(self):
        self.module.PATCHED = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "Patched sparse source digest mismatch"):
            self.module.apply(self.root / "checkouts")
        self.assertEqual(self.source.read_text(), "original\n")


class PinnedSparseTrieTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_patcher()
        # Exact upstream arena/mod.rs at REVISION, gzip-compressed with mtime=0.
        cls.pristine = gzip.decompress((HERE / "sparse-arena-pinned.rs.gz").read_bytes())
        # Historical combined-hook source is only a cache-upgrade fixture, never built.
        cls.combined = gzip.decompress((HERE / "sparse-arena-combined.rs.gz").read_bytes()).decode()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "checkouts/reth/pinned" / cls.module.SOURCE
        cls.source.parent.mkdir(parents=True)
        cls.source.write_bytes(cls.pristine)
        with patch.object(cls.module.subprocess, "check_output", return_value=cls.module.REVISION + "\n"):
            cls.module.apply(cls.root / "checkouts")
            cls.module.apply(cls.root / "checkouts")
        cls.patched = cls.source.read_text()

    def test_exact_pinned_source_and_real_git_apply_digest(self):
        self.assertEqual(hashlib.sha256(self.pristine).hexdigest(), self.module.PRISTINE)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.module.PATCHED)

    def test_observation_only_patch_preserves_all_upstream_behaviour(self):
        stripped = self.patched
        start = stripped.index("/// Observes a proof target")
        end = stripped.index("/// Returns the branch data", start)
        stripped = stripped[:start] + stripped[end:]
        stripped, count = re.subn(
            r"(?m)^ +antithesis_observe_proof_target\(\n.*?^ +\);\n", "", stripped, flags=re.S
        )
        self.assertEqual(count, 4)
        self.assertEqual(stripped.encode(), self.pristine)
        self.assertNotIn("antithesis_sparse_branch_shape", self.patched)
        self.assertNotIn("sometimes_each", self.patched)
        self.assertNotIn("// Observe live arena handles", self.patched)
        self.assertIn("if let RemoveLeafResult::NeedsProof { proof_key, parent, .. } = result", stripped)
        self.assertNotIn("self.required_proofs.push((idx, ArenaRequiredProof { key, parent }));", stripped)

    def test_parent_observer_resolves_explicit_extensions(self):
        start = self.patched.index("fn antithesis_observe_proof_target(")
        end = self.patched.index("/// Returns the branch data", start)
        self.assertIn("let branch = branch_data(arena, parent_idx);", self.patched[start:end])

    def test_reject_embedded_leaf_revert_without_changing_checkout(self):
        # A reverted duplicate proof request cannot pass the new pristine-source guard.
        source = self.pristine.replace(
            b"if let RemoveLeafResult::NeedsProof { proof_key, parent, .. } = result",
            b"if let RemoveLeafResult::NeedsProof { key, proof_key, parent } = result",
        ).replace(
            b".push((idx, ArenaRequiredProof { key: proof_key, parent }));",
            b".push((idx, ArenaRequiredProof { key: proof_key, parent }));\n"
            b"                        self.required_proofs.push((idx, ArenaRequiredProof { key, parent }));",
        )
        self.assertNotEqual(source, self.pristine)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "checkouts/reth/pinned" / self.module.SOURCE
            target.parent.mkdir(parents=True)
            target.write_bytes(source)
            with patch.object(self.module.subprocess, "check_output", return_value=self.module.REVISION + "\n"):
                with self.assertRaisesRegex(RuntimeError, "does not match pinned SHA256"):
                    self.module.apply(Path(directory) / "checkouts")
            self.assertEqual(target.read_bytes(), source)

    def test_all_four_proof_origins_use_local_parent(self):
        subtrie_start = self.patched.index("    fn update_leaves(&mut self, sorted_updates:")
        subtrie = self.patched[subtrie_start:self.patched.index("    fn reveal_nodes", subtrie_start)]
        self.assertEqual(subtrie.count("antithesis_observe_proof_target("), 1)
        self.assertIn("head_logical_branch_path_len(&self.arena)", subtrie)
        self.assertIn("self.buffers.cursor.head().map(|entry| (entry.index, logical_len))", subtrie)
        self.assertLess(subtrie.index("antithesis_observe_proof_target("), subtrie.index("self.required_proofs.push(("))
        upper = self.patched[self.patched.index("    fn update_leaves(\n"):]
        self.assertEqual(upper.count("antithesis_observe_proof_target("), 1)
        self.assertIn("head_logical_branch_path_len(&self.upper_arena)", upper)
        self.assertIn("cursor.head().map(|entry| (entry.index, logical_len))", upper)
        self.assertLess(upper.index("antithesis_observe_proof_target("), upper.index("proof_required_fn(key, parent)"))

    def test_sibling_only_origins_before_mutation(self):
        start = self.patched.index("    fn remove_leaf(")
        end = self.patched.index("    fn check_subtrie_collapse_needs_proof(", start)
        remove = self.patched[start:end]
        self.assertEqual(remove.count("antithesis_observe_proof_target("), 1)
        self.assertIn("Some((parent_idx, sibling_path.len() - 1)),\n                            &sibling_path,", remove)
        self.assertLess(remove.index("antithesis_observe_proof_target("), remove.index("RemoveLeafResult::NeedsProof {"))
        self.assertLess(remove.index("antithesis_observe_proof_target("), remove.index("arena.remove(head_idx)"))
        collapse = self.patched[end:self.patched.index("    fn collapse_branch(", end)]
        self.assertEqual(collapse.count("antithesis_observe_proof_target("), 1)
        self.assertIn("Some((parent_entry.index, sibling_path.len() - 1)),\n            &sibling_path,", collapse)
        self.assertLess(collapse.index("antithesis_observe_proof_target("), collapse.index("Some(ArenaRequiredProof {"))

    def test_actual_historical_cache_upgrades(self):
        self.assertEqual(hashlib.sha256(self.combined.encode()).hexdigest(), self.module.COMBINED_PATCHED)
        legacy = self.combined
        start = legacy.index("/// Observes a proof target")
        end = legacy.index("/// Returns the branch data", start)
        legacy = legacy[:start] + legacy[end:]
        legacy = re.sub(r"(?m)^ +antithesis_observe_proof_target\(\n.*?^ +\);\n", "", legacy, flags=re.S)
        self.assertEqual(hashlib.sha256(legacy.encode()).hexdigest(), self.module.LEGACY_PATCHED)
        for cached in (legacy, self.combined):
            with self.subTest(digest=hashlib.sha256(cached.encode()).hexdigest()), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "checkouts/reth/pinned" / self.module.SOURCE
                source.parent.mkdir(parents=True)
                source.write_text(cached)
                with patch.object(self.module.subprocess, "check_output", side_effect=[
                    self.module.REVISION + "\n", self.pristine,
                ]):
                    self.module.apply(Path(directory) / "checkouts")
                self.assertEqual(source.read_text(), self.patched)

    @unittest.skipUnless(shutil.which("rustc"), "rustc is needed for the executable ABI/mask contract")
    def test_rust_observer_contract(self):
        start = self.patched.index("fn antithesis_observe_proof_target(")
        end = self.patched.index("/// Returns the branch data", start)
        helper = self.patched[start:end]
        # Compile the real upstream extension-aware parent accessor as well.
        start = self.patched.index("fn branch_data(")
        end = self.patched.index("/// Returns the mutable branch data", start)
        helper += self.patched[start:end]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "observer.rs"
            binary = Path(directory) / "observer-tests"
            source.write_text(RUST_CONTRACT + "\n" + helper)
            subprocess.run(["rustc", "--edition=2024", "--test", str(source), "-o", str(binary)], check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=30)


# The actual patched helper is compiled, not a Python reimplementation. Tiny stand-ins expose
# only the pinned arena APIs used by that helper; full Reth checking remains a separate gate.
RUST_CONTRACT = r'''
use std::sync::Mutex;
type Index = usize;
type NodeArena = Vec<ArenaSparseNode>;
#[derive(Default, Clone, Copy)]
struct TrieMask(u16);
impl TrieMask {
    fn set_bit(&mut self, nibble: u8) { self.0 |= 1 << nibble; }
    fn get(self) -> u16 { self.0 }
}
struct Nibbles(Vec<u8>);
impl Nibbles { fn get_unchecked(&self, index: usize) -> u8 { self.0[index] } }
struct BranchChild(Option<Index>);
impl BranchChild { fn revealed_index(&self) -> Option<Index> { self.0 } }
struct ArenaSparseNodeBranch { state_mask: TrieMask, children: Vec<(u8, BranchChild)> }
impl ArenaSparseNodeBranch {
    fn child_iter(&self) -> impl Iterator<Item = (u8, &BranchChild)> {
        self.children.iter().map(|(n, c)| (*n, c))
    }
}
struct Subtrie { arena: NodeArena, root: Index }
enum ArenaSparseNode {
    Branch(ArenaSparseNodeBranch), Extension { child: Index }, Leaf {},
    Subtrie(Subtrie), EmptyRoot, TakenSubtrie,
}
fn branch_idx(arena: &NodeArena, idx: Index) -> Option<Index> {
    match &arena[idx] {
        ArenaSparseNode::Branch(_) => Some(idx),
        ArenaSparseNode::Extension { child, .. } => Some(*child),
        _ => None,
    }
}
impl ArenaSparseNode {
    fn branch_ref(&self) -> &ArenaSparseNodeBranch {
        match self { Self::Branch(branch) => branch, _ => panic!("not a branch") }
    }
}
type Event = (usize, bool, u8, u16, u16, u16);
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
#[unsafe(no_mangle)]
extern "C" fn antithesis_sparse_proof_target(d: usize, p: bool, t: u8, s: u16, r: u16, l: u16) {
    EVENTS.lock().unwrap().push((d, p, t, s, r, l));
}
fn wrap(node: ArenaSparseNode) -> ArenaSparseNode {
    ArenaSparseNode::Subtrie(Subtrie { arena: vec![node], root: 0 })
}
#[test]
fn actual_helper_masks_depth_target_and_no_parent_abi() {
    // No parent must not dereference an arena or read even one nibble.
    antithesis_observe_proof_target(&vec![], None, &Nibbles(vec![]));
    let mut arena = vec![
        ArenaSparseNode::EmptyRoot,
        ArenaSparseNode::Leaf {},
        wrap(wrap(ArenaSparseNode::Leaf {})),
        wrap(ArenaSparseNode::Branch(ArenaSparseNodeBranch { state_mask: TrieMask(3), children: vec![] })),
        ArenaSparseNode::TakenSubtrie,
        ArenaSparseNode::Branch(ArenaSparseNodeBranch { state_mask: TrieMask(3), children: vec![] }),
        ArenaSparseNode::Extension { child: 5 },
        ArenaSparseNode::Subtrie(Subtrie {
            arena: vec![
                ArenaSparseNode::Extension { child: 1 },
                ArenaSparseNode::Branch(ArenaSparseNodeBranch { state_mask: TrieMask(3), children: vec![] }),
            ],
            root: 0,
        }),
    ];
    let mut state = TrieMask::default();
    let children = (0..16).map(|n| {
        state.set_bit(n);
        let handle = match n { 2 => Some(1), 4 => Some(2), 6 => Some(6), 7 => Some(3), 8 => Some(7), 9 => Some(0), 12 => Some(4), _ => None };
        (n, BranchChild(handle))
    }).collect();
    arena.push(ArenaSparseNode::Branch(ArenaSparseNodeBranch { state_mask: state, children }));
    let path = Nibbles(vec![3, 2, 1, 0, 15, 8, 6, 5]);
    // Absolute logical branch depth includes an extension key; target is path[depth].
    antithesis_observe_proof_target(&arena, Some((8, 7)), &path);
    // A revealed root branch is a real parent, not a blinded/no-parent root.
    antithesis_observe_proof_target(&arena, Some((8, 0)), &path);
    // A cursor entry can name an extension, but the shape belongs to its backing branch.
    arena.push(ArenaSparseNode::Extension { child: 8 });
    antithesis_observe_proof_target(&arena, Some((9, 7)), &path);
    let revealed = (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 12);
    let leaves = (1 << 2) | (1 << 4);
    assert_eq!(*EVENTS.lock().unwrap(), vec![
        (0, false, 0, 0, 0, 0),
        (7, true, 5, u16::MAX, revealed, leaves),
        (0, true, 3, u16::MAX, revealed, leaves),
        (7, true, 5, u16::MAX, revealed, leaves),
    ]);
}
'''


if __name__ == "__main__":
    unittest.main()
