"""Standalone checks: no Reth build, SDK dependency, or Docker daemon required."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from generate_sparse_buckets import arms, generate
from validate_sparse_smoke import expected_ids, expected_proof_ids, validate
from verify_sparse_symbols import verify

ROOT = Path(__file__).resolve().parent


CALLBACKS = r"""
static GUARD_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PC_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PC_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static HITS: [AtomicU64; 500000] = [const { AtomicU64::new(0) }; 500000];
#[unsafe(no_mangle)] pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    HITS[unsafe { guard.read() } as usize].fetch_add(1, Ordering::Relaxed);
}
#[unsafe(no_mangle)] pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, end: *mut u32) {
    if start == end || unsafe { start.read() } != 0 { return; }
    GUARD_BASE.store(start as usize, Ordering::Relaxed);
    let length = unsafe { end.offset_from(start) } as usize;
    assert!(length < HITS.len());
    for i in 0..length { unsafe { start.add(i).write((i+1) as u32); } }
}
#[unsafe(no_mangle)] pub unsafe extern "C" fn __sanitizer_cov_pcs_init(start: *const usize, end: *const usize) {
    PC_BASE.store(start as usize, Ordering::Relaxed);
    PC_LEN.store(unsafe { end.offset_from(start) } as usize, Ordering::Relaxed);
}
fn entry_hits(index: usize) -> u64 {
    let pcs = unsafe { std::slice::from_raw_parts(PC_BASE.load(Ordering::Relaxed) as *const usize, PC_LEN.load(Ordering::Relaxed)) };
    let position = pcs.chunks_exact(2).position(|pair| pair[0] == ARMS[index] as usize && pair[1] & 1 != 0).unwrap();
    let guard = unsafe { (GUARD_BASE.load(Ordering::Relaxed) as *const u32).add(position).read() };
    HITS[guard as usize].load(Ordering::Relaxed)
}
"""


def callback_cases():
    result = []
    for depth in (0, 1, 2, 5, 9, 17, 33):
        for target, revealed, other in ((5, 10, 12), (12, 10, 5), (0, 1, 2), (15, 14, 13)):
            for is_leaf in (False, True):
                state = (1 << target) | (1 << revealed) | (1 << other)
                leaf = (1 << revealed) if is_leaf else 0
                ids = sorted(expected_proof_ids(depth, True, target, state, 1 << revealed, leaf))
                result.append('{ let ids = ' + str(ids) + '; let before = ids.map(entry_hits);')
                result.append(f'antithesis_sparse_proof_target({depth},true,{target},{state},{1 << revealed},{leaf});')
                result.append('for (index,previous) in ids.into_iter().zip(before) { assert!(entry_hits(index)>previous, "missing callback for {index}"); } }')
    return '\n'.join(result)


class SparseBucketTests(unittest.TestCase):
    def test_generation_and_optimized_rust(self):
        self.assertEqual((ROOT / 'src/sparse_buckets_generated.rs').read_text(), generate())
        self.assertEqual(len(arms()), 44898)
        metadata = json.loads(subprocess.check_output(
            ['python3', '-B', str(ROOT / 'generate_sparse_buckets.py'), '--metadata'], text=True))
        self.assertEqual(metadata['arm_count'], 44898)
        self.assertEqual(metadata['family_count'], 28)
        self.assertEqual(metadata['arms'], [{'id': index, 'name': name} for index, (name, _) in enumerate(arms())])
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'tests'
            subprocess.run(['rustc', '--edition=2024', '--test', '-Copt-level=3',
                            str(ROOT / 'src/sparse_guidance.rs'), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_actual_first_hit_output_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / 'harness.rs'
            source = (ROOT / 'src/sparse_guidance.rs').read_text().replace('//!', '//').replace('include!("sparse_buckets_generated.rs");', f'include!("{ROOT / "src/sparse_buckets_generated.rs"}");')
            harness.write_text(source + '\n' + (
                'fn main() { for _ in 0..10000 {\n'
                'antithesis_sparse_branch_shape(0, true, 65535, 255, 3);\n'
                'antithesis_sparse_branch_shape(63, false, 21845, 257, 1);\n'
                '}\n' + callback_cases() + '\n' +
                'for mask in 0..=65535u16 { for depth in [0, 1, 2, 5, 9, 17, 33] {\n'
                'for (state, revealed, leaf) in [(mask,0,0), (mask,mask,0), (mask,mask,mask),\n'
                '(65535,mask,0), (65535,65535,mask)] {\n'
                'antithesis_sparse_branch_shape(depth, depth==0, state, revealed, leaf); } } }\n'
                'for a in 0..=16 { for b in 0..=a { for c in 0..=b {\n'
                'let mask = |n| ((1u32 << n) - 1u32) as u16;\n'
                'for depth in [0, 1] { antithesis_sparse_branch_shape(\n'
                'depth, depth==0, mask(a), mask(b), mask(c)); } } } } }\n'
                + CALLBACKS))
            binary = root / 'harness'
            subprocess.run(['rustc', '--edition=2024', '-Copt-level=3', '-Clto=off',
                            '-Cpasses=sancov-module', '-Cllvm-args=-sanitizer-coverage-level=3',
                            '-Cllvm-args=-sanitizer-coverage-trace-pc-guard',
                            '-Cllvm-args=-sanitizer-coverage-pc-table',
                            str(harness), '-o', str(binary)], check=True)
            verify(binary)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            lines = result.stderr.splitlines()
            self.assertLessEqual(len(lines), len(arms()) + 64)
            self.assertEqual(len([line for line in lines if line.startswith('sparse_bucket_v1')]), 543)
            events = [json.dumps({'antithesis_setup': {'status': 'complete'}}),
                      json.dumps({'antithesis_assert': {'hit': True, 'message': 'Trie workload completes a round', 'condition': True}})]
            validate(events, lines)

    def test_smoke_accepts_runtime_and_rejects_missing_or_invalid_evidence(self):
        events = [json.dumps({'antithesis_setup': {'status': 'complete'}}),
                  json.dumps({'antithesis_assert': {'hit': True, 'message': 'Trie workload completes a round', 'condition': True}})]
        ids = expected_ids(0, True, 3, 3, 1)
        valid = [f'sparse_bucket_v1 id={index} depth=0 root=1 state=3 revealed=3 leaf=1\n' for index in sorted(ids)]
        proof_ids = expected_proof_ids(0, True, 5, (1<<5)|(1<<10)|(1<<12), 1<<10, 0)
        valid += [f'sparse_proof_bucket_v1 id={index} depth=0 target=5 parent=1 state=5152 revealed=1024 leaf=0\n' for index in sorted(proof_ids)]
        diagnostics = valid + ['sparse_observations_v1 count=1\n']
        validate(events, diagnostics)
        without_sandwich = [line for line in diagnostics if not line.startswith('sparse_proof_bucket_v1') or
                            int(line.split('id=')[1].split()[0]) < 29216]
        validate(events, without_sandwich)
        without_local = [line for line in diagnostics if not line.startswith('sparse_proof_bucket_v1') or
                         int(line.split('id=')[1].split()[0]) >= 29216]
        with self.assertRaisesRegex(AssertionError, 'Missing runtime coverage family: local'):
            validate(events, without_local)
        for bad in [[], valid, diagnostics + [valid[0]],
                    [valid[0], diagnostics[-1]],
                    [valid[0].replace('state=3', 'state=0'), diagnostics[-1]],
                    [valid[0].replace(f'id={min(ids)}', f'id={len(arms())-1}'), diagnostics[-1]],
                    [valid[0].replace('root=1', 'root=0'), diagnostics[-1]],
                    valid + ['sparse_observations_v1 count=3\n']]:
            with self.assertRaises((AssertionError, ValueError)):
                validate(events, bad)
        for missing in ids:
            incomplete = [line for line in valid if not line.startswith(f'sparse_bucket_v1 id={missing} ')]
            with self.assertRaisesRegex(AssertionError, 'Missing runtime coverage family'):
                validate(events, incomplete + [diagnostics[-1]])
        unreachable = {'antithesis_assert': {'hit': True, 'assert_type': 'reachability',
                        'display_type': 'Unreachable', 'must_hit': False, 'condition': False}}
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps(unreachable)], diagnostics)
        unreachable['antithesis_assert']['hit'] = False
        validate(events + [json.dumps(unreachable)], diagnostics)
        with self.assertRaises(AssertionError):
            validate([], diagnostics)
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps({'antithesis_assert': {'hit': True, 'assert_type': 'always', 'condition': False}})], diagnostics)
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps({'antithesis_guidance': {'message': 'Sparse trie branch shape'}})], diagnostics)


if __name__ == '__main__':
    unittest.main()
