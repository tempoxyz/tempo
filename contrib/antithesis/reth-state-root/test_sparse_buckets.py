"""Standalone checks: no Reth build, SDK dependency, or Docker daemon required."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from generate_sparse_buckets import LOCAL_COUNT, arms, generate
from validate_sparse_smoke import expected_proof_ids, validate
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
        # Include both former sandwich directions and boundary targets. Only local fires.
        for target, revealed, other in ((5, 10, 12), (12, 10, 5), (0, 1, 2), (15, 14, 13)):
            for is_leaf in (False, True):
                state = (1 << target) | (1 << revealed) | (1 << other)
                leaf = (1 << revealed) if is_leaf else 0
                ids = sorted(expected_proof_ids(depth, True, target, state, 1 << revealed, leaf))
                result.append('for _ in 0..10 { let ids = ' + str(ids) + '; let before = ids.map(entry_hits);')
                result.append(f'antithesis_sparse_proof_target({depth},true,{target},{state},{1 << revealed},{leaf});')
                result.append('for (index,previous) in ids.into_iter().zip(before) { assert_eq!(entry_hits(index),previous+1, "missing callback for {index}"); } }')
    # Minimal existing controls also keep callback-on-every-observation semantics.
    for index, args in ((LOCAL_COUNT, '0,false,0,0,0,0'),
                        (LOCAL_COUNT + 1, '64,true,5,32,0,0')):
        result.append(f'for _ in 0..10 {{ let before = entry_hits({index}); antithesis_sparse_proof_target({args}); assert_eq!(entry_hits({index}),before+1); }}')
    return '\n'.join(result)


class SparseBucketTests(unittest.TestCase):
    def test_generation_and_optimized_rust(self):
        generated = (ROOT / 'src/sparse_buckets_generated.rs').read_text()
        self.assertEqual(generated, generate())
        self.assertEqual(len(arms()), 28674)
        self.assertNotIn('sandwich', generated)
        self.assertNotIn('encoder', generated.lower())
        self.assertNotIn('fn dispatch', generated)
        self.assertNotIn('antithesis_sparse_branch_shape', (ROOT / 'src/sparse_guidance.rs').read_text())
        for index, (name, key) in enumerate(arms()[:LOCAL_COUNT]):
            depth, target, pattern = key
            self.assertEqual(index, (depth * 16 + target) * 256 + pattern)
            self.assertEqual(name, f'local_{depth}_{target}_{pattern}')
        self.assertEqual([name for name, _ in arms()[LOCAL_COUNT:]], ['proof_no_parent', 'invalid_proof'])
        metadata = json.loads(subprocess.check_output(
            ['python3', '-B', str(ROOT / 'generate_sparse_buckets.py'), '--metadata'], text=True))
        self.assertEqual({key: metadata[key] for key in (
            'arm_count', 'family_count', 'encoder_count', 'local_count', 'sandwich_count', 'control_count')},
            dict(arm_count=28674, family_count=1, encoder_count=0, local_count=28672, sandwich_count=0, control_count=2))
        self.assertEqual(metadata['arms'], [{'id': index, 'name': name} for index, (name, _) in enumerate(arms())])
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'tests'
            subprocess.run(['rustc', '--edition=2024', '--test', '-Copt-level=3',
                            str(ROOT / 'src/sparse_guidance.rs'), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_actual_first_hit_output_and_repeated_sancov_callbacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / 'harness.rs'
            source = (ROOT / 'src/sparse_guidance.rs').read_text().replace('//!', '//').replace('include!("sparse_buckets_generated.rs");', f'include!("{ROOT / "src/sparse_buckets_generated.rs"}");')
            harness.write_text(source + '\nfn main() {\n' + (
                callback_cases() + '\n'
                # Every synthetic entry must invoke its unique callback on every visit,
                # including padded/unreachable local patterns retained in the finite bank.
                'for (index, arm) in ARMS.iter().enumerate() {\n'
                'let o = Observation { branch_path_len:0, state_mask:0, revealed_mask:0,\n'
                'leaf_mask:0, proof_target:0, proof_parent:true };\n'
                'let before = entry_hits(index); arm(&o); arm(&o);\n'
                'assert_eq!(entry_hits(index), before+2); } }\n'
                + CALLBACKS))
            binary = root / 'harness'
            subprocess.run(['rustc', '--edition=2024', '-Dunreachable-pub', '-Copt-level=3', '-Clto=off',
                            '-Cpasses=sancov-module', '-Cllvm-args=-sanitizer-coverage-level=3',
                            '-Cllvm-args=-sanitizer-coverage-trace-pc-guard',
                            '-Cllvm-args=-sanitizer-coverage-pc-table',
                            str(harness), '-o', str(binary)], check=True)
            verify(binary)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            lines = result.stderr.splitlines()
            self.assertEqual(len(lines), len(arms()))
            self.assertTrue(all(line.startswith('sparse_proof_bucket_v1') for line in lines))
            self.assertEqual(len({line.split()[1] for line in lines}), len(arms()))
            # The final all-arms loop deliberately bypasses validation; validate only
            # the earlier real proof-hook evidence (invalid control is not valid smoke).
            valid = [line for line in lines if 'state=0 revealed=0 leaf=0' not in line
                     and f'id={LOCAL_COUNT+1} ' not in line]
            validate(self.events(), valid)

    @staticmethod
    def events():
        return [json.dumps({'antithesis_setup': {'status': 'complete'}}),
                json.dumps({'antithesis_assert': {'hit': True, 'message': 'Trie workload completes a round', 'condition': True}})]

    def test_smoke_accepts_only_local_runtime_evidence(self):
        events = self.events()
        ids = expected_proof_ids(0, True, 5, (1<<5)|(1<<10)|(1<<12), 1<<10, 0)
        valid = [f'sparse_proof_bucket_v1 id={index} depth=0 target=5 parent=1 state=5152 revealed=1024 leaf=0\n' for index in sorted(ids)]
        validate(events, valid)
        validate(events, valid + [f'sparse_proof_bucket_v1 id={LOCAL_COUNT} depth=0 target=0 parent=0 state=0 revealed=0 leaf=0'])
        for bad in [[], valid + valid,
                    [valid[0].replace('state=5152', 'state=0')],
                    [valid[0].replace('target=5', 'target=16')],
                    [valid[0].replace('depth=0', 'depth=64')],
                    [valid[0].replace('parent=1', 'parent=0')],
                    [valid[0].replace('leaf=0', 'leaf=1')],
                    [valid[0].replace('revealed=1024', 'revealed=1056')],
                    [valid[0].replace('revealed=1024', 'revealed=65535')],
                    [valid[0].replace(f'id={min(ids)}', f'id={min(ids)+544}')],
                    [valid[0].replace(f'id={min(ids)}', 'id=29216')],
                    [valid[0].replace(f'id={min(ids)}', f'id={len(arms())-1}')],
                    valid + ['sparse_bucket_v1 id=0 depth=0 root=1 state=3 revealed=3 leaf=1'],
                    valid + ['sparse_observations_v1 count=1'],
                    valid + ['sparse_encoder_v1 id=0'],
                    valid + ['coverage_sandwich_0_5_10_12_0'],
                    valid + ['sparse_sandwich_v1 id=0']]:
            with self.assertRaises((AssertionError, ValueError)):
                validate(events, bad)
        with self.assertRaisesRegex(AssertionError, 'Missing runtime coverage family: local'):
            validate(events, [f'sparse_proof_bucket_v1 id={LOCAL_COUNT} depth=0 target=0 parent=0 state=0 revealed=0 leaf=0'])
        unreachable = {'antithesis_assert': {'hit': True, 'assert_type': 'reachability',
                        'display_type': 'Unreachable', 'must_hit': False, 'condition': False}}
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps(unreachable)], valid)
        unreachable['antithesis_assert']['hit'] = False
        validate(events + [json.dumps(unreachable)], valid)
        with self.assertRaises(AssertionError):
            validate([], valid)
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps({'antithesis_assert': {'hit': True, 'assert_type': 'always', 'condition': False}})], valid)
        with self.assertRaises(AssertionError):
            validate(events + [json.dumps({'antithesis_guidance': {'message': 'Sparse trie branch shape'}})], valid)


if __name__ == '__main__':
    unittest.main()
