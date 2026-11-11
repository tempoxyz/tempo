"""Standalone checks: no Reth build, SDK dependency, or Docker daemon required."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from generate_sparse_buckets import arms, generate
from validate_sparse_smoke import expected_ids, validate
from verify_sparse_symbols import verify

ROOT = Path(__file__).resolve().parent


class SparseBucketTests(unittest.TestCase):
    def test_generation_and_optimized_rust(self):
        self.assertEqual((ROOT / 'src/sparse_buckets_generated.rs').read_text(), generate())
        self.assertEqual(len(arms()), 544)
        metadata = json.loads(subprocess.check_output(
            ['python3', '-B', str(ROOT / 'generate_sparse_buckets.py'), '--metadata'], text=True))
        self.assertEqual(metadata['arm_count'], 544)
        self.assertEqual(metadata['family_count'], 26)
        self.assertEqual(metadata['arms'], [{'id': index, 'name': name} for index, (name, _) in enumerate(arms())])
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'tests'
            subprocess.run(['rustc', '--edition=2024', '--test', '-Copt-level=3',
                            str(ROOT / 'src/sparse_guidance.rs'), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
            # Object relocations prove every arm is retained and individually instrumented,
            # without needing the large workload's runtime shim or dependency graph.
            obj = Path(temporary) / 'coverage.o'
            subprocess.run(['rustc', '--edition=2024', '--crate-type=lib', '--emit=obj',
                            '-Copt-level=3', '-Ccodegen-units=1', '-Clto=off',
                            '-Cpasses=sancov-module', '-Cllvm-args=-sanitizer-coverage-level=3',
                            '-Cllvm-args=-sanitizer-coverage-trace-pc-guard',
                            '-Cllvm-args=-sanitizer-coverage-pc-table',
                            str(ROOT / 'src/sparse_guidance.rs'), '-o', str(obj)], check=True)
            verify(obj)

    def test_actual_first_hit_output_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / 'harness.rs'
            harness.write_text(
                f'#[path = "{ROOT / "src/sparse_guidance.rs"}"] mod sparse_guidance;\n'
                'fn main() { for _ in 0..10000 {\n'
                'sparse_guidance::antithesis_sparse_branch_shape(0, true, 65535, 255, 3);\n'
                'sparse_guidance::antithesis_sparse_branch_shape(63, false, 21845, 257, 1);\n'
                '}\n'
                'for mask in 0..=65535u16 { for depth in [0, 1, 2, 5, 9, 17, 33] {\n'
                'for (state, revealed, leaf) in [(mask,0,0), (mask,mask,0), (mask,mask,mask),\n'
                '(65535,mask,0), (65535,65535,mask)] {\n'
                'sparse_guidance::antithesis_sparse_branch_shape(depth, depth==0, state, revealed, leaf); } } }\n'
                'for a in 0..=16 { for b in 0..=a { for c in 0..=b {\n'
                'let mask = |n| ((1u32 << n) - 1u32) as u16;\n'
                'for depth in [0, 1] { sparse_guidance::antithesis_sparse_branch_shape(\n'
                'depth, depth==0, mask(a), mask(b), mask(c)); } } } } }\n'
                '#[unsafe(no_mangle)] pub extern "C" fn __sanitizer_cov_trace_pc_guard(_: *mut u32) {}\n'
                '#[unsafe(no_mangle)] pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(_: *mut u32, _: *mut u32) {}\n'
                '#[unsafe(no_mangle)] pub extern "C" fn __sanitizer_cov_pcs_init(_: *const usize, _: *const usize) {}\n')
            binary = root / 'harness'
            subprocess.run(['rustc', '--edition=2024', '-Copt-level=3', '-Clto=off',
                            '-Cpasses=sancov-module', '-Cllvm-args=-sanitizer-coverage-level=3',
                            '-Cllvm-args=-sanitizer-coverage-trace-pc-guard',
                            '-Cllvm-args=-sanitizer-coverage-pc-table',
                            str(harness), '-o', str(binary)], check=True)
            verify(binary)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            lines = result.stderr.splitlines()
            self.assertLessEqual(len(lines), 544 + 64)
            self.assertEqual(len([line for line in lines if line.startswith('sparse_bucket_v1')]), 543)
            events = [json.dumps({'antithesis_setup': {'status': 'complete'}}),
                      json.dumps({'antithesis_assert': {'hit': True, 'message': 'Trie workload completes a round', 'condition': True}})]
            validate(events, lines)

    def test_smoke_accepts_runtime_and_rejects_missing_or_invalid_evidence(self):
        events = [json.dumps({'antithesis_setup': {'status': 'complete'}}),
                  json.dumps({'antithesis_assert': {'hit': True, 'message': 'Trie workload completes a round', 'condition': True}})]
        ids = expected_ids(0, True, 3, 3, 1)
        valid = [f'sparse_bucket_v1 id={index} depth=0 root=1 state=3 revealed=3 leaf=1\n' for index in sorted(ids)]
        diagnostics = valid + ['sparse_observations_v1 count=1\n']
        validate(events, diagnostics)
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
