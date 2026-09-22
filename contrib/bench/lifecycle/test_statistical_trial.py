import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from statistical_trial import CORE, LABELS, METRICS, admit, sanitize, unavailable


class StatisticalTrialTests(unittest.TestCase):
    def fixture(self, root, compressed=False):
        root.joinpath('run-order.txt').write_text('\n'.join(LABELS) + '\n')
        root.joinpath('summary-config.json').write_text(json.dumps({
            'baseline_label':'a'*40,'feature_label':'a'*40,'bloat_mib':102400,
            'token_count':4,'preset':'default','tps':15000,'duration':15,
            'summary_warmup_blocks':5,'run_side':'comparison','benchmark_id':'',
            'reference_epoch':0,'baseline_hardfork':'','feature_hardfork':'',
            'baseline_removed_args':'','feature_removed_args':''}))
        rows = []
        for index, label in enumerate(LABELS):
            root.joinpath(f'phase-range-{label}.json').write_text(json.dumps({
                'schema': 1, 'phase': label, 'started_ms': 10 + index,
                'finished_ms': 20 + index, 'stop_reason': 'load_finished'}))
            blocks = [{'number': n, 'timestamp': 1000 * n, 'tx_count': 10, 'ok_count': 10,
                       'err_count': 0, 'gas_used': 100_000_000, 'block_time_ms': 1000} for n in range(1, 8)]
            root.joinpath(f'report-{label}.json').write_text(json.dumps({'blocks': blocks}))
            samples = ''.join(json.dumps({'name': name, 'value': value, 'unix_ms': unix_ms,
                'labels': {'private': 'SECRET'}}) + '\n'
                for name in METRICS for unix_ms,value in ((6000,1),(7000,3)))
            path = root.joinpath(f'report-{label}.samples.ndjson' + ('.gz' if compressed else ''))
            if compressed:
                with gzip.open(path,'wt') as target: target.write(samples)
            else: path.write_text(samples)
            rows.append({'label': label, **{field: 1 for field in CORE},
                         'summary_warmup_blocks': 5, 'blocks': 2, 'total_tx': 20,
                         'ok': 20, 'err': 0, 'total_gas': 200, 'success_rate': 100})
        result = {field: 1 for field in CORE}
        root.joinpath('summary.json').write_text(json.dumps({
            'baseline_ref': 'a' * 40, 'feature_ref': 'a' * 40,
            'grafana_url': 'https://private.invalid/secret',
            'config': {'preset': 'default', 'bloat': 102400, 'tps': 15000, 'duration': 15,
                       'run_pairs': 6, 'summary_warmup_blocks': 5, 'token_count': 4, 'run_side': 'comparison', 'derek_command': 'SECRET'},
            'results': {'baseline': {**result, 'blocks': 12, 'unknown_private': 7},
                        'feature': {**result, 'blocks': 12}, 'deltas': result},
            'per_run': rows}))

    def test_admits_exact_complete_population_and_sanitizes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            admit(root); sanitize(root)
            result = json.loads((root / 'lifecycle/summary.json').read_text())
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(result['config']['read_readiness'], 'disabled')
            text = (root / 'lifecycle/summary.json').read_text() + (root / 'lifecycle/summary.md').read_text()
            self.assertNotIn('private.invalid', text); self.assertNotIn('SECRET', text)
            self.assertNotIn('unknown_private', text)
            self.assertIn('| mgas_s | Mgas/s |', text)
            self.assertIn('15 seconds per phase', text)
            self.assertIn('| feature-1 | 2 | 20 | 200 | 100.0% |', text)
            with gzip.open(root/'lifecycle/summary-inputs.ndjson.gz','rt') as source:
                retained=source.read()
            self.assertNotIn('SECRET',retained)
            self.assertIn('"series":0',retained)

    def test_admits_compressed_txgen_samples_and_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root,compressed=True)
            admit(root)
            sample=root/f'report-{LABELS[0]}.samples.ndjson.gz'
            sample.write_bytes(sample.read_bytes()[:10])
            with self.assertRaises(Exception) as rejected: admit(root)
            self.assertEqual(str(rejected.exception),'sample_format')

    @unittest.skipUnless(shutil.which('nu'),'Nu required for compressed summary regression')
    def test_compressed_inputs_complete_real_nu_summary_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root,compressed=True)
            admit(root)
            run=subprocess.run(['nu','bench-e2e.nu','summarize',str(root)],
                cwd=Path(__file__).resolve().parents[3],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            sanitize(root)
            self.assertEqual(json.loads((root/'summary.json').read_text())['status'],'complete')

    def test_rejects_missing_truncated_cutoff_and_missing_metric(self):
        for mutation in ('missing', 'truncated', 'cutoff', 'metric'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.fixture(root); label = LABELS[0]
                if mutation == 'missing': (root / f'report-{label}.json').unlink()
                elif mutation == 'truncated': (root / f'report-{label}.json').write_text('{')
                elif mutation == 'cutoff':
                    row = json.loads((root / f'phase-range-{label}.json').read_text()); row['stop_reason'] = 'backpressure'
                    (root / f'phase-range-{label}.json').write_text(json.dumps(row))
                else: (root / f'report-{label}.samples.ndjson').write_text('')
                with self.assertRaises(Exception): admit(root)
                if mutation == 'metric':
                    self.assertTrue((root/'lifecycle/summary-inputs.ndjson.gz').is_file())

    def test_cli_reports_only_bounded_rejection_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            run=subprocess.run([sys.executable,Path(__file__).with_name('statistical_trial.py'),
                'admit',directory],capture_output=True,text=True)
            self.assertNotEqual(run.returncode,0)
            self.assertEqual(run.stderr.strip(),'statistical_trial_rejected:run_order')

    def test_missing_standard_core_metric_is_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            summary = json.loads((root / 'summary.json').read_text())
            del summary['per_run'][0][CORE[0]]
            (root / 'summary.json').write_text(json.dumps(summary))
            with self.assertRaises(Exception): sanitize(root)

    def test_unavailable_is_bounded_and_contains_no_partial_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); unavailable(root, 3)
            value = json.loads((root / 'lifecycle/summary.json').read_text())
            self.assertEqual(value, {'schema': 1, 'status': 'unavailable', 'reason': 'backpressure',
                                     'attempted_phases': 3, 'expected_phases': 12})


if __name__ == '__main__': unittest.main()
