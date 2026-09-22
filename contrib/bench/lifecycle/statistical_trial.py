#!/usr/bin/env python3
"""Fail-closed phase admission for the selective-retry statistical trial."""
import argparse
import gzip
import json
import math
from pathlib import Path

PAIRS = 6
RUNS = [side for _ in range(PAIRS // 2) for side in ('feature', 'baseline', 'baseline', 'feature')]
LABELS = [f'{side}-{1 + RUNS[:i].count(side)}' for i, side in enumerate(RUNS)]
COUNTER_BASES = ('reth_tempo_payload_builder_payload_build_duration_seconds',
                 'reth_tempo_payload_builder_gas_per_second',
                 'reth_consensus_engine_beacon_new_payload_latency',
                 'reth_consensus_engine_beacon_new_payload_gas_per_second')
METRICS = {f'{base}_{suffix}' for base in COUNTER_BASES for suffix in ('sum', 'count')}
CORE = ('block_time_mean', 'block_time_p50', 'block_time_p90', 'block_time_p99',
        'builder_latency_p50', 'builder_latency_p90', 'builder_latency_p99', 'builder_gas_s',
        'validation_latency_p50', 'validation_latency_p90', 'validation_latency_p99',
        'validation_gas_s', 'tps', 'mgas_s')
PER_RUN = CORE + ('summary_warmup_blocks', 'blocks', 'total_tx', 'ok', 'err', 'total_gas',
                  'success_rate')


class Rejected(Exception):
    pass


def need(value, reason='contract'):
    if not value:
        raise Rejected(reason)


def load(path, limit, reason='json'):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, reason)
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise Rejected(reason) from None


def sample_paths(root):
    selected = {}
    actual = {path.name for path in root.glob('report-*.samples.ndjson*')}
    for label in LABELS:
        plain = root / f'report-{label}.samples.ndjson'
        compressed = root / f'report-{label}.samples.ndjson.gz'
        need(plain.is_file() != compressed.is_file(), 'sample_set')
        selected[label] = compressed if compressed.is_file() else plain
    need(actual == {path.name for path in selected.values()}, 'sample_set')
    return selected


def sample_rows(path):
    need(not path.is_symlink() and path.stat().st_size <= 1024**3, 'sample_size')
    opener = gzip.open if path.suffix == '.gz' else open
    total = 0
    try:
        with opener(path, 'rt') as source:
            while line := source.readline(1024 * 1024 + 1):
                total += len(line)
                need(len(line) <= 1024 * 1024 and total <= 2 * 1024**3, 'sample_size')
                if any(name in line for name in METRICS):
                    yield json.loads(line)
    except (OSError, UnicodeError, json.JSONDecodeError, EOFError):
        raise Rejected('sample_format') from None


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def retain_inputs(root, samples_by_label):
    public = root / 'lifecycle'
    public.mkdir(exist_ok=True)
    destination = public / 'summary-inputs.ndjson.gz'
    temporary = public / '.summary-inputs.ndjson.gz.tmp'
    metric_ids = {name: index for index, name in enumerate(sorted(METRICS))}
    coverage = {}
    try:
        with temporary.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as zipped:
            def write(row):
                zipped.write((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
            config = load(root / 'summary-config.json', 64 * 1024, 'config')
            safe_config = {key: config.get(key) for key in ('bloat_mib', 'token_count', 'preset', 'tps',
                           'duration', 'summary_warmup_blocks', 'run_side')}
            need(safe_config == {'bloat_mib': 102400, 'token_count': 4, 'preset': 'default',
                 'tps': 15000, 'duration': 15, 'summary_warmup_blocks': 5,
                 'run_side': 'comparison'}, 'config')
            refs = [config.get(key) for key in ('baseline_label', 'feature_label')]
            need(refs[0] == refs[1] and type(refs[0]) is str and len(refs[0]) == 40 and
                 all(char in '0123456789abcdef' for char in refs[0]), 'config')
            write({'type': 'config', 'schema': 1, **safe_config, 'source_sha': refs[0],
                   'metrics': sorted(METRICS)})
            for phase_id, label in enumerate(LABELS):
                receipt = load(root / f'phase-range-{label}.json', 4096, 'receipt')
                write({'type': 'phase', 'phase': phase_id, 'side': 1 if label.startswith('feature') else 0,
                       'started_ms': receipt['started_ms'], 'finished_ms': receipt['finished_ms']})
                report = load(root / f'report-{label}.json', 64 * 1024 * 1024, 'report')
                for block in report['blocks']:
                    kept = {key: block.get(key) for key in ('number', 'timestamp', 'timestamp_ms',
                            'tx_count', 'ok_count', 'err_count', 'gas_used', 'block_time_ms')}
                    need(all(value is None or finite(value) for value in kept.values()), 'report')
                    write({'type': 'block', 'phase': phase_id, **kept})
                series = {}
                retained = 0
                found = set()
                for row in sample_rows(samples_by_label[label]):
                    name = row.get('name')
                    if name not in METRICS:
                        continue
                    labels = row.get('labels')
                    need(type(labels) is dict and finite(row.get('value')) and finite(row.get('unix_ms')),
                         'sample_core')
                    signature = json.dumps(labels, sort_keys=True, separators=(',', ':'))
                    need(len(signature) <= 8192, 'sample_core')
                    series_id = series.setdefault(signature, len(series))
                    need(len(series) <= 1024, 'snapshot_bound')
                    output = {'type': 'metric', 'phase': phase_id, 'metric': metric_ids[name],
                              'series': series_id, 'unix_ms': row['unix_ms'], 'value': row['value']}
                    if finite(row.get('offset_ms')):
                        output['offset_ms'] = row['offset_ms']
                    write(output)
                    found.add(name)
                    retained += 1
                    need(retained <= 200_000, 'snapshot_bound')
                coverage[label] = found
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return coverage


def admit(root):
    try:
        need((root / 'run-order.txt').read_text().splitlines() == LABELS, 'run_order')
    except OSError:
        raise Rejected('run_order') from None
    need({p.name for p in root.glob('report-*.json')} == {f'report-{x}.json' for x in LABELS},
         'report_set')
    samples_by_label = sample_paths(root)
    need({p.name for p in root.glob('phase-range-*.json')} ==
         {f'phase-range-{x}.json' for x in LABELS}, 'receipt_set')
    for label in LABELS:
        receipt = load(root / f'phase-range-{label}.json', 4096, 'receipt')
        need(set(receipt) == {'schema', 'phase', 'started_ms', 'finished_ms', 'stop_reason'} and
             receipt['schema'] == 1 and receipt['phase'] == label and
             receipt['stop_reason'] == 'load_finished' and
             type(receipt['started_ms']) is int and type(receipt['finished_ms']) is int and
             0 < receipt['started_ms'] <= receipt['finished_ms'], 'receipt')
        report = load(root / f'report-{label}.json', 64 * 1024 * 1024, 'report')
        blocks = report.get('blocks')
        need(type(blocks) is list and 6 <= len(blocks) <= 100_000, 'report')
    coverage = retain_inputs(root, samples_by_label)
    need(all(coverage[label] == METRICS for label in LABELS), 'metric_coverage')


def unavailable(root, attempted, reason='backpressure'):
    need(type(attempted) is int and 0 <= attempted <= len(LABELS))
    need(reason in ('backpressure', 'summary_admission'))
    value = {'schema': 1, 'status': 'unavailable', 'reason': reason,
             'attempted_phases': attempted, 'expected_phases': len(LABELS)}
    public = root / 'lifecycle'
    public.mkdir(exist_ok=True)
    (public / 'summary.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    (public / 'summary.md').write_text(
        '# Benchmark confidence unavailable\n\n'
        'The trial did not pass complete-result admission; no partial comparison was published.\n')


def sanitize(root):
    source = load(root / 'summary.json', 16 * 1024 * 1024)
    rows = source.get('per_run')
    need(type(rows) is list and len(rows) == len(LABELS))
    clean_rows = []
    for row, label in zip(rows, LABELS):
        need(type(row) is dict and row.get('label') == label)
        need(all(finite(row.get(field)) for field in PER_RUN) and
             all(row[field] > 0 for field in CORE) and row['success_rate'] >= 99)
        report = load(root / f'report-{label}.json', 64 * 1024 * 1024)
        blocks = sorted(report['blocks'], key=lambda item: item.get('timestamp', item.get('timestamp_ms', -1)))[5:]
        need(blocks)
        timestamps = [item.get('timestamp', item.get('timestamp_ms')) for item in blocks]
        need(all(finite(value) for value in timestamps))
        receipt = load(root / f'phase-range-{label}.json', 4096)
        clean_rows.append({'label': label, **{field: row[field] for field in PER_RUN},
                           'phase_duration_ms': receipt['finished_ms'] - receipt['started_ms'],
                           'timestamp_span_ms': max(timestamps) - min(timestamps),
                           'first_retained_tx': blocks[0].get('tx_count'),
                           'first_retained_gas': blocks[0].get('gas_used')})
        need(all(finite(clean_rows[-1][field]) for field in
                 ('phase_duration_ms', 'timestamp_span_ms', 'first_retained_tx', 'first_retained_gas')))
    config = source.get('config')
    need(type(config) is dict and config.get('duration') == 15 and config.get('run_pairs') == PAIRS and
         config.get('summary_warmup_blocks') == 5 and config.get('preset') == 'default' and
         config.get('bloat') == 102400 and config.get('tps') == 15000 and
         config.get('token_count') == 4 and config.get('run_side') == 'comparison')
    results = source.get('results')
    need(type(results) is dict)
    clean_results = {}
    for side in ('baseline', 'feature'):
        values = results.get(side)
        need(type(values) is dict and all(finite(values.get(field)) for field in CORE + ('blocks',)) and
             all(values[field] > 0 for field in CORE + ('blocks',)))
        clean_results[side] = {field: values[field] for field in CORE + ('blocks',)}
    deltas = results.get('deltas')
    need(type(deltas) is dict and all(finite(deltas.get(field)) for field in CORE))
    clean_results['deltas'] = {field: deltas[field] for field in CORE}
    for name in ('baseline_ref', 'feature_ref'):
        need(type(source.get(name)) is str and len(source[name]) == 40 and
             all(char in '0123456789abcdef' for char in source[name]))
    need(source['baseline_ref'] == source['feature_ref'])
    public = {
        'schema': 1,
        'status': 'complete',
        'baseline_ref': source['baseline_ref'],
        'feature_ref': source['feature_ref'],
        'config': {
            'preset': 'default',
            'bloat_mib': config.get('bloat'),
            'tps': config.get('tps'),
            'accounts': 1000,
            'max_concurrent_requests': 100,
            'token_count': 4,
            'duration': 15,
            'run_pairs': PAIRS,
            'summary_warmup_blocks': 5,
            'order': RUNS,
            'storage_workers': 32,
            'account_workers': 32,
            'prewarming_threads': 16,
            'read_readiness': 'disabled',
            'control_flag': 'off',
            'feature_flag': 'selective_storage_retries',
        },
        'results': clean_results,
        'per_run': clean_rows,
    }
    need(all(value is None or finite(value) for key, value in public['config'].items()
             if key in ('bloat', 'tps')))
    (root / 'summary.json').write_text(json.dumps(public, sort_keys=True, indent=2) + '\n')
    units = {field: ('ms' if 'latency' in field or 'block_time' in field else
                     'Mgas/s' if field == 'mgas_s' else
                     'gas/s' if field.endswith('gas_s') else
                     'tx/s' if field == 'tps' else 'Mgas/s') for field in CORE}
    lines = ['# Standard benchmark summary', '',
             '| Metric | Unit | Baseline aggregate | Feature aggregate | Change |',
             '|---|---|---:|---:|---:|']
    for field in CORE:
        lines.append(f"| {field} | {units[field]} | {clean_results['baseline'][field]} | "
                     f"{clean_results['feature'][field]} | {clean_results['deltas'][field]:+.2f}% |")
    lines += ['', '## Trial configuration', '',
              'Six feature/control pairs; 15 seconds per phase; five warmup blocks excluded. '
              'Preset: default; target: 15,000 TPS; state: 100 GiB. Workers: 32 storage, 32 account, '
              '16 prewarming. Read-readiness instrumentation disabled.', '',
              '| Phase | Blocks | Transactions | Gas | Success |', '|---|---:|---:|---:|---:|']
    for row in clean_rows:
        lines.append(f"| {row['label']} | {row['blocks']} | {row['total_tx']} | "
                     f"{row['total_gas']} | {row['success_rate']:.1f}% |")
    lines += ['', 'The 15-second phases limit tail estimates and do not establish sustained-load performance.',
              'Run-level confidence and estimator notes are in `run-inference.md`.', '']
    (root / 'summary.md').write_text('\n'.join(lines))
    public_dir = root / 'lifecycle'
    public_dir.mkdir(exist_ok=True)
    for name in ('summary.json', 'summary.md'):
        (public_dir / name).write_bytes((root / name).read_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('admit', 'sanitize'):
        child = sub.add_parser(name)
        child.add_argument('root', type=Path)
    child = sub.add_parser('unavailable')
    child.add_argument('root', type=Path)
    child.add_argument('attempted', type=int)
    child.add_argument('reason', choices=('backpressure', 'summary_admission'), nargs='?', default='backpressure')
    args = parser.parse_args()
    try:
        if args.cmd == 'admit':
            admit(args.root)
        elif args.cmd == 'sanitize':
            sanitize(args.root)
        else:
            unavailable(args.root, args.attempted, args.reason)
    except Rejected as error:
        raise SystemExit(f'statistical_trial_rejected:{error}') from None
    except Exception:
        raise SystemExit('statistical_trial_rejected:internal') from None
