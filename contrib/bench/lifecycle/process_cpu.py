"""Closed whole-process accounting observations; no thread or block attribution."""
import json
from html import escape

MODE = 'rusage_self_v1'
PERIOD_NS = 250_000_000
CAP = 100_000
TOTALS = ('samples', 'unavailable', 'missed_deadlines')
DESCRIPTION = ('RUSAGE_SELF user/system CPU includes every validator thread, including the '
               'recorder and sampler. It excludes child-process CPU. Read brackets express '
               'snapshot uncertainty. This CPU overlaps worker/leaf totals; never add them. '
               'Intervals are not attributed to blocks and are not interpolated.')


def need(condition):
    if not condition:
        raise ValueError('invalid process CPU coverage')


def uint(value):
    need(type(value) is int and 0 <= value < 2**64)
    return value


def cutoff_for(window, cutoff):
    end = (window or {}).get('end_ns')
    if end is not None:
        uint(end)
    return min(x for x in (cutoff, end) if x is not None) if cutoff is not None or end is not None else None


class Stream:
    """Validate all source rows, including rows later censored by performance cutoff."""
    def __init__(self):
        self.header = self.footer = None
        self.samples = []
        self.last_success = None

    def observe(self, row):
        kind = row.get('type')
        if kind == 'header':
            need(self.header is None and self.footer is None and not self.samples)
            self.header = row
        elif kind == 'footer':
            need(self.footer is None)
            self.footer = row
        elif kind == 'process_cpu':
            need(self.header is not None and self.footer is None)
            need(self.header.get('process_cpu') == MODE)
            status = uint(row.get('status'))
            need(status in (0, 1, 2, 3))
            keys = {'type', 'sequence', 'read_start_ns', 'read_end_ns', 'status', 'missed_deadlines'}
            if status == 0:
                keys |= {'user_cpu_us', 'system_cpu_us'}
            need(set(row) == keys)
            for key in keys - {'type'}:
                uint(row[key])
            need(row['sequence'] == len(self.samples) + 1 <= CAP)
            need(row['read_start_ns'] <= row['read_end_ns'])
            if self.samples:
                need(self.samples[-1]['read_end_ns'] <= row['read_start_ns'])
            if status == 0:
                if self.last_success:
                    need(all(row[k] >= self.last_success[k] for k in ('user_cpu_us', 'system_cpu_us')))
                self.last_success = row
            self.samples.append(row)

    def finish(self):
        header, footer = self.header or {}, self.footer or {}
        mode = header.get('process_cpu', 'disabled')
        need(mode in ('disabled', MODE))
        extra_header = {k for k in header if k.startswith('process_cpu')}
        extra_footer = {k for k in footer if k.startswith('process_cpu')}
        if mode == 'disabled':
            need(extra_header <= {'process_cpu'} and not extra_footer and not self.samples)
            return dict(mode=mode, samples=[], footer={}, declared='process_cpu' in header)
        need(extra_header == {'process_cpu', 'process_cpu_period_ns'})
        need(uint(header['process_cpu_period_ns']) == PERIOD_NS)
        need(self.footer is not None and footer.get('dropped') == 0 and footer.get('io_error') is False)
        need(type(footer.get('dropped')) is int and not footer.get('invalid_lines', 0))
        required = {'process_cpu_' + k for k in (*TOTALS, 'failures')}
        pruned = {'process_cpu_pruned_' + k for k in TOTALS}
        need(extra_footer in (required, required | pruned))
        for key in extra_footer:
            uint(footer[key])
        need(footer['process_cpu_failures'] == 0)
        need(footer['process_cpu_samples'] <= CAP)
        actual = dict(samples=len(self.samples), unavailable=sum(r['status'] != 0 for r in self.samples),
                      missed_deadlines=sum(r['missed_deadlines'] for r in self.samples))
        for key, count in actual.items():
            need(count + footer.get('process_cpu_pruned_' + key, 0) == footer['process_cpu_' + key])
        need(footer.get('process_cpu_pruned_unavailable', 0) <= footer.get('process_cpu_pruned_samples', 0))
        need(all(r['status'] in (0, 1) for r in self.samples))
        return dict(mode=mode, samples=self.samples, footer={k: footer[k] for k in extra_footer}, declared=True)


def prune_metadata(source, cutoff):
    """Additional removed suffix counts, preserving any earlier pruning receipt."""
    rows = [r for r in source['samples'] if cutoff is not None and r['read_end_ns'] >= cutoff]
    counts = dict(samples=len(rows), unavailable=sum(r['status'] != 0 for r in rows),
                  missed_deadlines=sum(r['missed_deadlines'] for r in rows))
    return {f'process_cpu_pruned_{k}': source['footer'].get(f'process_cpu_pruned_{k}', 0) + v
            for k, v in counts.items()}


def inspect(sources, window=None, cutoff=None, expected=None):
    modes = {s['mode'] for _, s in sources}
    need(len(modes) == 1)
    mode = next(iter(modes))
    need(expected is None or (expected == mode and all(s["declared"] for _, s in sources)))
    cutoff = cutoff_for(window, cutoff)
    start = (window or {}).get('start_ns')
    if start is not None:
        uint(start)
        need(cutoff is not None and start <= cutoff)
    nodes = []
    for node, source in sources:
        rows = [r for r in source['samples'] if cutoff is None or r['read_end_ns'] < cutoff]
        intervals, gaps = [], []
        edge = 0
        for left, right in zip(rows, rows[1:]):
            if right['missed_deadlines']:
                gaps.append(dict(from_sequence=left['sequence'], to_sequence=right['sequence'], reason='missed_deadlines'))
            if left['status'] or right['status']:
                gaps.append(dict(from_sequence=left['sequence'], to_sequence=right['sequence'], reason='unavailable_endpoint'))
                continue
            need(right['sequence'] == left['sequence'] + 1)
            if start is not None and left['read_start_ns'] < start:
                edge += 1
                continue
            user = right['user_cpu_us'] - left['user_cpu_us']
            system = right['system_cpu_us'] - left['system_cpu_us']
            intervals.append(dict(from_sequence=left['sequence'], to_sequence=right['sequence'],
                left_read_start_ns=left['read_start_ns'], left_read_end_ns=left['read_end_ns'],
                right_read_start_ns=right['read_start_ns'], right_read_end_ns=right['read_end_ns'],
                elapsed_min_ns=right['read_start_ns']-left['read_end_ns'],
                elapsed_max_ns=right['read_end_ns']-left['read_start_ns'],
                user_cpu_us=user, system_cpu_us=system, process_cpu_us=user+system))
        pruned = prune_metadata(source, cutoff) if mode == MODE else {}
        status = ('disabled' if mode == 'disabled' else 'no_retained_samples' if not rows else
                  'too_few_samples' if len(rows) < 2 else 'no_complete_intervals' if not intervals else
                  'partial' if gaps or edge or any(r['missed_deadlines'] for r in rows) else 'observed')
        nodes.append(dict(node=node, status=status, samples=rows, intervals=intervals, gaps=gaps,
            summary=dict(retained_samples=len(rows), unavailable_samples=sum(r['status'] != 0 for r in rows),
                retained_missed_deadlines=sum(r['missed_deadlines'] for r in rows),
                excluded_window_pairs=edge, interval_count=len(intervals),
                user_cpu_us=sum(r['user_cpu_us'] for r in intervals) if intervals else None,
                system_cpu_us=sum(r['system_cpu_us'] for r in intervals) if intervals else None,
                covered_inner_ns=sum(r['elapsed_min_ns'] for r in intervals)),
            source_totals={k: v for k, v in source['footer'].items() if not k.startswith('process_cpu_pruned_')}, pruning=pruned))
    return dict(schema=1, mode=mode, description=DESCRIPTION, period_ns=PERIOD_NS if mode == MODE else None,
                cutoff_ns=cutoff, window_start_ns=start, nodes=nodes)


def write_view(data, out):
    if data['mode'] != MODE:
        for name in ('process-cpu.json', 'process-cpu.html'):
            (out/name).unlink(missing_ok=True)
        return
    (out/'process-cpu.json').write_text(json.dumps(data, separators=(',', ':'))+'\n')
    columns = ('retained_samples', 'unavailable_samples', 'retained_missed_deadlines',
               'excluded_window_pairs', 'interval_count', 'user_cpu_us', 'system_cpu_us', 'covered_inner_ns')
    rows = []
    for node in data['nodes']:
        values = [node['node'], node['status'], *[node['summary'][key] for key in columns],
                  node['pruning'].get('process_cpu_pruned_samples', 0), len(node['gaps'])]
        rows.append('<tr>'+''.join('<td>'+escape('unavailable' if value is None else str(value))+'</td>' for value in values)+'</tr>')
    headings = ('Node', 'Status', 'Retained samples', 'Failed reads', 'Missed deadlines',
                'Pairs before window', 'Intervals', 'User CPU (us)', 'System CPU (us)',
                'Covered inner time (ns)', 'Samples removed at cutoff', 'Gap observations')
    (out/'process-cpu.html').write_text('<!doctype html><meta charset="utf-8"><title>Whole-process CPU coverage</title><h1>Whole-process CPU coverage</h1><p>'+escape(DESCRIPTION)+'</p><p>CPU sums cover admitted adjacent endpoint pairs only. Missing edges are unavailable, not zero. Covered time uses disjoint inner bracket cores, not overlapping outer envelopes. Missed-deadline gaps preserve the exact cumulative CPU difference between adjacent successful reads; only unavailable endpoints prevent a delta. Samples and gap counts describe all retained source observations; CPU interval sums require complete loaded-window endpoints.</p><table><tr>'+''.join('<th>'+escape(h)+'</th>' for h in headings)+'</tr>'+''.join(rows)+'</table><p><a href="process-cpu.json">Exact brackets, samples, gaps and totals</a></p>')



def admission(paths, expected, timeout=0):
    import time
    from pathlib import Path
    if expected not in ('disabled', MODE) or len(paths) != 2 or not 0 <= timeout <= 30:
        return False
    deadline = time.monotonic() + timeout
    while True:
        ready = True
        for path in paths:
            try:
                with Path(path).open() as stream:
                    line = stream.readline(4097)
                if not line.endswith('\n'):
                    if len(line) > 4096:
                        return False
                    ready = False
                    continue
                header = json.loads(line)
                need(type(header) is dict and header.get('type') == 'header')
                need(type(header.get('schema')) is int and header['schema'] == 1)
                need(header.get('clock') == 'shared_monotonic_relative_ns')
                need(header.get('detail') == 'milestones' and header.get('process_cpu') == expected)
                need(header.get('prewarm_cpu') == 'disabled')
                if expected == MODE:
                    need(uint(header.get('process_cpu_period_ns')) == PERIOD_NS)
                else:
                    need('process_cpu_period_ns' not in header)
            except (FileNotFoundError, json.JSONDecodeError):
                ready = False
            except (OSError, ValueError):
                return False
        if ready:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', choices=('disabled', MODE), required=True)
    parser.add_argument('--timeout', type=float, default=0)
    parser.add_argument('captures', type=Path, nargs=2)
    args = parser.parse_args()
    if not admission(args.captures, args.expected, args.timeout):
        raise SystemExit('process_cpu_admission_failed')
