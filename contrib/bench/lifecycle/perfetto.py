#!/usr/bin/env python3
"""Export measured wall-time intervals on reusable, non-overlapping visual lanes."""
import argparse
from collections import defaultdict
import heapq
import json
from pathlib import Path


def trace_events(data, block_id=None):
    """Keep every interval; lane count scales with concurrency, not event count.

    These are virtual display lanes, not worker threads. Interval partitioning
    prevents crossing async intervals from becoming invalid nested Chrome slices.
    Aggregate envelopes use separate lanes and explicitly describe their bounds.
    """
    blocks = data['blocks']
    spans = data['spans']
    transfers = data.get('transfers', [])
    network_events = data.get('network_events', [])
    if block_id is not None:
        blocks = [b for b in blocks if b['id'] == block_id]
        if not blocks:
            raise ValueError(f'Block {block_id} is not in this capture')
        spans = [s for s in spans if s['block'] == block_id]
        block = blocks[0]
        transfers = [t for t in transfers if block_id in t.get('blocks', []) or (t['start'] < block['end'] and t['end'] > block['start'])]
        network_events = [e for e in network_events if block_id in e.get('blocks', [])]

    nodes = {q['node']: i + 1 for i, q in enumerate(data['quality'])}
    intervals = []
    for s in spans:
        aggregate = bool(s.get('count'))
        args = {'block': s['block'], 'span_id': s['id'], 'parent_span_id': s['parent'],
                'semantics': 'aggregate envelope, not continuous work' if aggregate else s.get('timing_semantics', 'span_lifetime')}
        args.update(s.get('details', {}))
        if 'worker_completion_count' in args:
            args['worker_cpu_scope'] = ('Synchronous worker.run thread CPU; excludes construction '
                'and result forwarding. worker_run_ns includes receive waits and teardown. '
                'Worker CPU sums overlap across threads; they are not block elapsed time. '
                'Missing or duplicate completions do not imply zero CPU.')
        if s.get('context_reason'):
            args['context_reason'] = s['context_reason']
        if data.get('focus_block') is not None:
            args['association'] = 'selected block' if s['block'] == data['focus_block'] else 'causal ancestor; no selected-block attribution'
        if s.get('attempt') is not None:
            args['proposal_attempt'] = s['attempt']
        if aggregate:
            args.update(call_count=s['count'], elapsed_sum_ms=s['elapsed_sum_ms'])
        else:
            args.update(active_wall_ms=s['active_ms'], source_thread_ordinal=s['thread'],
                        retained_after_operation_ms=(s.get('retained_after_operation_ms')
                            if 'reference_right_censored' in s else None),
                        reference_right_censored=s.get('reference_right_censored'),
                        reference_retention_lower_bound_ms=s.get('reference_retention_lower_bound_ms'))
            if s['active_ms'] is None:
                args['active_wall_status'] = 'not recorded in milestone-only capture'
        if s.get('right_censored'):
            args.update(right_censored=True, semantics='reference lifetime truncated at cutoff; operation completion unknown')
        intervals.append((nodes[s['node']], s['category'], 'aggregate envelope' if aggregate else 'wall time',
                          round(s['start'] * 1_000_000), round(s['end'] * 1_000_000),
                          s['name'] + (' [aggregate envelope]' if aggregate else ' [cutoff]' if s.get('right_censored') else ''), args))
    for t in transfers:
        # Source/decode association does not isolate network transit from scheduling.
        intervals.append((nodes[t['from']], 'network', 'frame context',
                          round(t['start'] * 1_000_000), round(t['end'] * 1_000_000),
                          'encrypted frame transfer [' + ('associated' if t.get('blocks') else 'context') + ']',
                          {**{k:v for k,v in t.items() if k not in ('start', 'end')}, 'semantics': 'encryption complete to ciphertext receipt, not pure wire time; ' + ('block sets describe causal source or codec membership, not byte attribution or semantic validation' if t.get('blocks') else 'no block attribution')}))

    metadata = []
    events = []
    for node, pid in nodes.items():
        metadata.extend([
            {'name': 'process_name', 'ph': 'M', 'pid': pid, 'tid': 0, 'args': {'name': node}},
            {'name': 'thread_name', 'ph': 'M', 'pid': pid, 'tid': 0, 'args': {'name': 'Block milestones'}},
        ])
    lanes = defaultdict(list)
    counts = defaultdict(int)
    next_tid = defaultdict(lambda: 1)
    for pid, category, kind, start, end, name, args in sorted(intervals, key=lambda i: (i[3], -i[4], i[0], i[1], i[2], i[5])):
        if end < start:
            raise ValueError('Negative interval in capture')
        key = (pid, category, kind)
        available = lanes[key]
        if available and available[0][0] <= start:
            _, tid = heapq.heappop(available)
        else:
            tid = next_tid[pid]
            next_tid[pid] += 1
            counts[key] += 1
            metadata.append({'name': 'thread_name', 'ph': 'M', 'pid': pid, 'tid': tid,
                             'args': {'name': f'{category} / {kind} lane {counts[key]} (virtual)'}})
        heapq.heappush(available, (end, tid))
        events.append({'name': name, 'cat': category, 'ph': 'X', 'pid': pid, 'tid': tid,
                       'ts': start / 1000, 'dur': (end - start) / 1000, 'args': args})
    for b in blocks:
        for e in b['markers']:
            events.append({'name': e['stage'], 'ph': 'i', 's': 't', 'ts': round(e['ts'] * 1_000_000) / 1000,
                           'pid': nodes[e['node']], 'tid': 0, 'args': {'block': b['id'], **({'proposal_attempt': b['attempt']} if b.get('attempt') is not None else {})}})
    for node, pid in nodes.items():
        selected = [e for e in network_events if e['node'] == node]
        if selected:
            tid = next_tid[pid]
            metadata.append({'name':'thread_name', 'ph':'M', 'pid':pid, 'tid':tid, 'args':{'name':'Network lineage milestones'}})
            events.extend({'name':e['stage'], 'cat':'network', 'ph':'i', 's':'t', 'pid':pid, 'tid':tid, 'ts':round(e['ts'] * 1_000_000)/1000, 'args':{k:v for k,v in e.items() if k not in ('ts','node','stage')}} for e in selected)
    events.sort(key=lambda e: (e['ts'], e['pid'], e['tid']))
    return metadata + events


def write_trace(data, path, block_id=None):
    events = trace_events(data, block_id)
    path.write_text(json.dumps({'traceEvents': events, 'displayTimeUnit': 'ms'}, separators=(',', ':')))
    return {'file': path.name, 'events': sum(e['ph'] != 'M' for e in events),
            'tracks': sum(e['name'] == 'thread_name' and e['ph'] == 'M' for e in events)}


def write_exports(data, out, block_id=None, full=False):
    out.mkdir(parents=True, exist_ok=True)
    if block_id is not None:
        return [write_trace(data, out / f'perfetto-block-{block_id}.json', block_id)]
    full_data = dict(data, blocks=data['blocks'] + [dict(a, id=None, attempt=a['id'])
        for a in data.get('attempt_details', []) if not a.get('block')])
    results = [write_trace(full_data, out / 'perfetto.json')] if full else []
    for percentile in (50, 90, 99):
        path = out / f'perfetto-p{percentile}.json'
        representative = data['representatives'].get(str(percentile))
        if representative is not None and not data['bad_capture']:
            results.append(write_trace(data, path, representative))
        elif path.exists():
            # Do not leave an earlier run's percentile file attached to an invalid capture.
            path.unlink()
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path, help='Existing lifecycle.json; raw captures are not needed')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--block', type=int, help='Export just this report-local block number')
    parser.add_argument('--full', action='store_true', help='Also export the potentially very large complete Perfetto trace')
    args = parser.parse_args()
    data = json.loads(args.report.read_text())
    for result in write_exports(data, args.out, args.block, args.full):
        print(f"{result['file']}: {result['events']} events on {result['tracks']} visual lanes")
