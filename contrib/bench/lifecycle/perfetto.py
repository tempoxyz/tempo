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
    if block_id is not None:
        blocks = [b for b in blocks if b['id'] == block_id]
        if not blocks:
            raise ValueError(f'Block {block_id} is not in this capture')
        spans = [s for s in spans if s['block'] == block_id]
        block = blocks[0]
        transfers = [t for t in transfers if t['start'] < block['end'] and t['end'] > block['start']]

    nodes = {q['node']: i + 1 for i, q in enumerate(data['quality'])}
    intervals = []
    for s in spans:
        aggregate = bool(s.get('count'))
        args = {'block': s['block'], 'span_id': s['id'], 'parent_span_id': s['parent'],
                'semantics': 'aggregate envelope, not continuous work' if aggregate else s.get('timing_semantics', 'span_lifetime')}
        args.update(s.get('details', {}))
        if s.get('attempt') is not None:
            args['proposal_attempt'] = s['attempt']
        if aggregate:
            args.update(call_count=s['count'], elapsed_sum_ms=s['elapsed_sum_ms'])
        else:
            args.update(active_wall_ms=s['active_ms'], source_thread_ordinal=s['thread'],
                        retained_after_operation_ms=s.get('retained_after_operation_ms'),
                        reference_right_censored=s.get('reference_right_censored', False),
                        reference_retention_lower_bound_ms=s.get('reference_retention_lower_bound_ms'))
        if s.get('right_censored'):
            args.update(right_censored=True, semantics='reference lifetime truncated at cutoff; operation completion unknown')
        intervals.append((nodes[s['node']], s['category'], 'aggregate envelope' if aggregate else 'wall time',
                          round(s['start'] * 1_000_000), round(s['end'] * 1_000_000),
                          s['name'] + (' [aggregate envelope]' if aggregate else ' [cutoff]' if s.get('right_censored') else ''), args))
    for t in transfers:
        # This is a matched frame transfer, not a proven application/block dependency.
        intervals.append((nodes[t['from']], 'network', 'frame context',
                          round(t['start'] * 1_000_000), round(t['end'] * 1_000_000),
                          'encrypted frame transfer [context]',
                          {'to': t['to'], 'bytes': t['bytes'], 'semantics': 'encryption complete to ciphertext receipt; no block attribution'}))

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
                           'pid': nodes[e['node']], 'tid': 0, 'args': {'block': b['id']}})
    events.sort(key=lambda e: (e['ts'], e['pid'], e['tid']))
    return metadata + events


def write_trace(data, path, block_id=None):
    events = trace_events(data, block_id)
    path.write_text(json.dumps({'traceEvents': events, 'displayTimeUnit': 'ms'}, separators=(',', ':')))
    return {'file': path.name, 'events': sum(e['ph'] != 'M' for e in events),
            'tracks': sum(e['name'] == 'thread_name' and e['ph'] == 'M' for e in events)}


def write_exports(data, out, block_id=None):
    out.mkdir(parents=True, exist_ok=True)
    if block_id is not None:
        return [write_trace(data, out / f'perfetto-block-{block_id}.json', block_id)]
    results = [write_trace(data, out / 'perfetto.json')]
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
    args = parser.parse_args()
    data = json.loads(args.report.read_text())
    for result in write_exports(data, args.out, args.block):
        print(f"{result['file']}: {result['events']} events on {result['tracks']} visual lanes")
