#!/usr/bin/env python3
"""Build an offline lifecycle report from privacy-filtered node captures."""
import argparse
import json
import math
from pathlib import Path

BLOCK_FIELDS = ('block_hash', 'hash', 'digest', 'proposal', 'payload')
STAGES = ('proposal_start', 'payload_built', 'proposal_ready', 'digest_released',
          'verify_start', 'body_ready', 'replay_start', 'replay_done', 'verify_done',
          'notarize_vote_sent', 'notarized', 'finalize_vote_sent', 'finalized', 'finalization_received')


def block_key(fields):
    return next((fields[k] for k in BLOCK_FIELDS if isinstance(fields.get(k), str)
                 and len(fields[k]) == 24 and all(c in '0123456789abcdef' for c in fields[k])), None)


def nearest_rank(blocks, percentile):
    ordered = sorted(blocks, key=lambda b: (b['duration'], b['id']))
    return ordered[max(0, math.ceil(len(ordered) * percentile / 100) - 1)]['id'] if ordered else None


def read_node(path, role):
    spans, events, links, polls = {}, [], [], {}
    header, footer, invalid = None, None, 0
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            invalid += 1
            continue
        kind = event.get('type')
        if kind == 'header':
            header = event
        elif kind == 'footer':
            footer = event
        elif kind == 'start':
            spans[event['id']] = dict(event, node=role, end=None, active=[])
        elif kind == 'fields' and event['id'] in spans:
            spans[event['id']]['fields'].update(event['fields'])
        elif kind == 'end' and event['id'] in spans:
            spans[event['id']]['end'] = event['ts']
        elif kind == 'event':
            events.append(dict(event, node=role))
        elif kind == 'link':
            links.append(event)
        elif kind == 'enter':
            polls.setdefault((event['id'], event['thread']), []).append(event['ts'])
        elif kind == 'exit':
            stack = polls.get((event['id'], event['thread']), [])
            if stack and event['id'] in spans:
                spans[event['id']]['active'].append((stack.pop(), event['ts'], event['thread']))
    # A marker can bind a previously anonymous build/attempt span after its hash exists.
    for event in events:
        key = block_key(event['fields'])
        span = spans.get(event['id'])
        if key and span and not block_key(span['fields']):
            span['fields']['block_hash'] = key
    payloads = {s['fields']['payload_id']: block_key(s['fields']) for s in spans.values()
                if s['fields'].get('payload_id') and block_key(s['fields'])}
    for s in spans.values():
        if not block_key(s['fields']) and s['fields'].get('payload_id') in payloads:
            s['fields']['block_hash'] = payloads[s['fields']['payload_id']]

    def inherited(s):
        seen = set()
        while s and s['id'] not in seen:
            seen.add(s['id'])
            key = block_key(s['fields'])
            if key:
                return key
            s = spans.get(s.get('parent'))
        return None

    for span in spans.values():
        span['block'] = inherited(span)
    for event in events:
        event['block'] = block_key(event['fields']) or inherited(spans.get(event['id']))
    quality = {'node': role, 'header': bool(header and header.get('schema') == 1),
               'footer': footer is not None, 'dropped': (footer or {}).get('dropped', 0),
               'io_error': (footer or {}).get('io_error', False), 'invalid_lines': invalid,
               'open_spans': sum(s['end'] is None for s in spans.values())}
    return list(spans.values()), events, quality


def active_wall_ns(intervals):
    end, duration = 0, 0
    for start, finish, _ in sorted(intervals):
        duration += max(0, finish-max(start,end))
        end = max(end,finish)
    return duration


def build(paths, warmup=5, window=None):
    spans, events, quality = [], [], []
    for index, path in enumerate(paths):
        ss, es, qq = read_node(path, f'Validator {chr(65 + index)}')
        spans.extend(ss)
        events.extend(es)
        quality.append(qq)
    first = min((x['ts'] for x in spans + events), default=0)
    keys = sorted({e['block'] for e in events if e.get('block')},
                  key=lambda key: min(e['ts'] for e in events if e.get('block') == key))
    aliases = {key: i + 1 for i, key in enumerate(keys)}
    blocks = []
    for key in keys:
        markers = [dict(stage=e['fields'].get('stage'), ts=(e['ts']-first)/1e6, node=e['node'])
                   for e in events if e.get('block') == key and e['fields'].get('stage') in STAGES]
        starts = [e['ts'] for e in markers if e['stage'] == 'proposal_start']
        ends = [e['ts'] for e in markers if e['stage'] == 'finalized']
        complete = bool(starts and ends and min(ends) >= min(starts))
        start = min(starts) if starts else min((e['ts'] for e in markers), default=0)
        finish = min(ends) if complete else max((e['ts'] for e in markers), default=start)
        totals = [dict(node=e['node'], **{k:v for k,v in e['fields'].items()
                  if k in ('execution_ns','receipt_ns','wait_ns','transactions')})
                  for e in events if e.get('block') == key and e['fields'].get('stage') == 'execution_totals']
        blocks.append({'execution_totals': totals, 'id': aliases[key], 'start': start, 'end': finish,
                       'duration': finish-start, 'complete': complete, 'markers': markers})
    completed = sorted((b for b in blocks if b['complete']), key=lambda b: b['start'])
    for b in completed[:warmup]:
        b['warmup'] = True
    eligible = [b for b in completed if not b.get('warmup') and (window is None or
                (b['start'] >= (window['start_ns']-first)/1e6 and b['end'] <= (window['end_ns']-first)/1e6))]
    for b in blocks:
        b['in_population'] = b in eligible
    bad_capture = any(not q['header'] or not q['footer'] or q['dropped'] or q['io_error'] or q['invalid_lines'] for q in quality)
    # Lost events invalidate percentile completeness, even if some endpoints survived.
    representatives = {str(p): nearest_rank(eligible, p) if not bad_capture else None for p in (50,90,99)}
    rows = []
    for s in spans:
        if s['end'] is None or s['end'] < s['ts']:
            continue
        rows.append({'id': s['id'], 'node': s['node'], 'parent': s.get('parent'),
                     'name': s['name'], 'category': s['category'], 'block': aliases.get(s['block']),
                     'start': (s['ts']-first)/1e6, 'end': (s['end']-first)/1e6,
                     'thread': s['thread'], 'active_ms': active_wall_ns(s['active'])/1e6})
    frames = {}
    for event in events:
        f = event['fields']
        if f.get('stage') in ('frame_send','frame_receive') and f.get('frame_hash'):
            frames.setdefault(f['frame_hash'], []).append({'node':event['node'], 'ts':(event['ts']-first)/1e6, 'stage':f['stage'], 'bytes':f.get('bytes',0)})
    transfers = []
    for group in frames.values():
        sends = [e for e in group if e['stage'] == 'frame_send']
        receives = [e for e in group if e['stage'] == 'frame_receive']
        if len(sends) == 1 and len(receives) == 1:
            transfers.append({'from': sends[0]['node'], 'to': receives[0]['node'], 'start': sends[0]['ts'], 'end': receives[0]['ts'], 'bytes': sends[0]['bytes']})
    attempts = [s for s in spans if s['name'] == 'handle_propose']
    return {'schema':1, 'blocks':blocks, 'spans':rows, 'transfers':transfers, 'quality':quality,
            'representatives':representatives, 'eligible':len(eligible), 'warmup':warmup,
            'attempts':len(attempts), 'unbound_attempts':sum(not s.get('block') for s in attempts),
            'coverage':sorted({s['name'] for s in rows}), 'stages':list(STAGES), 'bad_capture':bad_capture,
            'definition':'Proposal handling start on proposer → first accepted finalization certificate on a validator. Nearest-rank percentiles select actual complete blocks; initial complete blocks are excluded as warmup. When load boundaries are available, both endpoints must fall inside the load window.'}


def write_report(paths, out, warmup=5, window=None):
    data = build(paths, warmup, window)
    out.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, separators=(',',':')).replace('<', '\\u003c')
    template = Path(__file__).with_name('viewer.html').read_text()
    (out/'index.html').write_text(template.replace('__LIFECYCLE_DATA__', encoded))
    (out/'lifecycle.json').write_text(encoded)
    trace = [{'name':s['name'], 'cat':s['category'], 'ph':'X', 'ts':s['start']*1000,
              'dur':(s['end']-s['start'])*1000, 'pid':s['node'], 'tid':f"operation {s['id']}",
              'args':{'block':s['block'], 'active_wall_ms':s['active_ms']}} for s in data['spans']]
    for b in data['blocks']:
        trace += [{'name':e['stage'], 'ph':'i', 's':'p', 'ts':e['ts']*1000, 'pid':e['node'],
                   'tid':'milestones', 'args':{'block':b['id']}} for e in b['markers']]
    (out/'perfetto.json').write_text(json.dumps({'traceEvents':trace}, separators=(',',':')))
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--warmup', type=int, default=5)
    parser.add_argument('--window', type=Path)
    parser.add_argument('captures', type=Path, nargs='+')
    args = parser.parse_args()
    result = write_report(args.captures, args.out, args.warmup, json.loads(args.window.read_text()) if args.window else None)
    print(f"Lifecycle report: {len(result['blocks'])} blocks, {result['eligible']} complete post-warmup blocks; capture loss: {result['bad_capture']}")
    if result['bad_capture'] or not result['eligible']:
        raise SystemExit(2)
