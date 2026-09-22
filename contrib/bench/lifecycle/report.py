#!/usr/bin/env python3
"""Build an offline lifecycle report from privacy-filtered node captures."""
import argparse
import json
import math
from pathlib import Path
from report_package import write_package
from backpressure import first_boundary, prepare_captures
import prewarm
import read_readiness
from collections import defaultdict

BLOCK_FIELDS = ('block_hash', 'hash', 'digest', 'proposal', 'payload')
STAGES = ('builder_execution_done', 'state_root_result_ready', 'proposal_start', 'payload_built', 'proposal_ready', 'digest_released',
          'verify_start', 'body_ready', 'replay_start', 'replay_done', 'verify_done',
          'notarize_vote_sent', 'notarized', 'finalize_vote_sent', 'finalized', 'finalization_received', 'cancelled', 'proposal_failed')

WORKER_STAGES = {'proof_storage_worker_totals': 'storage_worker',
                 'proof_account_worker_totals': 'account_worker'}
WORKER_FIELDS = ('worker_run_ns', 'worker_thread_cpu_ns',
                 'worker_cpu_measured', 'worker_success')


def attach_worker_details(rows, events):
    """Attach only exact, unique worker completions; never infer from ancestry/time."""
    workers = {(s['node'], s['id']): s for s in rows
               if s['name'] in WORKER_STAGES.values()}
    completions = {}
    for event in events:
        key = (event['node'], event['id'])
        span = workers.get(key)
        if span and WORKER_STAGES.get(event['fields'].get('stage')) == span['name']:
            completions.setdefault(key, []).append(event['fields'])
    for key, span in workers.items():
        matches = completions.get(key, [])
        span['details']['worker_completion_count'] = len(matches)
        if len(matches) == 1:
            span['details'].update({k: v for k, v in matches[0].items()
                                    if k in WORKER_FIELDS})


def block_key(fields):
    return next((fields[k] for k in BLOCK_FIELDS if isinstance(fields.get(k), str)
                 and len(fields[k]) == 24 and all(c in '0123456789abcdef' for c in fields[k])), None)


def nearest_rank(blocks, percentile):
    ordered = sorted(blocks, key=lambda b: (b['duration'], b['id']))
    return ordered[max(0, math.ceil(len(ordered) * percentile / 100) - 1)]['id'] if ordered else None


def read_node(path, role, cutoff=None):
    spans, events, links, polls, aggregates = {}, [], [], {}, []
    header, footer, invalid = None, None, 0
    excluded_aggregates = 0
    with path.open() as capture:
        for line in capture:
            try:
                event = json.loads(line)
            except ValueError:
                invalid += 1
                continue
            kind = event.get('type')
            # Parse structural metadata after the cutoff for capture-integrity checks,
            # but never let later fields, identities or milestones affect the report.
            if cutoff is not None and kind not in ('header', 'footer'):
                if event.get('ts', cutoff) >= cutoff:
                    continue
                if kind == 'aggregate' and event['end'] >= cutoff:
                    excluded_aggregates += 1
                    continue

            if kind == 'header':
                header = event
            elif kind == 'footer':
                footer = event
            elif kind == 'start':
                spans[event['id']] = dict(event, node=role, end=None, active=[])
            elif kind == 'fields' and event['id'] in spans:
                spans[event['id']]['fields'].update(event['fields'])
            elif kind == 'end' and event['id'] in spans:
                spans[event['id']]['reference_end'] = event['ts']
                if not spans[event['id']].get('operation_status'):
                    spans[event['id']]['end'] = event['ts']
            elif kind == 'aggregate':
                aggregates.append(event)
            elif kind == 'event':
                events.append(dict(event, node=role))
                stage = event.get('fields', {}).get('stage')
                if stage in ('operation_completed', 'operation_abandoned') and event['id'] in spans:
                    span = spans[event['id']]
                    if not span.get('operation_status'):
                        span['end'] = event['ts']
                        span['operation_status'] = stage.removeprefix('operation_')
            elif kind == 'link':
                links.append(event)
            elif kind == 'enter':
                polls.setdefault((event['id'], event['thread']), []).append(event['ts'])
            elif kind == 'exit':
                stack = polls.get((event['id'], event['thread']), [])
                if stack and event['id'] in spans:
                    spans[event['id']]['active'].append((stack.pop(), event['ts'], event['thread']))
    censored = 0
    if cutoff is not None:
        for (span_id, thread), stack in polls.items():
            if span_id in spans:
                spans[span_id]['active'].extend((start, cutoff, thread) for start in stack)
        for span in spans.values():
            if span['end'] is None:
                span['end'] = cutoff
                span['right_censored'] = True
                censored += 1
    # A completion marker, unlike the last poll exit, proves the operation ended.
    # Preserve causal parent IDs even when detached children outlive that operation.
    for span in spans.values():
        if span.get('operation_status'):
            span['active'] = [(a, min(b, span['end']), t) for a, b, t in span['active']
                              if a < span['end']]
    for index, event in enumerate(aggregates,1):
        spans[-index] = dict(event, id=-index, parent=event['id'] or None, node=role,
                             thread=0, fields={}, active=[])
    # A marker can bind a previously anonymous build/attempt span after its hash exists.
    for event in events:
        key = block_key(event['fields'])
        span = spans.get(event['id'])
        if key and span and not block_key(span['fields']):
            span['fields']['block_hash'] = key
    payloads = {}
    for span in spans.values():
        payload = span['fields'].get('payload_id')
        block = block_key(span['fields'])
        if payload and block:
            payloads.setdefault(payload, set()).add(block)
    for s in spans.values():
        if not block_key(s['fields']):
            owners = payloads.get(s['fields'].get('payload_id'), set())
            if len(owners) == 1:
                s['fields']['block_hash'] = next(iter(owners))

    # A mailbox span travels with exactly one message; timestamps delimit its queue wait.
    queued = {}
    next_id = min([0, *spans]) - 1
    for event in events:
        stage = event['fields'].get('stage')
        if stage == 'marshal_enqueued':
            queued[event['id']] = event['ts']
        elif stage == 'marshal_dequeued' and event['id'] in queued:
            start = queued.pop(event['id'])
            if event['ts'] >= start:
                spans[next_id] = dict(id=next_id, parent=event['id'], node=role,
                    ts=start, end=event['ts'], thread=0, fields={}, active=[],
                    name='marshal.queue_wait', category='lifecycle')
                next_id -= 1
    for span_id, start in queued.items():
        owner = spans.get(span_id)
        if cutoff is not None and owner and owner.get('right_censored'):
            spans[next_id] = dict(id=next_id, parent=span_id, node=role, ts=start,
                end=cutoff, thread=0, fields={}, active=[], right_censored=True,
                name='marshal.queue_wait', category='lifecycle')
            next_id -= 1

    def attempt_owner(s):
        seen = set()
        while s and s['id'] not in seen:
            seen.add(s['id'])
            if s['name'] == 'handle_propose':
                return s['id']
            if s.get('attempt_root') is not None:
                return s['attempt_root']
            s = spans.get(s.get('parent'))
        return None

    # Detached payload jobs can retain their attempt identity before a block exists.
    # Only a unique payload-to-attempt mapping is evidence; never guess by timing.
    payload_attempts = {}
    for span in spans.values():
        span['attempt_root'] = attempt_owner(span)
        payload = span['fields'].get('payload_id')
        if payload and span['attempt_root'] is not None:
            payload_attempts.setdefault(payload, set()).add(span['attempt_root'])
    for span in spans.values():
        owners = payload_attempts.get(span['fields'].get('payload_id'), set())
        if span['attempt_root'] is None and len(owners) == 1:
            span['attempt_root'] = next(iter(owners))
    for span in spans.values():
        span['attempt_root'] = attempt_owner(span)

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
               'read_readiness': (header or {}).get('read_readiness', 'disabled'),
               'detail': (header or {}).get('detail', 'full'),
               'prewarm_cpu': (header or {}).get('prewarm_cpu'),
               'prewarm_coverage_failures': (footer or {}).get('prewarm_coverage_failures'),
               'footer': footer is not None, 'dropped': (footer or {}).get('dropped', 0),
               'io_error': (footer or {}).get('io_error', False), 'invalid_lines': invalid + (footer or {}).get('invalid_lines', 0),
               'open_spans': sum(s['end'] is None for s in spans.values()),
               'cutoff_spans': censored, 'crossing_aggregates_excluded': excluded_aggregates}
    return list(spans.values()), events, quality


def operation_category(span):
    if span['category'] != 'lifecycle':
        return span['category']
    for prefixes, category in ((('network.',),'network'), (('simplex.','marshal.','broadcast.','block.','proposal.'),'consensus'),
                              (('builder.',),'builder'), (('execution.','prewarm.','receipt.'),'execution'),
                              (('state.',),'state'), (('persistence.','storage.'),'storage')):
        if span['name'].startswith(prefixes):
            return category
    return 'lifecycle'


def active_wall_ns(intervals):
    end, duration = 0, 0
    for start, finish, _ in sorted(intervals):
        duration += max(0, finish-max(start,end))
        end = max(end,finish)
    return duration


def valid_load_window(window):
    if not isinstance(window, dict) or window.get('stop_reason') != 'load_finished':
        return False
    start, end = window.get('start_ns'), window.get('end_ns')
    return (type(start) is int and type(end) is int and 0 <= start < end)


def shutdown_tail_open_spans(spans, events, quality, window):
    """Count a structurally proven, unbound terminal payload forest before window end."""
    if (not valid_load_window(window) or not quality['header'] or not quality['footer'] or
            quality['dropped'] or quality['io_error'] or quality['invalid_lines']):
        return 0
    opened = [span for span in spans if span['end'] is None]
    if not opened or any(span.get('block') for span in opened):
        return 0
    proposals = [span for span in opened if span['name'] == 'handle_propose']
    builds = [span for span in opened if span['name'] == 'build_payload']
    resources = [span for span in opened if span['name'] == 'payload_resources']
    if len(proposals) != 1 or len(builds) != 1 or len(resources) != 1:
        return 0
    proposal, build, resource = proposals[0], builds[0], resources[0]
    if any(span.get('parent') is not None for span in (proposal, build, resource)):
        return 0
    all_proposals = [span for span in spans if span['name'] == 'handle_propose']
    if proposal is not max(all_proposals, key=lambda span: (span['ts'], span['id'])):
        return 0
    proposal_starts = [event for event in events if event['id'] == proposal['id'] and
                       event['fields'].get('stage') == 'proposal_start']
    if len(proposal_starts) != 1:
        return 0
    finalized = [event for event in events if event['fields'].get('stage') == 'finalized' and
                 block_key(event['fields'])]
    if not finalized:
        return 0
    latest_finalized = block_key(max(finalized, key=lambda event: event['ts'])['fields'])
    parent = proposal['fields'].get('parent_digest')
    payload = build['fields'].get('payload_id')
    if (not parent or parent != build['fields'].get('parent_hash') or
            parent != latest_finalized or not payload or
            payload != resource['fields'].get('payload_id')):
        return 0
    descendants = [span for span in opened if span not in (proposal, build, resource)]
    if (not any(span['name'] == 'sparse_trie_task' for span in descendants) or
            any(span['name'] not in ('account_worker', 'storage_worker', 'sparse_trie_task') or
                span.get('parent') != resource['id'] for span in descendants)):
        return 0
    if any(span['ts'] < proposal['ts'] for span in opened):
        return 0
    return sum(span['ts'] < window['end_ns'] for span in opened)


def build(paths, warmup=5, window=None, expected_detail=None, expected_prewarm_cpu=None, workload_blocks=None):
    spans, events, quality = [], [], []
    boundary = first_boundary(paths)
    recorded = (window or {}).get('backpressure')
    if recorded and (boundary is None or recorded['ts'] < boundary['ts']):
        boundary = recorded
    cutoff = boundary['ts'] if boundary else None
    for index, path in enumerate(paths):
        ss, es, qq = read_node(path, f'Validator {chr(65 + index)}', cutoff)
        spans.extend(ss)
        events.extend(es)
        pruned = next((q for q in (window or {}).get('pruning', []) if q['node'] == qq['node']), {})
        qq['crossing_aggregates_excluded'] += pruned.get('crossing_aggregates_excluded', 0)
        window_ok = valid_load_window(window)
        capture_ok = (qq['header'] and qq['footer'] and not qq['dropped'] and
                      not qq['io_error'] and not qq['invalid_lines'])
        qq['post_window_open_spans'] = (sum(s['end'] is None and s['ts'] >= window['end_ns'] for s in ss)
                                       if window_ok and capture_ok else 0)
        qq['shutdown_tail_open_spans'] = shutdown_tail_open_spans(ss, es, qq, window)
        quality.append(qq)
    first = min((x['ts'] for x in spans + events), default=0)
    by_block = {}
    for event in events:
        if event.get('block'):
            by_block.setdefault(event['block'],[]).append(event)
    keys = sorted(by_block,key=lambda key: min(e['ts'] for e in by_block[key]))
    aliases = {key: i + 1 for i, key in enumerate(keys)}
    readiness = read_readiness.build(events, quality, aliases, first, cutoff)
    blocks = []
    for key in keys:
        markers = [dict(stage=e['fields'].get('stage'), ts=(e['ts']-first)/1e6, node=e['node'],
                        **({'success': e['fields']['success']} if
                           e['fields'].get('stage') == 'state_root_result_ready' and
                           type(e['fields'].get('success')) is int and
                           e['fields']['success'] in (0, 1) else {}))
                   for e in by_block[key] if e['fields'].get('stage') in STAGES]
        starts = [e['ts'] for e in markers if e['stage'] == 'proposal_start']
        ends = [e['ts'] for e in markers if e['stage'] == 'finalized']
        complete = bool(starts and ends and min(ends) >= min(starts))
        start = min(starts) if starts else min((e['ts'] for e in markers), default=0)
        finish = min(ends) if complete else max((e['ts'] for e in markers), default=start)
        totals = [dict(node=e['node'], **{k:v for k,v in e['fields'].items()
                  if k in ('execution_ns','receipt_ns','wait_ns','transactions',
                           'execution_loop_ns','execution_thread_cpu_ns','execution_cpu_measured',
                           'execution_resources_measured',
                           'execution_voluntary_context_switches',
                           'execution_involuntary_context_switches',
                           'execution_minor_page_faults',
                           'execution_major_page_faults',
                           'execution_block_input_operations',
                           'execution_block_output_operations')})
                  for e in by_block[key] if e['fields'].get('stage') == 'execution_totals']
        worker_totals = [dict(node=e['node'], span=e['id'], ts=(e['ts']-first)/1e6,
                             **{k:v for k,v in e['fields'].items()
                                if k in ('stage','worker_run_ns','worker_thread_cpu_ns',
                                         'worker_cpu_measured','worker_success',
                                         'worker_job_counts_measured','worker_jobs','worker_account_targets',
                                         'worker_storage_targets','worker_storage_groups','worker_root_requests',
                                         'worker_jobs_storage_only_single_group',
                                         'worker_target_max','worker_jobs_targets_0','worker_jobs_targets_1',
                                         'worker_jobs_targets_2_8','worker_jobs_targets_9_32',
                                         'worker_jobs_targets_33_plus','worker_job_counts_saturated')})
                         for e in by_block[key] if e['fields'].get('stage') in
                         ('proof_storage_worker_totals','proof_account_worker_totals')]
        blocks.append({'proof_worker_totals': worker_totals, 'execution_totals': totals, 'id': aliases[key], 'start': start, 'end': finish,
                       'duration': finish-start, 'complete': complete, 'markers': markers})
    for block in blocks:
        block['read_readiness'] = readiness['by_block'].get(block['id'], [])
    completed = sorted((b for b in blocks if b['complete']), key=lambda b: b['start'])
    for b in completed[:warmup]:
        b['warmup'] = True
    eligible = [b for b in completed if not b.get('warmup') and (not window or 'start_ns' not in window or
                (b['start'] >= (window['start_ns']-first)/1e6 and b['end'] <= (window['end_ns']-first)/1e6))]
    workload_population = {'source': 'process_window'}
    if workload_blocks is not None:
        import workload
        eligible, workload_population = workload.select(eligible, by_block, aliases, workload_blocks)
    for b in blocks:
        b['in_population'] = b in eligible
    details = {q['detail'] for q in quality}
    detail = next(iter(details)) if len(details) == 1 else 'mixed'
    detail_valid = detail in ('full', 'milestones') and (expected_detail is None or detail == expected_detail)
    try:
        prewarm_data = prewarm.inspect(spans, events, quality, aliases, cutoff, expected_prewarm_cpu)
        prewarm_valid = True
    except ValueError as error:
        prewarm_data = dict(schema=1, mode='invalid', description=prewarm.DESCRIPTION,
                            contexts=[], leaves=[], summary=[], error=str(error))
        prewarm_valid = False
    prewarm_data['time_origin_ns'] = first
    leaves_by_block = defaultdict(list)
    for leaf in prewarm_data['leaves']:
        leaves_by_block[leaf['block']].append(leaf)
    for block in blocks:
        block['prewarm_calls'] = prewarm.summarize(leaves_by_block[block['id']])
    bad_capture = (not prewarm_valid or not detail_valid or not readiness['mode_valid'] or
                   any(not q['header'] or not q['footer'] or q['dropped'] or q['io_error'] or q['invalid_lines'] or
                       q['open_spans'] > q['post_window_open_spans'] + q['shutdown_tail_open_spans']
                       for q in quality))
    # Unexplained gaps invalidate completeness even when some blocks survived.
    representatives = {str(p): nearest_rank(eligible, p) if not bad_capture else None for p in (50,90,99)}
    attempts = sorted((s for s in spans if s['name'] == 'handle_propose'),
                      key=lambda s: (s['ts'], s['node'], s['id']))
    attempt_ids = {(s['node'], s['id']): i for i, s in enumerate(attempts, 1)}
    attempt_details = []
    for attempt in attempts:
        markers = [dict(stage=e['fields']['stage'], ts=(e['ts']-first)/1e6, node=e['node'])
                   for e in events if e['node'] == attempt['node'] and e['id'] == attempt['id']
                   and e['fields'].get('stage') in STAGES]
        stages = {e['stage'] for e in markers}
        status = ('post_window' if valid_load_window(window) and attempt['ts'] >= window['end_ns'] else
                  'cancelled' if 'cancelled' in stages else
                  'failed' if 'proposal_failed' in stages else
                  'cutoff_incomplete' if attempt.get('right_censored') else
                  'shutdown_incomplete' if attempt['end'] is None else
                  'associated' if attempt.get('block') else 'unexplained_unassociated')
        start = (attempt['ts']-first)/1e6
        end = (attempt['end']-first)/1e6 if attempt['end'] is not None else max(
            [start, *(m['ts'] for m in markers)])
        attempt_details.append(dict(id=attempt_ids[(attempt['node'], attempt['id'])],
            node=attempt['node'], block=aliases.get(attempt.get('block')), status=status,
            start=start, end=end, duration=end-start, markers=markers, execution_totals=[],
            complete=status in ('cancelled', 'failed', 'associated')))
    if any(a['status'] == 'unexplained_unassociated' for a in attempt_details):
        bad_capture = True
        representatives = {key: None for key in representatives}
    rows = []
    node_details = {q['node']: q['detail'] for q in quality}
    for s in spans:
        if s['end'] is None or s['end'] < s['ts']:
            continue
        rows.append({'id': s['id'], 'node': s['node'], 'parent': s.get('parent'),
                     'name': s['name'], 'category': operation_category(s), 'block': aliases.get(s['block']),
                     'start': (s['ts']-first)/1e6, 'end': (s['end']-first)/1e6,
                     'thread': s['thread'], 'active_ms': (None if node_details[s['node']] == 'milestones'
                         else active_wall_ns(s['active'])/1e6),
                     'right_censored': s.get('right_censored', False),
                     'timing_semantics': ('aggregate_envelope' if s.get('count') else
                         'operation_' + s['operation_status'] if s.get('operation_status') else
                         'span_lifetime'),
                     'retained_after_operation_ms': (max(0, s['reference_end'] - s['end'])/1e6
                         if 'reference_end' in s and s.get('operation_status') else None),
                     'reference_right_censored': bool(cutoff is not None and s.get('operation_status')
                         and 'reference_end' not in s),
                     'reference_retention_lower_bound_ms': (max(0, cutoff-s['end'])/1e6
                         if cutoff is not None and s.get('operation_status') and 'reference_end' not in s else None),
                     'attempt': attempt_ids.get((s['node'], s.get('attempt_root'))),
                     'details': {k:v for k,v in s['fields'].items() if k in (
                         'block_count', 'state_trie_block_count', 'first_block_number',
                         'last_block_number', 'canonical_height', 'persisted_height',
                         'state_trie_height', 'backlog', 'queued_jobs', 'in_flight_proof_batches',
                         'pending_updates', 'pending_targets', 'result_count') and isinstance(v, (int, float))},
                     'count': s.get('count'), 'elapsed_sum_ms': s.get('elapsed_ns',0)/1e6})
    attach_worker_details(rows, events)
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
    return {'schema':1, 'time_origin_ns':first, 'capture_detail':detail, 'detail_valid':detail_valid,
            'prewarm_cpu':prewarm_data['mode'], 'prewarm_valid':prewarm_valid, 'prewarm':prewarm_data,
            'boundary': dict(boundary, relative_ms=(cutoff-first)/1e6) if boundary else None, 'blocks':blocks, 'spans':rows, 'transfers':transfers, 'quality':quality,
            'representatives':representatives, 'eligible':len(eligible), 'warmup':warmup,
            'unexplained_attempts':sum(a['status'] == 'unexplained_unassociated' for a in attempt_details),
            'attempt_details':attempt_details, 'attempts':len(attempts), 'unbound_attempts':sum(not s.get('block') for s in attempts),
            'read_readiness': readiness, 'workload_population': workload_population,
            'coverage':sorted({s['name'] for s in rows}), 'stages':list(STAGES), 'bad_capture':bad_capture,
            'definition':('Milestone-only capture: detailed proof, storage, network and poll spans are intentionally disabled. This report measures coarse lifecycle intervals and does not provide complete operation coverage. ' if detail == 'milestones' else '') +
                'Proposal handling start on proposer → first accepted finalization certificate on a validator. Nearest-rank percentiles select actual complete blocks; initial complete blocks are excluded as warmup. When load boundaries are available, both endpoints must fall inside the process window. If workload_population.source is sender_block_range_nonempty, percentiles additionally require a nonempty sender-listed block with matching transaction count; setup and post-load processing blocks are excluded. All views exclude data at or after the first engine persistence backpressure event on either validator; crossing spans are right-censored and crossing aggregates omitted.'}


def write_report(paths, out, warmup=5, window=None, prune=False, expected_detail=None, expected_prewarm_cpu=None, scheduler_dir=None, workload_report=None):
    from progress import emit
    if prune:
        emit('lifecycle_prune', 'begin')
        paths, window = prepare_captures(paths, out, window)
        emit('lifecycle_prune', 'end')
    emit('lifecycle_build', 'begin')
    workload_blocks = None
    workload_status = None
    if workload_report is not None:
        import workload
        workload_blocks, workload_status = workload.load_for_capture(workload_report, window)
    data = build(paths, warmup, window, expected_detail, expected_prewarm_cpu, workload_blocks)
    if workload_status is not None:
        data['workload_population']['sender_report'] = workload_status
    emit('lifecycle_build', 'end')
    out.mkdir(parents=True, exist_ok=True)
    if scheduler_dir is not None:
        from scheduler.report import load, publish, close
        if not prune or data['bad_capture'] or not data['detail_valid']:
            raise ValueError('scheduler diagnostic requires a valid pruned lifecycle capture')
        emit('scheduler_load', 'begin')
        captures, coverage = load(scheduler_dir, out, window, retain_records=False)
    try:
        if scheduler_dir is not None:
            emit('scheduler_load', 'end')
        emit('report_write', 'begin')
        encoded = json.dumps(data, separators=(',',':')).replace('<', '\\u003c')
        (out/'lifecycle.json').write_text(encoded)
        del encoded  # Release the full serialization before allocating package views.
        emit('report_write', 'end')
        emit('package', 'begin')
        write_package(data, out)
        prewarm.write_view(data['prewarm'], out)
        emit('package', 'end')
        if scheduler_dir is not None:
            emit('scheduler_publish', 'begin')
            publish(data, captures, out, coverage)
            emit('scheduler_publish', 'end')
    finally:
        if scheduler_dir is not None:
            close(captures)
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--warmup', type=int, default=5)
    parser.add_argument('--window', type=Path)
    parser.add_argument('--workload-report', type=Path, help='Private sender report; select its complete nonempty workload blocks')
    parser.add_argument('--scheduler-dir', type=Path, help='Require matching private scheduler captures')
    parser.add_argument('--prune', action='store_true', help='Publish only pre-backpressure raw captures alongside the report')
    parser.add_argument('--expected-detail', choices=('full', 'milestones'), help='Reject captures whose recorder detail does not match the requested mode')
    parser.add_argument('--expected-prewarm-cpu', choices=('disabled', 'leaf_v1'), help='Require selected prewarm CPU observer admission')
    parser.add_argument('captures', type=Path, nargs='+')
    args = parser.parse_args()
    window = json.loads(args.window.read_text()) if args.window and args.window.exists() else (
        {'start_ns': 0, 'end_ns': 0, 'stop_reason': 'load_not_started'} if args.window else None)
    result = write_report(args.captures, args.out, args.warmup, window, args.prune, args.expected_detail, args.expected_prewarm_cpu, args.scheduler_dir, args.workload_report)
    print(f"Lifecycle report: {len(result['blocks'])} blocks, {result['eligible']} complete post-warmup blocks; invalid capture: {result['bad_capture']}")
    if result['bad_capture'] or not result['eligible']:
        raise SystemExit(2)
