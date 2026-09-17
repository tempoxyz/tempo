"""Selected actor observations, never exact executor enqueue or block causality."""
import argparse
import json
from pathlib import Path
import time

ROLES = {1: 'marshal', 2: 'voter', 3: 'resolver', 4: 'batcher', 5: 'peer send', 6: 'peer receive'}
FIELDS = {
    'async_task_register': {'task_id', 'task_role'},
    'async_task_wake': {'task_id', 'task_poll'},
    'async_task_poll_begin': {'task_id', 'task_poll', 'task_wakes'},
    'async_task_poll_end': {'task_id', 'task_poll', 'task_outcome'},
    'async_task_terminal': {'task_id', 'task_outcome'},
    'async_task_coverage': {'task_outcome'},
}
MAX_EVENTS = 2_000_000  # Explicit failure, never sampling or silent truncation.


def unsigned(value):
    return type(value) is int and 0 <= value < 2**64


def inspect(events, header, footer, cutoff=None, expected=None, require_footer=True):
    mode = (header or {}).get('async_tasks', 'disabled')
    errors = set()
    if mode not in ('disabled', 'selected_v1') or expected is not None and mode != expected:
        errors.add('mode_mismatch')
    if mode == 'selected_v1' and (header or {}).get('detail', 'full') != 'full':
        errors.add('unsupported_detail')
    if require_footer and mode == 'selected_v1':
        failures = (footer or {}).get('async_coverage_failures')
        if not unsigned(failures) or failures:
            errors.add('coverage_failure')
    tasks, retained, seen = {}, [], 0
    for e in events:
        fields = e.get('fields', {})
        stage = fields.get('stage', '')
        if not isinstance(stage, str) or not stage.startswith('async_task_'):
            continue
        # Coverage failures remain disqualifying even beyond the source cutoff.
        if stage == 'async_task_coverage':
            errors.add('coverage_failure')
        if cutoff is not None and e.get('ts', cutoff) >= cutoff:
            continue
        if mode != 'selected_v1':
            errors.add('unexpected_observer')
        if stage not in FIELDS or set(fields) != FIELDS.get(stage, set()) | {'stage'} or any(
                not unsigned(v) for k, v in fields.items() if k != 'stage') or not unsigned(e.get('ts')) or not unsigned(e.get('thread')) or e.get('id') != 0:
            errors.add('invalid_event')
            continue
        seen += 1
        if seen > MAX_EVENTS:
            errors.add('event_limit')
            break
        retained.append(e)
        if stage == 'async_task_coverage':
            continue
        task = fields['task_id']
        if not task:
            errors.add('invalid_task')
            continue
        if stage == 'async_task_register':
            if task in tasks or fields['task_role'] not in ROLES:
                errors.add('invalid_registration')
                continue
            tasks[task] = {'role': fields['task_role'], 'registered': e['ts'], 'polls': {}, 'wakes': {}, 'terminal': None}
            continue
        if task not in tasks:
            errors.add('missing_registration')
            continue
        state = tasks[task]
        if stage == 'async_task_terminal':
            if state['terminal'] is not None or fields['task_outcome'] not in (1, 2):
                errors.add('invalid_terminal')
            state['terminal'] = e
            continue
        generation = fields['task_poll']
        if not generation:
            errors.add('invalid_poll')
            continue
        if stage == 'async_task_wake':
            # Wake publication may follow begin/end/terminal. Do not reopen tasks,
            # reject a valid race, or move its timestamp back to state transition.
            if generation in state['wakes']:
                errors.add('duplicate_wake')
            state['wakes'][generation] = e
        else:
            if state['terminal'] is not None:
                errors.add('poll_after_terminal')
            part = 'begin' if stage == 'async_task_poll_begin' else 'end'
            poll = state['polls'].setdefault(generation, {})
            if part in poll:
                errors.add('duplicate_poll')
            poll[part] = e
    roles = {t['role'] for t in tasks.values()}
    if mode == 'selected_v1' and roles != set(ROLES):
        errors.add('missing_required_roles')
    intervals, observations = [], []
    for task, state in tasks.items():
        last_end, last_outcome = None, None
        ordered = sorted(state['polls'].items())
        for ordinal, (generation, poll) in enumerate(ordered, 1):
            begin, end = poll.get('begin'), poll.get('end')
            if begin is None or generation != ordinal:
                errors.add('missing_poll_begin')
                continue
            terminal = state['terminal']
            if ordinal > 1 and last_outcome != 0:
                errors.add('poll_after_nonpending')
            if end is None and (ordinal != len(ordered) or terminal is not None or require_footer and cutoff is None):
                errors.add('missing_poll_end')
            if terminal and terminal['ts'] < begin['ts'] or last_end is not None and last_end > begin['ts']:
                errors.add('invalid_poll_order')
            common = dict(task_id=task, task_role=state['role'], task_poll=generation)
            if end is not None:
                if end['ts'] < begin['ts'] or end['thread'] != begin['thread'] or end['fields']['task_outcome'] not in (0, 1, 2):
                    errors.add('invalid_poll_end')
                else:
                    intervals.append(dict(common, start=begin['ts'], end=end['ts'], thread=begin['thread'], kind='poll'))
                    last_end = end['ts']
                    last_outcome = end['fields']['task_outcome']
                    if terminal and terminal['ts'] < end['ts']:
                        errors.add('end_after_terminal')
            wake = state['wakes'].get(generation)
            count = begin['fields']['task_wakes']
            status = 'initial_poll' if generation == 1 and not count else 'no_wake_evidence'
            if count:
                if wake is None and require_footer and cutoff is None:
                    errors.add('missing_wake')
                status = 'wake_missing_or_cutoff' if wake is None else 'wake_publication_raced'
                if wake is not None and wake['ts'] < begin['ts']:
                    status = 'observed_wake_request_to_poll'
                    # Overlapping previous poll is deliberately retained: this is
                    # wake request latency, not non-running or exact queue time.
                    intervals.append(dict(common, start=wake['ts'], end=begin['ts'], thread=0, kind='wake request to poll'))
            elif wake is not None:
                errors.add('wake_count_mismatch')
            observations.append(dict(common, begin=begin['ts'], status=status, wakes=count, end_observed=end is not None))
        terminal = state['terminal']
        if terminal is None and require_footer and cutoff is None:
            errors.add('missing_terminal')
        if terminal is not None:
            outcome = terminal['fields']['task_outcome']
            if terminal['ts'] < state['registered'] or (outcome == 1 and last_outcome != 1) or (outcome == 2 and last_outcome == 1):
                errors.add('terminal_outcome_mismatch')
        # Unconsumed and late-terminal wakes stay observations, not invented spans.
        for generation, wake in state['wakes'].items():
            if generation > len(ordered)+1:
                errors.add('invalid_wake_generation')
            if generation not in state['polls']:
                observations.append(dict(task_id=task, task_role=state['role'], task_poll=generation,
                    wake=wake['ts'], status='unconsumed_or_terminal_race'))
    return dict(mode=mode, valid=not errors, errors=sorted(errors), roles=sorted(roles),
        tasks=len(tasks), events=len(retained), intervals=intervals, observations=observations)


def source(path):
    with path.open() as capture:
        for line in capture:
            try:
                event = json.loads(line)
            except ValueError:
                continue  # Main recorder integrity gate rejects malformed records.
            yield event


def admission(paths, expected, timeout=0):
    deadline = time.monotonic() + timeout
    while True:
        valid = True
        for path in paths:
            header = None
            events = []
            if path.exists():
                for e in source(path):
                    if e.get('type') == 'header': header = e
                    if e.get('fields', {}).get('stage') in ('async_task_register', 'async_task_coverage'):
                        events.append(e)
            valid &= header is not None and inspect(events, header, None, expected=expected, require_footer=False)['valid']
        if valid or time.monotonic() >= deadline:
            return bool(valid)
        time.sleep(0.1)


def clear_exports(out):
    import re
    for path in out.iterdir():
        if re.fullmatch(r'async-tasks(?:-index|-\d{4,})?\.json|async-tasks\.html', path.name):
            path.unlink()


def write_observations(results, out):
    """Independent bounded context traces; no block association inferred by overlap."""
    from perfetto import write_trace
    clear_exports(out)
    out.joinpath('async-tasks.json').write_text(json.dumps(results, separators=(',', ':')))
    chunks = []
    for node, result in results.items():
        rows = sorted(result['intervals'], key=lambda r: (r['start'], r['end']))
        for offset in range(0, len(rows), 10_000):
            spans = [dict(id=offset+i+1, node=node, parent=None, block=None,
                name=ROLES[r['task_role']] + ' / ' + r['kind'], category='selected async task',
                start=r['start']/1e6, end=r['end']/1e6, thread=r['thread'], active_ms=None,
                timing_semantics='observed poll wall time' if r['kind']=='poll' else 'observed wake request to poll; may overlap prior poll; not exact enqueue',
                active_wall_status='thread CPU not measured; explicit poll wall interval' if r['kind']=='poll' else 'not an execution interval',
                details={k:r[k] for k in ('task_id','task_role','task_poll')}) for i,r in enumerate(rows[offset:offset+10_000])]
            name = f'async-tasks-{len(chunks)+1:04d}.json'
            chunks.append(write_trace(dict(blocks=[], spans=spans, quality=[dict(node=node)]), out/name))
    out.joinpath('async-tasks-index.json').write_text(json.dumps(dict(chunks=chunks), separators=(',', ':')))
    from html import escape
    from collections import Counter
    summaries = []
    for node, result in results.items():
        counts = Counter(row['status'] for row in result['observations'])
        summaries.append('<p>' + escape(node) + ': ' + escape(result['mode']) +
            f"; {result['tasks']} tasks; {result['events']} retained events; valid={result['valid']}. " +
            escape(', '.join(f'{key}: {value}' for key,value in sorted(counts.items()))) + '</p>')
    links = ''.join(f'<li><a href="{row["file"]}">{row["file"]}</a> ({row["events"]} intervals, {row["tracks"]} virtual lanes)</li>' for row in chunks)
    out.joinpath('async-tasks.html').write_text('<!doctype html><meta charset="utf-8"><title>Selected async tasks</title>'
        '<h1>Selected async task observations</h1><p><a href="index.html">Lifecycle summary</a></p>'
        '<p>Poll intervals measure wall time, not CPU. Wake-request-to-poll intervals begin at observed publication, '
        'not executor enqueue; they can overlap the previous poll. Late publications, missing wake evidence and open polls '
        'remain unavailable. These actors handle many blocks: no block causality is inferred from temporal overlap. '
        'This covers only the six selected actor roles, not all runtime tasks. Times use the source phase-relative clock.</p>'
        + ''.join(summaries) + '<p>Import a bounded context file into Perfetto:</p><ul>' + links +
        '</ul><p><a href="async-tasks.json">Complete selected-task observations</a> · '
        '<a href="async-tasks-index.json">Context manifest</a></p>')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', choices=('disabled', 'selected_v1'), required=True)
    parser.add_argument('--timeout', type=float, default=0)
    parser.add_argument('captures', type=Path, nargs='+')
    args = parser.parse_args()
    if not admission(args.captures, args.expected, args.timeout):
        raise SystemExit('async_task_admission_failed')
