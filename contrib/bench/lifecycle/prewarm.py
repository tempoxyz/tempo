"""Exact selected prewarm call accounting; never exclusive task CPU."""
from collections import Counter, defaultdict
from html import escape
import json
import re

STAGES = {'prewarm_context_started', 'prewarm_leaf_started', 'prewarm_leaf_completed',
          'prewarm_context_completed', 'prewarm_coverage_failure'}
ROLES = {1: 'engine_tx', 2: 'builder_tx'}
MODES = {1: 'transactions', 2: 'BAL_unmeasured', 3: 'skipped_at_selection'}
OUTCOMES = {0: 'unwound', 1: 'EVM_unavailable', 2: 'stopped', 3: 'already_executed',
            4: 'execution_error', 5: 'executed', 6: 'executed_then_stopped',
            7: 'parallel_ineligible', 8: 'replay_unavailable', 9: 'with_replay'}
DESCRIPTION = ('Inclusive current-thread CPU while selected synchronous calls are active; '
               'remote worker CPU excluded, nested same-thread helping included. '
               'Overlapping call CPU must not be summed as exclusive prewarming CPU. '
               'Initialization broadcasts, coordination, cleanup and BAL work are outside this coverage. '
               'Missing/censored calls are unknown, not zero. Outcomes describe call returns, not transaction success.')


def uint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('invalid prewarm unsigned field')
    return value


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def summarize(leaves):
    result = []
    for node, role in sorted({(x['node'], x['role']) for x in leaves}):
        rows = [x for x in leaves if (x['node'], x['role']) == (node, role)]
        done = [x for x in rows if x['end_ns'] is not None]
        measured = [x for x in done if x['cpu_ns'] is not None]
        result.append(dict(node=node, role=role, started=len(rows), completed=len(done),
            censored=len(rows)-len(done), cpu_measured=len(measured),
            cpu_unavailable=len(done)-len(measured),
            summed_inclusive_call_cpu_ns=sum(x['cpu_ns'] for x in measured) if measured else None,
            summed_call_envelope_ns=sum(x['end_ns']-x['start_ns'] for x in done),
            overlapping_completed_calls=sum(x['overlaps_same_thread'] for x in done),
            outcomes=dict(sorted(Counter(OUTCOMES[x['outcome']] for x in done).items()))))
    return result


def inspect(spans, events, quality, aliases, cutoff, expected=None):
    modes = {'disabled' if q.get('prewarm_cpu') is None else q['prewarm_cpu'] for q in quality}
    require(expected is None or all(q.get('prewarm_cpu') in ('disabled', 'leaf_v1') for q in quality),
            'requested prewarm mode not explicitly declared')
    require(len(modes) == 1 and modes <= {'disabled', 'leaf_v1'}, 'inconsistent prewarm mode')
    mode = next(iter(modes))
    require(expected is None or mode == expected, 'requested prewarm mode unavailable')
    for q in quality:
        if q.get('prewarm_coverage_failures') is not None:
            require(uint(q['prewarm_coverage_failures']) == 0, 'prewarm producer coverage failure')
    selected = [e for e in events if e['fields'].get('stage') in STAGES]
    sources = {(s['node'], s['id']): s for s in spans if s['name'] == 'prewarm.context'}
    if mode == 'disabled':
        require(not selected and not sources, 'disabled prewarm mode contains records')
        return dict(schema=1, mode=mode, description=DESCRIPTION, contexts=[], leaves=[], summary=[])
    for q in quality:
        require(uint(q.get('prewarm_coverage_failures')) == 0, 'prewarm producer coverage failure')
    contexts, declarations, finishes, starts, ends = {}, {}, {}, {}, {}
    for key, span in sources.items():
        role, selection = uint(span['fields'].get('prewarm_role')), uint(span['fields'].get('prewarm_mode'))
        require(role in ROLES and selection in MODES, 'invalid prewarm context declaration')
        require(role != 2 or selection != 2, 'builder BAL declaration invalid')
        contexts[key] = dict(node=key[0], id=key[1], role=ROLES[role], role_id=role,
            mode=MODES[selection], mode_id=selection, block=aliases.get(span.get('block')),
            start_ns=span['ts'], end_ns=None, status='cutoff_context',
            declared_dispatched=None, observed_started=0, observed_completed=0)
    for e in selected:
        fields, stage = e['fields'], e['fields']['stage']
        require(stage != 'prewarm_coverage_failure', 'prewarm producer coverage failure')
        key = (e['node'], e['id'])
        require(key in contexts, 'prewarm event without exact context')
        context, source = contexts[key], sources[key]
        ts = uint(e['ts'])
        require(ts >= source['ts'] and (cutoff is None or ts < cutoff), 'prewarm event outside source bounds')
        if source.get('end') is not None:
            require(ts <= source['end'], 'prewarm event after context lifetime')
        if stage == 'prewarm_context_started':
            require(key not in declarations, 'duplicate prewarm declaration')
            require(uint(fields.get('prewarm_role')) == context['role_id'] and
                    uint(fields.get('prewarm_mode')) == context['mode_id'], 'prewarm role mismatch')
            declarations[key] = e
        elif stage == 'prewarm_context_completed':
            require(key not in finishes, 'duplicate prewarm context completion')
            finishes[key] = e
        else:
            ordinal = uint(fields.get('prewarm_leaf'))
            require(ordinal > 0 and context['mode_id'] == 1, 'invalid prewarm leaf identity/mode')
            leaf_key = (*key, ordinal)
            target = starts if stage == 'prewarm_leaf_started' else ends
            require(leaf_key not in target, 'duplicate prewarm leaf record')
            target[leaf_key] = e
    require(set(ends) <= set(starts), 'prewarm completion without retained start')
    leaves = []
    for leaf_key, begin in starts.items():
        key, ordinal = leaf_key[:2], leaf_key[2]
        context = contexts[key]
        require(key in declarations and begin['ts'] >= declarations[key]['ts'], 'leaf precedes context declaration')
        end = ends.get(leaf_key)
        leaf = dict(node=key[0], context=key[1], ordinal=ordinal, role=context['role'],
            block=context['block'], thread=uint(begin['thread']), start_ns=uint(begin['ts']),
            end_ns=None, cpu_ns=None, outcome=None, overlaps_same_thread=False)
        require(leaf['thread'] > 0, 'prewarm leaf thread unavailable')
        if end:
            require(end['thread'] == begin['thread'] and end['ts'] >= begin['ts'], 'prewarm leaf thread/order mismatch')
            fields = end['fields']
            flag, outcome = uint(fields.get('prewarm_cpu_measured')), uint(fields.get('prewarm_outcome'))
            allowed = set(range(7)) if context['role_id'] == 1 else {0,1,2,4,5,7,8,9}
            require(flag in (0,1) and outcome in allowed, 'invalid prewarm completion flags')
            cpu = fields.get('prewarm_thread_cpu_ns')
            if flag:
                uint(cpu)
            else:
                require(cpu is None, 'unavailable prewarm CPU is not zero')
            leaf.update(end_ns=end['ts'], cpu_ns=cpu, outcome=outcome)
            context['observed_completed'] += 1
        else:
            require(cutoff is not None and key not in finishes, 'unexplained missing prewarm completion')
        context['observed_started'] += 1
        leaves.append(leaf)
    by_context = defaultdict(list)
    for leaf in leaves:
        by_context[(leaf['node'],leaf['context'])].append(leaf)
    for key, context in contexts.items():
        source, finish = sources[key], finishes.get(key)
        require(key in declarations or (cutoff is not None and source.get('right_censored') and not by_context[key] and not finish),
                'missing prewarm context declaration')
        if finish:
            require(key in declarations and finish['ts'] >= declarations[key]['ts'], 'invalid prewarm context order')
            fields = finish['fields']
            dispatched, started, completed = [uint(fields.get('prewarm_'+k)) for k in ('dispatched','started','completed')]
            outcome = uint(fields.get('prewarm_context_outcome'))
            require(outcome in (0,1), 'invalid prewarm context outcome')
            require(started == context['observed_started'] and completed == context['observed_completed'], 'prewarm completion cardinality mismatch')
            require(completed <= started <= dispatched, 'invalid declared dispatch bounds')
            require(context['mode_id'] == 1 or dispatched == 0, 'unmeasured selection cannot dispatch transaction leaves')
            require(max((x['ordinal'] for x in by_context[key]),default=0) <= dispatched, 'prewarm ordinal exceeds dispatch declaration')
            require(outcome != 0 or dispatched == started == completed, 'normal prewarm scope incomplete')
            require(all(x['end_ns'] is not None and x['end_ns'] <= finish['ts'] for x in by_context[key]), 'leaf extends past context completion')
            context.update(end_ns=finish['ts'], status='completed' if outcome == 0 else 'unwound', declared_dispatched=dispatched)
        else:
            require(cutoff is not None and source.get('right_censored'), 'unexplained missing context completion')
    for q in quality:
        roles = {c['role_id'] for key,c in contexts.items() if c['node'] == q['node'] and key in declarations}
        require(roles == {1,2}, 'missing required prewarm role declaration')
    # Inclusive same-thread call envelopes may overlap under nested cooperative work.
    by_thread = defaultdict(list)
    for leaf in leaves:
        if leaf['end_ns'] is not None:
            by_thread[(leaf['node'],leaf['thread'])].append(leaf)
    for rows in by_thread.values():
        longest = None
        for leaf in sorted(rows,key=lambda x:(x['start_ns'],x['end_ns'])):
            if longest and leaf['start_ns'] < longest['end_ns'] and leaf['end_ns'] > leaf['start_ns']:
                leaf['overlaps_same_thread'] = longest['overlaps_same_thread'] = True
            if longest is None or leaf['end_ns'] > longest['end_ns']:
                longest = leaf
    return dict(schema=1, mode=mode, description=DESCRIPTION,
                contexts=sorted(contexts.values(),key=lambda c:(c['node'],c['id'])),
                leaves=sorted(leaves,key=lambda x:(x['start_ns'],x['node'],x['context'],x['ordinal'])),
                summary=summarize(leaves))


def write_view(data, out, limit=10000):
    for old in out.iterdir():
        if re.fullmatch(r'prewarm-(?:[0-9]+|manifest)\.json|prewarm\.html', old.name):
            old.unlink()
    if data['mode'] != 'leaf_v1':
        return
    require(limit > 0, 'invalid prewarm trace limit')
    traces = []
    for offset in range(0,len(data['leaves']),limit):
        rows = data['leaves'][offset:offset+limit]
        events = []
        for node in sorted({row['node'] for row in rows}):
            pid=1 if node=='Validator A' else 2
            events.append(dict(ph='M',name='process_name',pid=pid,tid=0,args=dict(name=node)))
            for thread in sorted({row['thread'] for row in rows if row['node']==node}):
                events.append(dict(ph='M',name='thread_name',pid=pid,tid=thread,args=dict(name=f'Observed thread {thread}')))
        for row in rows:
            args = {k:row[k] for k in ('context','ordinal','block','cpu_ns','outcome','overlaps_same_thread')}
            event = dict(name=row['role']+'.call', cat='prewarm_inclusive', pid=1 if row['node']=='Validator A' else 2,
                         tid=row['thread'], ts=(row['start_ns']-data.get('time_origin_ns',0))/1000, args=args)
            if row['end_ns'] is None:
                event.update(ph='i',s='t'); event['name'] += '.cutoff_censored'
            else:
                event.update(ph='X',dur=(row['end_ns']-row['start_ns'])/1000)
            events.append(event)
        name=f'prewarm-{len(traces)+1:04d}.json'
        (out/name).write_text(json.dumps(dict(traceEvents=events,displayTimeUnit='ms'),separators=(',',':')))
        traces.append(dict(file=name, leaves=len(rows)))
    (out/'prewarm-manifest.json').write_text(json.dumps(dict(schema=1,chunks=traces,leaves=len(data['leaves'])),indent=2))
    links=' '.join(f'<a href="{x["file"]}">Perfetto {i+1} ({x["leaves"]} calls)</a>' for i,x in enumerate(traces))
    summary=''.join('<tr>'+''.join(f'<td>{escape(str(row[k]))}</td>' for k in (
        'node','role','started','completed','censored','cpu_measured','cpu_unavailable','summed_inclusive_call_cpu_ns','overlapping_completed_calls'))+'</tr>' for row in data['summary'])
    text=f'''<!doctype html><meta charset="utf-8"><title>Prewarm call CPU</title><h1>Selected prewarming calls</h1><p>{escape(DESCRIPTION)}</p><p><a href="index.html">Block lifecycle</a> · <a href="lifecycle.json">Complete source-derived data</a></p><table><tr><th>Node</th><th>Role</th><th>Started</th><th>Completed</th><th>Censored</th><th>CPU measured</th><th>CPU unavailable</th><th>Summed inclusive call CPU (ns)</th><th>Calls overlapping on same thread</th></tr>{summary}</table><p>{links}</p><p>Skipped/BAL contexts and unassociated attempts remain in lifecycle.json; absence of leaves does not measure total prewarming as zero.</p>'''
    (out/'prewarm.html').write_text(text)


def admission(paths, expected, timeout=0):
    """Before load, require both source headers to explicitly declare milestones/off-or-on."""
    import json
    import time
    from pathlib import Path
    if expected not in ('disabled', 'leaf_v1') or len(paths) != 2 or not 0 <= timeout <= 30:
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
                if (type(header) is not dict or header.get('type') != 'header'
                        or type(header.get('schema')) is not int or header['schema'] != 1
                        or header.get('clock') != 'shared_monotonic_relative_ns'
                        or header.get('detail') != 'milestones' or header.get('prewarm_cpu') != expected):
                    return False
            except (FileNotFoundError, json.JSONDecodeError):
                ready = False
            except OSError:
                # A present but unreadable source cannot establish admission.
                # Keep native paths and exception details out of CLI diagnostics.
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
    parser.add_argument('--expected', choices=('disabled', 'leaf_v1'), required=True)
    parser.add_argument('--timeout', type=float, default=0)
    parser.add_argument('captures', type=Path, nargs=2)
    args = parser.parse_args()
    if not admission(args.captures, args.expected, args.timeout):
        raise SystemExit('prewarm_cpu_admission_failed')
