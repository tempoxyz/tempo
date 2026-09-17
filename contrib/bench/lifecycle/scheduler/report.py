"""Validate and publish only anonymous, cutoff-intersected scheduler context."""
from collections import Counter
import json
from pathlib import Path
import time
try:
    from .failures import failure_summary
except ImportError:
    from failures import failure_summary

KINDS = {'register', 'switch_out', 'switch_in', 'wakeup', 'exit', 'migration'}
INTERVALS = {'scheduled_on_cpu', 'runnable_off_cpu', 'blocked_before_wakeup',
             'runnable_after_wakeup', 'off_cpu_unsplit'}
QUALITY = {'event_loss_detected', 'registered_threads', 'all_registered_threads_exited',
           'unclassified_off_cpu_intervals', 'unclosed_intervals_excluded', 'unmatched_wakeups',
           'at_or_post_cutoff_records_pruned'}


def integer(value, low=0, high=2**64-1):
    return type(value) is int and low <= value <= high


def validate(capture, process, cutoff, reason):
    keys = {'schema','scope','process','clock','cutoff_ns','records','intervals','quality',
            'registered_window_edges_complete','cutoff_reason','registration'}
    if set(capture) != keys or capture['schema'] != 1 or capture['process'] != process:
        raise ValueError('scheduler schema/process mismatch')
    if (capture['scope'] != 'registered validator thread windows only'
            or capture['clock'] != 'monotonic_relative_ns'
            or capture['registration'] != 'registered_threads_v1'
            or capture['cutoff_ns'] != cutoff or capture['cutoff_reason'] != reason):
        raise ValueError('scheduler scope/clock/cutoff mismatch')
    quality = capture['quality']
    if set(quality) != QUALITY or quality['event_loss_detected'] is not False or quality['all_registered_threads_exited'] is not True:
        raise ValueError('scheduler capture integrity failed')
    if any(not integer(value) for key,value in quality.items() if key not in {'event_loss_detected','all_registered_threads_exited'}):
        raise ValueError('invalid scheduler quality counter')
    complete = not any(quality[key] for key in ('unclassified_off_cpu_intervals','unclosed_intervals_excluded','unmatched_wakeups'))
    if capture['registered_window_edges_complete'] is not complete:
        raise ValueError('invalid scheduler completeness')
    if not isinstance(capture['records'], list) or not isinstance(capture['intervals'], list):
        raise ValueError('invalid scheduler rows')
    for row in capture['records']:
        if (set(row) != {'ts','thread','kind','state_bits'} or row['kind'] not in KINDS
                or not integer(row['thread'], 1, 8192) or not integer(row['ts'], 0, cutoff-1)
                or not integer(row['state_bits'], 0, 256)):
            raise ValueError('invalid scheduler event or cutoff drift')
    previous = {}
    for row in capture['intervals']:
        if (set(row) != {'thread','start','end','kind','right_censored'} or row['kind'] not in INTERVALS
                or not integer(row['thread'], 1, 8192) or not integer(row['start'], 0, cutoff-1)
                or not integer(row['end'], row['start']+1, cutoff-1) or type(row['right_censored']) is not bool):
            raise ValueError('invalid scheduler interval or cutoff drift')
        if row['start'] < previous.get(row['thread'], 0):
            raise ValueError('overlapping scheduler states')
        previous[row['thread']] = row['end']
    return capture


def source_registration(path, capture):
    registrations = {row['thread']:row['ts'] for row in capture['records'] if row['kind'] == 'register'}
    early = max_gap = 0
    with path.open() as stream:
        for line in stream:
            event = json.loads(line)
            if 'thread' not in event or event.get('ts', capture['cutoff_ns']) >= capture['cutoff_ns']:
                continue
            registered = registrations.get(event['thread'])
            if registered is None:
                raise ValueError('source thread registration missing; scheduler attribution unavailable')
            if event['ts'] < registered:
                early += 1
                max_gap = max(max_gap, registered-event['ts'])
    return {'source_events_before_registration':early, 'maximum_registration_gap_ns':max_gap}


def load(directory, out, window, timeout=90):
    paths = [directory / 'scheduler-a.json', directory / 'scheduler-b.json']
    deadline = time.monotonic() + timeout
    while not all(path.exists() for path in paths):
        if any((directory / f'scheduler-{role}.failed').exists() for role in ('a','b')):
            raise ValueError('scheduler supervisor failed; diagnostic unavailable; ' + '; '.join(failure_summary(directory)))
        if time.monotonic() > deadline:
            raise ValueError('scheduler capture not finalized')
        time.sleep(.1)
    hit = window.get('backpressure')
    cutoff, reason = (hit['ts'], 'backpressure') if hit else (window['end_ns'], 'load_finished')
    result, coverage = [], []
    for index, path in enumerate(paths):
        # Lifecycle headers must prove the requested hook was active, even if
        # BPF happens to have observed another instrumented process by mistake.
        with (out / f'{"ab"[index]}.jsonl').open() as stream:
            header = json.loads(stream.readline())
        if header.get('scheduler') != 'registered_threads_v1':
            raise ValueError('lifecycle scheduler registration header missing')
        capture = validate(json.loads(path.read_text()), index+1, cutoff, reason)
        coverage.append(source_registration(out / f'{"ab"[index]}.jsonl', capture))
        result.append(capture)
    # Write neither validator until both are validated.
    for path, capture in zip(paths, result):
        (out / path.name).write_text(json.dumps(capture, separators=(',', ':')) + '\n')
    return result, coverage


def scheduler_events(captures, origin, low, high):
    rows, used = [], set()
    for capture in captures:
        pid = 100 + capture['process']
        for row in capture['intervals']:
            start, end = (row['start']-origin)/1000, (row['end']-origin)/1000
            if start >= high or end <= low:
                continue
            clipped_start, clipped_end = start < low, end > high
            start, end = max(start, low), min(end, high)
            used.add((pid, row['thread']))
            rows.append({'name':row['kind'], 'cat':'scheduler context', 'ph':'X', 'pid':pid,
                         'tid':row['thread'], 'ts':start, 'dur':end-start,
                         'args':{'source_thread_ordinal':row['thread'],
                                 'association':'thread context; temporal overlap does not establish block causality',
                                 'right_censored':row['right_censored'],
                                 'focus_clipped_start':clipped_start, 'focus_clipped_end':clipped_end,
                                 'semantics':'scheduler residency; includes kernel and interrupts, not task CPU time'}})
    metadata = [{'name':'process_name','ph':'M','pid':100+c['process'],'tid':0,
                 'args':{'name':f'Validator {chr(64+c["process"])} scheduler'}} for c in captures]
    metadata.extend({'name':'thread_name','ph':'M','pid':pid,'tid':thread,
                     'args':{'name':f'Anonymous thread {thread}'}} for pid,thread in sorted(used))
    return metadata + rows


def publish(data, captures, out, coverage):
    summary = {'schema':1, 'scope':'registered thread windows only; not complete async-task attribution',
               'cutoff_ns':captures[0]['cutoff_ns'], 'nodes':[], 'pages':[], 'percentiles':[]}
    for capture in captures:
        totals = Counter()
        for row in capture['intervals']:
            totals[row['kind']] += row['end'] - row['start']
        summary['nodes'].append({'node':f'Validator {chr(64+capture["process"])}',
                                 'quality':capture['quality'],
                                 'registration_coverage':coverage[capture["process"]-1],
                                 'thread_wall_ns_by_state':dict(totals)})
    for block in data['blocks']:
        source = out / f'perfetto-block-{block["id"]}.json'
        trace = json.loads(source.read_text())
        trace['traceEvents'].extend(scheduler_events(captures, data['time_origin_ns'],
                                                      block['start']*1000, block['end']*1000))
        name = f'perfetto-scheduler-block-{block["id"]}.json'
        (out / name).write_text(json.dumps(trace, separators=(',', ':')))
        summary['pages'].append({'block':block['id'], 'trace':name})
    for percentile, block in data['representatives'].items():
        if not data['bad_capture']:
            summary['percentiles'].append({'percentile':int(percentile),'block':block,
                                          'trace':f'perfetto-scheduler-block-{block}.json'})
    (out / 'scheduler-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    percentile_links = ' · '.join(f'<a href="{p["trace"]}">p{p["percentile"]}: block {p["block"]}</a>' for p in summary['percentiles'])
    rows = ''.join(f'<li><a href="{p["trace"]}">Block {p["block"]} + scheduler context</a></li>' for p in summary['pages'])
    (out / 'scheduler.html').write_text(f'''<!doctype html><meta charset="utf-8"><title>Scheduler diagnostic</title>
<h1>Registered thread scheduler diagnostic</h1><p><a href="index.html">Lifecycle summary</a> · <a href="scheduler-summary.json">Quality and measured intervals</a></p>
<p>Open a trace below in Perfetto. The ordinary lifecycle lanes are accompanied by anonymous scheduler thread tracks. Thread ordinals match source capture enter/exit records. These scheduler tracks are temporal context, not automatic attribution to a block or async task.</p>
<p>Scheduled intervals include kernel execution and interrupts; they are not measured task CPU time. Off-CPU intervals split into blocked-before-wakeup and runnable-after-wakeup only when both edges and wakeup are observed. Missing wakeups remain unsplit. Time before registration, missing edges, and unclosed intervals is unavailable. Async tasks awaiting without a thread cannot be assigned scheduler time. Overlapping scopes and threads are not additive wall or CPU time.</p>
<p>Only observed intervals intersected with the strict source cutoff are exported. Perfetto context is additionally clipped to each actual block lifecycle. Percentiles select the same actual complete blocks as the lifecycle report.</p><p>{percentile_links}</p><ul>{rows}</ul>''')
    index = out / 'index.html'
    index.write_text(index.read_text().replace('</h1>', '</h1><p><a href="scheduler.html">Opt-in scheduler diagnostic</a></p>', 1))
