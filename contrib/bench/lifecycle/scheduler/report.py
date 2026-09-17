"""Validate and publish only anonymous, cutoff-intersected scheduler context."""
from collections import Counter
import json
import gzip
import shutil
from pathlib import Path
import time
try:
    from .wait_reasons import REASONS, STATUSES, checked, counts, add_count
    from .failures import failure_summary
    from .index import CaptureIndex, DiskRows, RecordSummary, read_capture
    from .budget import Budget, CappedSink, FOCUSED_BYTES
except ImportError:
    from wait_reasons import REASONS, STATUSES, checked, counts, add_count
    from failures import failure_summary
    from index import CaptureIndex, DiskRows, RecordSummary, read_capture
    from budget import Budget, CappedSink, FOCUSED_BYTES

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
    if capture.get('schema') in (4,5):keys.add('wait_reasons')
    if set(capture) != keys or type(capture['schema']) is not int or capture['schema'] not in (1,2,3,4,5) or capture['process'] != process:
        raise ValueError('scheduler schema/process mismatch')
    if (capture['scope'] != 'registered validator thread windows only'
            or capture['clock'] != 'monotonic_relative_ns'
            or capture['registration'] != 'registered_threads_v1'
            or capture['cutoff_ns'] != cutoff or capture['cutoff_reason'] != reason):
        raise ValueError('scheduler scope/clock/cutoff mismatch')
    quality = capture['quality']
    expected_quality = (QUALITY | ({'probe_misses'} if capture['schema']>=2 else set())
                        | ({'wakeups_while_running'} if capture['schema']>=3 else set()))
    if capture['schema']>=2 and (type(quality.get('probe_misses')) is not int or quality['probe_misses']!=0):
        raise ValueError('scheduler probe misses; capture unavailable')
    if set(quality) != expected_quality or quality['event_loss_detected'] is not False or quality['all_registered_threads_exited'] is not True:
        raise ValueError('scheduler capture integrity failed')
    if any(not integer(value) for key,value in quality.items() if key not in {'event_loss_detected','all_registered_threads_exited'}):
        raise ValueError('invalid scheduler quality counter')
    complete = not any(quality[key] for key in ('unclassified_off_cpu_intervals','unclosed_intervals_excluded','unmatched_wakeups'))
    if capture['registered_window_edges_complete'] is not complete:
        raise ValueError('invalid scheduler completeness')
    if not isinstance(capture['records'], (list, DiskRows)) or not isinstance(capture['intervals'], (list, DiskRows)):
        raise ValueError('invalid scheduler rows')
    previous = {}
    version=2 if capture['schema']==5 else 1
    source_modes=set();interval_modes=set();wait_counts=counts(version=version)
    for row in capture['records']:
        validate_record(row,cutoff,version)
        if row['kind']=='switch_out' and row['state_bits'] not in (0,256):source_modes.add('wait_status' in row)
        add_count(wait_counts,row)
    for row in capture['intervals']:
        validate_interval(row,cutoff,previous,version)
        if row['kind']=='blocked_before_wakeup':interval_modes.add('wait_status' in row)
    validate_wait_metadata(capture,source_modes,interval_modes,wait_counts)
    return capture


def validate_record(row, cutoff, version=1):
    fields={'wait_reason','wait_status'} if isinstance(row,dict) and ('wait_reason' in row or 'wait_status' in row) else set()
    if (not isinstance(row,dict) or set(row) != {'ts','thread','kind','state_bits'}|fields or row['kind'] not in KINDS
            or not integer(row['thread'],1,8192) or not integer(row['ts'],0,cutoff-1)
            or not integer(row['state_bits'],0,256)):
        raise ValueError('invalid scheduler event or cutoff drift')
    if fields:
        if row['kind']!='switch_out' or row['state_bits'] in (0,256):raise ValueError('invalid kernel wait category')
        checked(row['wait_reason'],row['wait_status'],row['state_bits'],version)


def validate_interval(row, cutoff, previous, version=1):
    fields={'wait_reason','wait_status'} if isinstance(row,dict) and ('wait_reason' in row or 'wait_status' in row) else set()
    if (not isinstance(row,dict) or set(row) != {'thread','start','end','kind','right_censored'}|fields or row['kind'] not in INTERVALS
            or not integer(row['thread'],1,8192) or not integer(row['start'],0,cutoff-1)
            or not integer(row['end'],row['start']+1,cutoff-1) or type(row['right_censored']) is not bool):
        raise ValueError('invalid scheduler interval or cutoff drift')
    if fields:
        if row['kind']!='blocked_before_wakeup':raise ValueError('invalid kernel wait category')
        checked(row['wait_reason'],row['wait_status'],4 if row['wait_status']==9 else 1,version)
    if row['start'] < previous.get(row['thread'],0):
        raise ValueError('overlapping scheduler states')
    previous[row['thread']] = row['end']


def validate_wait_metadata(capture,source_modes,interval_modes,wait_counts):
    enabled=capture['schema'] in (4,5)
    if source_modes-{enabled} or interval_modes-{enabled}:raise ValueError('kernel wait schema/row mismatch')
    if enabled:
        supplied=capture.get('wait_reasons')
        if not isinstance(supplied,dict) or set(supplied)!=set(wait_counts):raise ValueError('invalid kernel wait coverage')
        if supplied.get('mode')!=counts(version=2 if capture['schema']==5 else 1)['mode']:raise ValueError('invalid kernel wait coverage')
        for name in ('sampled','known','unknown','not_sampled'):
            if not integer(supplied[name]):raise ValueError('invalid kernel wait coverage')
        statuses=supplied['status_counts']
        if not isinstance(statuses,dict) or set(statuses)!={str(i) for i in STATUSES} or any(not integer(v) for v in statuses.values()):raise ValueError('invalid kernel wait coverage')
        if supplied!=wait_counts:raise ValueError('kernel wait coverage mismatch')


def indexed_capture(path, directory, process, cutoff, reason, *, retain_records=True):
    owner = CaptureIndex(directory, retain_records=retain_records)
    previous = {}
    source_modes=set();interval_modes=set();wait_counts=counts();reason_codes=set()
    try:
        def add(table,row):
            if 'wait_reason' in row:reason_codes.add(row['wait_reason'])
            if table == 'records':
                validate_record(row,cutoff,2)
                if row['kind']=='switch_out' and row['state_bits'] not in (0,256):source_modes.add('wait_status' in row)
                add_count(wait_counts,row)
            else:
                validate_interval(row,cutoff,previous,2)
                if row['kind']=='blocked_before_wakeup':interval_modes.add('wait_status' in row)
            owner.add(table,row)
        metadata = read_capture(path,add)
        version=2 if metadata.get('schema')==5 else 1
        if version==1 and 6 in reason_codes:raise ValueError('kernel wait schema/reason mismatch')
        wait_counts['mode']=counts(version=version)['mode']
        # Metadata gates apply identically; rows were validated on ingestion.
        checked_metadata=dict(metadata,records=[],intervals=[])
        # Empty row arrays validate metadata shape; actual counters are verified below.
        validation_copy=dict(checked_metadata)
        if metadata.get('schema') in (4,5):validation_copy['wait_reasons']=counts(version=version)
        validate(validation_copy,process,cutoff,reason)
        validate_wait_metadata(checked_metadata,source_modes,interval_modes,wait_counts)
        return owner.finish(metadata)
    except BaseException:
        owner.close()
        raise


def source_registration(path, capture):
    registrations = (capture['records'].registrations() if isinstance(capture['records'],(DiskRows,RecordSummary)) else
                     {row['thread']:row['ts'] for row in capture['records'] if row['kind'] == 'register'})
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


# A17M-edge sizing proof takes102s just to validate/publish one source.
# Bound post-shutdown processing separately from the90s lifecycle-footer gate.
def load(directory, out, window, timeout=900, *, retain_records=True):
    from progress import emit
    paths = [directory / f'scheduler-{role}.json.gz' for role in ('a','b')]
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
    try:
        for index, path in enumerate(paths):
            # Lifecycle headers must prove the requested hook was active, even if
            # BPF happens to have observed another instrumented process by mistake.
            with (out / f'{"ab"[index]}.jsonl').open() as stream:
                header = json.loads(stream.readline())
            if header.get('scheduler') != 'registered_threads_v1':
                raise ValueError('lifecycle scheduler registration header missing')
            emit('scheduler_index', 'begin', index+1)
            capture = indexed_capture(path, directory, index+1, cutoff, reason, retain_records=retain_records)
            result.append(capture)
            emit('scheduler_index', 'end', index+1)
            coverage.append(source_registration(out / f'{"ab"[index]}.jsonl', capture))
        # Both versions carry mandatory probe evidence; schema 2 retains its
        # original wake semantics, while newly published captures use schema 3.
        if (any(capture['schema'] not in (2,3,4,5) for capture in result)
                or len({capture['schema'] for capture in result}) != 1):
            raise ValueError('scheduler probe counter proof missing')
        # Write neither validator until both are validated.
        for path, capture in zip(paths, result):
            shutil.copyfile(path, out / path.name)
        return result, coverage
    except BaseException:
        close(result)
        raise



def close(captures):
    for capture in captures:
        if isinstance(capture['intervals'],DiskRows):
            capture['intervals'].owner.close()


def scheduler_event_rows(captures, origin, low, high):
    used = set()
    for capture in captures:
        intervals = capture['intervals']
        if isinstance(intervals,DiskRows):
            used.update((100+capture['process'],thread) for thread in intervals.threads(origin+low*1000,origin+high*1000))
        else:
            used.update((100+capture['process'],row['thread']) for row in intervals
                        if (row['start']-origin)/1000 < high and (row['end']-origin)/1000 > low)
    for capture in captures:
        yield {'name':'process_name','ph':'M','pid':100+capture['process'],'tid':0,
               'args':{'name':f'Validator {chr(64+capture["process"])} scheduler'}}
    for pid,thread in sorted(used):
        yield {'name':'thread_name','ph':'M','pid':pid,'tid':thread,
               'args':{'name':f'Anonymous thread {thread}'}}
    for capture in captures:
        pid = 100 + capture['process']
        source_rows = (capture['intervals'].overlap(origin+low*1000,origin+high*1000)
                       if isinstance(capture['intervals'],DiskRows) else capture['intervals'])
        for row in source_rows:
            start, end = (row['start']-origin)/1000, (row['end']-origin)/1000
            if start >= high or end <= low:
                continue
            clipped_start, clipped_end = start < low, end > high
            start, end = max(start, low), min(end, high)
            wait_args=({'kernel_wait_reason':row['wait_reason'],'kernel_wait_status':row['wait_status'],
                        'observed_kernel_wait_path':REASONS[row['wait_reason']],
                        'wait_path_semantics':'observed sleeping kernel path; not lock owner, I/O cause or task CPU'}
                       if 'wait_status' in row else {})
            yield {'name':row['kind'], 'cat':'scheduler context', 'ph':'X', 'pid':pid,
                         'tid':row['thread'], 'ts':start, 'dur':end-start,
                         'args':{'source_thread_ordinal':row['thread'],
                                 'association':'thread context; temporal overlap does not establish block causality',
                                 'right_censored':row['right_censored'],
                                 'focus_clipped_start':clipped_start, 'focus_clipped_end':clipped_end,
                                 'semantics':'scheduler residency; includes kernel and interrupts, not task CPU time',**wait_args}}


def scheduler_events(captures, origin, low, high):
    return list(scheduler_event_rows(captures,origin,low,high))


def publish(data, captures, out, coverage):
    summary = {'schema':1, 'scope':'registered thread windows only; not complete async-task attribution',
               'cutoff_ns':captures[0]['cutoff_ns'], 'nodes':[], 'pages':[], 'percentiles':[]}
    for capture in captures:
        totals = Counter(capture['intervals'].totals()) if isinstance(capture['intervals'],DiskRows) else Counter()
        if not isinstance(capture['intervals'],DiskRows):
            for row in capture['intervals']:
                totals[row['kind']] += row['end'] - row['start']
        wait_summary={}
        if 'wait_reasons' in capture:
            wait_totals=(capture['intervals'].wait_totals() if isinstance(capture['intervals'],DiskRows) else dict(Counter()))
            if not isinstance(capture['intervals'],DiskRows):
                for row in capture['intervals']:
                    if 'wait_status' in row:
                        name=REASONS[row['wait_reason']];wait_totals[name]=wait_totals.get(name,0)+row['end']-row['start']
            wait_summary={'wait_reasons':capture['wait_reasons'],'blocked_wall_ns_by_wait_reason':wait_totals}
        summary['nodes'].append({'node' :f'Validator {chr(64+capture["process"])}',
                                 'quality':capture['quality'],
                                 'registration_coverage':coverage[capture["process"]-1],
                                 'thread_wall_ns_by_state':dict(totals),**wait_summary})
    budget = Budget(FOCUSED_BYTES)
    for block in data['blocks']:
        source = out / f'perfetto-block-{block["id"]}.json'
        trace = json.loads(source.read_text())
        name = f'perfetto-scheduler-block-{block["id"]}.json.gz'
        expanded = Budget(8*1024**3)
        with (out / name).open('wb') as raw, gzip.GzipFile(filename='',mode='wb',
                fileobj=CappedSink(raw,budget),compresslevel=1,mtime=0) as destination:
            events = trace.pop('traceEvents')
            expanded.write(destination,json.dumps(trace,separators=(',',':')).encode()[:-1])
            expanded.write(destination,((',' if trace else '')+'"traceEvents":[').encode())
            first = True
            import itertools
            for event in itertools.chain(events,scheduler_event_rows(captures,data['time_origin_ns'],
                                        block['start']*1000,block['end']*1000)):
                if not first:
                    expanded.write(destination,b',')
                first = False
                expanded.write(destination,json.dumps(event,separators=(',',':')).encode())
            expanded.write(destination,b']}')
        summary['pages'].append({'block':block['id'], 'trace':name})
    for percentile, block in data['representatives'].items():
        if not data['bad_capture']:
            summary['percentiles'].append({'percentile':int(percentile),'block':block,
                                          'trace':f'perfetto-scheduler-block-{block}.json.gz'})
    (out / 'scheduler-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    percentile_links = ' · '.join(f'<a href="{p["trace"]}">p{p["percentile"]}: block {p["block"]}</a>' for p in summary['percentiles'])
    fault_note=('<p>File-backed fault ancestry identifies a kernel path, not a file, instruction, device, physical read or persistence operation.</p>' if captures[0]['schema']==5 else '')
    rows = ''.join(f'<li><a href="{p["trace"]}">Block {p["block"]} + scheduler context</a></li>' for p in summary['pages'])
    (out / 'scheduler.html').write_text(f'''<!doctype html><meta charset="utf-8"><title>Scheduler diagnostic</title>
<h1>Registered thread scheduler diagnostic</h1><p><a href="index.html">Lifecycle summary</a> · <a href="scheduler-summary.json">Quality and measured intervals</a></p>
<p>Open a trace below in Perfetto. The ordinary lifecycle lanes are accompanied by anonymous scheduler thread tracks. Thread ordinals match source capture enter/exit records. These scheduler tracks are temporal context, not automatic attribution to a block or async task.</p>
<p>Scheduled intervals include kernel execution and interrupts; they are not measured task CPU time. Off-CPU intervals split into blocked-before-wakeup and runnable-after-wakeup only when both edges and wakeup are observed. Missing wakeups remain unsplit. Time before registration, missing edges, and unclosed intervals is unavailable. Async tasks awaiting without a thread cannot be assigned scheduler time. Overlapping scopes and threads are not additive wall or CPU time.</p>
<p>Optional kernel wait categories describe the observed sleeping kernel path only. Futex does not identify a lock or owner; kernel IO scheduling does not identify an I/O cause or device. Unknown, unavailable, truncated and conflicting stacks remain explicit. Runnable-after-wakeup time is not charged to that category. Stack sampling adds observer cost; comparisons require matched instrumentation.</p>
{fault_note}<p>Only observed intervals intersected with the strict source cutoff are exported. Perfetto context is additionally clipped to each actual block lifecycle. Percentiles select the same actual complete blocks as the lifecycle report.</p><p>{percentile_links}</p><ul>{rows}</ul>''')
    index = out / 'index.html'
    index.write_text(index.read_text().replace('</h1>', '</h1><p><a href="scheduler.html">Opt-in scheduler diagnostic</a></p>', 1))
