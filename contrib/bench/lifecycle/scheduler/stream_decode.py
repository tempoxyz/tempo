"""Validate sorted scheduler edges with bounded per-thread state and pruned sinks."""
import json
import gzip
import struct
import tempfile

from diagnostic import KINDS
from budget import Budget, CappedSink, SOURCE_BYTES, COMPRESSED_SOURCE_BYTES
from binary_transport import EVENT
from spool import sorted_rows

KIND_CODES = {value:key for key,value in KINDS.items()}
INTERVAL_KINDS = ('scheduled_on_cpu','runnable_off_cpu','blocked_before_wakeup','runnable_after_wakeup','off_cpu_unsplit')
INTERVAL = struct.Struct('<IIQQBB')


def decode_stream(rows, origin, cutoff, emitted, emit_record, emit_interval, *, expected_threads=None, classify_running_wakes=False):
    if cutoff <= 0:
        raise ValueError('clock mismatch')
    states = {}
    exited = set()
    total = kept = unknown = unclosed = unmatched = running_wakeups = 0
    last = -1

    def interval(thread, start, end, kind):
        low, high = max(0,start), min(cutoff-1,end)
        if low < high:
            emit_interval(states[thread]['rank'], thread, low, high, kind, end >= cutoff)

    for timestamp, thread, kind, bits in rows:
        total += 1
        ts = timestamp-origin
        if ts < 0 or ts < last:
            raise ValueError('clock mismatch')
        last = ts
        if not 0 < thread <= 8192 or kind not in KINDS or (expected_threads is not None and thread not in expected_threads):
            raise ValueError('unexpected ordinal/event')
        if bits > 256 or (kind != 1 and bits):
            raise ValueError('unexpected scheduler state')
        if kind == 0:
            if thread in states:
                raise ValueError('ordinal reused')
            states[thread] = dict(rank=len(states), running=ts, out=None, wake=None)
        elif thread not in states or thread in exited:
            raise ValueError('registration/exit gap')
        state = states[thread]
        if kind == 1:
            if state['out'] is not None:
                raise ValueError('missing switch-in')
            if state['running'] is not None:
                interval(thread,state['running'],ts,0)
            state.update(out=(ts,bits),running=None,wake=None)
        elif kind == 3:
            if state['out'] is not None and state['wake'] is None:
                state['wake'] = ts
            elif classify_running_wakes and state['running'] is not None and state['out'] is None:
                # A wake may cancel an intended sleep before the task schedules
                # out. Preserve the event, without inventing an off-CPU interval.
                running_wakeups += int(ts < cutoff)
            else:
                unmatched += int(ts < cutoff)
        elif kind == 2:
            if state['out'] is None:
                raise ValueError('missing switch-out')
            start,bits = state['out']
            if bits in (0,256):
                interval(thread,start,ts,1)
            elif state['wake'] is not None:
                interval(thread,start,state['wake'],2)
                interval(thread,state['wake'],ts,3)
            else:
                interval(thread,start,ts,4)
                unknown += int(start < cutoff)
            state.update(out=None,wake=None,running=ts)
        elif kind == 4:
            exited.add(thread)
            if state['running'] is not None:
                interval(thread,state['running'],ts,0)
            if state['out'] is not None:
                unclosed += int(state['out'][0] < cutoff)
            state.update(running=None,out=None)
        if ts < cutoff:
            kept += 1
            emit_record({'ts':ts,'thread':thread,'kind':KINDS[kind],'state_bits':bits if kind==1 else 0})
    if total != emitted:
        raise ValueError('capture tool reported event loss')
    registered = set(states)
    if not registered or exited != registered or (expected_threads is not None and registered != expected_threads):
        raise ValueError('registration/exit coverage incomplete')
    return {
        'schema':1,'scope':'synthetic registered windows only','process':1,
        'clock':'monotonic_relative_ns','cutoff_ns':cutoff,
        'quality':{'event_loss_detected':False,'registered_threads':len(states),
                   'all_registered_threads_exited':True,'unclassified_off_cpu_intervals':unknown,
                   'unclosed_intervals_excluded':unclosed,'unmatched_wakeups':unmatched,
                   'at_or_post_cutoff_records_pruned':total-kept,
                   **({'wakeups_while_running':running_wakeups} if classify_running_wakes else {})},
        'registered_window_edges_complete':unknown==0 and unclosed==0 and unmatched==0,
    }, kept


def publish_streamed(output, source, directory, origin, cutoff, emitted, metadata, evidence=None, probe_misses=None):
    """Publish atomically only after every edge/count has validated and been pruned."""
    if set(metadata)-{'scope','process','cutoff_reason','registration'}:
        raise ValueError('unexpected scheduler publication metadata')
    temporary = output.with_suffix('.partial')
    owned = False
    with tempfile.TemporaryFile(dir=directory) as records, tempfile.TemporaryFile(dir=directory) as intervals:
        intermediate = Budget(SOURCE_BYTES)
        publication = Budget(SOURCE_BYTES)
        def record(row):
            kind = KIND_CODES[row['kind']]
            intermediate.write(records,EVENT.pack(row['ts'],row['thread'],kind,row['state_bits']))
        def interval(rank, thread, start, end, kind, censored):
            intermediate.write(intervals,INTERVAL.pack(rank,thread,start,end,kind,censored))
        result,kept = decode_stream(sorted_rows(source,directory),origin,cutoff,emitted,record,interval,
                                    classify_running_wakes=probe_misses is not None)
        if probe_misses is not None:
            if type(probe_misses) is not int or probe_misses != 0:
                raise ValueError('capture tool reported probe misses')
            result['schema'] = 3
            result['quality']['probe_misses'] = 0
        if evidence is not None:
            evidence.update(kept=kept,pruned=emitted-kept)
        result.update(metadata)
        try:
            with temporary.open('xb') as raw:
                owned = True
                compressed = output.suffix == '.gz'
                import contextlib
                with (gzip.GzipFile(filename='',mode='wb',fileobj=CappedSink(raw,Budget(COMPRESSED_SOURCE_BYTES)),
                                    compresslevel=1,mtime=0) if compressed else contextlib.nullcontext(raw)) as destination:
                    publication.write(destination,json.dumps(result,separators=(',',':')).encode()[:-1])
                    publication.write(destination,b',"records":[')
                    records.seek(0)
                    from spool import rows
                    first = True
                    for ts,thread,kind,bits in rows(records):
                        if not first:
                            publication.write(destination,b',')
                        first = False
                        row = {'ts':ts,'thread':thread,'kind':KINDS[kind],'state_bits':bits}
                        publication.write(destination,json.dumps(row,separators=(',',':')).encode())
                    publication.write(destination,b'],"intervals":[')
                    first = True
                    for _,thread,start,end,kind,censored in sorted_rows(intervals,directory,record=INTERVAL,key=lambda row:(row[0],row[2])):
                        if not first:
                            publication.write(destination,b',')
                        first = False
                        row = {'thread':thread,'start':start,'end':end,'kind':INTERVAL_KINDS[kind],'right_censored':bool(censored)}
                        publication.write(destination,json.dumps(row,separators=(',',':')).encode())
                    publication.write(destination,b']}\n')
            temporary.replace(output)
        finally:
            if owned:
                temporary.unlink(missing_ok=True)
    return kept, emitted-kept
