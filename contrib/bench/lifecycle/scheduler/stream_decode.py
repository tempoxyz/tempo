"""Validate sorted scheduler edges with bounded per-thread state and pruned sinks."""
import json
import gzip
import struct
import tempfile

from diagnostic import KINDS
from budget import Budget, CappedSink, SOURCE_BYTES, COMPRESSED_SOURCE_BYTES
from binary_transport import EVENT
from spool import sorted_rows
from wait_reasons import unpack, pack, counts, add_count

KIND_CODES = {value:key for key,value in KINDS.items()}
INTERVAL_KINDS = ('scheduled_on_cpu','runnable_off_cpu','blocked_before_wakeup','runnable_after_wakeup','off_cpu_unsplit')
INTERVAL = struct.Struct('<IIQQBB')
WAIT_INTERVAL = struct.Struct('<IIQQBBBB')


def decode_stream(rows, origin, cutoff, emitted, emit_record, emit_interval, *, expected_threads=None, classify_running_wakes=False, wait_reasons=False):
    if cutoff <= 0:
        raise ValueError('clock mismatch')
    states = {}
    exited = set()
    total = kept = unknown = unclosed = unmatched = running_wakeups = 0
    last = -1
    wait_counts=counts()

    def interval(thread, start, end, kind, reason=0, status=0):
        low, high = max(0,start), min(cutoff-1,end)
        if low < high:
            args=(states[thread]['rank'],thread,low,high,kind,end>=cutoff)
            emit_interval(*args,reason,status) if wait_reasons else emit_interval(*args)

    for timestamp, thread, kind, bits in rows:
        total += 1
        ts = timestamp-origin
        if ts < 0 or ts < last:
            raise ValueError('clock mismatch')
        last = ts
        if not 0 < thread <= 8192 or kind not in KINDS or (expected_threads is not None and thread not in expected_threads):
            raise ValueError('unexpected ordinal/event')
        bits,fields=unpack(kind,bits,wait_reasons)
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
            state.update(out=(ts,bits,fields.get('wait_reason',0),fields.get('wait_status',0)),running=None,wake=None)
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
            start,bits,out_reason,out_status = state['out']
            if bits in (0,256):
                interval(thread,start,ts,1)
            elif state['wake'] is not None:
                interval(thread,start,state['wake'],2,out_reason,out_status)
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
            row={'ts':ts,'thread':thread,'kind':KINDS[kind],'state_bits':bits if kind==1 else 0,**fields}
            add_count(wait_counts,row)
            emit_record(row)
    if total != emitted:
        raise ValueError('capture tool reported event loss')
    registered = set(states)
    if not registered or exited != registered or (expected_threads is not None and registered != expected_threads):
        raise ValueError('registration/exit coverage incomplete')
    return {
        **({'wait_reasons':wait_counts} if wait_reasons else {}),
        'schema':1,'scope':'synthetic registered windows only','process':1,
        'clock':'monotonic_relative_ns','cutoff_ns':cutoff,
        'quality':{'event_loss_detected':False,'registered_threads':len(states),
                   'all_registered_threads_exited':True,'unclassified_off_cpu_intervals':unknown,
                   'unclosed_intervals_excluded':unclosed,'unmatched_wakeups':unmatched,
                   'at_or_post_cutoff_records_pruned':total-kept,
                   **({'wakeups_while_running':running_wakeups} if classify_running_wakes else {})},
        'registered_window_edges_complete':unknown==0 and unclosed==0 and unmatched==0,
    }, kept


def publish_streamed(output, source, directory, origin, cutoff, emitted, metadata, evidence=None, probe_misses=None, wait_reasons=False):
    """Publish atomically only after every edge/count has validated and been pruned."""
    if set(metadata)-{'scope','process','cutoff_reason','registration'}:
        raise ValueError('unexpected scheduler publication metadata')
    if wait_reasons and probe_misses is None:raise ValueError('kernel waits require probe evidence')
    interval_format=WAIT_INTERVAL if wait_reasons else INTERVAL
    temporary = output.with_suffix('.partial')
    owned = False
    with tempfile.TemporaryFile(dir=directory) as records, tempfile.TemporaryFile(dir=directory) as intervals:
        intermediate = Budget(SOURCE_BYTES)
        publication = Budget(SOURCE_BYTES)
        def record(row):
            kind = KIND_CODES[row['kind']]
            bits=pack(row['state_bits'],row['wait_reason'],row['wait_status']) if 'wait_status' in row else row['state_bits']
            intermediate.write(records,EVENT.pack(row['ts'],row['thread'],kind,bits))
        def interval(*args):
            intermediate.write(intervals,interval_format.pack(*args))
        result,kept = decode_stream(sorted_rows(source,directory),origin,cutoff,emitted,record,interval,
                                    classify_running_wakes=probe_misses is not None,wait_reasons=wait_reasons)
        if probe_misses is not None:
            if type(probe_misses) is not int or probe_misses != 0:
                raise ValueError('capture tool reported probe misses')
            result['schema'] = 4 if wait_reasons else 3
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
                        bits,fields=unpack(kind,bits,wait_reasons)
                        row = {'ts':ts,'thread':thread,'kind':KINDS[kind],'state_bits':bits,**fields}
                        publication.write(destination,json.dumps(row,separators=(',',':')).encode())
                    publication.write(destination,b'],"intervals":[')
                    first = True
                    for item in sorted_rows(intervals,directory,record=interval_format,key=lambda row:(row[0],row[2])):
                        _,thread,start,end,kind,censored=item[:6]
                        fields={'wait_reason':item[6],'wait_status':item[7]} if wait_reasons and kind==2 else {}
                        if not first:
                            publication.write(destination,b',')
                        first = False
                        row = {'thread':thread,'start':start,'end':end,'kind':INTERVAL_KINDS[kind],'right_censored':bool(censored),**fields}
                        publication.write(destination,json.dumps(row,separators=(',',':')).encode())
                    publication.write(destination,b']}\n')
            temporary.replace(output)
        finally:
            if owned:
                temporary.unlink(missing_ok=True)
    return kept, emitted-kept
