"""Private immutable kernel-stack classification and closed source vocabulary."""
import errno
import re
from pathlib import Path

MODE = 'kernel_stacks_v1'
REASONS = {0:'unknown', 1:'futex_wait', 2:'kernel_io_schedule', 3:'timer_sleep', 4:'pipe_read', 5:'poll_wait'}
STATUSES = {1:'matched', 2:'unmatched', 3:'helper_failure', 4:'stack_collision', 5:'stack_map_full',
            6:'truncated', 7:'unresolved_symbol', 8:'conflicting', 9:'unsupported_state'}
SYMBOLS = {b'futex_wait_queue':1,b'futex_wait_queue_me':1,b'futex_wait':1,b'__futex_wait':1,
           b'futex_wait_multiple':1,b'futex_wait_requeue_pi':1,b'io_schedule':2,b'io_schedule_timeout':2,
           b'hrtimer_nanosleep':3,b'do_nanosleep':3,b'pipe_read':4,b'ep_poll':5,b'do_poll':5,b'do_select':5}
STACK_LIMIT = 1024


def classify_symbols(symbols, *, truncated=False):
    if truncated:return 0,6
    if not symbols:return 0,3
    # Exact kernel symbols only, no addresses, offsets, module suffix or guesses.
    if any(not isinstance(s,bytes) or re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_.$]*',s) is None for s in symbols):
        return 0,7
    found={SYMBOLS[s] for s in symbols if s in SYMBOLS}
    if len(found)>1:return 0,8
    return (next(iter(found)),1) if found else (0,2)


def helper_failure(code):
    return 0,4 if code == -errno.EEXIST else 5 if code == -errno.ENOMEM else 3


def checked(reason,status,state):
    if type(reason) is not int or type(status) is not int or reason not in REASONS or status not in STATUSES:
        raise ValueError('invalid kernel wait category')
    if (status==1) != (reason!=0) or (state in (1,2)) != (status!=9):
        raise ValueError('invalid kernel wait category')
    return reason,status


def pack(state,reason,status):
    checked(reason,status,state)
    return state | reason<<9 | status<<12


def unpack(kind,bits,enabled):
    state=bits & 511 if enabled else bits
    if state>256 or (kind!=1 and state):raise ValueError('unexpected scheduler state')
    fields={}
    if enabled and kind==1 and state not in (0,256):
        reason,status=checked((bits>>9)&7,bits>>12,state)
        fields={'wait_reason':reason,'wait_status':status}
    elif bits!=state:raise ValueError('invalid kernel wait category')
    return state,fields


def counts(rows=None):
    result={'mode':MODE,'sampled':0,'known':0,'unknown':0,'not_sampled':0,
            'status_counts':{str(i):0 for i in STATUSES}}
    if rows is not None:
        for row in rows:add_count(result,row)
    return result


def add_count(result,row):
    if 'wait_status' not in row:return
    status=row['wait_status'];result['status_counts'][str(status)]+=1
    if status==9:result['not_sampled']+=1
    else:
        result['sampled']+=1
        result['known' if status==1 else 'unknown']+=1


def stack_depth():
    # A kernel limit lower than the map value size also truncates valid stacks.
    raw=Path('/proc/sys/kernel/perf_event_max_stack').read_text().strip()
    if re.fullmatch(r'[0-9]{1,7}',raw) is None or not 0<int(raw)<=1_000_000:
        raise ValueError('kernel wait stack depth unavailable')
    return int(raw)


def resolver(bpf, maximum_depth=None):
    """Called at most once per immutable private stack ID by the native collector."""
    table=bpf['wait_stacks']
    maximum_depth=stack_depth() if maximum_depth is None else maximum_depth
    if type(maximum_depth) is not int or maximum_depth<1:raise ValueError('kernel wait stack depth unavailable')
    def resolve(stack_id):
        try:
            if not 0<=stack_id<STACK_LIMIT:return 3<<12
            entry=table[table.Key(stack_id)]
            addresses=list(entry.ip)
            # An entirely filled map value cannot prove that the stack is complete.
            limit=min(len(addresses),maximum_depth)
            if limit and addresses[limit-1]:return 6<<12
            frames=[]
            for address in addresses:
                if not address:break
                frames.append(bpf.ksym(address))
            reason,status=classify_symbols(frames)
            return reason<<9 | status<<12
        except Exception:
            return 3<<12
    return resolve
