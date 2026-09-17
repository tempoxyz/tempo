"""Synthetic-only bounded feasibility probe; emits closed numeric summaries only.

Never run a node. Kernel addresses, symbols, native TIDs and stack IDs remain in
kernel/private process memory. This is not a complete scheduler/cutoff capture.
"""
import ctypes as C
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import time
import sys
from classify import Reason, classify, covered

ROOT = Path(__file__).resolve().parent
PROGRAMS=(b'reg',b'tracepoint__sched__sched_switch',b'tracepoint__sched__sched_process_exit')


def run():
    if os.geteuid()!=0:raise ValueError('privilege unavailable')
    from bcc import BPF
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with tempfile.TemporaryDirectory(prefix='kernel-wait-synthetic-') as temporary:
        directory=Path(temporary);binary=directory/'child';library=directory/'collector.so'
        subprocess.run(['gcc','-O2','-pthread',str(ROOT/'child.c'),'-o',str(binary)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        subprocess.run(['gcc','-O3','-shared','-fPIC',str(ROOT.parent/'collector.c'),'-o',str(library)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        native=C.CDLL(str(library));native.probe_misses.argtypes=[C.c_int,C.POINTER(C.c_uint64)];native.probe_misses.restype=C.c_int
        parent=os.getpid();child=os.fork()
        if child==0:
            try:
                if C.CDLL(None).prctl(1,signal.SIGKILL,0,0,0) or os.getppid()!=parent:os._exit(127)
                os.kill(os.getpid(),signal.SIGSTOP)
                os.execv(str(binary),[str(binary)])
            finally:os._exit(127)
        try:
            _,status=os.waitpid(child,os.WUNTRACED)
            if not os.WIFSTOPPED(status):child=None;raise ValueError('synthetic admission failed')
            bpf=BPF(text=(ROOT/'probe.bpf.c.in').read_text().replace('WATCHED',str(child)))
            bpf.attach_uprobe(name=str(binary),sym='reth_lifecycle_thread_register',fn_name='reg',pid=child)
            def misses():
                values=[]
                for name in PROGRAMS:
                    count=C.c_uint64()
                    if native.probe_misses(bpf.funcs[name].fd,C.byref(count)):raise ValueError('probe counters unavailable')
                    values.append(count.value)
                return values
            before=misses();os.kill(child,signal.SIGCONT)
            deadline=time.monotonic()+5
            while True:
                done,status=os.waitpid(child,os.WNOHANG)
                if done:child=None;break
                if time.monotonic()>=deadline:raise ValueError('synthetic child timed out')
                time.sleep(.005)
            for event in ('sched_switch','sched_process_exit'):bpf.detach_tracepoint(tp='sched:'+event)
            for event in list(bpf.uprobe_fds):bpf.detach_uprobe_event(event)
            after=misses()
            if any(b<a for a,b in zip(before,after)):raise ValueError('probe counter reset')
            probe_misses=sum(b-a for a,b in zip(before,after))
            counters=[sum(bpf['counts'][bpf['counts'].Key(i)]) for i in range(4)]
            reason_counts={str(i):{str(int(reason)):0 for reason in Reason} for i in range(1,4)}
            unique={};observed=0
            for key,value in bpf['samples'].items():
                if key.ordinal not in (1,2,3) or key.stack_id<0:raise ValueError('invalid sample')
                if key.stack_id not in unique:
                    # Immutable map entries, resolved once. Neither addresses nor
                    # symbols are written to any file, exception or output.
                    symbols=[bpf.ksym(address) for address in bpf['stacks'].walk(key.stack_id)]
                    unique[key.stack_id]=classify(symbols)
                reason_counts[str(key.ordinal)][str(int(unique[key.stack_id]))]+=value.value
                observed+=value.value
            if len(list(bpf['ordinals'].items())):raise ValueError('unclosed synthetic thread')
            if os.waitstatus_to_exitcode(status)!=0:raise ValueError('synthetic child failed')
            if observed+counters[1]+counters[2]!=counters[0]:raise ValueError('sample counts disagree')
            registrations=[bpf['registrations'][bpf['registrations'].Key(i)].value for i in range(1,4)]
            coverage=covered(registrations,[sum(reason_counts[str(i)].values()) for i in range(1,4)])
            expected=all(reason_counts[str(role)][str(int(reason))]>0 for role,reason in [(1,Reason.TIMER_SLEEP),(2,Reason.FUTEX_WAIT),(3,Reason.PIPE_READ)])
            return dict(schema=1,registration_counts=registrations,roles_covered=bool(coverage),expected_paths_observed=expected,synthetic_only=True,blocked_samples=counters[0],stack_errors=counters[1],map_errors=counters[2],registration_errors=counters[3],probe_misses=probe_misses,unique_private_stacks=len(unique),reason_counts=reason_counts,
                        complete_samples=bool(coverage) and not any(counters[1:]) and probe_misses==0)
        finally:
            if child is not None:
                try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
                except ProcessLookupError:pass


if __name__=='__main__':
    # BCC/tool diagnostics may contain native addresses or paths. They are
    # discarded even on failure; only the closed category below is public.
    with open(os.devnull,'wb') as sink:os.dup2(sink.fileno(),2)
    try:
        result=run();print(json.dumps(result,sort_keys=True))
        sys.exit(0 if result['complete_samples'] and result['expected_paths_observed'] else 2)
    except Exception:
        print(json.dumps(dict(schema=1,synthetic_only=True,status='probe_unavailable')))
        sys.exit(2)
