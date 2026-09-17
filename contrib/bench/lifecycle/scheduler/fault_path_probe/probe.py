"""Owned-file, synthetic-only kernel ancestry feasibility; closed numeric output."""
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
from classify import classify
from wait_reasons import stack_depth

ROOT=Path(__file__).resolve().parent
PROGRAMS=(b'reg',b'tracepoint__sched__sched_switch',b'tracepoint__sched__sched_process_exit')


def run(scratch):
    if os.geteuid()!=0:raise ValueError('privilege unavailable')
    from bcc import BPF
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with tempfile.TemporaryDirectory(prefix='kernel-fault-synthetic-',dir=scratch) as temporary:
        directory=Path(temporary);binary=directory/'child';library=directory/'collector.so'
        for command in (['gcc','-O2','-pthread',str(ROOT/'child.c'),'-o',str(binary)],
                        ['gcc','-O3','-shared','-fPIC',str(ROOT.parent/'collector.c'),'-o',str(library)]):
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        native=C.CDLL(str(library));native.probe_misses.argtypes=[C.c_int,C.POINTER(C.c_uint64)];native.probe_misses.restype=C.c_int
        with (directory/'owned-data').open('xb+') as data:
            for _ in range(32):data.write(bytes([113])*1024**2)
            data.flush();os.fsync(data.fileno());os.set_inheritable(data.fileno(),True)
            read_fd,write_fd=os.pipe2(os.O_CLOEXEC);parent=os.getpid();child=os.fork()
            if child==0:
                try:
                    os.close(read_fd);os.dup2(write_fd,1);os.close(write_fd)
                    if C.CDLL(None).prctl(1,signal.SIGKILL,0,0,0) or os.getppid()!=parent:os._exit(127)
                    os.kill(os.getpid(),signal.SIGSTOP)
                    os.execv(str(binary),[str(binary),str(data.fileno())])
                finally:os._exit(127)
            os.close(write_fd)
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
                depth=stack_depth();before=misses();os.kill(child,signal.SIGCONT);deadline=time.monotonic()+30
                while True:
                    done,status=os.waitpid(child,os.WNOHANG)
                    if done:child=None;break
                    if time.monotonic()>=deadline:raise ValueError('synthetic child timed out')
                    time.sleep(.01)
                for event in ('sched_switch','sched_process_exit'):bpf.detach_tracepoint(tp='sched:'+event)
                for event in list(bpf.uprobe_fds):bpf.detach_uprobe_event(event)
                after=misses()
                if stack_depth()!=depth or any(b<a for a,b in zip(before,after)):raise ValueError('probe capability changed')
                probe_misses=sum(b-a for a,b in zip(before,after))
                faults=os.read(read_fd,128).split()
                if len(faults)!=2 or any(not value.isdigit() for value in faults):raise ValueError('child evidence unavailable')
                faults=[int(value) for value in faults]
                counters=[sum(bpf['counts'][bpf['counts'].Key(i)]) for i in range(4)]
                reasons={str(i):{str(reason):0 for reason in range(7)} for i in (1,2)}
                statuses={str(i):{str(status):0 for status in range(1,10)} for i in (1,2)}
                unique={};observed=0;table=bpf['stacks']
                for key,value in bpf['samples'].items():
                    if key.ordinal not in (1,2) or not 0<=key.stack_id<1024:raise ValueError('invalid sample')
                    if key.stack_id not in unique:
                        addresses=list(table[table.Key(key.stack_id)].ip)
                        limit=min(len(addresses),depth);truncated=bool(limit and addresses[limit-1])
                        symbols=[]
                        for address in addresses:
                            if not address:break
                            symbols.append(bpf.ksym(address))
                        unique[key.stack_id]=classify(symbols,truncated=truncated)
                    reason,category=unique[key.stack_id]
                    reasons[str(key.ordinal)][str(reason)]+=value.value
                    statuses[str(key.ordinal)][str(category)]+=value.value;observed+=value.value
                if list(bpf['ordinals'].items()) or os.waitstatus_to_exitcode(status)!=0:raise ValueError('synthetic child failed')
                if observed+counters[1]+counters[2]!=counters[0]:raise ValueError('sample counts disagree')
                registrations=[bpf['registrations'][bpf['registrations'].Key(i)].value for i in (1,2)]
                covered=registrations==[1,1] and all(sum(reasons[str(i)].values())>0 for i in (1,2))
                expected=reasons['1']['6']>0 and faults[0]>0 and reasons['2']['6']==0 and reasons['2']['2']>0
                return dict(schema=1,synthetic_only=True,reason_vocabulary='experimental_filemap_fault_v1',
                    registration_counts=registrations,roles_covered=covered,major_fault_counts=faults,
                    file_bytes=32*1024**2,read_passes_per_role=2,blocked_samples=counters[0],
                    stack_errors=counters[1],map_errors=counters[2],registration_errors=counters[3],
                    probe_misses=probe_misses,reason_counts=reasons,status_counts=statuses,
                    positive_fault_and_generic_control=expected,
                    complete_samples=covered and not any(counters[1:]) and probe_misses==0)
            finally:
                os.close(read_fd)
                if child is not None:
                    try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
                    except ProcessLookupError:pass


if __name__=='__main__':
    with open(os.devnull,'wb') as sink:os.dup2(sink.fileno(),2)
    try:
        if len(sys.argv)!=2:raise ValueError('owned scratch directory required')
        result=run(sys.argv[1]);print(json.dumps(result,sort_keys=True))
        sys.exit(0 if result['complete_samples'] and result['positive_fault_and_generic_control'] else 2)
    except Exception:
        print(json.dumps(dict(schema=1,synthetic_only=True,status='probe_unavailable')));sys.exit(2)
