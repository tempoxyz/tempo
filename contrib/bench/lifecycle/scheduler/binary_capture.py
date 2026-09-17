"""Root-only helper: stopped child admission and bounded native binary capture."""
import argparse
import base64
import ctypes as C
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile

from spool import FOOTER, MAGIC, WAIT_FOOTER, WAIT_MAGIC
from wait_reasons import resolver, stack_depth

ROOT = Path(__file__).parent


def dependencies():
    if os.geteuid() or sys.byteorder != 'little':
        raise ValueError('binary scheduler prerequisite unavailable')
    from bcc import BPF
    from bcc.table import _RINGBUF_CB_TYPE
    return BPF, _RINGBUF_CB_TYPE


def prepare_native(directory):
    library = Path(directory) / 'collector.so'
    subprocess.run(['gcc', '-O3', '-shared', '-fPIC', str(ROOT / 'collector.c'), '-o', str(library)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    native = C.CDLL(str(library))
    native.probe_misses.argtypes = [C.c_int,C.POINTER(C.c_uint64)]
    native.probe_misses.restype = C.c_int
    native.allocate.argtypes = [C.c_int]
    native.allocate.restype = C.c_void_p
    native.finalize.argtypes = [C.c_void_p]
    native.metric.argtypes = [C.c_void_p, C.c_int]
    native.metric.restype = C.c_size_t
    native.release.argtypes = [C.c_void_p]
    return native


PROGRAMS = (b'tracepoint__sched__sched_switch', b'raw_tracepoint__sched_wakeup',
            b'raw_tracepoint__sched_migrate_task', b'tracepoint__sched__sched_process_exit', b'reg')


def miss_counts(native,bpf):
    result = []
    for name in PROGRAMS:
        count = C.c_uint64()
        if native.probe_misses(bpf.funcs[name].fd,C.byref(count)):
            raise ValueError('binary scheduler probe counters unavailable')
        result.append(count.value)
    return result


def miss_delta(initial,final):
    if len(initial) != len(PROGRAMS) or len(final) != len(PROGRAMS) or any(b<a for a,b in zip(initial,final)):
        raise ValueError('binary scheduler probe counters unavailable')
    return sum(b-a for a,b in zip(initial,final))


def program_for(incarnation, epoch, wait_reasons=False):
    if not 0 < incarnation < 2**32 or not 0 < epoch < 2**64:
        raise ValueError('binary scheduler configuration invalid')
    return (ROOT / 'scheduler.bpf.c.in').read_text().replace('WATCHED', str(incarnation)).replace('EPOCH', str(epoch)).replace('WAIT_ENABLED', '1' if wait_reasons else '0')


def run(binary, command, epoch, spool_fd, scratch, wait_reasons=False):
    BPF, callback_type = dependencies()
    os.set_inheritable(spool_fd, False)
    with tempfile.TemporaryDirectory(prefix='lifecycle-scheduler-native-', dir=scratch) as directory:
        native = prepare_native(directory)
        context = native.allocate(spool_fd)
        if not context:
            raise ValueError('binary scheduler allocation failed')
        child = None
        launch = os.memfd_create('lifecycle-launch', os.MFD_CLOEXEC)
        try:
            # The shell opens the memory-only script before it closes this fd.
            os.write(launch, ('#!/bin/bash\nexec ' + str(launch) + '<&-\nexec ' + command + '\n').encode())
            os.set_inheritable(launch, True)
            parent = os.getpid()
            child = os.fork()
            if child == 0:
                try:
                    # Parent death must not leave an unobserved benchmark child.
                    libc = C.CDLL(None)
                    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
                        os._exit(127)
                    os.kill(os.getpid(), signal.SIGSTOP)
                    with open(os.devnull, 'wb') as sink:
                        os.dup2(sink.fileno(), 1)
                        os.dup2(sink.fileno(), 2)
                    os.execv('/bin/bash', ['/bin/bash', f'/proc/self/fd/{launch}'])
                finally:
                    os._exit(127)
            _, stopped = os.waitpid(child, os.WUNTRACED)
            if not os.WIFSTOPPED(stopped):
                child = None
                raise ValueError('binary scheduler admission failed')
            # Native incarnation is substituted only in this private memory.
            incarnation = child
            program = program_for(incarnation, epoch, wait_reasons)
            bpf = BPF(text=program)
            bpf.attach_uprobe(name=str(binary), sym='reth_lifecycle_thread_register', fn_name='reg', pid=child)
            if wait_reasons:
                resolve_type=C.CFUNCTYPE(C.c_int,C.c_int)
                maximum_depth=stack_depth()
                resolve_callback=resolve_type(resolver(bpf,maximum_depth))
                native.configure_waits.argtypes=[C.c_void_p,resolve_type]
                native.configure_waits.restype=C.c_int
                if native.configure_waits(context,resolve_callback):raise ValueError('kernel wait collector unavailable')
            callback = C.cast(native.collect, callback_type)
            bpf._open_ring_buffer(bpf['events'].map_fd, callback, C.c_void_p(context))
            initial_misses = miss_counts(native,bpf)
            os.kill(child, signal.SIGCONT)
            while True:
                bpf.ring_buffer_poll(20)
                done, status = os.waitpid(child, os.WNOHANG)
                if done:
                    child = None  # Never signal an already-reaped/reusable PID.
                    break
            # Freeze every probe after all child threads exit, before draining
            # and reading final counters. Counter coverage includes post-cutoff
            # shutdown edges; no kernel suppression may be hidden by ring counts.
            for event in ('sched_switch','sched_process_exit'):
                bpf.detach_tracepoint(tp='sched:'+event)
            for event in ('sched_wakeup','sched_migrate_task'):
                bpf.detach_raw_tracepoint(tp=event)
            # Close only our already-owned link; do not resolve a reaped PID.
            for event in list(bpf.uprobe_fds):
                bpf.detach_uprobe_event(event)
            bpf.ring_buffer_consume()
            probe_misses = miss_delta(initial_misses,miss_counts(native,bpf))
            if wait_reasons and stack_depth()!=maximum_depth:raise ValueError('kernel wait stack depth changed')
            counts = bpf['counts']
            emitted, lost, invalid = (sum(counts[counts.Key(index)]) for index in range(3))
            native.finalize(context)
            collected = native.metric(context, 0)
            invalid += native.metric(context, 1)
            overflow = native.metric(context, 2)
            io_error = native.metric(context, 3)
            received = native.metric(context, 4)
            duration = native.metric(context, 5)
            # Only fixed numeric counters enter the supervisor pipe. Anonymous
            # source records remain in its unlinked, byte-capped scratch fd.
            values=(collected,emitted,lost,invalid,overflow,io_error,received,duration,probe_misses)
            sys.stdout.buffer.write(WAIT_FOOTER.pack(WAIT_MAGIC,*values,1) if wait_reasons else FOOTER.pack(MAGIC,*values))
            sys.stdout.buffer.flush()
            if os.waitstatus_to_exitcode(status) != 0:
                raise ValueError('scheduler child failed')
        finally:
            if child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                except ProcessLookupError:
                    pass
            os.close(launch)
            native.release(context)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--command-base64')
    parser.add_argument('--epoch', type=int)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--wait-reasons',action='store_true')
    parser.add_argument('--spool-fd', type=int)
    parser.add_argument('--scratch-dir', type=Path)
    args = parser.parse_args()
    try:
        parent = os.getppid()
        if parent <= 1 or C.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            raise ValueError('binary scheduler parent unavailable')
        if args.preflight:
            BPF, _ = dependencies()
            check = BPF(text='int probe(void *ctx) { return 0; }')
            function = check.load_func('probe',BPF.KPROBE)
            with tempfile.TemporaryDirectory(prefix='lifecycle-scheduler-check-') as directory:
                native = prepare_native(directory)
                count = C.c_uint64()
                if native.probe_misses(function.fd,C.byref(count)):
                    raise ValueError('binary scheduler probe counters unavailable')
        else:
            if args.binary is None or args.epoch is None or args.command_base64 is None or args.spool_fd is None or args.scratch_dir is None:
                raise ValueError('binary scheduler configuration missing')
            command = base64.b64decode(args.command_base64, validate=True).decode()
            run(args.binary, command, args.epoch, args.spool_fd, args.scratch_dir, args.wait_reasons)
        return 0
    except Exception:
        # BCC/compiler diagnostics are captured privately by the supervisor;
        # no traceback, native mapping, command or raw data file is published.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
