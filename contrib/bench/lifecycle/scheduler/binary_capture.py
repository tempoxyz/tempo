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

from binary_transport import HEADER, MAGIC

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
    native.allocate.restype = C.c_void_p
    native.records.argtypes = [C.c_void_p]
    native.records.restype = C.c_void_p
    native.metric.argtypes = [C.c_void_p, C.c_int]
    native.metric.restype = C.c_size_t
    native.release.argtypes = [C.c_void_p]
    return native


def program_for(incarnation, epoch):
    if not 0 < incarnation < 2**32 or not 0 < epoch < 2**64:
        raise ValueError('binary scheduler configuration invalid')
    return (ROOT / 'scheduler.bpf.c.in').read_text().replace('WATCHED', str(incarnation)).replace('EPOCH', str(epoch))


def run(binary, command, epoch):
    BPF, callback_type = dependencies()
    with tempfile.TemporaryDirectory(prefix='lifecycle-scheduler-native-') as directory:
        native = prepare_native(directory)
        context = native.allocate()
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
            program = program_for(child, epoch)
            bpf = BPF(text=program)
            bpf.attach_uprobe(name=str(binary), sym='reth_lifecycle_thread_register', fn_name='reg', pid=child)
            callback = C.cast(native.collect, callback_type)
            bpf._open_ring_buffer(bpf['events'].map_fd, callback, C.c_void_p(context))
            os.kill(child, signal.SIGCONT)
            while True:
                bpf.ring_buffer_poll(20)
                done, status = os.waitpid(child, os.WNOHANG)
                if done:
                    child = None  # Never signal an already-reaped/reusable PID.
                    break
            # ring_buffer_consume drains until empty after every traced thread exits.
            bpf.ring_buffer_consume()
            counts = bpf['counts']
            emitted, lost, invalid = (sum(counts[counts.Key(index)]) for index in range(3))
            collected = native.metric(context, 0)
            invalid += native.metric(context, 1)
            overflow = native.metric(context, 2)
            # Header and records go only to the supervisor's private pipe.
            sys.stdout.buffer.write(HEADER.pack(MAGIC, collected, emitted, lost, invalid, overflow,
                                               int(os.waitstatus_to_exitcode(status) != 0)))
            record_type = C.c_char * (collected * 16)
            sys.stdout.buffer.write(record_type.from_address(native.records(context)))
            sys.stdout.buffer.flush()
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
    args = parser.parse_args()
    try:
        parent = os.getppid()
        if parent <= 1 or C.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            raise ValueError('binary scheduler parent unavailable')
        if args.preflight:
            BPF, _ = dependencies()
            BPF(text='int probe(void *ctx) { return 0; }')
            with tempfile.TemporaryDirectory(prefix='lifecycle-scheduler-check-') as directory:
                prepare_native(directory)
        else:
            if args.binary is None or args.epoch is None or args.command_base64 is None:
                raise ValueError('binary scheduler configuration missing')
            command = base64.b64decode(args.command_base64, validate=True).decode()
            run(args.binary, command, args.epoch)
        return 0
    except Exception:
        # BCC/compiler diagnostics are captured privately by the supervisor;
        # no traceback, native mapping, command or raw data file is published.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
