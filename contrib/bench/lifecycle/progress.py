"""Closed post-capture progress markers; ordinary reporter output stays private."""
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

FD_ENV = 'TEMPO_LIFECYCLE_REPORT_PROGRESS_FD'
STAGES = ('lifecycle_prune', 'lifecycle_build', 'scheduler_load', 'scheduler_index',
          'report_write', 'package', 'scheduler_publish')
LINE = re.compile(rb'(' + b'|'.join(s.encode() for s in STAGES) + rb')\|(begin|end)\|([012])\n')
MAX_LINE = 96
MAX_MARKERS = 64
PRIVATE_TAIL = 65536


def emit(stage, edge, node=0):
    """No output unless invoked under the dedicated report wrapper."""
    if FD_ENV not in os.environ:
        return
    if (stage not in STAGES or edge not in ('begin', 'end') or type(node) is not int or
            node not in ((1, 2) if stage == 'scheduler_index' else (0,))):
        raise ValueError('invalid report progress marker')
    fd = int(os.environ[FD_ENV])
    row = f'{stage}|{edge}|{node}\n'.encode('ascii')
    if os.write(fd, row) != len(row):
        raise OSError('report progress write failed')


def run(command):
    started = time.monotonic_ns()
    def announce(stage, edge, node=0, status=None):
        elapsed = (time.monotonic_ns()-started)//1_000_000
        suffix = '' if status is None else f' status={status}'
        print(f'lifecycle_report stage={stage} edge={edge} node={node} elapsed_ms={elapsed}{suffix}', file=sys.stderr, flush=True)

    announce('process', 'begin')
    read_fd, write_fd = os.pipe()
    child = None
    status = 2
    try:
        with selectors.DefaultSelector() as ready:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(write_fd,),
                env=dict(os.environ, **{FD_ENV: str(write_fd)}))
            os.close(write_fd); write_fd = None
            ready.register(read_fd, selectors.EVENT_READ, 'progress')
            ready.register(child.stdout, selectors.EVENT_READ, 'stdout')
            ready.register(child.stderr, selectors.EVENT_READ, 'stderr')
            pending = bytearray()
            tails = {'stdout': bytearray(), 'stderr': bytearray()}
            markers = 0
            while ready.get_map():
                for key, _ in ready.select():
                    fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                    data = os.read(fd, 4096)
                    if not data:
                        ready.unregister(key.fileobj)
                        continue
                    if key.data != 'progress':
                        tail = tails[key.data]
                        tail.extend(data)
                        del tail[:-PRIVATE_TAIL]
                        continue
                    pending.extend(data)
                    while b'\n' in pending:
                        raw, _, rest = pending.partition(b'\n'); pending[:] = rest
                        match = LINE.fullmatch(raw+b'\n')
                        if match is None or len(raw) >= MAX_LINE or markers >= MAX_MARKERS:
                            raise ValueError('invalid progress channel')
                        stage, edge = (v.decode('ascii') for v in match.groups()[:2])
                        node = int(match.group(3))
                        if node not in ((1, 2) if stage == 'scheduler_index' else (0,)):
                            raise ValueError('invalid progress channel')
                        markers += 1
                        announce(stage, edge, node)
                    if len(pending) >= MAX_LINE:
                        raise ValueError('invalid progress channel')
            if pending:
                raise ValueError('incomplete progress channel')
            code = child.wait()
            status = code if code >= 0 else min(255, 128-code)
    except (OSError, ValueError, subprocess.SubprocessError):
        # Never include exception text, child output, argv, or native process identity.
        announce('wrapper_failure', 'end', status=2)
    finally:
        if child is not None:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            child.stdout.close(); child.stderr.close()
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    announce('process', 'end', status=status)
    return status


if __name__ == '__main__':
    # The workflow can invoke only its pinned reporter, never artifact-provided code.
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        status = run([sys.executable, str(Path(__file__).with_name('report.py')), *sys.argv[1:]])
    except (Exception, KeyboardInterrupt):
        print('lifecycle_report stage=wrapper_failure edge=end node=0 elapsed_ms=0 status=2', file=sys.stderr, flush=True)
        status = 2
    raise SystemExit(status)
