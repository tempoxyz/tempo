"""Private, opt-in BPF supervisor for one benchmark validator process incarnation."""
import argparse
import base64
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import threading
import time

from diagnostic import ROOT, decode, preflight, verify_marker
from failures import failure_code, failure_summary
from binary_transport import HEADER, decode_binary
sys.path.insert(0, str(ROOT.parent))
from backpressure import first_boundary

MAX_BYTES = 256 * 1024 * 1024


def publish_capture(output, result):
    temporary = output.with_suffix('.partial')
    owned = False
    try:
        with temporary.open('x') as destination:
            owned = True
            json.dump(result, destination, separators=(',', ':'))
            destination.write('\n')
        temporary.replace(output)
    finally:
        if owned:
            temporary.unlink(missing_ok=True)


def capture(command, pass_fds=(), *, binary=False):
    """Drain both pipes without persisting tool output, with bounded retention."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(source, result, limit):
        while chunk := source.read(65536):
            if len(result) + len(chunk) <= limit:
                result.extend(chunk)
            else:
                overflow.set()
        source.close()

    readers = [threading.Thread(target=drain, args=(process.stdout, buffers[0], MAX_BYTES + (HEADER.size if binary else 0))),
               threading.Thread(target=drain, args=(process.stderr, buffers[1], 1024 * 1024))]
    for reader in readers:
        reader.start()
    status = process.wait()
    for reader in readers:
        reader.join()
    if overflow.is_set():
        raise ValueError("scheduler memory limit exceeded; diagnostic unavailable")
    try:
        return (buffers[0] if binary else buffers[0].decode()), buffers[1].decode(), status
    except UnicodeError:
        raise ValueError("unexpected private tool output") from None


def capture_finished(path):
    if not path.exists():
        return False
    with path.open('rb') as source:
        source.seek(max(0, path.stat().st_size - 2048))
        lines = source.read().splitlines()
    if not lines:
        return False
    try:
        footer = json.loads(lines[-1])
    except ValueError:
        return False
    if footer.get('type') != 'footer':
        return False
    if footer.get('dropped') or footer.get('io_error'):
        raise ValueError('lifecycle capture integrity failed')
    return True


def final_cutoff(directory, timeout=90):
    paths = [directory / 'a.jsonl', directory / 'b.jsonl']
    deadline = time.monotonic() + timeout
    while not all(capture_finished(path) for path in paths):
        if time.monotonic() > deadline:
            raise ValueError('lifecycle shutdown or footer incomplete')
        time.sleep(.1)
    window_path = directory / 'window.json'
    if not window_path.exists():
        raise ValueError('load window unavailable')
    window = json.loads(window_path.read_text())
    hit = first_boundary(paths)
    recorded = window.get('backpressure')
    if recorded and (hit is None or recorded['ts'] < hit['ts']):
        hit = recorded
    cutoff = hit['ts'] if hit else window['end_ns']
    if not isinstance(cutoff, int) or cutoff <= 0:
        raise ValueError('invalid scheduler cutoff')
    return cutoff, 'backpressure' if hit else 'load_finished'


def program_for(binary, epoch):
    template = (ROOT / 'scheduler.bt.in').read_text()
    template = template[:template.index('uprobe:__BINARY__:lifecycle_cutoff')] + 'END { print(@emitted); clear(@emitted); clear(@ordinal); clear(@alive); }\n'
    return (template.replace('__BINARY__', str(binary))
            .replace('lifecycle_thread_register', 'reth_lifecycle_thread_register')
            .replace('/pid == cpid && @alive[cpid]/', f'/pid == cpid && @alive[cpid] && arg1 == {epoch}/'))


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--failure-summary':
        print('\n'.join(failure_summary(Path(sys.argv[2]))))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--role', choices=('a', 'b'), required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--command-base64', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.directory / f'scheduler-{args.role}.json'
    failure = args.directory / f'scheduler-{args.role}.failed'
    stage = 'configuration'
    try:
        if os.geteuid() != 0:
            raise ValueError('scheduler supervisor requires the benchmark root scope')
        if output.exists() or failure.exists():
            raise ValueError('scheduler output already exists')
        if os.environ.get('TEMPO_LIFECYCLE_SCHEDULER') != 'registered_threads_v1':
            raise ValueError('scheduler registration was not enabled')
        epoch = int(os.environ['RETH_LIFECYCLE_EPOCH_NS'])
        if epoch <= 0 or epoch > time.monotonic_ns():
            raise ValueError('invalid phase epoch')
        command = base64.b64decode(args.command_base64, validate=True).decode()
        binary = args.binary.resolve(strict=True)
        if any(character in str(binary) for character in '\n:\" '):
            raise ValueError('unsupported binary path')
        stage = 'capability'
        preflight()
        _, diagnostics, status = capture([sys.executable, str(ROOT / 'binary_capture.py'), '--preflight'])
        if status or diagnostics.strip():
            raise ValueError('binary scheduler prerequisite unavailable')
        stage = 'marker'
        verify_marker(binary, 'reth_lifecycle_thread_register')
        stage = 'capture'
        stdout, stderr, status = capture([sys.executable, str(ROOT / 'binary_capture.py'),
            '--binary', str(binary), '--epoch', str(epoch), '--command-base64', args.command_base64], binary=True)
        if status:
            raise ValueError('scheduler capture tool exited unsuccessfully')
        if stderr.strip():
            raise ValueError('scheduler capture tool reported diagnostics')
        stage = 'cutoff'
        cutoff, reason = final_cutoff(args.directory)
        stage = 'decode'
        result = decode_binary(stdout, epoch, cutoff)
        result.update(scope='registered validator thread windows only', process=1 if args.role == 'a' else 2,
                      cutoff_reason=reason, registration='registered_threads_v1')
        stage = 'publish'
        publish_capture(output, result)
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        # Neither exception strings nor commands can escape: either can contain
        # a native identity, environment value, path, or child-process output.
        try:
            failure.write_text(failure_code(stage, error) + '\n')
        except OSError:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
