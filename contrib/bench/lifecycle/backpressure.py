#!/usr/bin/env python3
"""Stop a benchmark process group at a source-timestamped backpressure boundary."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def boundary(line, node):
    if b'"backpressure_start"' not in line:
        return None
    event = json.loads(line)
    if event.get('type') == 'event' and event.get('fields', {}).get('stage') == 'backpressure_start':
        return {'ts': event['ts'], 'node': node}
    return None


class CaptureTail:
    def __init__(self, path, node):
        self.path, self.node = path, node
        self.offset, self.pending = 0, b''
        self.first = None

    def poll(self):
        if not self.path.exists():
            return self.first
        with self.path.open('rb') as capture:
            capture.seek(self.offset)
            while chunk := capture.read(1024 * 1024):
                self.offset += len(chunk)
                lines = (self.pending + chunk).split(b'\n')
                self.pending = lines.pop()
                for line in lines:
                    try:
                        hit = boundary(line, self.node)
                    except (ValueError, KeyError):
                        continue  # The report separately rejects malformed captures.
                    if hit and (self.first is None or hit['ts'] < self.first['ts']):
                        self.first = hit
        return self.first


def first_boundary(paths):
    hits = []
    for index, path in enumerate(paths):
        tail = CaptureTail(path, f'Validator {chr(65 + index)}')
        hit = tail.poll()
        # Also accept the final record without a newline in offline fixtures.
        if tail.pending:
            try:
                last = boundary(tail.pending, tail.node)
                if last and (hit is None or last['ts'] < hit['ts']):
                    hit = last
            except (ValueError, KeyError):
                pass
        if hit:
            hits.append(hit)
    return min(hits, key=lambda h: h['ts'], default=None)


def prepare_captures(paths, out, window=None):
    """Copy only pre-boundary records into the directory that may be uploaded.

    Originals and partial shutdown data live outside the artifact directory.
    Footer integrity flags are retained, but its written count describes the
    pruned stream. No post-boundary performance records survive this copy.
    """
    hit = first_boundary(paths)
    recorded = (window or {}).get('backpressure')
    if recorded and (hit is None or recorded['ts'] < hit['ts']):
        hit = recorded
    cutoff = hit['ts'] if hit else None
    clean_window = {key: value for key, value in (window or {}).items()
                    if key in ('start_ns', 'end_ns', 'stop_reason')}
    if hit:
        clean_window['backpressure'] = hit
        clean_window['end_ns'] = min(clean_window.get('end_ns', cutoff), cutoff)
        clean_window['stop_reason'] = 'backpressure'
    out.mkdir(parents=True, exist_ok=True)
    clean_paths, pruning = [], []
    for index, path in enumerate(paths):
        destination = out / path.name
        if path.resolve() == destination.resolve():
            raise ValueError('Raw captures must be outside the upload directory')
        temporary = destination.with_suffix('.tmp')
        written, invalid, excluded_aggregates, footer = 0, 0, 0, None
        try:
            with path.open() as source, temporary.open('w') as target:
                for line in source:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        invalid += 1
                        continue
                    kind = event.get('type')
                    if kind == 'footer':
                        footer = event
                        continue
                    if cutoff is not None and kind != 'header':
                        if event.get('ts', cutoff) >= cutoff:
                            continue
                        if kind == 'aggregate' and event['end'] >= cutoff:
                            excluded_aggregates += 1
                            continue
                    target.write(json.dumps(event, separators=(',', ':')) + '\n')
                    written += 1
                if footer is not None:
                    clean_footer = {'type': 'footer', 'written': written,
                                    'dropped': footer.get('dropped', 0),
                                    'io_error': footer.get('io_error', False),
                                    'invalid_lines': invalid + footer.get('invalid_lines', 0)}
                    target.write(json.dumps(clean_footer, separators=(',', ':')) + '\n')
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        clean_paths.append(destination)
        pruning.append({'node': f'Validator {chr(65 + index)}',
                        'crossing_aggregates_excluded': excluded_aggregates})
    clean_window['pruning'] = pruning
    (out / 'window.json').write_text(json.dumps(clean_window, indent=2) + '\n')
    return clean_paths, clean_window


def stop_group(process, grace=5):
    # Only our isolated load process group; validators are drained by the harness.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
    process.wait()


def run(command, paths, window_path, epoch, poll_interval=0.05):
    tails = [CaptureTail(path, f'Validator {chr(65 + i)}') for i, path in enumerate(paths)]
    start = time.monotonic_ns() - epoch
    process, hit, result = None, None, 1
    try:
        while True:
            hits = [h for tail in tails if (h := tail.poll()) is not None]
            hit = min(hits, key=lambda h: h['ts'], default=None)
            if hit:
                if process is not None:
                    stop_group(process)
                result = 0  # An intentional stop is not a failed benchmark.
                break
            if process is None:
                process = subprocess.Popen(command, start_new_session=True)
            if process.poll() is not None:
                result = process.returncode
                break
            time.sleep(poll_interval)
    finally:
        if process is not None and process.poll() is None:
            stop_group(process)
        finished = time.monotonic_ns() - epoch
        window = {'start_ns': start, 'end_ns': min(finished, hit['ts']) if hit else finished,
                  'stop_reason': 'backpressure' if hit else 'load_finished',
                  'load_stopped_ns': finished}
        if hit:
            window['backpressure'] = hit
        window_path.write_text(json.dumps(window, indent=2) + '\n')
    if hit:
        print(f"Stopped at first engine persistence backpressure on {hit['node']}; only pre-boundary data enters the report.", flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, action='append', required=True)
    parser.add_argument('--window', type=Path, required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command is required after --')
    raise SystemExit(run(command, args.capture, args.window, args.epoch))
