#!/usr/bin/env python3
"""Node-local, fixed-operation maintenance for the nonvoting Zone RPC follower."""
import argparse
import ctypes
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

SOCKET = '/run/zone-node-control.sock'
STOP_TIMEOUT = 30
OFFLINE_TIMEOUT = 120
RECOVERY_TIMEOUT = 120


def event(state, operation, **fields):
    record = dict(state=state, operation=operation, **fields)
    print(json.dumps(record), flush=True)
    return record


def report(result):
    if result['operation'] not in ('repair-trie', 'unwind') or result['state'] == 'interrupted':
        return result
    try:
        subprocess.run(['/usr/local/bin/tempo-zone-xtask', 'antithesis',
            'report-maintenance', '--operation', result['operation'],
            '--outcome', result['state'], '--details', json.dumps(result)],
            check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return event('failed', result['operation'], error='SDK report failed: ' + str(exc), details=result)
    return result


def option(argv, name, default=None):
    for i, arg in enumerate(argv):
        if arg == name:
            return argv[i + 1]
        if arg.startswith(name + '='):
            return arg.split('=', 1)[1]
    if default is None:
        raise ValueError('missing trusted node option ' + name)
    return default


def receive(conn):
    data = bytearray()
    while b'\n' not in data:
        part = conn.recv(4096)
        if not part:
            raise ValueError('incomplete request')
        data.extend(part)
        if len(data) > 4096:
            raise ValueError('request too large')
    return json.loads(data.split(b'\n', 1)[0])


class Supervisor:
    def __init__(self, argv):
        if len(argv) < 2 or argv[1] != 'node':
            raise ValueError('serve requires the original node argv')
        self.argv = argv
        self.base = ['--chain', option(argv, '--chain'),
                     '--datadir', option(argv, '--datadir')]
        addr = option(argv, '--http.addr', '127.0.0.1')
        if addr == '0.0.0.0':
            addr = '127.0.0.1'
        self.url = 'http://' + addr + ':' + option(argv, '--http.port', '8545')
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.node = self.offline = None
        self.shutting_down = False

    def signal(self, signum, frame):
        self.shutting_down = True
        for child in (self.node, self.offline):
            if child is not None:
                self.kill_group(child, signal.SIGTERM)

    @staticmethod
    def kill_group(child, sig):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass

    def stop(self, child):
        if child is None:
            return
        self.kill_group(child, signal.SIGTERM)
        try:
            child.wait(timeout=STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.kill_group(child, signal.SIGKILL)
            child.wait()
            raise RuntimeError('graceful stop timed out; killed, maintenance rejected')
        finally:
            # A node must not leave its own subprocesses behind, even after exiting.
            self.kill_group(child, signal.SIGKILL)

    def start(self):
        if not self.shutting_down:
            self.node = subprocess.Popen(self.argv, start_new_session=True)

    def alive(self):
        if self.shutting_down:
            raise RuntimeError('supervisor shutting down')
        if self.node is None or self.node.poll() is not None:
            raise RuntimeError('node exited unexpectedly')

    def block(self, tag):
        request = urllib.request.Request(self.url, headers={'Content-Type': 'application/json'},
            data=json.dumps(dict(jsonrpc='2.0', id=1, method='eth_getBlockByNumber',
                                 params=[tag, False])).encode())
        with self.http.open(request, timeout=3) as response:
            block = json.loads(response.read(1024 * 1024))['result']
        number, block_hash = int(block['number'], 16), block['hash']
        if number < 0 or not re.fullmatch(r'0x[0-9a-fA-F]{64}', block_hash):
            raise ValueError('invalid local block')
        return number, block_hash.lower()

    def run_offline(self, command):
        with tempfile.TemporaryFile() as output:
            self.offline = subprocess.Popen([self.argv[0], '--color', 'never', *command],
                env=dict(os.environ, L1_OFFLINE='true'), stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + OFFLINE_TIMEOUT
                while self.offline.poll() is None:
                    if self.shutting_down or time.monotonic() >= deadline:
                        raise RuntimeError('offline operation interrupted or timed out')
                    time.sleep(0.1)
                if self.offline.returncode:
                    output.seek(0)
                    raise RuntimeError('offline CLI exited ' + str(self.offline.returncode) + ': ' + output.read().decode(errors='replace')[-4096:])
                output.seek(0)
                return output.read().decode(errors='replace')
            finally:
                self.stop(self.offline)
                self.offline = None

    def recover(self, before):
        deadline = time.monotonic() + RECOVERY_TIMEOUT
        while time.monotonic() < deadline:
            self.alive()
            try:
                finalized = self.block('finalized')
                if finalized[0] >= before[0] and self.block(hex(before[0])) == before:
                    return
            except (OSError, ValueError, KeyError, TypeError):
                pass
            time.sleep(0.25)
        raise RuntimeError('pre-maintenance finalized height/hash not restored within 120s')

    def maintenance(self, request):
        operation = request.get('operation')
        if operation == 'repair-trie' and set(request) == {'operation'}:
            blocks = None
        elif (operation == 'unwind' and set(request) == {'operation', 'blocks'}
              and type(request['blocks']) is int and 1 <= request['blocks'] <= 32):
            blocks = request['blocks']
        else:
            raise ValueError('only repair-trie dry-run or unwind blocks 1..32 permitted')
        self.alive()
        before = self.block('finalized')
        latest = self.block('latest')[0]
        if blocks and blocks >= latest:
            raise ValueError('unwind must retain block 1')
        target = latest - blocks if blocks else None
        event('armed', operation, finalized=before[0], latest=latest, target=target)
        # Never enter offline mode unless this exact child stopped gracefully.
        self.alive()
        self.stop(self.node)
        self.node = None
        error = None
        try:
            if self.shutting_down:
                raise RuntimeError('supervisor shutting down')
            if blocks is None:
                output = self.run_offline(['db', *self.base, 'repair-trie', '--dry-run'])
                if ('Found 0 inconsistencies (dry run - no changes made)' not in output
                        or 'Inconsistency found:' in output):
                    raise RuntimeError('trie dry-run did not attest zero inconsistencies')
                evidence = dict(dry_run=True, inconsistencies=0)
            else:
                output = self.run_offline(['stage', 'unwind', *self.base, 'num-blocks', str(blocks)])
                opened = re.search(r'Executing a pipeline unwind\.[^\n]*', output)
                closed = re.search(r'Unwound blocks[^\n]*', output)
                start = re.search(r'highest_static_file_block=(\d+)', opened[0]) if opened else None
                end = re.search(r'target=(\d+)', closed[0]) if closed else None
                requested = re.search(r'target=(\d+)', opened[0]) if opened else None
                if not (start and end and requested and int(end[1]) == int(requested[1])
                        and int(start[1]) - int(end[1]) == blocks):
                    raise RuntimeError('unwind output did not attest an effective bounded unwind')
                evidence = dict(from_block=int(start[1]), to_block=int(end[1]))
            event('fired', operation, **evidence)
        except Exception as exc:
            error = exc
        finally:
            self.start()  # Explicit maintenance is the only restart path.
        if not self.shutting_down:
            self.recover(before)
        if error:
            raise error
        if self.shutting_down:
            raise RuntimeError('supervisor shutting down')
        return event('recovered', operation, finalized=before[0], hash=before[1])

    def serve(self, path):
        # Adopt and reap descendants if a node exits before its subprocesses.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise RuntimeError('cannot enable child subreaper')
        signal.signal(signal.SIGTERM, self.signal)
        signal.signal(signal.SIGINT, self.signal)
        with socket.socket(socket.AF_UNIX) as server:
            old_umask = os.umask(0o177)
            try:
                server.bind(path)  # Refuse an existing socket rather than stealing it.
            finally:
                os.umask(old_umask)
            server.listen(1)
            server.settimeout(0.25)
            try:
                self.start()
                while not self.shutting_down:
                    self.alive()
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(2)
                        request = {}
                        try:
                            request = receive(conn)
                            if not isinstance(request, dict):
                                raise ValueError('request must be an object')
                            result = self.maintenance(request)
                        except Exception as exc:
                            op = request.get('operation', 'invalid') if isinstance(request, dict) else 'invalid'
                            result = event('interrupted' if self.shutting_down else 'failed', op, error=str(exc))
                        result = report(result)
                        try:
                            conn.sendall(json.dumps(result).encode() + b'\n')
                        except OSError:
                            pass
            finally:
                self.shutting_down = True
                for child in (self.offline, self.node):
                    try:
                        self.stop(child)
                    except RuntimeError:
                        pass
                while True:
                    try:
                        os.waitpid(-1, 0)
                    except ChildProcessError:
                        break
                os.unlink(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default=SOCKET)
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--socket', default=argparse.SUPPRESS)
    serve.add_argument('argv', nargs=argparse.REMAINDER)
    repair = commands.add_parser('repair-trie')
    repair.add_argument('--dry-run', action='store_true', help='always enforced')
    unwind = commands.add_parser('unwind')
    unwind.add_argument('--blocks', type=int, choices=range(1, 33), required=True)
    args = parser.parse_args()
    if args.command == 'serve':
        Supervisor(args.argv[1:] if args.argv[:1] == ['--'] else args.argv).serve(args.socket)
        return 0
    request = dict(operation=args.command)
    if args.command == 'unwind':
        request['blocks'] = args.blocks
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(STOP_TIMEOUT + OFFLINE_TIMEOUT + RECOVERY_TIMEOUT + 15)
        client.connect(args.socket)
        client.sendall(json.dumps(request).encode() + b'\n')
        result = receive(client)
    print(json.dumps(result), flush=True)
    return 0 if result.get('state') == 'recovered' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        event('failed', 'control', error=str(exc))
        sys.exit(1)
