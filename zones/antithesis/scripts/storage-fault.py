#!/usr/bin/env python3
"""Opt-in Zone RPC storage supervisor; never install on voting nodes."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location('node_control', Path(__file__).with_name('node-control.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
RUN = Path('/run/zone-storage')
BACKING = Path('/data/durable')

class Supervisor(base.Supervisor):
    def __init__(self, argv):
        super().__init__(argv)
        self.datadir = Path(base.option(argv, '--datadir'))
        self.mount = RUN / 'fs'
        self.database = self.datadir / 'db/mdbx.dat'
        if (os.environ.get('TORN_WRITES') != '1'
                or os.environ.get('HOSTNAME') != 'zone-rpc'):
            raise ValueError('requires explicit TORN_WRITES=1 on zone-rpc only')
        if (not self.datadir.is_absolute() or self.datadir.resolve() != self.datadir
                or any(c.isspace() or c in ',"\\' for c in str(self.datadir))
                or any(a == b or a in b.parents or b in a.parents
                       for a, b in ((self.datadir, BACKING), (self.datadir, RUN)))):
            raise ValueError('trusted datadir must be absolute and separate from backing/control')
        self.daemon = None
        self.torn = False
        self.fatal = False
        self.log = RUN / 'lazyfs.log'
    def ctl(self, command, timeout=5):
        ident = uuid.uuid4().hex
        deadline = time.monotonic() + timeout
        reader = os.open(RUN / 'done.fifo', os.O_RDONLY | os.O_NONBLOCK)
        try:
            writer = os.open(RUN / 'faults.fifo', os.O_WRONLY | os.O_NONBLOCK)
            try:
                payload = f'bedrock {ident} {command}\n'.encode()
                if len(payload) > 4096 or os.write(writer, payload) != len(payload):
                    raise RuntimeError('short FIFO command')
            finally:
                os.close(writer)
            pending = b''
            while time.monotonic() < deadline:
                try:
                    pending += os.read(reader, 4096)
                except BlockingIOError:
                    pass
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    if line.startswith(ident.encode() + b' '):
                        reply = json.loads(line[len(ident) + 1:])
                        if reply.get('ok') is not True:
                            raise RuntimeError('LazyFS rejected command: ' + str(reply))
                        return reply
                if len(pending) > 65536:
                    raise RuntimeError('oversized FIFO reply')
                time.sleep(.02)
            raise RuntimeError('LazyFS FIFO acknowledgement timed out')
        finally:
            os.close(reader)
    def mounted(self, path=None):
        return any(line.split()[1] == str(self.mount if path is None else path)
                   for line in Path('/proc/self/mounts').read_text().splitlines())

    def checkpoint(self):
        subprocess.run(['sync', '-f', str(self.mount)], timeout=10, check=True)
        self.ctl('checkpoint', timeout=10)

    def mount_storage(self):
        if not os.access('/dev/fuse', os.R_OK | os.W_OK):
            raise RuntimeError('FUSE unavailable or permission denied')
        RUN.mkdir(parents=True, exist_ok=True)
        (BACKING / 'db').mkdir(parents=True, exist_ok=True)
        self.mount.mkdir(parents=True, exist_ok=True)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if (self.mounted() or self.mounted(self.database) or any(self.mount.iterdir())
                or self.database.is_symlink()
                or (self.database.exists() and self.database.stat().st_size != 0)):
            raise RuntimeError('refuse existing mount or populated MDBX target; seed /data/durable/db instead')
        # Keep version files, lock files, the checker and RocksDB on normal storage.
        # Only the MDBX data inode is redirected, without a symlink in the database path.
        (BACKING / 'db/mdbx.dat').touch(exist_ok=True)
        self.database.touch(exist_ok=True)
        for name in ('faults.fifo', 'done.fifo'):
            (RUN / name).unlink(missing_ok=True)
        config = RUN / 'lazyfs.toml'
        config.write_text(f'[faults]\nfifo_path="{RUN}/faults.fifo"\n'
            f'fifo_path_completed="{RUN}/done.fifo"\n[cache]\napply_eviction=false\n'
            '[cache.simple]\ncustom_size="128mb"\nblocks_per_page=1\n'
            '[filesystem]\nlog_all_operations=false\nlogfile=""\n')
        with self.log.open('ab', buffering=0) as output:
            self.daemon = subprocess.Popen(['/usr/local/bin/lazyfs', str(self.mount),
                '--config-path', str(config), '-o',
                f'allow_other,modules=subdir,subdir={BACKING},fsname=lazyfs', '-f', '-s'],
                stdout=output, stderr=output, start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.shutting_down or self.daemon.poll() is not None:
                raise RuntimeError('LazyFS exited or startup interrupted')
            if self.mounted() and (RUN / 'done.fifo').exists():
                try:
                    self.ctl('checkpoint')  # Cold recovery before node access.
                    subprocess.run(['mount', '--bind', str(self.mount / 'db/mdbx.dat'),
                                    str(self.database)], check=True, timeout=10)
                    return
                except OSError as exc:
                    if exc.errno not in (errno.ENOENT, errno.ENXIO):
                        raise
            time.sleep(.05)
        raise RuntimeError('LazyFS mount timeout')
    def start(self):
        if self.daemon is None:
            self.mount_storage()
        if not self.shutting_down:
            if self.daemon.poll() is not None or not self.mounted() or not self.mounted(self.database):
                raise RuntimeError('refuse node startup without live LazyFS')
            super().start()
    def alive(self):
        if self.fatal:
            raise RuntimeError('fatal storage failure; no automatic restart')
        super().alive()
        if self.daemon is None or self.daemon.poll() is not None:
            raise RuntimeError('LazyFS exited unexpectedly; no automatic restart')
    def signal(self, signum, frame):
        self.shutting_down = True  # Torn-write cleanup must kill, not gracefully flush, the node.
        if not self.torn:
            super().signal(signum, frame)
    def reap_holders(self):
        deadline = time.monotonic() + 10
        while True:
            children = []
            for entry in Path('/proc').iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    parent = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[1])
                    pid = int(entry.name)
                    if parent == os.getpid() and (self.daemon is None or pid != self.daemon.pid):
                        children.append(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if not children:
                return
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, os.WNOHANG)
                except ProcessLookupError:
                    pass
            if time.monotonic() >= deadline:
                raise RuntimeError('node descendants not reaped; refuse daemon cleanup')
            time.sleep(.02)
    def kill_node(self):
        for child in (self.offline, self.node):
            if child is not None:
                self.kill_group(child, signal.SIGKILL)
                child.wait(timeout=10)
        self.node = self.offline = None
        self.reap_holders()
    def close_storage(self, flush):
        self.reap_holders()  # No daemon cleanup while any node holder exists.
        if flush and self.daemon is not None and self.daemon.poll() is None:
            synced = subprocess.run(['sync', '-f', str(self.mount)], timeout=10, check=False)
            if self.daemon.poll() is None:
                self.ctl('checkpoint', timeout=10)  # FUSE syncfs alone misses userspace cache.
                if synced.returncode:
                    raise RuntimeError('sync -f failed while LazyFS remained alive')
        if self.mounted(self.database):
            subprocess.run(['umount', str(self.database)], check=True, timeout=10)
        if self.mounted():
            subprocess.run(['umount', str(self.mount)], check=True, timeout=10)
        if self.daemon is not None:
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.kill_group(self.daemon, signal.SIGTERM)
                self.daemon.wait(timeout=5)
            self.daemon = None
    def evidence(self, offset):
        with self.log.open('rb') as log:
            log.seek(offset)
            text = log.read().decode(errors='replace')
        marker = re.search(r'\[lazyfs\.faults\]: Write to path '
            + re.escape(str(BACKING / 'db/mdbx.dat'))
            + r': will persist ([1-9][0-9]*) bytes from offset ([0-9]+)(?=\r?\n|$)', text)
        return dict(persisted_bytes=int(marker[1]), offset=int(marker[2])) if (
            marker and 'Triggered fault condition (op=write,timing=after)' in text
            and self.daemon.poll() == -signal.SIGKILL) else None
    def maintenance(self, request):
        if self.torn:
            raise ValueError('storage operation already in progress')
        if request.get('operation') != 'torn-write':
            return super().maintenance(request)
        if set(request) != {'operation'}:
            raise ValueError('torn-op accepts no target or tuning parameters')
        self.alive()
        before = self.block('finalized')
        latest = self.block('latest')[0]
        offset = self.log.stat().st_size
        self.torn = True
        error = None
        fired = None
        try:
            self.checkpoint()  # Compensate syncfs before arming; flush live startup writes.
            self.armed = True  # A lost acknowledgement may still have armed the daemon.
            self.ctl(f'torn-op {BACKING}/db/mdbx.dat 2 1 1')
            armed = base.report(base.event('armed', 'torn-write', finalized=before[0], hash=before[1], log_offset=offset))
            if armed['state'] != 'armed':
                raise RuntimeError('could not report armed torn write')
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not self.shutting_down:
                fired = self.evidence(offset)
                if fired:
                    base.event('fired', 'torn-write', **fired)
                    break
                if self.daemon.poll() is not None:
                    raise base.Incomplete('LazyFS exited without exact actual-persist evidence')
                if self.node.poll() is not None:
                    raise base.Incomplete('node exited before observed tear')
                time.sleep(.05)
            if not fired:
                raise base.Incomplete('torn write not fired within bounded arm window')
        except Exception as exc:
            error = exc
            base.event('interrupted' if self.shutting_down else 'failed',
                       'torn-write', error=str(exc), fired=False)
        finally:
            try:
                self.kill_node()
                self.close_storage(flush=not bool(fired))
                # A flush may trigger an armed fault: preserve logs, but never upgrade failure.
                if not self.shutting_down:
                    self.start()
            except Exception:
                self.fatal = True  # Report a failed assertion before the next alive check exits.
                raise
            finally:
                self.torn = False
        if isinstance(error, base.SafetyFailure):
            raise error
        if self.shutting_down:
            return base.event('interrupted', 'torn-write', fired=bool(fired))
        try:
            self.recover(before)
            deadline = time.monotonic() + base.RECOVERY_TIMEOUT
            while time.monotonic() < deadline and not self.shutting_down:
                if (self.node is None or self.node.poll() is not None
                        or self.daemon is None or self.daemon.poll() is not None):
                    raise base.Incomplete('node or filesystem unavailable during recovery')
                try:
                    if self.block('latest')[0] > latest:
                        if self.block(hex(before[0])) != before:
                            raise base.SafetyFailure('pre-fault finalized hash changed')
                        if error:
                            raise error
                        return base.event('recovered', 'torn-write', finalized=before[0], hash=before[1], **fired)
                except (OSError, ValueError, KeyError, TypeError):
                    pass
                time.sleep(.25)
            raise base.Incomplete('recovery did not advance a block')
        except Exception as recovery_error:
            if error is not None and not isinstance(error, (base.Rejected, base.Incomplete)):
                raise error from recovery_error
            raise

    def cleanup(self):
        # Close every database holder before retiring the faulted filesystem.
        for child in (self.offline, self.node):
            try:
                self.stop(child)
            except (RuntimeError, TimeoutError):
                pass
        self.node = self.offline = None
        self.reap_holders()
        self.close_storage(flush=True)
        super().cleanup()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve', 'torn-op'))
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == 'serve':
        Supervisor(args.argv[1:] if args.argv[:1] == ['--'] else args.argv).serve(base.SOCKET)
        return 0
    if args.argv:
        parser.error('torn-op takes no arguments')
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(30 + 60 + 2 * base.RECOVERY_TIMEOUT)
        client.connect(base.SOCKET)
        client.sendall(b'{"operation":"torn-write"}\n')
        result = base.receive(client)
    print(json.dumps(result), flush=True)
    return 0 if result.get('state') == 'recovered' else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        base.event('failed', 'storage-supervisor', error=str(exc))
        sys.exit(1)
