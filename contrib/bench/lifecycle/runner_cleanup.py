"""Final run-owned cleanup. Input is private; output is closed numeric counters."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time

STATE_ROOT = Path('/var/lib/schelk')
SNAPSHOT_ROOTS = tuple(map(Path, ('/reth-bench-a', '/reth-bench-b',
                                '/mnt/virgin', '/var/lib/schelk')))
SCHELK_SHA = 'fd7eae0849f8bcf07e8e3e0ca9d21d529529e40c674510c291fffd9a142bf751'
SCRIPTS = {'bench-e2e.nu', 'contrib/bench/lifecycle/backpressure.py',
           'contrib/bench/lifecycle/progress.py', 'contrib/bench/lifecycle/report.py',
           'contrib/bench/lifecycle/prewarm.py', 'contrib/bench/lifecycle/phase_archive.py',
           'contrib/bench/lifecycle/scheduler/runtime.py',
           'contrib/bench/lifecycle/scheduler/binary_capture.py'}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Rejected(ValueError):
    pass


def need(value):
    if not value:
        raise Rejected()


def integer(value):
    return type(value) is int and 0 <= value < 2**63


def identity(st):
    return st.st_dev, st.st_ino


def open_dir(path):
    """Reject symlinks in every ancestor, not just the final directory."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path != Path('/'))
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def contained_inode(path, workspace, root_fd, expected):
    """A proc path spelling is insufficient: compare the current owned inode."""
    try:
        relative = Path(path).relative_to(workspace)
        need('..' not in relative.parts)
        fd = os.dup(root_fd)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            actual = os.stat(relative.parts[-1], dir_fd=fd, follow_symlinks=False) if relative.parts else os.fstat(fd)
            return identity(actual) == identity(expected) and not stat.S_ISLNK(actual.st_mode)
        finally:
            os.close(fd)
    except (OSError, ValueError, IndexError):
        return False


def process_row(pid):
    base = Path('/proc') / str(pid)
    fields = (base / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'parent': int(fields[1]), 'start': int(fields[19]), 'state': fields[0]}


def owned_process(pid, workspace, root_fd):
    base = Path('/proc') / str(pid)
    try:
        executable = os.readlink(base / 'exe')
        if contained_inode(executable, workspace, root_fd, os.stat(base / 'exe')):
            return True
        interpreter = Path(executable).name
        if interpreter != 'nu' and re.fullmatch(r'python(?:3(?:\.\d+)?)?', interpreter) is None:
            return False
        if not contained_inode(os.readlink(base / 'cwd'), workspace, root_fd, os.stat(base / 'cwd')):
            return False
        with (base / 'cmdline').open('rb') as source:
            raw = source.read(65537)
        need(len(raw) <= 65536)
        args = [os.fsdecode(s) for s in raw.split(b'\0') if s]
        options = {'--no-config-file', '--no-history'} if interpreter == 'nu' else {'-I', '-u', '-B', '-E', '-s', '-S'}
        arguments = iter(args[1:])
        arg = next(arguments, '')
        while arg in options:
            arg = next(arguments, '')
        # A script-looking data argument to -c/-m is not a script invocation.
        if not arg or arg.startswith('-'):
            return False
        candidate = Path(arg)
        if candidate.is_absolute():
            try: arg = str(candidate.relative_to(workspace))
            except ValueError: return False
        return arg in SCRIPTS
    except (OSError, ValueError):
        return False


def stop_processes(workspace, root_fd):
    excluded = set()
    pid = os.getpid()
    while pid > 0 and pid not in excluded:
        excluded.add(pid)
        try: pid = process_row(pid)['parent']
        except OSError: break
    handles = {}
    try:
        # Re-scan after TERM to catch children born while shutdown began.
        for attempt in range(3):
            rows = {}
            for entry in Path('/proc').iterdir():
                if entry.name.isdecimal():
                    try: rows[int(entry.name)] = process_row(int(entry.name))
                    except (OSError, ValueError, IndexError): pass
            owned = {pid for pid in rows if pid not in excluded and owned_process(pid, workspace, root_fd)}
            parents = owned | {pid for pid, start in handles if pid in rows and rows[pid]['start'] == start}
            while True:
                children = {pid for pid, row in rows.items() if row['parent'] in parents and pid not in excluded}
                new = children - parents
                if not new: break
                parents |= new
            for pid in parents:
                row = rows.get(pid)
                if row is None or row['state'] == 'Z': continue
                key = pid, row['start']
                if key in handles: continue
                fd = None
                try:
                    fd = os.pidfd_open(pid, 0)
                    if process_row(pid)['start'] == row['start']:
                        handles[key] = fd
                        fd = None
                except (ProcessLookupError, FileNotFoundError): pass
                finally:
                    if fd is not None: os.close(fd)
            sig = signal.SIGTERM if attempt == 0 else signal.SIGKILL
            for fd in handles.values():
                try: signal.pidfd_send_signal(fd, sig)
                except ProcessLookupError: pass
            end = time.monotonic() + (3 if attempt == 0 else 2)
            while handles and time.monotonic() < end:
                if all(select.select([fd], [], [], 0)[0] for fd in handles.values()): break
                time.sleep(.025)
        need(all(select.select([fd], [], [], 0)[0] for fd in handles.values()))
        # Refuse deletion if any remaining process is demonstrably owned.
        for entry in Path('/proc').iterdir():
            if entry.name.isdecimal() and int(entry.name) not in excluded:
                need(not owned_process(int(entry.name), workspace, root_fd))
        return len(handles)
    finally:
        for fd in handles.values(): os.close(fd)


def no_mounts(workspace):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4])
        path = Path(mount)
        need(path != workspace and workspace not in path.parents)


def check_workspace(workspace):
    """Refuse snapshot roots, their ancestors/children, symlinks and mounts.

    Used before the startup reset as well as the final owned-file cleanup.
    Snapshot recovery is a separate operation; recursive deletion is never
    allowed to reach the snapshot storage or schelk state directory.
    """
    need(workspace.anchor == '/' and '..' not in workspace.parts)
    for protected in SNAPSHOT_ROOTS:
        need(workspace != protected and workspace not in protected.parents
             and protected not in workspace.parents)
    fd = open_dir(workspace)
    try:
        no_mounts(workspace)
    finally:
        os.close(fd)


def snapshot_cleanup(workspace, root_fd, uid, report):
    try: marker = os.stat('.bench-snapshot-dirty', dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError: return 0
    need(stat.S_ISREG(marker.st_mode) and marker.st_uid == uid and marker.st_size <= 4096)
    script = workspace / 'bench-schelk.nu'
    need(not script.is_symlink() and stat.S_ISREG(script.stat().st_mode))
    need(hashlib.sha256(script.read_bytes()).hexdigest() == SCHELK_SHA)
    state_fd = open_dir(STATE_ROOT)
    os.close(state_fd)
    states = []
    for role in ('a', 'b'):
        path = STATE_ROOT / (role + '.json')
        need(not path.is_symlink() and path.stat().st_size <= 65536)
        state = json.loads(path.read_bytes())
        need(state.get('mount_point') == '/reth-bench-' + role)
        need(type(state.get('dm_era_name')) is str and state['dm_era_name'])
        states.append((path, state))
    need(states[0][1]['dm_era_name'] != states[1][1]['dm_era_name'])
    account = pwd.getpwuid(uid)
    failed = False
    for path, _ in states:
        process = None
        try:
            process = subprocess.Popen(['sudo', '-n', '-u', '#' + str(uid), 'env',
                'HOME=' + account.pw_dir, 'USER=' + account.pw_name,
                'PATH=/usr/local/bin:/usr/bin:/bin', 'nu', str(script), 'cleanup', str(path)],
                cwd=workspace, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
            need(process.wait(timeout=90) == 0)
            report['snapshots_cleaned'] += 1
        except (OSError, ValueError, subprocess.SubprocessError):
            failed = True
        finally:
            if process is not None and process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
    need(not failed)


def clear_directory(fd, device, report, deadline, depth=0):
    need(depth <= 64 and time.monotonic() < deadline)
    for name in os.listdir(fd):
        need(time.monotonic() < deadline and report['removed_entries'] < 250000)
        value = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(value.st_dev == device)
        if stat.S_ISDIR(value.st_mode):
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                need(identity(os.fstat(child)) == identity(value))
                clear_directory(child, device, report, deadline, depth + 1)
            finally: os.close(child)
            need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(value))
            os.rmdir(name, dir_fd=fd)
        else:
            # Removing an owned symlink does not follow or alter its target.
            os.unlink(name, dir_fd=fd)
        report['removed_entries'] += 1


def cleanup(config, report):
    need(type(config) is dict and set(config) == {'workspace', 'owner', 'capacity_paths'})
    workspace = Path(config['workspace'])
    check_workspace(workspace)
    fd = open_dir(workspace)
    try:
        root = os.fstat(fd);owner = config['owner']
        paths = config['capacity_paths']
        need(type(paths) is list and len(paths) <= 2 and all(type(p) is str for p in paths))
        no_mounts(workspace)
        if owner is not None:
            need(type(owner) is dict and set(owner) == {'dev', 'ino', 'uid'})
            need(all(integer(v) for v in owner.values()))
            need((root.st_dev, root.st_ino, root.st_uid) == (owner['dev'], owner['ino'], owner['uid']))
            report['processes_stopped'] = stop_processes(workspace, fd)
            snapshot_failed = False
            try: snapshot_cleanup(workspace, fd, owner['uid'], report)
            except (OSError, ValueError, subprocess.SubprocessError): snapshot_failed = True
            no_mounts(workspace)
            need(identity(os.stat(workspace, follow_symlinks=False)) == identity(root))
            clear_directory(fd, root.st_dev, report, time.monotonic() + 90)
            need(not os.listdir(fd))
            need(not snapshot_failed)
        else:
            for relative in paths:
                parts = Path(relative).parts
                need(len(parts) == 2 and re.fullmatch(r'\.capacity-(reservation|admission)-[A-Za-z0-9_-]+', parts[0]))
                need(parts[1] == ('receipt.json' if parts[0].startswith('.capacity-reservation-') else 'admission.json'))
                try: child = os.open(parts[0], DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError: continue
                try:
                    directory = os.fstat(child);need(directory.st_uid == root.st_uid and directory.st_dev == root.st_dev)
                    need(set(os.listdir(child)) <= {parts[1]})
                    if parts[1] in os.listdir(child):
                        value = os.stat(parts[1], dir_fd=child, follow_symlinks=False)
                        need(stat.S_ISREG(value.st_mode) and value.st_uid == root.st_uid)
                        os.unlink(parts[1], dir_fd=child);report['removed_entries'] += 1
                finally: os.close(child)
                need(identity(os.stat(parts[0], dir_fd=fd, follow_symlinks=False)) == identity(directory))
                os.rmdir(parts[0], dir_fd=fd);report['removed_entries'] += 1
        need(identity(os.stat(workspace, follow_symlinks=False)) == identity(root))
    finally: os.close(fd)


def main():
    check_only = len(sys.argv) == 3 and sys.argv[1] == '--check-workspace'
    report = (dict(schema=1, status=1, workspace_checked=0) if check_only else
              dict(schema=1, status=1, processes_stopped=0, snapshots_cleaned=0, removed_entries=0))
    try:
        if check_only:
            check_workspace(Path(sys.argv[2]))
            report['workspace_checked'] = 1
        else:
            need(len(sys.argv) == 1)
            raw = sys.stdin.buffer.read(65537);need(len(raw) <= 65536)
            cleanup(json.loads(raw), report)
        report['status'] = 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    print(json.dumps(report, separators=(',', ':')), flush=True)
    return report['status']


if __name__ == '__main__':
    raise SystemExit(main())
