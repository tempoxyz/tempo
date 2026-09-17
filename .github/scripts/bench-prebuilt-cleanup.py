"""Identity-bound cleanup for exclusive portable producer directories.

Init output is private Actions state; cleanup output contains numeric counters only.
No cache, system toolchain, or benchmark snapshot path is accepted.
"""
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time

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


def clear_directory(fd, device, report, deadline, depth=0):
    need(depth <= 64 and time.monotonic() < deadline)
    for name in os.listdir(fd):
        need(time.monotonic() < deadline and report['removed_entries'] < 2000000)
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


def owned_process(pid, workspace, root_fd):
    # Both executable and cwd matches must name the current inode within a
    # freshly exclusive job root. Compiler processes often execute outside it.
    proc = Path('/proc') / str(pid)
    for name in ('exe', 'cwd'):
        try:
            if contained_inode(os.readlink(proc/name), workspace, root_fd, os.stat(proc/name)):
                return True
        except (OSError, ValueError):
            pass
    return False


def claim(st):
    return dict(dev=st.st_dev, ino=st.st_ino, uid=st.st_uid)


def same(st, value):
    need(type(value) is dict and set(value) == {'dev', 'ino', 'uid'})
    need(all(integer(v) for v in value.values()))
    need(claim(st) == value)


def initialize(workspace, temporary, run, attempt):
    need(re.fullmatch(r'[1-9][0-9]{0,19}', run) and re.fullmatch(r'[1-9][0-9]{0,5}', attempt))
    name = '.prebuilt-owned-' + run + '-' + attempt
    parents = [Path(workspace), Path(temporary)]
    need(all(p.is_absolute() for p in parents))
    need(parents[0] != parents[1])
    result = {'schema': 1, 'roots': []}
    opened = []
    try:
        for parent in parents:
            fd = open_dir(parent); opened.append(fd)
        for parent, fd in zip(parents, opened):
            os.mkdir(name, mode=0o700, dir_fd=fd)  # never adopt a prior directory
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                result['roots'].append(dict(parent=str(parent), name=name,
                    parent_owner=claim(os.fstat(fd)), owner=claim(os.fstat(child))))
            finally: os.close(child)
        return result
    except BaseException:
        for row, fd in zip(result['roots'], opened):
            # Initialization has created only empty exclusive directories.
            try:
                same(os.stat(row['name'], dir_fd=fd, follow_symlinks=False), row['owner'])
                os.rmdir(row['name'], dir_fd=fd)
            except OSError: pass
        raise
    finally:
        for fd in opened: os.close(fd)


def cleanup(config, report):
    need(type(config) is dict and set(config) == {'schema', 'roots'})
    need(type(config['schema']) is int and config['schema'] == 1)
    need(type(config['roots']) is list and len(config['roots']) == 2)
    opened = []
    try:
        for row in config['roots']:
            need(type(row) is dict and set(row) == {'parent', 'name', 'parent_owner', 'owner'})
            need(type(row['name']) is str and re.fullmatch(r'\.prebuilt-owned-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}', row['name']))
            parent = Path(row['parent']); fd = open_dir(parent)
            opened.append([fd, None, row, parent / row['name']])
            same(os.fstat(fd), row['parent_owner'])
            child = os.open(row['name'], DIR_FLAGS, dir_fd=fd); opened[-1][1] = child
            same(os.fstat(child), row['owner'])
            need(row['owner']['uid'] == os.getuid())
            need(row['owner']['dev'] == row['parent_owner']['dev'])
            no_mounts(parent / row['name'])
        paths = [item[3] for item in opened]
        need(paths[0] != paths[1] and paths[0] not in paths[1].parents and paths[1] not in paths[0].parents)
        # Validate every root before signaling or deleting anything.
        for _, child, _, path in opened:
            report['processes_stopped'] += stop_processes(path, child)
        deadline = time.monotonic() + 300
        for fd, child, row, path in opened:
            no_mounts(path)
            same(os.stat(row['name'], dir_fd=fd, follow_symlinks=False), row['owner'])
            clear_directory(child, row['owner']['dev'], report, deadline)
            same(os.stat(row['name'], dir_fd=fd, follow_symlinks=False), row['owner'])
            need(not os.listdir(child))
            os.rmdir(row['name'], dir_fd=fd)
            report['roots_removed'] += 1
    finally:
        for fd, child, _, _ in opened:
            if child is not None: os.close(child)
            os.close(fd)


def main():
    if sys.argv[1:] == ['init']:
        result = initialize(os.environ['GITHUB_WORKSPACE'], os.environ['RUNNER_TEMP'],
                            os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'])
        print(json.dumps(result, separators=(',', ':')))
        return 0
    report = dict(schema=1, status=1, processes_stopped=0, removed_entries=0, roots_removed=0)
    try:
        need(sys.argv[1:] == ['clean'])
        raw = sys.stdin.buffer.read(65537); need(len(raw) <= 65536)
        cleanup(json.loads(raw), report)
        report['status'] = 0
    except (OSError, ValueError, TypeError, KeyError):
        pass
    print(json.dumps(report, separators=(',', ':')), flush=True)
    return report['status']


if __name__ == '__main__':
    raise SystemExit(main())
