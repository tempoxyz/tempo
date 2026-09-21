"""Bounded read-only snapshot metadata inventory; never read dataset contents."""
import errno
import fcntl
import json
import os
import re
import selectors
import signal
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

# Match immutable bench-e2e.nu and tempo.nu; ordering defines the public bitmask.
REQUIRED = ('.bench-meta/genesis.json', '.bench-meta/trusted-peers.txt',
            '.bench-meta/marker.json', 'signing.key', 'signing.share',
            'enode.key', 'enode.identity', 'db', 'static_files')
ROOTS = ((Path('/var/lib/schelk/a.json'), Path('/reth-bench-a')),
         (Path('/var/lib/schelk/b.json'), Path('/reth-bench-b')))
DATASET = 'tempo_e2e_100000mb'
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError()
        value[key] = item
    return value


def parent_fd(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError()
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def state(path, expected_mount):
    # status: 0 valid, 1 missing, 2 denied, 3 malformed/unsafe, 4 other IO.
    result = dict(status=3, mounted=2, mount_matches=False, dm_name_valid=False)
    try:
        fd = parent_fd(path)
        try:
            child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        finally:
            os.close(fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
                return result, None
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
        if len(raw) > 65536 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return result, None
        value = json.loads(raw, object_pairs_hook=no_duplicates)
        if type(value) is not dict:
            return result, None
        mounted = value.get('is_mounted')
        result['mounted'] = int(mounted) if type(mounted) is bool else 2
        result['mount_matches'] = value.get('mount_point') == str(expected_mount)
        dm = value.get('dm_era_name')
        result['dm_name_valid'] = type(dm) is str and 0 < len(dm) <= 256
        if result['mounted'] != 2 and result['mount_matches'] and result['dm_name_valid']:
            result['status'] = 0
        return result, dm if result['dm_name_valid'] else None
    except FileNotFoundError:
        result['status'] = 1
    except PermissionError:
        result['status'] = 2
    except (ValueError, UnicodeError):
        pass
    except OSError as error:
        result['status'] = 3 if error.errno in (errno.ELOOP, errno.ENOTDIR) else 4
    return result, None


def path_masks(root):
    out = dict(present=0, readable=0, missing=0, denied=0, unsafe=0, other_error=0)
    for bit, relative in enumerate(REQUIRED):
        path = root / relative
        try:
            fd = parent_fd(path)
            try:
                value = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(value.st_mode) or not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)):
                    out['unsafe'] |= 1 << bit
                    continue
                out['present'] |= 1 << bit
                required = os.R_OK | (os.X_OK if stat.S_ISDIR(value.st_mode) else 0)
                if os.access(path.name, required, dir_fd=fd, follow_symlinks=False, effective_ids=True):
                    out['readable'] |= 1 << bit
                else:
                    out['denied'] |= 1 << bit
            finally:
                os.close(fd)
        except FileNotFoundError:
            out['missing'] |= 1 << bit
        except PermissionError:
            out['denied'] |= 1 << bit
        except OSError as error:
            out['unsafe' if error.errno in (errno.ELOOP, errno.ENOTDIR) else 'other_error'] |= 1 << bit
    return out


def mounted(path):
    try:
        result = subprocess.run(['/usr/bin/mountpoint', '-q', str(path)], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5, check=False)
        return {0: 1, 32: 0}.get(result.returncode, 2)
    except (OSError, subprocess.SubprocessError):
        return 2


def bounded_debugfs(tool, device_fd, request, deadline):
    """Drain metadata privately with fixed limits; never enable write/checksum bypass."""
    remaining = min(2.0, deadline - time.monotonic())
    if remaining <= 0:
        return None
    process = subprocess.Popen([tool, '-R', request, f'/proc/self/fd/{device_fd}'],
        pass_fds=(device_fd,), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    end = time.monotonic() + remaining
    completed = False
    try:
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            wait = end - time.monotonic()
            if wait <= 0:
                return None
            for key, _ in selector.select(wait):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                if len(buffers[key.data]) > 65536:
                    return None
        remaining = end - time.monotonic()
        if remaining <= 0:
            return None
        status = process.wait(timeout=remaining)
        completed = True
        if status != 0:
            return None
        return bytes(buffers['stdout']), bytes(buffers['stderr'])
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        selector.close()
        if not completed:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        process.stdout.close(); process.stderr.close()
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired: pass


def inode_status(output, path, expected):
    # debugfs can return exit 0 for missing files AND unusable filesystems.
    if output is None:
        return 'unavailable'
    stdout, stderr = output
    lines = stderr.splitlines()
    if not lines or re.fullmatch(rb'debugfs [0-9]+\.[0-9]+(?:\.[0-9]+)? \([^\r\n]*\)', lines[0]) is None:
        return 'unavailable'
    if not stdout and len(lines) == 2 and lines[1].strip() == (path + ': File not found by ext2_lookup').encode():
        return 'missing'
    if len(lines) != 1:
        return 'unavailable'
    first = stdout.splitlines()[0] if stdout else b''
    match = re.fullmatch(rb'Inode: [1-9][0-9]* +Type: ([a-z]+) +Mode: +[0-7]+ +Flags: 0x[0-9a-fA-F]+', first)
    if match is None:
        return 'unavailable'
    return 'present' if match[1].decode() == expected else 'unsafe'


def virgin_masks(tool, device_fd, deadline):
    """Only fixed stat requests; inspect parent types before traversing children."""
    result = dict(present=0, missing=0, unsafe=0, unavailable=0)
    root = '/' + DATASET
    dataset = inode_status(bounded_debugfs(tool, device_fd, 'stat ' + root, deadline), root, 'directory')
    meta = None
    for bit, relative in enumerate(REQUIRED):
        kind = dataset
        if kind == 'present' and relative.startswith('.bench-meta/'):
            if meta is None:
                parent = root + '/.bench-meta'
                meta = inode_status(bounded_debugfs(tool, device_fd, 'stat ' + parent, deadline), parent, 'directory')
            kind = meta
        if kind == 'present':
            path = root + '/' + relative
            expected = 'directory' if relative in ('db', 'static_files') else 'regular'
            kind = inode_status(bounded_debugfs(tool, device_fd, 'stat ' + path, deadline), path, expected)
        result[kind] |= 1 << bit
    return result


def trusted_fd(path, flags, block=False):
    # Every resolved ancestor must be root-owned and not group/world-writable.
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError()
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd);os.close(fd);fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError()
        child = os.open(path.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        info = os.fstat(child)
        if info.st_uid != 0 or info.st_mode & (0o002 if block else 0o022) or (block and not stat.S_ISBLK(info.st_mode)):
            os.close(child);raise ValueError()
        return child
    finally:
        os.close(fd)


def virgin_inventory(state_path, expected_mount, deadline):
    # status: 0 observed, 1 unprivileged, 2 state/lock unavailable, 3 non-ext4,
    # 4 unsafe devices, 5 tool unavailable, 6 incomplete metadata, 7 mounted virgin.
    result = dict(status=1, ext4=False, devices_distinct=False, lock_acquired=False,
                  state_unchanged=False, required=dict(present=0, missing=0, unsafe=0, unavailable=511))
    if os.geteuid() != 0:
        return result
    fds = []
    try:
        result['status'] = 2
        lock = trusted_fd(state_path.parent / 'schelk.lock', os.O_RDONLY);fds.append(lock)
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            return result
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB);result['lock_acquired'] = True
        state_fd = trusted_fd(state_path, os.O_RDONLY);fds.append(state_fd)
        before = os.fstat(state_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
            return result
        raw = os.read(state_fd, 65537)
        value = json.loads(raw, object_pairs_hook=no_duplicates)
        if type(value) is not dict or type(value.get('is_mounted')) is not bool or value.get('mount_point') != str(expected_mount):
            return result
        result['ext4'] = value.get('fstype') == 'ext4'
        if not result['ext4']:
            result['status'] = 3;return result
        result['status'] = 4
        devices = []
        for name in ('virgin', 'scratch'):
            text = value.get(name)
            if type(text) is not str or not text.startswith('/dev/') or '..' in Path(text).parts:
                return result
            path = Path(text).resolve(strict=True)
            if not path.is_relative_to('/dev'):
                return result
            fd = trusted_fd(path, os.O_RDONLY, block=True);fds.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISBLK(info.st_mode):
                return result
            devices.append((fd, info.st_rdev))
        if devices[0][1] == devices[1][1]:
            return result
        result['devices_distinct'] = True
        # Do not inspect a mounted virgin filesystem, even read-only; state may be stale.
        device_id = f'{os.major(devices[0][1])}:{os.minor(devices[0][1])}'
        if any(line.split()[2] == device_id for line in Path('/proc/self/mountinfo').read_text().splitlines()):
            result['status'] = 7;return result
        result['status'] = 5
        tool = Path('/usr/sbin/debugfs').resolve(strict=True)
        tool_fd = trusted_fd(tool, os.O_RDONLY);fds.append(tool_fd)
        if not stat.S_ISREG(os.fstat(tool_fd).st_mode) or not os.access(tool, os.X_OK):
            return result
        result['required'] = virgin_masks(str(tool), devices[0][0], deadline)
        after = os.stat(state_path, follow_symlinks=False)
        os.lseek(state_fd, 0, os.SEEK_SET)
        result['state_unchanged'] = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and raw == os.read(state_fd, 65537)
        if not result['state_unchanged']:
            result['required'] = dict(present=0, missing=0, unsafe=0, unavailable=511)
            result['status'] = 2
        else:
            result['status'] = 6 if result['required']['unavailable'] else 0
    except (OSError, ValueError, UnicodeError, TypeError, subprocess.SubprocessError):
        pass
    finally:
        for fd in reversed(fds):os.close(fd)
    return result


def inspect(roots=ROOTS):
    sides = []
    names = []
    deadline = time.monotonic() + 25
    for state_path, mount in roots:
        before, dm = state(state_path, mount)
        actual_before = mounted(mount)
        masks = path_masks(mount / DATASET)
        virgin = virgin_inventory(state_path, mount, deadline)
        actual_after = mounted(mount)
        after, dm_after = state(state_path, mount)
        sides.append(dict(state=before, actual_mounted=actual_before,
                          state_observation_unchanged=(before == after and dm == dm_after),
                          mount_observation_unchanged=(actual_before == actual_after), required=masks, virgin=virgin))
        names.append(dm)
    home = Path.home()
    candidates = {'cargo_home': Path(os.environ.get('CARGO_HOME', str(home / '.cargo'))) / 'bin/schelk',
                  'home_cargo': home / '.cargo/bin/schelk',
                  'usr_local': Path('/usr/local/bin/schelk'), 'usr_bin': Path('/usr/bin/schelk')}
    available = {key: (path.is_file() and os.access(path, os.X_OK)) for key, path in candidates.items()}
    return dict(schema=1, privileged=(os.geteuid() == 0), schelk_on_path=(shutil.which('schelk') is not None),
                executable_candidates=available,
                snapshot_atomic=False, required_mask=511, dm_names_distinct=(all(n is not None for n in names) and len(set(names)) == 2),
                sides=sides)


def main():
    try:
        print(json.dumps(inspect(), separators=(',', ':')))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # Never emit exception details, contents, native identifiers, or paths.
        print('{"schema":1,"unavailable":true}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
