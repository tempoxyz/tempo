"""Bounded read-only snapshot metadata inventory; never read dataset contents."""
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

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


def inspect(roots=ROOTS):
    sides = []
    names = []
    for state_path, mount in roots:
        before, dm = state(state_path, mount)
        actual_before = mounted(mount)
        masks = path_masks(mount / DATASET)
        actual_after = mounted(mount)
        after, dm_after = state(state_path, mount)
        sides.append(dict(state=before, actual_mounted=actual_before,
                          state_observation_unchanged=(before == after and dm == dm_after),
                          mount_observation_unchanged=(actual_before == actual_after), required=masks))
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
