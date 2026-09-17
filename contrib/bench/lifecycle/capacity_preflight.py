"""Read-only topology plus tiny owned write probes; output contains no native paths/IDs."""
import json
import os
from pathlib import Path
import stat
import sys
import uuid

ROLES = ('root', 'workspace', 'runner_temp', 'optional_scratch')


def probe(role, path, filesystems):
    row = dict(role=role, exists=False, filesystem=None, total_bytes=None,
               free_bytes=None, read_only=None, writable=None, write_tested=False,
               status='unset')
    if path is None or path == '':
        return row
    directory = None
    try:
        path = Path(path)
        if not path.is_absolute():
            row['status'] = 'invalid_path'
            return row
        info = path.lstat()
        row['exists'] = True
        if path.resolve(strict=True) != path or stat.S_ISLNK(info.st_mode):
            row['status'] = 'redirected'
            return row
        if not stat.S_ISDIR(info.st_mode):
            row['status'] = 'not_directory'
            return row
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        actual = os.fstat(directory)
        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
            row['status'] = 'changed_directory'
            return row
        capacity = os.fstatvfs(directory)
        # Device identity is used only as an in-memory equality key, never output.
        row['filesystem'] = filesystems.setdefault(actual.st_dev, len(filesystems) + 1)
        row['total_bytes'] = capacity.f_blocks * capacity.f_frsize
        row['free_bytes'] = capacity.f_bavail * capacity.f_frsize
        row['read_only'] = bool(capacity.f_flag & os.ST_RDONLY)
        if row['read_only']:
            row.update(writable=False, status='read_only')
            return row
        if not os.access(path, os.W_OK | os.X_OK):
            row.update(writable=False, status='access_denied')
            return row
        # No directory creation, shared-file rewrite, traversal, or generic cleanup.
        # Open relative to the verified directory and unlink only our exclusive file.
        name = '.tempo-capacity-' + uuid.uuid4().hex
        owned = False
        file = None
        try:
            row['write_tested'] = True
            file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            owned = True
            if os.write(file, b'\0') != 1:
                raise OSError('short write')
            os.fsync(file)
            row.update(writable=True, status='writable')
        except OSError:
            row.update(writable=False, status='write_failed')
        finally:
            if file is not None:
                try:
                    os.close(file)
                except OSError:
                    row.update(writable=None, status='write_failed')
            if owned:
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    row.update(writable=None, status='cleanup_failed')
        return row
    except FileNotFoundError:
        row['status'] = 'missing'
        return row
    except OSError:
        row['status'] = 'unavailable'
        return row
    finally:
        if directory is not None:
            os.close(directory)


def collect():
    # Intentionally do not inspect data snapshots, virgin image paths, mount tables,
    # host identity, device names, caches, or arbitrary environment entries.
    paths = ('/', os.environ.get('GITHUB_WORKSPACE'), os.environ.get('RUNNER_TEMP'), '/schelk')
    filesystems = {}
    return dict(schema=1, locations=[probe(role, path, filesystems) for role, path in zip(ROLES, paths)])


def main():
    try:
        result = collect()
        print(json.dumps(result, separators=(',', ':')))
        if any(row['status'] == 'cleanup_failed' for row in result['locations']):
            return 1
        return 0
    except BaseException:
        # Never publish exception text: it can contain native paths or environment values.
        print('{"schema":1,"status":"probe_unavailable"}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
