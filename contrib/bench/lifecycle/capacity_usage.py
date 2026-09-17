"""Bounded read-only allocated-byte metadata; never publish native paths or errors.

Schema1 capacity is preserved separately. Usage totals overlap and exclude protected
state directories and nested filesystems; they are not an additive disk inventory.
"""
import fnmatch
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

import capacity_preflight

ROLES = ('runner_work', 'runner_temp', 'workspace', 'cargo_registry', 'cargo_git',
         'sccache_default', 'sccache_env', 'home', 'var', 'tmp', 'opt', 'usr')
SCRATCH_ROLES = ('bench_scratch_a', 'bench_scratch_b')
STATUSES = ('ok', 'unset', 'invalid_path', 'protected', 'missing', 'redirected',
            'not_directory', 'unavailable', 'timeout', 'budget_exhausted')
EXCLUDES = ('*virgin*', '*snapshot*', 'reth-data', 'schelk', 'mnt', 'media',
            'db', '*-db', 'static_files', 'static-files', 'chaindata', 'datadir')
PER_CATEGORY_SECONDS = 15
TOTAL_SECONDS = 150
MAX_UINT = 2**53-1


def paths(env):
    # Only these documented cache/runtime variables are consulted. Their values
    # never enter output. Unexpected runner layout leaves runner_work unavailable.
    temp = env.get('RUNNER_TEMP')
    work = str(Path(temp).parent) if temp and Path(temp).name == '_temp' else None
    home = env.get('HOME')
    cargo = env.get('CARGO_HOME') or (str(Path(home)/'.cargo') if home else None)
    cache = env.get('XDG_CACHE_HOME') or (str(Path(home)/'.cache') if home else None)
    return (work, temp, env.get('GITHUB_WORKSPACE'),
            str(Path(cargo)/'registry') if cargo else None,
            str(Path(cargo)/'git') if cargo else None,
            str(Path(cache)/'sccache') if cache else None,
            env.get('SCCACHE_DIR'), '/home', '/var', '/tmp', '/opt', '/usr')


def run_du(path, timeout):
    command = ['/usr/bin/du', '--summarize', '--one-file-system', '--block-size=1',
               '--null', '--no-dereference', *['--exclude='+x for x in EXCLUDES], '--', str(path)]
    # The deadline owner shares du's privilege, so a non-root caller need not
    # signal an elevated scanner. The fixed wrapper permits only this du command.
    command = ['/usr/bin/timeout', '--signal=KILL', format(timeout, '.6f')+'s', *command]
    # Only fixed du metadata operations may be elevated. No shell, directory
    # listings, contents, cleanup, service changes, or command supplied by env.
    if os.geteuid() != 0 and Path('/usr/bin/sudo').is_file():
        command = ['/usr/bin/sudo', '-n', '--', *command]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout+2)
    except subprocess.TimeoutExpired:
        # The noninteractive pipeline has no shell or detached child. Kill its
        # owned process group, never another job, then reap before returning.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        process.communicate(timeout=2)
        return 'timeout', None
    if process.returncode in (124, 137, -signal.SIGKILL):
        return 'timeout', None
    if process.returncode != 0:
        return 'unavailable', None
    # GNU du emits one NUL-terminated summary. Discard its private path entirely.
    if len(output) > 16384 or not output.endswith(b'\0') or output.count(b'\0') != 1:
        return 'unavailable', None
    number, separator, _ = output[:-1].partition(b'\t')
    if not separator or not number.isdigit() or len(number) > 16:
        return 'unavailable', None
    size = int(number)
    return ('ok', size) if size <= MAX_UINT else ('unavailable', None)


def usage(role, path, deadline, filesystems):
    row = dict(role=role, status='unset', allocated_bytes=None, filesystem=None,
               elapsed_ms=0, exclusions_applied=True)
    started = time.monotonic()
    try:
        if started >= deadline:
            row['status'] = 'budget_exhausted'
            return row
        if not path:
            return row
        path = Path(path)
        if not path.is_absolute() or len(str(path)) > 4096 or path == Path('/'):
            row['status'] = 'invalid_path'
            return row
        if any(fnmatch.fnmatch(part.lower(), pattern) for part in path.parts for pattern in EXCLUDES):
            row['status'] = 'protected'
            return row
        info = path.lstat()
        if path.resolve(strict=True) != path or stat.S_ISLNK(info.st_mode):
            row['status'] = 'redirected'
            return row
        if not stat.S_ISDIR(info.st_mode):
            row['status'] = 'not_directory'
            return row
        row['filesystem'] = filesystems.setdefault(info.st_dev, len(filesystems)+1)
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            row['status'] = 'budget_exhausted'
            return row
        row['status'], row['allocated_bytes'] = run_du(path, min(PER_CATEGORY_SECONDS, remaining))
        return row
    except FileNotFoundError:
        row['status'] = 'missing'
        return row
    except (OSError, ValueError, subprocess.SubprocessError):
        row['status'] = 'unavailable'
        return row
    finally:
        row['elapsed_ms'] = min(MAX_UINT, max(0, int((time.monotonic()-started)*1000)))



def scratch_capacity(role, path, filesystems):
    """Fixed benchmark mount metadata only: no tiny write probe or traversal."""
    row = dict(role=role, status='unavailable', exists=False, filesystem=None,
               total_bytes=None, free_bytes=None, read_only=None,
               mountpoint=None, distinct_from_parent=None)
    directory = None
    try:
        path = Path(path)
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
        row.update(status='ok', filesystem=filesystems.setdefault(actual.st_dev,len(filesystems)+1),
                   total_bytes=capacity.f_blocks*capacity.f_frsize,
                   free_bytes=capacity.f_bavail*capacity.f_frsize,
                   read_only=bool(capacity.f_flag & os.ST_RDONLY),
                   mountpoint=os.path.ismount(path),
                   distinct_from_parent=actual.st_dev != path.parent.stat().st_dev)
        return row
    except FileNotFoundError:
        row['status'] = 'missing'
        return row
    except OSError:
        return row
    finally:
        if directory is not None:
            os.close(directory)

def collect():
    filesystems = {}
    locations = [capacity_preflight.probe(role, path, filesystems) for role, path in zip(
        capacity_preflight.ROLES, ('/', os.environ.get('GITHUB_WORKSPACE'), os.environ.get('RUNNER_TEMP'), '/schelk'))]
    scratch = [scratch_capacity(role,path,filesystems) for role,path in zip(SCRATCH_ROLES,('/reth-bench-a','/reth-bench-b'))]
    deadline = time.monotonic()+TOTAL_SECONDS
    rows = [usage(role, path, deadline, filesystems) for role, path in zip(ROLES, paths(os.environ))]
    return dict(schema=2, locations=locations, scratch_locations=scratch, usage=rows,
                per_category_timeout_ms=PER_CATEGORY_SECONDS*1000, total_usage_budget_ms=TOTAL_SECONDS*1000)



def validate(report):
    location_fields = {'role','exists','filesystem','total_bytes','free_bytes','read_only','writable','write_tested','status'}
    location_statuses = {'unset','invalid_path','missing','redirected','not_directory','changed_directory','read_only','access_denied','write_failed','cleanup_failed','writable','unavailable'}
    def uint(value): return type(value) is int and 0 <= value <= MAX_UINT
    def optional_uint(value): return value is None or uint(value)
    def flag(value): return value is None or type(value) is bool
    assert set(report) == {'schema','locations','scratch_locations','usage','per_category_timeout_ms','total_usage_budget_ms'}
    assert type(report['schema']) is int and report['schema'] == 2
    assert type(report['per_category_timeout_ms']) is int and report['per_category_timeout_ms'] == 15000
    assert type(report['total_usage_budget_ms']) is int and report['total_usage_budget_ms'] == 150000
    assert len(report['locations']) == 4 and len(report['usage']) == len(ROLES)
    for role,row in zip(capacity_preflight.ROLES,report['locations']):
        assert set(row) == location_fields and row['role'] == role and row['status'] in location_statuses
        assert type(row['exists']) is bool and type(row['write_tested']) is bool
        assert flag(row['read_only']) and flag(row['writable'])
        assert all(optional_uint(row[k]) for k in ('filesystem','total_bytes','free_bytes'))
        assert row['filesystem'] is None or 1 <= row['filesystem'] <= 4
    assert len(report['scratch_locations']) == 2
    for role,row in zip(SCRATCH_ROLES,report['scratch_locations']):
        assert set(row) == {'role','status','exists','filesystem','total_bytes','free_bytes','read_only','mountpoint','distinct_from_parent'}
        assert row['role'] == role and row['status'] in {'ok','unavailable','redirected','not_directory','changed_directory','missing'}
        assert type(row['exists']) is bool and all(flag(row[k]) for k in ('read_only','mountpoint','distinct_from_parent'))
        assert all(optional_uint(row[k]) for k in ('filesystem','total_bytes','free_bytes'))
        assert row['filesystem'] is None or 1 <= row['filesystem'] <= 6
        if row['status'] == 'ok':
            assert row['exists'] and all(row[k] is not None for k in ('filesystem','total_bytes','free_bytes','read_only','mountpoint','distinct_from_parent'))
    for role,row in zip(ROLES,report['usage']):
        assert set(row) == {'role','status','allocated_bytes','filesystem','elapsed_ms','exclusions_applied'}
        assert row['role'] == role and row['status'] in STATUSES and row['exclusions_applied'] is True
        assert optional_uint(row['allocated_bytes']) and optional_uint(row['filesystem']) and uint(row['elapsed_ms'])
        assert row['filesystem'] is None or 1 <= row['filesystem'] <= 18
        assert (row['allocated_bytes'] is not None) == (row['status'] == 'ok')
        assert row['status'] != 'ok' or row['filesystem'] is not None
    return report

def main():
    try:
        report = validate(collect())
        print(json.dumps(report, separators=(',', ':')))
        return int(any(row['status']=='cleanup_failed' for row in report['locations']))
    except BaseException:
        print('{"schema":2,"status":"probe_unavailable"}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
