"""Bounded, no-follow, read-only inventory; exported records contain no native paths/IDs."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

LIMIT = 120_000
SECONDS = 20
DEPTH = 32
PHASE = re.compile(r'(?:baseline|feature)-[1-4]\Z')


def empty():
    return dict(allocated_bytes=0, apparent_bytes=0, files=0, directories=0,
                symlinks_skipped=0, inaccessible_entries=0, cross_device_skipped=0,
                special_files_skipped=0, changed_entries=0, hardlinks_deduplicated=0,
                foreign_uid_entries=0)


def open_root(path):
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            if component in ('.', '..'): raise ValueError('noncanonical root')
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory); directory = child
        result = directory; directory = None
        return result
    finally:
        if directory is not None: os.close(directory)


def scan(path, role, *, limit=LIMIT, seconds=SECONDS, classify=False):
    row = dict(role=role, status='unavailable', exclusive_task_ownership_proven=False,
               current_uid_owns_root=None, free_bytes_before=None, free_bytes_after=None,
               counters=empty(), categories={}, result_runs=[], result_runs_truncated=False, localnet_phase_logs={})
    fd = None
    try:
        path = Path(path)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            row['status'] = 'redirected_or_relative'; return row
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode):
            row['status'] = 'not_directory'; return row
        fd = open_root(path)
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
            row['status'] = 'changed_root'; return row
        row['current_uid_owns_root'] = actual.st_uid == os.getuid()
        v = os.fstatvfs(fd); row['free_bytes_before'] = v.f_bavail * v.f_frsize
        deadline = time.monotonic() + seconds
        seen = {}; runs = {}; visited = 0; partial = False

        def targets(parts):
            out = [('total', row['counters'])]
            if not classify or not parts: return out
            category = {'target':'checkout_target', '.bench-worktrees':'build_worktrees',
                        'bench-results':'retained_results', 'localnet':'localnet'}.get(parts[0], 'other_workspace')
            out.append((category, row['categories'].setdefault(category, empty())))
            if parts[0] == 'localnet' and len(parts) >= 2:
                match = re.fullmatch(r'logs-e2e-local-((?:baseline|feature)-[1-4])-([ab])', parts[1])
                if match:
                    label = match[1]+':'+match[2]
                    out.append(('localnet'+label,row['localnet_phase_logs'].setdefault(label,empty())))
            if parts[0] == 'bench-results' and len(parts) >= 2:
                name = parts[1]
                if name not in runs and len(runs) < 32:
                    record = dict(ordinal=len(runs)+1, counters=empty(), phases={}, exclusive_task_ownership_proven=False)
                    runs[name] = record; row['result_runs'].append(record)
                if name not in runs: row['result_runs_truncated'] = True
                if name in runs:
                    r = runs[name]; prefix = 'run'+str(r['ordinal']); out.append((prefix,r['counters']))
                    phase = None; kind = None
                    if len(parts) >= 4 and parts[2] == 'lifecycle':
                        leaf = parts[3]
                        if leaf.endswith('.zip') and PHASE.fullmatch(leaf[:-4]): phase,kind=leaf[:-4],'archive'
                        elif PHASE.fullmatch(leaf): phase,kind=leaf,'expanded_report'
                    elif len(parts) >= 4 and parts[2] == 'lifecycle-raw' and PHASE.fullmatch(parts[3]): phase,kind=parts[3],'raw_capture'
                    elif len(parts) >= 3:
                        m=re.fullmatch(r'logs-((?:baseline|feature)-[1-4])-[ab]',parts[2])
                        if m:phase,kind=m[1],'copied_logs'
                    if phase:
                        label=phase+':'+kind
                        out.append((prefix+label,r['phases'].setdefault(label,empty())))
            return out

        def walk(directory, parts, depth):
            nonlocal visited, partial
            identity = os.fstat(directory)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if visited >= limit or time.monotonic() >= deadline:
                            partial=True; return
                        visited += 1; rel=parts+(entry.name,); groups=targets(rel)
                        def add(key,value=1):
                            for _,counts in groups:counts[key]+=value
                        try: info=os.stat(entry.name,dir_fd=directory,follow_symlinks=False)
                        except OSError:add('inaccessible_entries');continue
                        if stat.S_ISLNK(info.st_mode):add('symlinks_skipped');continue
                        if info.st_dev != actual.st_dev:add('cross_device_skipped');continue
                        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                            add('special_files_skipped');continue
                        if info.st_uid != os.getuid():add('foreign_uid_entries')
                        for key,counts in groups:
                            inode=(info.st_dev,info.st_ino); unique=seen.setdefault(key,set())
                            if inode in unique: counts['hardlinks_deduplicated']+=1;continue
                            unique.add(inode);counts['allocated_bytes']+=info.st_blocks*512
                            counts['apparent_bytes']+=info.st_size
                            counts['directories' if stat.S_ISDIR(info.st_mode) else 'files']+=1
                        if stat.S_ISDIR(info.st_mode):
                            if depth >= DEPTH:partial=True;continue
                            child=None
                            try:
                                child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                                opened=os.fstat(child)
                                if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):add('changed_entries');continue
                                walk(child,rel,depth+1)
                            except OSError:add('inaccessible_entries')
                            finally:
                                if child is not None:os.close(child)
            except OSError:
                for _,counts in targets(parts):counts['inaccessible_entries']+=1
            end=os.fstat(directory)
            if (identity.st_mtime_ns,identity.st_ctime_ns)!=(end.st_mtime_ns,end.st_ctime_ns):
                for _,counts in targets(parts):counts['changed_entries']+=1

        walk(fd,(),0)
        final=os.fstat(fd);current=path.lstat()
        if (final.st_dev,final.st_ino)!=(current.st_dev,current.st_ino):partial=True;row['counters']['changed_entries']+=1
        v=os.fstatvfs(fd);row['free_bytes_after']=v.f_bavail*v.f_frsize
        row['entries_examined']=visited
        c=row['counters']
        row['status']='partial' if partial or any(c[k] for k in ['inaccessible_entries','cross_device_skipped','special_files_skipped','changed_entries']) else 'complete_no_follow'
    except FileNotFoundError:row['status']='missing'
    except (OSError,ValueError):row['status']='inaccessible'
    finally:
        if fd is not None:os.close(fd)
    return row


def collect(env):
    required=['GITHUB_WORKSPACE','RUNNER_TEMP','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','CAPACITY_SLOT']
    if any(not env.get(k) for k in required):raise ValueError('missing closed configuration')
    if not re.fullmatch('[0-9a-f]{40}',env['GITHUB_SHA']):raise ValueError('invalid source')
    nums={k:int(env[k]) for k in ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','CAPACITY_SLOT']}
    if any(v<=0 for v in nums.values()) or nums['CAPACITY_SLOT']>5:raise ValueError('invalid binding')
    rows=[scan(env['GITHUB_WORKSPACE'],'workspace',classify=True),scan(env['RUNNER_TEMP'],'runner_temp')]
    # Only the conventional per-user sccache root is inspected. No arbitrary env path.
    if env.get('HOME'):
        cache=Path(env['HOME'])/'.cache'/'sccache'
        row=scan(cache,'conventional_sccache');row['active_cache_location_confirmed']=env.get('SCCACHE_DIR')==str(cache)
        row['configured_cache_elsewhere_uninspected']=bool(env.get('SCCACHE_DIR') and env['SCCACHE_DIR']!=str(cache))
        rows.append(row)
    return dict(schema=1,workflow_sha=env['GITHUB_SHA'],run_id=nums['GITHUB_RUN_ID'],run_attempt=nums['GITHUB_RUN_ATTEMPT'],slot=nums['CAPACITY_SLOT'],
                source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                read_only_inventory=True,snapshot_atomic=False,cleanup_authorized=False,
                limits=dict(entries_per_root=LIMIT,seconds_per_root=SECONDS,depth=DEPTH,result_runs=32),roots=rows)


if __name__=='__main__':
    try:
        print(json.dumps(collect(os.environ),separators=(',',':')))
    except Exception:
        raise SystemExit('Owned capacity inventory unavailable') from None
