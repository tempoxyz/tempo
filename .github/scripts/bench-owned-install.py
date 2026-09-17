#!/usr/bin/env python3
"""Contain one Cargo install's generated target/temp files; leave shared caches alone."""
import ctypes
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
import uuid


class Refused(Exception):
    pass


def subreaper():
    # Local supervisor property, not system tuning. Adopt and reap compiler
    # grandchildren if Cargo exits unexpectedly; never reap another job's group.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise Refused('supervisor_unavailable')


def group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def reap_group(group):
    while True:
        try:
            pid, _ = os.waitpid(-group, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def finished_unreaped(process):
    return os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None


def stop_group(process):
    # Keep the leader unreaped until the last signal, preventing group-ID reuse.
    # No signals follow wait()/reaping, even if an unexpected group remains.
    try:
        os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline=time.monotonic()+3
    while not finished_unreaped(process) and time.monotonic()<deadline:
        time.sleep(.02)
    try:
        os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        reap_group(process.pid)
        if not group_exists(process.pid):
            return
        time.sleep(.02)
    raise Refused('owned_processes_unreaped')



def validate_wrappers(environment, arguments):
    # This workflow intentionally uses sccache or no wrapper. Do not silently
    # disable arbitrary user code-generation wrappers. Cargo install --git reads
    # user Cargo configuration, not the caller's project configuration.
    if any(a == '--config' or a.startswith('--config=') for a in arguments):
        raise Refused('custom_install_configuration')
    wrappers=[environment.get(k,'') for k in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER',
        'CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER')]
    home=environment.get('CARGO_HOME') or str(Path(environment.get('HOME',''))/'.cargo')
    for filename in ('config','config.toml'):
        config=Path(home)/filename
        if not config.exists():
            continue
        with config.open('rb') as source:
            data=source.read(65537)
        if len(data)>65536:
            raise Refused('unsupported_cargo_configuration')
        parsed=tomllib.loads(data.decode())
        if 'include' in parsed:
            raise Refused('unsupported_cargo_configuration')
        build=parsed.get('build',{})
        wrappers.extend(build.get(k,'') for k in ('rustc-wrapper','rustc-workspace-wrapper'))
    if any(not isinstance(w,str) or w and Path(w).name != 'sccache' for w in wrappers):
        raise Refused('custom_compiler_wrapper')

def install(workspace, arguments):
    if not arguments or arguments[0] != 'install':
        raise Refused('invalid_install_arguments')
    validate_wrappers(os.environ,arguments)
    workspace=Path(workspace)
    if not workspace.is_absolute() or workspace.resolve(strict=True)!=workspace or not workspace.is_dir():
        raise Refused('redirected_workspace')
    if not shutil.rmtree.avoids_symlink_attacks:
        raise Refused('safe_cleanup_unavailable')
    subreaper()
    parent=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    name='.bench-txgen-install-'+uuid.uuid4().hex
    created=False;identity=None;process=None;safe=False;stopping=[False]
    previous={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig,lambda *_:stopping.__setitem__(0,True))
        os.mkdir(name,0o700,dir_fd=parent);created=True
        identity=os.stat(name,dir_fd=parent,follow_symlinks=False)
        owned=workspace/name
        (owned/'target').mkdir();(owned/'tmp').mkdir()
        environment=dict(os.environ)
        # Keep toolchain, Rust flags, exact dependency/ref/features and install root.
        # Shared registry/git and compiler-cache services remain intact. Disable
        # only this invocation's cache wrappers so no persistent daemon inherits
        # its temporary directory or places compiler temporary files elsewhere.
        environment.update(CARGO_TARGET_DIR=str(owned/'target'),CARGO_BUILD_TARGET_DIR=str(owned/'target'),
                           CARGO_BUILD_BUILD_DIR=str(owned/'target'),TMPDIR=str(owned/'tmp'),
                           TMP=str(owned/'tmp'),TEMP=str(owned/'tmp'),RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
        if stopping[0]:
            safe=True
            return 130
        process=subprocess.Popen(['cargo',*arguments],env=environment,start_new_session=True)
        while not finished_unreaped(process) and not stopping[0]:
            time.sleep(.05)
        stop_group(process)
        safe=True
        return 130 if stopping[0] else (process.returncode if process.returncode >= 0 else 128-process.returncode)
    finally:
        try:
            if process is None:
                safe=True
            elif not safe and process.returncode is None:
                stop_group(process);safe=True
            if created and safe:
                current=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if (current.st_dev,current.st_ino)!=(identity.st_dev,identity.st_ino) or not stat.S_ISDIR(current.st_mode):
                    raise Refused('owned_directory_changed')
                shutil.rmtree(name,dir_fd=parent)
        finally:
            for sig,handler in previous.items():
                signal.signal(sig,handler)
            os.close(parent)


def main():
    try:
        return install(os.environ.get('GITHUB_WORKSPACE',''),sys.argv[1:])
    except BaseException:
        # Never print private command arguments, environment, or native paths.
        print('Owned txgen install failed; unsafe cleanup was refused',file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
