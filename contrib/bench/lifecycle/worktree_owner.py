"""Private invocation receipts for failure cleanup of newly created worktrees."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def identity(info):
    return [info.st_dev, info.st_ino]


def snapshot(path):
    path=Path(os.path.abspath(path))
    if path.resolve(strict=True)!=path:raise ValueError('redirected worktree')
    directory=path.lstat();marker=path/'.git';git_file=marker.lstat()
    if not stat.S_ISDIR(directory.st_mode) or not stat.S_ISREG(git_file.st_mode):
        raise ValueError('invalid worktree identity')
    if git_file.st_size>4096:raise ValueError('invalid worktree marker')
    content=marker.read_bytes()
    if not content.startswith(b'gitdir: '):raise ValueError('invalid worktree marker')
    return dict(path=str(path),directory=identity(directory),git_file=identity(git_file),
                git_sha256=hashlib.sha256(content).hexdigest())


def remove(receipt):
    # This is an owned, single-writer build area. Identity verification refuses a
    # replaced directory/marker or symlink; it is not an adversarial rename lock.
    if snapshot(receipt['path'])!=receipt:return False
    result=subprocess.run(['git','worktree','remove','--force','--',receipt['path']],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return result.returncode==0


if __name__=='__main__':
    try:
        if sys.argv[1]=='record':print(json.dumps(snapshot(sys.argv[2])))
        elif sys.argv[1]=='remove':
            receipt=json.loads(sys.stdin.read(8193))
            if not remove(receipt):raise ValueError('owned cleanup refused')
        else:raise ValueError('unknown ownership command')
    except (OSError,ValueError,KeyError,IndexError,TypeError):
        # Caller retains the original build diagnostic; private paths/identities
        # never become an additional diagnostic or artifact.
        print('Owned worktree identity unavailable',file=sys.stderr)
        sys.exit(1)
