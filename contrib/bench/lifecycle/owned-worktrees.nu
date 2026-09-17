# These receipts remain private within this invocation, never in report artifacts.
def e2e-record-worktree-owner [worktree: string] {
    let result = (^python3 contrib/bench/lifecycle/worktree_owner.py record $worktree | complete)
    if $result.exit_code != 0 {
        error make { msg: "Unable to record newly created worktree ownership" }
    }
    $result.stdout | from json
}

def e2e-cleanup-owned-worktrees [owners: list<record>] {
    for owner in $owners {
        # No recursive fallback: replacement/refusal/failure leaves the path alone.
        # Cleanup errors cannot replace the original build or trim error.
        try {
            $owner | to json --raw | ^python3 contrib/bench/lifecycle/worktree_owner.py remove | complete | ignore
        } catch { }
    }
}
