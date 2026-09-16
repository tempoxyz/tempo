# Report the filesystem used by the supplied benchmark path without changing it.
def lifecycle-available-disk [phase: string, path: string] {
    let result = (^df -Pm $path | complete)
    if $result.exit_code != 0 {
        error make { msg: $"Unable to inspect lifecycle disk space ($phase)" }
    }
    let available = try {
        $result.stdout | lines | skip 1 | first | split row --regex '\s+' | get 3 | into int
    } catch {
        error make { msg: $"Invalid lifecycle disk-space report ($phase)" }
    }
    if $available < 0 {
        error make { msg: $"Invalid lifecycle disk-space report ($phase)" }
    }
    $available
}

def lifecycle-report-disk [phase: string, path: string] {
    let available = (lifecycle-available-disk $phase $path)
    print $"Lifecycle disk space ($phase): ($available) MiB available"
}

# Refuse a new build/capture before storage exhaustion can disrupt the runner.
# Thresholds reserve headroom; they cannot predict all later disk consumption.
def lifecycle-require-disk [phase: string, path: string, minimum_mib: int] {
    let available = (lifecycle-available-disk $phase $path)
    print $"Lifecycle disk space ($phase): ($available) MiB available; ($minimum_mib) MiB required"
    if $available < $minimum_mib {
        error make { msg: $"Insufficient lifecycle disk space ($phase): ($available) MiB available; ($minimum_mib) MiB required" }
    }
}

# Validate the destination before a cache download or a compiler can write to it.
def lifecycle-validate-build-path [worktree: string, profile: string] {
    if $profile !~ '^[A-Za-z0-9][A-Za-z0-9_-]*$' {
        error make { msg: "Invalid lifecycle build profile" }
    }
    let original = ($worktree | path expand --no-symlink)
    let worktree = ($worktree | path expand --strict)
    if $original != $worktree {
        error make { msg: "Refusing redirected lifecycle worktree" }
    }
    let target = ([$worktree "target"] | path join)
    let directory = ([$target (if $profile == "dev" { "debug" } else { $profile })] | path join)
    for path in [$target $directory ($directory | path join "tempo")] {
        # path type also catches dangling links, unlike path exists.
        let kind = ($path | path type | default "")
        if $kind == "symlink" or ($kind != "" and ($path | path expand --strict) != $path) {
            error make { msg: "Refusing redirected lifecycle binary retrieval or build" }
        }
        let expected = if $path == ($directory | path join "tempo") { "file" } else { "dir" }
        if $kind != "" and $kind != $expected {
            error make { msg: "Invalid lifecycle binary retrieval or build path" }
        }
    }
}

# These worktrees are disposable benchmark builds. Preserve the linked executable
# and trim only intermediates after the build and binary-cache upload finish.
def lifecycle-trim-worktree [worktree: string, profile: string] {
    if $profile !~ '^[A-Za-z0-9][A-Za-z0-9_-]*$' {
        error make { msg: "Invalid build profile for lifecycle intermediate cleanup" }
    }
    let worktree = ($worktree | path expand --strict)
    let directory = ([$worktree "target" (if $profile == "dev" { "debug" } else { $profile })] | path join)
    if ($directory | path expand --strict) != $directory {
        error make { msg: "Refusing lifecycle cleanup through a redirected target directory" }
    }
    let binary = ($directory | path join "tempo")
    if ($binary | path type) != "file" or ($binary | path expand --strict) != $binary {
        error make { msg: "Refusing lifecycle cleanup around a redirected Tempo executable" }
    }
    let version = (run-external $binary "--version" | complete)
    if $version.exit_code != 0 {
        error make { msg: "Tempo binary verification failed; build intermediates retained" }
    }
    let intermediates = (["incremental" "build" "deps" ".fingerprint" "examples"]
        | each { |name| $directory | path join $name }
        | where { |path| $path | path exists })
    # Validate every candidate before deleting any. Never follow a link to a
    # shared target or another directory outside this disposable build.
    for path in $intermediates {
        if ($path | path type) != "dir" or ($path | path expand --strict) != $path {
            error make { msg: "Refusing redirected lifecycle build intermediate cleanup" }
        }
    }
    for path in $intermediates {
        rm -rf $path
    }
    print "Trimmed lifecycle build intermediates; Tempo executable retained"
}
