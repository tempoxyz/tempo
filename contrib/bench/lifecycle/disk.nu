# Report the filesystem used by the supplied benchmark path without changing it.
def lifecycle-report-disk [phase: string, path: string] {
    let result = (^df -Pm $path | complete)
    if $result.exit_code != 0 {
        error make { msg: $"Unable to inspect lifecycle disk space ($phase)" }
    }
    let available = ($result.stdout | lines | skip 1 | first | split row --regex '\s+' | get 3 | into int)
    print $"Lifecycle disk space ($phase): ($available) MiB available"
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
