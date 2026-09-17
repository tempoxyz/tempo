# Expand an existing baseline/feature order without changing ordinary runs.
# Compare mode alternates detail order per pair, within one runner job.
def lifecycle-run-plan [sides: list<string>, detail: string] {
    mut plan = []
    if $detail == "compare" {
        for pair in ($sides | chunks 2 | enumerate) {
            let modes = if ($pair.index mod 2) == 0 { [full milestones] } else { [milestones full] }
            for mode in $modes {
                for side in $pair.item {
                    $plan = ($plan | append {side: $side detail: $mode})
                }
            }
        }
    } else {
        $plan = ($sides | each {|side| {side: $side detail: $detail}})
    }
    mut counts = {}
    mut phases = []
    for run in $plan {
        let key = if $detail == "compare" { $"($run.detail)-($run.side)" } else { $run.side }
        let index = (($counts | get -o $key | default 0) + 1)
        $counts = ($counts | upsert $key $index)
        $phases = ($phases | append ($run | insert phase $"($key)-($index)"))
    }
    $phases
}

# Fixed node-only observer environment. These are never txgen arguments.
def lifecycle-cache-config [mode: string, side: string] {
    if $mode == "disabled" { return {expected: "" env: ""} }
    if $mode != "compare" or $side not-in ["baseline" "feature"] {
        error make {msg: "Invalid cache observer comparison mode or side"}
    }
    if $side == "baseline" {
        {expected: "disabled" env: "TEMPO_LIFECYCLE_CACHE_INSERT=0 "}
    } else {
        {expected: "counts_v1" env: "TEMPO_LIFECYCLE_CACHE_INSERT=1 "}
    }
}

# Both sides share profile, toolchain and default-feature settings. Reuse only
# an exact immutable revision with identical effective build inputs; preserve
# separate builds for no-cache requests, mutable refs and ordinary benchmarks.
def lifecycle-reuse-build [enabled: bool, no_cache: bool, builds: list<record>] {
    if not $enabled or $no_cache or ($builds | length) != 2 { return false }
    let a = $builds.0
    let b = $builds.1
    ($a.label == "baseline" and $b.label == "feature" and
        ($a.sha =~ '^[0-9a-f]{40}$') and $a.sha == $b.sha and
        $a.features == $b.features and
        $a.extra_rustflags == $b.extra_rustflags and
        $a.bench_features == $b.bench_features)
}
