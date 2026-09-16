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
