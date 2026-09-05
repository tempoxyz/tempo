# Parse bounded, existing calibration presets without accepting paths or scenario expressions.
def e2e-calibration-presets [preset: string] {
    if not ($preset starts-with "gas-compare:") {
        return { kind: "code", baseline: $preset, feature: $preset }
    }
    let names = ($preset | str replace 'gas-compare:' '' | split row ',')
    if ($names | length) != 2 {
        error make { msg: "gas-compare requires exactly two individual calibration preset names" }
    }
    for name in $names {
        if not ($name =~ '^(gas-|precompile-|native-read-)[a-z0-9-]+$') or ($name ends-with '-smoke') {
            error make { msg: $"invalid individual calibration preset: ($name)" }
        }
    }
    { kind: "workload", baseline: $names.0, feature: $names.1 }
}

def e2e-validate-calibration-match [baseline: record, feature: record, run_side: string] {
    if $run_side != "comparison" {
        error make { msg: "workload calibration requires both comparison sides" }
    }
    if not ($baseline.ref =~ '^[0-9a-f]{40}$') or $baseline.hardfork == "" or $baseline != $feature {
        error make { msg: "workload calibration requires the same full node SHA, hardfork, build features, node args and environment on both sides" }
    }
}

def e2e-phase-preset [phase: string, presets: record] {
    if $phase starts-with "baseline-" { $presets.baseline } else if $phase starts-with "feature-" {
        $presets.feature
    } else {
        error make { msg: $"unknown calibration phase: ($phase)" }
    }
}
