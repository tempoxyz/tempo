source ../../../bench-e2e.nu
use std/assert

assert equal (e2e-calibration-presets "tip20").kind "code"
let name = "gas-compare:gas-hash-control-256,gas-sha256-256"
let presets = (e2e-calibration-presets $name)
assert equal $presets {kind: "workload", baseline: "gas-hash-control-256", feature: "gas-sha256-256"}
assert equal (e2e-phase-preset "baseline-2" $presets) "gas-hash-control-256"
assert equal (e2e-phase-preset "feature-1" $presets) "gas-sha256-256"
assert (try { e2e-phase-preset "unknown" $presets | ignore; false } catch { true })
for invalid in [
    "gas-compare:gas-echo" "gas-compare:gas-echo,gas-copy-32,gas-branch"
    "gas-compare:../gas-echo,gas-branch" "gas-compare:gas-echo,gas-calibration-smoke"
    "gas-compare:default,gas-echo" "gas-compare:gas-echo,gas-echo;false"
] {
    assert (try { e2e-calibration-presets $invalid | ignore; false } catch { true }) $invalid
}
let settings = {
    ref: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", hardfork: "T10",
    features: "", args: "", env: ""
}
e2e-validate-calibration-match $settings $settings "comparison"
for field in [ref hardfork features args env] {
    assert (try {
        e2e-validate-calibration-match $settings ($settings | upsert $field "different") "comparison"
        false
    } catch { true }) $field
}
assert (try { e2e-validate-calibration-match $settings $settings "baseline"; false } catch { true })
let unpinned = ($settings | upsert ref "main")
assert (try { e2e-validate-calibration-match $unpinned $unpinned "comparison"; false } catch { true })
let unspecified_fork = ($settings | upsert hardfork "")
assert (try { e2e-validate-calibration-match $unspecified_fork $unspecified_fork "comparison"; false } catch { true })

# Rendering checks both files without building, funding, or running nodes.
let rendered = (^nu bench-e2e.nu render-txgen-spec --preset $name | str trim)
assert ($rendered ends-with '/gas-hash-control-256.yml')
let missing = (^nu bench-e2e.nu render-txgen-spec --preset "gas-compare:gas-echo,gas-no-such-preset" | complete)
assert ($missing.exit_code != 0)

# Exercise the actual summary pipeline with synthetic report data, not node execution.
let scratch = (mktemp -d)
let blocks = (1..8 | each { |number|
    {number: $number, timestamp_ms: ($number * 1000), tx_count: 10, ok_count: 10,
     err_count: 0, gas_used: 210000, block_time_ms: 1000}
})
for label in ["baseline-1" "feature-1"] {
    {blocks: $blocks, samples: []} | to json | save ($scratch | path join $"report-($label).json")
}
e2e-write-summary-config $scratch $settings.ref $settings.ref 1000 4 $name 1000 20 "fixture" 0 2 "comparison" "T10" "T10" "" ""
e2e-generate-summary $scratch | ignore
let summary = (open ($scratch | path join summary.json))
assert equal $summary.config.comparison_kind "workload"
assert equal $summary.config.baseline_preset "gas-hash-control-256"
assert equal $summary.config.feature_preset "gas-sha256-256"
assert equal $summary.classification.label "Workload Comparison - Unpriced"
assert not $summary.classification.pricing_ready
assert ((open --raw ($scratch | path join summary.md)) | str contains "Baseline workload: gas-hash-control-256")
print "Calibration pair parsing, matching, routing and rendering checks passed"
exit 0
