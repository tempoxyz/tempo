#!/usr/bin/env nu
source helpers.nu
use std/assert

let default = (txgen-resolve-bench-spec default)
let public_mix = (txgen-resolve-bench-spec public-mix)
assert equal $default $public_mix
assert equal $default.kind static
assert equal ($default.spec_path | path basename) public-mix.yml
assert equal (txgen-scenario-metadata-args default $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public-mix" "-m" "requested_preset=default"]
assert equal (txgen-scenario-metadata-args public-mix $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public-mix"]
assert equal (txgen-scenario-metadata-args public $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public"]
assert equal (txgen-parse-tip20-scenario default) null

# Keep the old workload available only through an explicit name/scenario.
let existing = (txgen-parse-tip20-scenario tip20_existing_recipients)
assert equal $existing (txgen-parse-tip20-scenario "tip20:recipient=existing,fee-token=any_tip20")
assert equal $existing.recipient existing
assert equal $existing.fee_token any_tip20
assert equal (txgen-parse-tip20-scenario public).recipient users

# Alias resolution must retain the actual mix and state-bloat setup.
let mix = (^uv run --no-project --with yq==3.4.3 yq -c .mix $default.spec_path | from json)
assert equal ($mix | get weight | math sum) 100
txgen-configure-existing-recipients-env $default.spec_path 1000 4
txgen-configure-existing-recipients-env $default.spec_path 1024 4
assert equal ($env.TXGEN_EXISTING_RECIPIENTS_START | into int) 10000
assert (($env.TXGEN_EXISTING_RECIPIENTS_END | into int) > 10000)
assert equal (txgen-workload-metadata-args $default.scenario_id $default.spec_path) (txgen-workload-metadata-args public-mix $public_mix.spec_path)
for preset in [tip20 tip20_existing_recipients mix dex mpp neobank-deposit neobank-swap neobank-withdraw zones vault-deposit vault-withdraw] {
    assert equal (txgen-workload-metadata-args $preset "") ["-m" "workload_mix_weighting=gas"]
}
# The policy preset uses distinct issuer and receiver lists on the current layout.
let policy_spec = (txgen-resolve-bench-spec tip20-policy)
assert equal $policy_spec.kind static
assert ("tip20-policy" in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
assert equal (open $policy_spec.spec_path).merge.templates.tip20_transfer.fee_token (txgen-tip20-token-address 1)
let policy = (txgen-tip20-policy-calls 2 17)
assert equal ($policy.admin_calls | where function == changeTransferPolicyId | get args) [["20"] ["24"]]
assert equal ($policy.admin_calls | where function == createCompoundPolicy | get args) [[17 18 19] [21 22 23]]
assert equal ($policy.admin_calls | where function == createPolicy | length) 8
assert equal $policy.receive_call.function setReceivePolicy
assert equal $policy.receive_call.args [25 26 "0x0000000000000000000000000000000000000000"]
print "Preset, policy setup, state-bloat, and workload metadata checks passed"
