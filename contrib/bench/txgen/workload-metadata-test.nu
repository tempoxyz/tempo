use std/assert
use ./workload-metadata.nu *

let preset = ($env.FILE_PWD | path join presets public-mix.yml)
let metadata = (txgen-workload-metadata (txgen-workload-mix $preset))
assert equal $metadata.workload_mix_version "1"
assert equal ($metadata.workload_mix_weights | from json) {mpp_open_only: 15, public_mint: 5, public_transfer: 80}

# An expanded fixture must remain bounded by categories, not account count.
let expanded = (0..<10000 | each { |i| [
    {template: $"zone_deposit_($i)", weight: 5}
    {template: $"vault_withdraw_($i)", weight: 4}
] } | flatten)
let compact = (txgen-workload-metadata $expanded)
assert equal ($compact.workload_mix_weights | from json) {vault_withdraw: 40000, zone_deposit: 50000}
assert (($compact.workload_mix_weights | str length) < 100)
assert equal ((txgen-workload-metadata [{sequence: mpp_open_only, weight: 15} {template: custom_123, weight: 0}]).workload_mix_weights | from json) {custom_123: 0, mpp_open_only: 15}

for mix in [[] [{template: x, weight: 0}] [{template: x, weight: -1}] [{template: x, weight: "1"}] [{template: x, sequence: y, weight: 1}]] {
    assert (try { txgen-workload-metadata $mix | ignore; false } catch { true })
}

# Exercise included/composed presets and fixture-generated mix overrides.
source ./helpers.nu
let tip20 = (txgen-preset-path tip20)
assert equal ((txgen-workload-metadata (txgen-workload-mix $tip20)).workload_mix_weights | from json) {tip20_transfer: 100}
let vault = (txgen-prepare-vault-preset ($env.FILE_PWD | path join presets vault-deposit.yml) 10 1337)
assert equal ((txgen-workload-metadata (txgen-workload-mix $vault)).workload_mix_weights | from json) {vault_deposit: 10}
print "Workload metadata tests passed"
