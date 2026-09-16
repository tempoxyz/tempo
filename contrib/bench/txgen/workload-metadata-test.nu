use std/assert
source ./helpers.nu

let preset = ($env.FILE_PWD | path join presets public-mix.yml)
let args = (txgen-workload-metadata-args public-mix $preset)
assert equal ($args | first 3) ["-m" "workload_mix_version=1" "-m"]
assert equal ($args.3 | str replace 'workload_mix_weights=' '' | from json) {mpp_open_only: 15, public_mint: 5, public_transfer: 80}

# Non-public-mix workloads must not even open the spec or invoke yq.
for name in [default tip20 dex mpp mix zones vault-deposit vault-withdraw neobank-deposit neobank-swap neobank-withdraw "tip20:nonce=2d"] {
    assert equal (txgen-workload-metadata-args $name /does/not/exist.yml) []
}
let two_dimensional = (txgen-preset-path "tip20:nonce=2d")
assert equal (txgen-workload-metadata-args ($two_dimensional | path basename | str replace '.yml' '') $two_dimensional) []

# Expanded public-mix stays bounded, and unrelated u64 YAML values are harmless.
let fixture = (mktemp --suffix .yml)
let expanded = (0..<10000 | each { |i| [
    {template: $"zone_deposit_($i)", weight: 5}
    {template: $"vault_withdraw_($i)", weight: 4}
] } | flatten)
{mix: ($expanded | append [{sequence: mpp_open_only, weight: 15} {template: custom_123, weight: 1}])} | to yaml | save -f $fixture
"unrelated: 18446744073709551615\ninclude: /does/not/exist.yml\n" | save --append $fixture
let before = (open --raw $fixture)
let compact = (txgen-workload-metadata-args public-mix $fixture).3
assert equal ($compact | str replace 'workload_mix_weights=' '' | from json) {custom_123: 1, mpp_open_only: 15, vault_withdraw: 40000, zone_deposit: 50000}
assert (($compact | str length) < 150)
assert equal (open --raw $fixture) $before
rm $fixture
assert (try { txgen-workload-metadata-args public-mix /does/not/exist.yml | ignore; false } catch { true })
print "Workload metadata tests passed"
