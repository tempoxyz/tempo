# Run from the repository root: nu contrib/bench/txgen/helpers-test.nu
source helpers.nu
use std/assert

let fixtures = (mktemp -d)
let piece = "setup:\n  keychain_authorize_pool:\n    nonce: 18446744073709551615\n"
$piece | save ($fixtures | path join "piece.yml")
let absolute_piece = ($fixtures | path join "piece.yml" | to json)

for header in [
    "include: piece.yml"
    "include: [piece.yml]"
    "includes: piece.yml"
    "includes:\n  - piece.yml"
    $"include: ($absolute_piece)"
] {
    let raw = $"($header)\nnonce: { uniform: [0, 18446744073709551615] }\n"
    let spec = ($fixtures | path join "spec.yml")
    $raw | save -f $spec
    assert equal (txgen-spec-effective-text $spec) ($piece + "\n" + $raw)
    assert (txgen-spec-has-keychain-setup $spec)
    assert equal (open --raw $spec) $raw
}

let plain = "nonce: { uniform: [0, 18446744073709551615] }\n"
let spec = ($fixtures | path join "plain.yml")
$plain | save $spec
assert equal (txgen-spec-effective-text $spec) $plain
assert (not (txgen-spec-has-keychain-setup $spec))

# Preserve include order and surface invalid YAML rather than dropping includes.
let spec = ($fixtures | path join "multiple.yml")
"includes: [piece.yml, plain.yml]\n" | save $spec
assert equal (txgen-spec-effective-text $spec) (
    $piece + "\n" + $plain + "\n" + (open --raw $spec)
)
let invalid = ($fixtures | path join "invalid.yml")
"include: [\n" | save $invalid
assert error { txgen-spec-effective-text $invalid }

# Exercise the actual preset that panicked before benchmark startup.
let public_mix = "contrib/bench/txgen/presets/public-mix.yml"
assert equal (txgen-spec-effective-text $public_mix) (
    (open --raw contrib/bench/txgen/presets/mpp.yml)
    + "\n" + (open --raw $public_mix)
)
print "txgen include and u64 regression tests passed"
