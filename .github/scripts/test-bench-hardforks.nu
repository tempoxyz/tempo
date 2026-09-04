#!/usr/bin/env nu
# Run from the repository root: nu .github/scripts/test-bench-hardforks.nu
use std/assert
source ../../tempo.nu

let expected = [T0 T1 T1A T1B T1C T2 T3 T4 T5 T6 T7 T8 T9 T10 T11 T12]
assert equal (tempo-hardforks) $expected
assert equal (latest-tempo-hardfork) T12
assert equal (highest-hardfork [T9 T10 T1A]) T10

# Every selected fork must retain all predecessors and disable all successors,
# including when the fixture's JSON keys put T10 before T1.
for cutoff in $expected {
    let fields = (hardfork-genesis-config-fields $cutoff)
    let index = ($expected | enumerate | where item == $cutoff | get 0.index)
    assert equal ($fields | where value == 0 | get fork) ($expected | take ($index + 1))
    assert equal ($fields | where value != 0 | get fork) ($expected | skip ($index + 1))
}

print "Benchmark hardfork order and activation cutoffs are valid"
