#!/usr/bin/env nu

# Run from the repository root: nu contrib/bench/test-hardforks.nu
def main [] {
    source ../../tempo.nu
    use std/assert

    assert ((hardfork-index T1) < (hardfork-index T1A))
    assert ((hardfork-index T1C) < (hardfork-index T2))
    assert ((hardfork-index T9) < (hardfork-index T10))
    assert ((hardfork-index T10) < (hardfork-index T11))
    assert equal (highest-hardfork [T9 T10 T11]) T11

    for fork in [T10 T11] {
        let fields = (hardfork-genesis-config-fields $fork)
        assert equal ($fields | where fork == T9 | get 0.value) 0
        assert equal ($fields | where fork == $fork | get 0.value) 0
        assert equal ($fields | where fork == T12 | get 0.value) $TEMPO_DISABLED_HARDFORK_TIME
    }
    assert equal (
        hardfork-genesis-config-fields T10 | where fork == T11 | get 0.value
    ) $TEMPO_DISABLED_HARDFORK_TIME
    assert equal (
        hardfork-genesis-config-fields (latest-tempo-hardfork)
        | where value != 0 | length
    ) 0
    print "Hardfork ordering tests passed"
}
