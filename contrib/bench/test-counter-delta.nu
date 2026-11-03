#!/usr/bin/env nu
source counter-delta.nu
use std/assert

let metric = "reth_tempo_payload_builder_pool_transactions_skipped_total"
let sample = { |reason: string, node: string, unix_ms: int, value: float|
    { name: $metric, labels: { node: $node, reason: $reason }, value: $value, unix_ms: $unix_ms }
}

# Series present at their node's first scrape start from their first value;
# series first exported mid-run start from 0.
let first_scrapes = { a: 1000, b: 1005 }
let samples = [
    (do $sample nonce_too_low a 1000 100.0)
    (do $sample nonce_too_low a 2000 130.0)
    (do $sample nonce_too_low b 1005 20.0)
    (do $sample nonce_too_low b 2005 25.0)
    (do $sample invalid_tx b 3000 4390.0)
    (do $sample invalid_tx b 4000 4390.0)
    (do $sample invalid_tx a 3000 6.0)
    (do $sample invalid_tx a 4000 132.0)
]
assert equal (counter-delta-total $samples $metric $first_scrapes) 4557.0
assert equal (counter-delta-total ($samples | where { |s| $s.labels.reason == nonce_too_low }) $metric $first_scrapes) 35.0

# A reset contributes the new value after the reset.
assert equal (counter-delta-total [(do $sample nonce_too_low a 1000 50.0) (do $sample nonce_too_low a 2000 5.0)] $metric $first_scrapes) 5.0
assert equal (counter-delta-total [] $metric $first_scrapes) 0.0

let reset_cases = [
    {name: monotonic, values: [100.0 130.0 150.0], start_ms: 1000, expected: 50.0}
    {name: intermediate_reset, values: [100.0 120.0 5.0 15.0], start_ms: 1000, expected: 35.0}
    {name: reset_catches_up, values: [10.0 15.0 0.0 20.0], start_ms: 1000, expected: 25.0}
    {name: repeated_resets, values: [10.0 30.0 2.0 5.0 1.0 6.0], start_ms: 1000, expected: 31.0}
    {name: first_seen_mid_run, values: [100.0 130.0], start_ms: 2000, expected: 130.0}
    {name: mid_run_then_reset, values: [100.0 120.0 5.0 15.0], start_ms: 2000, expected: 135.0}
    {name: unchanged, values: [10.0 10.0 10.0], start_ms: 1000, expected: 0.0}
    {name: reset_to_zero, values: [10.0 0.0], start_ms: 1000, expected: 0.0}
    {name: initial_single_sample, values: [7.0], start_ms: 1000, expected: 0.0}
    {name: late_single_sample, values: [7.0], start_ms: 2000, expected: 7.0}
    {name: late_repeated_resets, values: [10.0 30.0 2.0 5.0 1.0 6.0], start_ms: 2000, expected: 41.0}
]

for case in $reset_cases {
    let points = ($case.values | enumerate | each { |point|
        do $sample invalid_tx a ($case.start_ms + $point.index * 1000) $point.item
    })
    assert equal (counter-delta-total $points $metric $first_scrapes) $case.expected $case.name
    assert equal (counter-delta-total ($points | reverse) $metric $first_scrapes) $case.expected $"($case.name), unordered"
}

# Each label set has its own baseline and resets. Round after summing series.
let independent_series = [
    (do $sample invalid_tx a 1000 100.0)
    (do $sample invalid_tx a 2000 120.0)
    (do $sample invalid_tx a 3000 5.0)
    (do $sample invalid_tx a 4000 15.0)
    (do $sample nonce_too_low a 1000 1.0)
    (do $sample nonce_too_low a 2000 1.7)
    (do $sample nonce_too_low b 1005 5.0)
    (do $sample nonce_too_low b 2005 5.7)
]
assert equal (counter-delta-total $independent_series $metric $first_scrapes) 36.0
let fractional_series = ($independent_series | where { |point| $point.labels.reason == nonce_too_low })
assert equal (counter-delta-total $fractional_series $metric $first_scrapes) 1.0
assert equal (counter-delta-total ($independent_series | reverse) $metric $first_scrapes) 36.0

# Null samples and unrelated metrics do not change the observed counter deltas.
let ignored_points = ($independent_series | append [
    {name: $metric, labels: {node: a, reason: invalid_tx}, unix_ms: 2500, value: null}
    {name: other_metric, labels: {node: a, reason: invalid_tx}, unix_ms: 5000, value: 999.0}
])
assert equal (counter-delta-total $ignored_points $metric $first_scrapes) 36.0
assert equal (counter-delta-total [
    {name: $metric, labels: {node: a}, unix_ms: 1000, value: null}
] $metric $first_scrapes) 0.0
