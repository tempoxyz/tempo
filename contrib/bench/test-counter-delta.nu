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

# Counter resets use the last value.
assert equal (counter-delta-total [(do $sample nonce_too_low a 1000 50.0) (do $sample nonce_too_low a 2000 5.0)] $metric $first_scrapes) 5.0
assert equal (counter-delta-total [] $metric $first_scrapes) 0.0
