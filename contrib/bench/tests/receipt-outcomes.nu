source ../receipt-outcomes.nu
use std/assert

let absent = (receipt-outcomes [{tx_count: 10}])
assert equal $absent.ok null
assert equal $absent.err null
assert equal $absent.success_rate null
assert equal $absent.receipt_unknown_tx 10

let known = (receipt-outcomes [{tx_count: 10 ok_count: 8 err_count: 2}])
assert equal $known.ok 8
assert equal $known.err 2
assert equal $known.success_rate 80.0
assert $known.receipt_outcomes_complete

let partial = (receipt-outcomes [
    {tx_count: 10 ok_count: 8 err_count: 2}
    {tx_count: 5}
])
assert equal $partial.receipt_known_tx 10
assert equal $partial.receipt_unknown_tx 5
assert equal $partial.success_rate null

for bad in [
    {tx_count: 10 ok_count: 10}
    {tx_count: 10 ok_count: 8 err_count: 1}
    {tx_count: 10 ok_count: -1 err_count: 11}
    {tx_count: 10 ok_count: "8" err_count: 2}
    {tx_count: 10 ok_count: 8.0 err_count: 2}
] {
    let outcome = (receipt-outcomes [$bad])
    assert equal $outcome.success_rate null
    assert equal $outcome.receipt_unknown_tx 10
}

for empty in [[] [{tx_count: 0}]] {
    let outcome = (receipt-outcomes $empty)
    assert equal $outcome.ok 0
    assert equal $outcome.success_rate null
    assert $outcome.receipt_outcomes_complete
}
let inconsistent_empty = (receipt-outcomes [
    {tx_count: 0 ok_count: 1 err_count: 0}
    {tx_count: 10 ok_count: 10 err_count: 0}
])
assert not $inconsistent_empty.receipt_outcomes_complete
assert equal $inconsistent_empty.success_rate null
print "Receipt outcome checks passed"
