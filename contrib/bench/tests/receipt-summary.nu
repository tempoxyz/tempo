source ../../../tempo.nu
use std/assert

let scratch = (mktemp -d)
let blocks = (1..8 | each { |number|
    {
        number: $number
        timestamp_ms: ($number * 1000)
        tx_count: 10
        gas_used: 210000
        block_time_ms: 1000
    }
})
for label in ["baseline-1" "feature-1"] {
    {blocks: $blocks samples: []} | to json | save ($scratch | path join $"report-($label).json")
}
generate-summary $scratch "same" "same" 0 "fixture" 10 8 --summary-warmup-blocks 2 | ignore
let unknown = (open ($scratch | path join summary.json))
assert equal $unknown.per_run.0.total_tx 60
assert equal $unknown.per_run.0.success_rate null
assert equal $unknown.per_run.0.receipt_unknown_tx 60
assert ((open --raw ($scratch | path join summary.md)) | str contains "Receipt outcomes are unknown")

let known_blocks = ($blocks | each { |block| $block | merge {ok_count: 8 err_count: 2} })
for label in ["baseline-1" "feature-1"] {
    {blocks: $known_blocks samples: []} | to json | save -f ($scratch | path join $"report-($label).json")
}
generate-summary $scratch "same" "same" 0 "fixture" 10 8 --summary-warmup-blocks 2 | ignore
let known = (open ($scratch | path join summary.json))
assert equal $known.per_run.0.ok 48
assert equal $known.per_run.0.err 12
assert equal $known.per_run.0.success_rate 80.0
assert equal $known.per_run.0.receipt_unknown_tx 0
assert not ((open --raw ($scratch | path join summary.md)) | str contains "Receipt outcomes are unknown")
print $"Generated summary checks passed; fixtures: ($scratch)"
