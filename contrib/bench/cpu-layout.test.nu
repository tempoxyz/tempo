use std assert
use cpu-layout.nu *

let topology = (0..<32 | each { |cpu| {cpu: $cpu, core: ($cpu mod 16 | into string), socket: '0', online: true} })
let a = '0-7,16-23'
let b = '8-15,24-31'

assert equal (expand-cpu-list '3,1-2,2') [1 2 3]
for cores in [0 2 4 6 8 10 12 14] {
    let layout = (bench-cpu-layout $a $b $cores $topology)
    assert equal $layout.validator_cores [(8 - $cores // 2) (8 - $cores // 2)]
    let a_ids = (expand-cpu-list $layout.a)
    let b_ids = (expand-cpu-list $layout.b)
    let tx_ids = if $cores == 0 { [] } else { expand-cpu-list $layout.txgen }
    assert equal ($tx_ids | length) ($cores * 2)
    assert equal ([$a_ids $b_ids $tx_ids] | flatten | sort) (0..<32 | each { $in })
    for ids in [$a_ids $b_ids $tx_ids] {
        for cpu in $ids { assert (($cpu + 16) mod 32 in $ids) }
    }
}
let four = (bench-cpu-layout $a $b 4 $topology)
assert equal $four.a '0,1,2,3,4,5,16,17,18,19,20,21'
assert equal $four.b '8,9,10,11,12,13,24,25,26,27,28,29'
assert equal $four.txgen '6,7,14,15,22,23,30,31'
for invalid in [-2 -1 1 3 16 18] {
    assert error { bench-cpu-layout $a $b $invalid $topology }
}
assert error { bench-cpu-layout $a $a 4 $topology }
assert error { bench-cpu-layout '0-15' '16-31' 4 $topology }
assert error { bench-cpu-layout $a $b 4 ($topology | where cpu != 31) }
assert error { bench-cpu-layout $a $b 4 ($topology | update 31 {cpu: 31, core: '15', socket: '0', online: false}) }
assert error { bench-cpu-layout $a $b 4 ($topology | append $topology.0) }
assert error { bench-cpu-layout $a $b 4 ($topology | update 31 {cpu: 31, core: '15', socket: '0', online: true, allowed: false}) }

# Socket-local core IDs must not merge unrelated cores.
let sockets = ($topology | each { |row| $row | update socket ($row.cpu mod 16 // 8 | into string) | update core ($row.cpu mod 8 | into string) })
assert equal (bench-cpu-layout $a $b 4 $sockets) $four
# Non-SMT hosts and non-contiguous numbering work without assuming +16 siblings.
let single_threaded = (0..<16 | each { |cpu| {cpu: ($cpu * 2), core: ($cpu | into string), socket: '0', online: true} })
let single = (bench-cpu-layout '0,2,4,6,8,10,12,14' '16,18,20,22,24,26,28,30' 4 $single_threaded)
assert equal $single.txgen '12,14,28,30'
print 'CPU layout tests passed'
