# Total increase of a counter across all of its series. A series first seen after
# its node's first scrape (`first_scrape_ms_by_node`) was exported at its first
# increment, so it counts from 0.
def counter-delta-total [samples: list<any>, metric: string, first_scrape_ms_by_node: record] {
    let deltas = (
        $samples
            | where name == $metric
            | group-by { |sample| $sample.labels | to json --raw }
            | transpose labels samples
            | each { |series|
                let points = (
                    $series.samples
                        | where { |sample| ($sample | get -o value | default null) != null }
                        | sort-by unix_ms
                )
                if ($points | length) == 0 {
                    0.0
                } else {
                    let first = ($points | first)
                    let node = ($first.labels | get -o node | default "")
                    let start = if ($first.unix_ms | into int) > ($first_scrape_ms_by_node | get $node) { 0.0 } else { $first.value }
                    $points | reduce --fold {previous: $start, total: 0.0} { |point, acc|
                        let delta = ($point.value - $acc.previous)
                        let increase = if $delta >= 0 { $delta } else { $point.value }
                        {previous: $point.value, total: ($acc.total + $increase)}
                    } | get total
                }
            }
    )
    if ($deltas | length) > 0 { $deltas | math sum | math round --precision 0 } else { 0.0 }
}
