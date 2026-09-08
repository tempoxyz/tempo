# Receipt counts are optional in txgen reports. Submission success and builder
# revert observations do not establish canonical block receipt outcomes.
def receipt-outcomes [blocks: list<any>] {
    let counts = ($blocks | each { |block|
        let tx = $block.tx_count
        let ok = ($block | get -o ok_count)
        let err = ($block | get -o err_count)
        let valid = if $ok == null and $err == null and $tx == 0 {
            true
        } else if ($ok | describe) != "int" or ($err | describe) != "int" {
            false
        } else {
            $ok >= 0 and $err >= 0 and ($ok + $err) == $tx
        }
        {
            tx: $tx
            valid: $valid
            known: (if $valid { $tx } else { 0 })
            unknown: (if $valid { 0 } else { $tx })
            ok: (if $valid { $ok | default 0 } else { 0 })
            err: (if $valid { $err | default 0 } else { 0 })
        }
    })
    let total = ($counts | get tx | prepend 0 | math sum)
    let known = ($counts | get known | prepend 0 | math sum)
    let unknown = ($counts | get unknown | prepend 0 | math sum)
    let ok = ($counts | get ok | prepend 0 | math sum)
    let err = ($counts | get err | prepend 0 | math sum)
    let complete = ($counts | all { |count| $count.valid })
    {
        receipt_outcomes_complete: $complete
        receipt_known_tx: $known
        receipt_unknown_tx: $unknown
        ok: (if $complete { $ok } else { null })
        err: (if $complete { $err } else { null })
        success_rate: (if $complete and $total > 0 {
            100.0 * $ok / $total | math round --precision 1
        } else { null })
    }
}
