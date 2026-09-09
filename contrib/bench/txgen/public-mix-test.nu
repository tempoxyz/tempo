# Run from the repository root: nu contrib/bench/txgen/public-mix-test.nu
source helpers.nu
use std/assert

let preset = ($env.PWD | path join contrib/bench/txgen/presets/public-mix.yml)
let expected = {
    public_transfer: 25, public_transfer_memo: 40, public_mint: 1,
    mpp_open_only: 15, zone_deposit: 5, zone_withdraw: 4,
    vault_deposit: 6, vault_withdraw: 4
}
assert equal (open $preset).accounts.deployer.index 100002
for case in [[users portals]; [1 1] [3 2] [2 5] [100 13] [100 143]] {
    let spec = (open (txgen-prepare-public-mix-preset $preset 10000 $case.users $case.portals 1337))
    let total = ($spec.mix | get weight | math sum)
    for group in ($expected | columns) {
        let weight = ($spec.mix | where { |entry|
            let name = ($entry | get -o template | default ($entry | get -o sequence))
            $name == $group or (($name | str replace --regex '_[0-9]+$' '') == $group)
        } | get weight | math sum)
        assert equal ($weight * 100) (($expected | get $group) * $total)
    }
    let steps = $spec.setup.steps
    assert equal ($steps | get id | uniq | length) ($steps | length)
    # Fixed-nonce vault deployments precede dynamically addressed zone deployments.
    let vault_deploys = ($steps | where { |step| ($step | get -o deploy.nonce) != null })
    assert equal ($vault_deploys | get deploy.nonce) (0..11 | each { |n| $n })
    assert equal $steps.0.id authority
    let settlement_index = ($steps | get id | enumerate | where item == settlement | first | get index)
    assert ($settlement_index > ($vault_deploys | length))
    assert equal ($steps | where { |step| $step.id | str starts-with 'prepare_user_' } | length) $case.users
    assert equal ($steps | where { |step| $step.id | str starts-with 'portal_' } | length) $case.portals
    for kind in [deposit withdraw] {
        for user in 0..<$case.users {
            let template = ($spec.templates | get $"vault_($kind)_($user)")
            assert equal $template.from.select.index $user
            assert equal $template.calls.1.args.1.pool.select.index $user
        }
        # Each portal receives equal aggregate traffic within its operation group.
        mut weights = []
        for portal in 0..<$case.portals {
            let weight = ($spec.mix | where { |entry|
                let name = ($entry | get -o template | default '')
                if not ($name | str starts-with $"zone_($kind)_") { return false }
                let call = ($spec.templates | get $name | get calls | last)
                $call.args.0.var == $"setup.portal_($portal).address"
            } | get weight | math sum)
            $weights = ($weights | append $weight)
        }
        assert equal ($weights | uniq | length) 1
    }
    assert (not ('valid_for_secs' in ($spec.templates.public_mpp_open | columns)))
    assert (not ('expiring_nonce' in ($spec.templates.public_mpp_open | columns)))
    print $"PASS: ($case.users) users, ($case.portals) portals; exact mix and fixture setup"
}
assert error { txgen-prepare-public-mix-preset $preset 100 0 1 1337 }
assert error { txgen-prepare-public-mix-preset $preset 100 1 0 1337 }
assert error { txgen-prepare-public-mix-preset $preset 100 1 1 1 }
