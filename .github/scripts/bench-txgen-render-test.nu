# Run from the repository root: nu .github/scripts/bench-txgen-render-test.nu
use std/assert

def render [preset: string, output: string, accounts: int = 3] {
    let result = (^nu --no-config-file bench-e2e.nu render-txgen-spec
        --preset $preset --accounts $accounts --tps 50000 --duration 30
        --out-dir $output | complete)
    assert equal $result.exit_code 0 $result.stderr
    let path = ($result.stdout | str trim)
    assert equal ($path | path dirname) $output
    open $path
}

def main [] {
    let output = ([($env.PWD) .bench-tmp $"render-test-(random uuid)"] | path join)
    for case in [{accounts: 3, zones: 2, steps: 31} {accounts: 1000, zones: 715, steps: 3451}] {
        with-env {TXGEN_ZONE_COUNT: ($case.zones | into string)} {
            let spec = (render public-mix $output $case.accounts)
            assert equal ($spec.setup.steps | length) $case.steps
            assert equal ($spec.setup.steps.id | uniq | length) $case.steps
            let total = ($spec.mix.weight | math sum)
            for category in [
                {name: public_transfer, weight: 25}
                {name: public_transfer_memo, weight: 40}
                {name: public_mint, weight: 1}
                {name: mpp_open_only, weight: 15}
                {name: zone_deposit, weight: 5}
                {name: zone_withdraw, weight: 4}
                {name: vault_deposit, weight: 6}
                {name: vault_withdraw, weight: 4}
            ] {
                let weight = ($spec.mix | where { |entry|
                    let name = ($entry | get -o template | default ($entry | get -o sequence))
                    ($name | str replace --regex '_[0-9]+$' '') == $category.name
                } | get weight | math sum)
                assert equal ($weight * 100) ($total * $category.weight)
            }
            # Receipt dependencies must survive fixture composition.
            for step in ($spec.setup.steps | where { |step| ($step | get -o depends_on) != null }) {
                for dependency in $step.depends_on {
                    assert ($dependency in $spec.setup.steps.id)
                }
            }
            assert equal ($spec.setup.steps | where { |step| ($step | get -o depends_on) != null } | length) 4
        }
    }
    for preset in [vault-deposit vault-withdraw] {
        let spec = (render $preset $output)
        assert equal ($spec.append.setup.steps | length) 3
        assert equal ($spec.mix | length) 3
    }
    for case in [{mode: mixed, templates: 6, steps: 8} {mode: deposit, templates: 3, steps: 8} {mode: withdraw, templates: 3, steps: 5}] {
        with-env {TXGEN_ZONE_COUNT: "2", TXGEN_ZONE_MODE: $case.mode} {
            let spec = (render zones $output)
            assert equal ($spec.mix | length) $case.templates
            assert equal ($spec.setup.steps | length) $case.steps
        }
    }
    # Rendering must reject unsupported fixture inputs before any node is started.
    for args in [[--accounts 0] [--chain-id 1] [--tps 0] [--duration 0]] {
        let result = (^nu --no-config-file bench-e2e.nu render-txgen-spec --preset public-mix ...$args | complete)
        assert ($result.exit_code != 0)
    }
    with-env {TXGEN_ZONE_COUNT: "0"} {
        let result = (^nu --no-config-file bench-e2e.nu render-txgen-spec --preset public-mix | complete)
        assert ($result.exit_code != 0)
    }
    let static = (^nu --no-config-file bench-e2e.nu render-txgen-spec --preset neobank-withdraw | str trim)
    assert equal $static ([($env.PWD) contrib/bench/txgen/presets/neobank-withdraw.yml] | path join)
    let tip20 = (^nu --no-config-file bench-e2e.nu render-txgen-spec --preset tip20 --out-dir $output | str trim | open)
    assert (($tip20.include | length) > 0)
    rm -r $output
    print "Renderer checks passed"
}
