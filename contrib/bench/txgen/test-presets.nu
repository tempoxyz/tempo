#!/usr/bin/env nu
source helpers.nu
use std/assert

let default = (txgen-resolve-bench-spec default)
let public_mix = (txgen-resolve-bench-spec public-mix)
assert equal $default $public_mix
assert equal $default.kind static
assert equal ($default.spec_path | path basename) public-mix.yml
assert equal (txgen-scenario-metadata-args default $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public-mix" "-m" "requested_preset=default"]
assert equal (txgen-scenario-metadata-args public-mix $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public-mix"]
assert equal (txgen-scenario-metadata-args public $default.spec_path) ["-m" "preset=public-mix" "-m" "scenario=public"]
assert equal (txgen-parse-tip20-scenario default) null

# Keep the old workload available only through an explicit name/scenario.
let existing = (txgen-parse-tip20-scenario tip20_existing_recipients)
assert equal $existing (txgen-parse-tip20-scenario "tip20:recipient=existing,fee-token=any_tip20")
assert equal $existing.recipient existing
assert equal $existing.fee_token any_tip20
assert equal (txgen-parse-tip20-scenario public).recipient users

# Alias resolution must retain the actual mix and state-bloat setup.
let mix = (^uv run --no-project --with yq==3.4.3 yq -c .mix $default.spec_path | from json)
assert equal ($mix | get weight | math sum) 100
txgen-configure-existing-recipients-env $default.spec_path 1000 4
txgen-configure-existing-recipients-env $default.spec_path 1024 4
assert equal ($env.TXGEN_EXISTING_RECIPIENTS_START | into int) 10000
assert (($env.TXGEN_EXISTING_RECIPIENTS_END | into int) > 10000)
assert equal (txgen-workload-metadata-args $default.scenario_id $default.spec_path) (txgen-workload-metadata-args public-mix $public_mix.spec_path)
for preset in [tip20 tip20_existing_recipients mix dex mpp neobank-deposit neobank-swap neobank-withdraw zones vault-deposit vault-withdraw bridge-mix] {
    assert equal (txgen-workload-metadata-args $preset "") ["-m" "workload_mix_weighting=gas"]
}
# The policy preset uses distinct issuer and receiver lists on the current layout.
let policy_spec = (txgen-resolve-bench-spec tip20-policy)
assert equal $policy_spec.kind static
assert ("tip20-policy" in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
assert equal (open $policy_spec.spec_path).merge.templates.tip20_transfer.fee_token (txgen-tip20-token-address 1)
let policy = (txgen-tip20-policy-calls 2 17)
assert equal ($policy.admin_calls | where function == changeTransferPolicyId | get args) [["20"] ["24"]]
assert equal ($policy.admin_calls | where function == createCompoundPolicy | get args) [[17 18 19] [21 22 23]]
assert equal ($policy.admin_calls | where function == createPolicy | length) 8
assert equal $policy.receive_call.function setReceivePolicy
assert equal $policy.receive_call.args [25 26 "0x0000000000000000000000000000000000000000"]
# Single-workload throughput presets reuse public-mix fixtures and keep their own label.
for preset in [zone-portal-throughput vault-throughput] {
    let spec = (txgen-resolve-bench-spec $preset)
    assert equal ($spec.spec_path | path basename) $"($preset).yml"
    assert ($preset in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
    assert ($preset in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
    assert equal (txgen-scenario-metadata-args $preset $spec.spec_path) ["-m" $"preset=($preset)" "-m" $"scenario=($preset)"]
    txgen-configure-existing-recipients-env $spec.spec_path 1024 4
    assert (($env.TXGEN_EXISTING_RECIPIENTS_END | into int) > 10000)
    let out_dir = (mktemp -d)
    let rendered = (txgen-prepare-public-mix-preset $spec.spec_path 1000 4 2 1337 --out-dir $out_dir)
    assert equal ($rendered | path basename) $"($preset).yml"
    hide-env TXGEN_EXISTING_RECIPIENTS_END
    txgen-configure-existing-recipients-env $rendered 1024 4
    assert (($env.TXGEN_EXISTING_RECIPIENTS_END | into int) > 10000)
    let kind = if $preset == "vault-throughput" { "vault" } else { "zone" }
    let categories = (txgen-workload-metadata-args $preset $rendered | last | str replace "workload_mix_weights=" "" | from json | columns | sort)
    assert equal $categories [$"($kind)_deposit" $"($kind)_withdraw"]
    rm -rf $out_dir
}
# Customer-shaped presets keep their own label; zone-earn-mix reuses the public-mix fixtures.
for preset in [zone-earn-mix bridge-mix] {
    let spec = (txgen-resolve-bench-spec $preset)
    assert equal ($spec.spec_path | path basename) $"($preset).yml"
    assert ($preset in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
    assert equal (txgen-scenario-metadata-args $preset $spec.spec_path) ["-m" $"preset=($preset)" "-m" $"scenario=($preset)"]
    let mix = (^uv run --no-project --with yq==3.4.3 yq -c .mix $spec.spec_path | from json)
    assert equal ($mix | get weight | math sum) 100
}
assert ("zone-earn-mix" in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
assert ("bridge-mix" not-in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
let zone_earn_dir = (mktemp -d)
let zone_earn = (txgen-prepare-public-mix-preset (txgen-resolve-bench-spec zone-earn-mix).spec_path 1000 4 2 1337 --out-dir $zone_earn_dir)
assert equal ($zone_earn | path basename) "zone-earn-mix.yml"
let zone_earn_weights = (txgen-workload-metadata-args zone-earn-mix $zone_earn | last | str replace "workload_mix_weights=" "" | from json)
assert equal ($zone_earn_weights | columns | sort) [public_transfer vault_deposit vault_withdraw zone_deposit zone_withdraw]
rm -rf $zone_earn_dir
# Gap variants: pinned portal count, single-sender settlement, fresh payees.
for preset in [zone-earn-hot zone-earn-serial zone-portal-hot bridge-mix-new-accounts card-settlement] {
    let spec = (txgen-resolve-bench-spec $preset)
    assert equal ($spec.spec_path | path basename) $"($preset).yml"
    assert ($preset in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
}
assert equal (txgen-zone-count zone-earn-hot 143) 1
assert equal (txgen-zone-count zone-portal-hot 143) 1
assert equal (txgen-zone-count zone-earn-mix 143) 143
let serial_dir = (mktemp -d)
let serial = (open (txgen-prepare-public-mix-preset (txgen-resolve-bench-spec zone-earn-serial).spec_path 1000 4 2 1337 --out-dir $serial_dir))
let serial_names = ($serial.templates | columns | where { |name| $name =~ '^(zone_withdraw|vault_deposit)_[0-9]+$' })
assert (($serial_names | length) > 0)
for name in $serial_names {
    let template = ($serial.templates | get $name)
    assert equal $template.from {pool: users, select: {index: 0}}
    assert equal $template.expiring_nonce false
}
assert equal ($serial.templates.zone_deposit_0.expiring_nonce) true
rm -rf $serial_dir
# Card settlement keeps 18 unsponsored shard senders that forward redemptions.
let card_dir = (mktemp -d)
let card = (open (txgen-prepare-public-mix-preset (txgen-resolve-bench-spec card-settlement).spec_path 1000 40 2 1337 --out-dir $card_dir))
let card_mix = ($card.mix | get template)
assert equal ($card_mix | length) 18
assert ($card_mix | all { |name| $name | str starts-with "vault_withdraw_" })
let shard = ($card.templates | get vault_withdraw_0)
assert equal ($shard | get -o sponsor) null
assert equal $shard.nonce {uniform: [0 9223372036854775807]}
assert equal ($shard.calls | last | get function) transfer
assert equal ($shard.calls | last | get args | first) $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT
rm -rf $card_dir
# The generic neobank keeps ordinary vault withdrawals alongside 18 card shards.
let neobank_dir = (mktemp -d)
let neobank_spec = (txgen-resolve-bench-spec neobank-generic)
assert ("neobank-generic" in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
assert ("neobank-generic" in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
assert equal ((^uv run --no-project --with yq==3.4.3 yq -c .mix $neobank_spec.spec_path | from json) | get weight | math sum) 100
let neobank_path = (txgen-prepare-public-mix-preset $neobank_spec.spec_path 1000 40 2 1337 --out-dir $neobank_dir)
let neobank = (open $neobank_path)
let neobank_cards = ($neobank.mix | get template | where { |name| $name | str starts-with "card_settlement_" })
assert equal ($neobank_cards | length) 18
assert equal ($neobank.mix | get template | where { |name| $name | str starts-with "vault_withdraw_" } | length) 40
assert equal ($neobank.templates.card_settlement_0.calls | last | get args | first) $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT
assert equal ($neobank.templates.vault_withdraw_0.calls | length) (($neobank.templates.card_settlement_0.calls | length) - 1)
let neobank_weights = (txgen-workload-metadata-args neobank-generic $neobank_path | last | str replace "workload_mix_weights=" "" | from json)
assert equal ($neobank_weights | columns | sort) [access_key_create access_key_rotate account_first_receive card_refund card_settlement card_spend cash_out dex_swap keychain_agent_spend keychain_merchant_pull payroll_existing payroll_new public_transfer public_transfer_memo reward_distribution vault_deposit vault_withdraw zone_deposit zone_withdraw]
assert equal ($neobank_weights.cash_out * 3) ($neobank_weights.account_first_receive * 10)
assert equal ($neobank.setup.steps | where id == authorize_keychain_users | length) 1
assert equal ($neobank.templates.payroll_existing.calls | length) 32
assert (($neobank.templates.reward_distribution.gas_limit) <= $TXGEN_HELPER_TX_GAS_LIMIT_CAP)
assert equal ($neobank.setup.steps | where id =~ "^dex_wall_" | length) 6
rm -rf $neobank_dir
# Module toggles filter neobank-generic's mix before composition; DEX and keychain setup follow it.
assert equal ($TXGEN_HELPER_NEOBANK_MODULES | values | flatten | sort) ((^uv run --no-project --with yq==3.4.3 yq -c .mix $neobank_spec.spec_path | from json) | get template | sort)
assert equal (txgen-neobank-modules "") [account deposit earn transfer spend cashout]
assert equal (txgen-neobank-modules " cashout,spend ") [spend cashout]
assert (try { txgen-neobank-modules "earn,cards"; false } catch { true })
let toggle_dir = (mktemp -d)
with-env {TXGEN_NEOBANK_MODULES: "spend,cashout"} {
    let path = (txgen-prepare-public-mix-preset $neobank_spec.spec_path 1000 40 2 1337 --out-dir $toggle_dir)
    let toggled = (open $path)
    let weights = (txgen-workload-metadata-args neobank-generic $path | last | str replace "workload_mix_weights=" "" | from json)
    assert equal ($weights | columns | sort) [card_refund card_settlement card_spend cash_out keychain_agent_spend keychain_merchant_pull]
    assert equal ($weights.cash_out * 3) ($weights.card_spend * 10)
    assert equal ($toggled.setup.steps | where id == authorize_keychain_users | length) 1
    assert equal ($toggled.setup.steps | where id =~ "^dex_wall_" | length) 0
}
with-env {TXGEN_NEOBANK_MODULES: "earn,transfer"} {
    let toggled = (open (txgen-prepare-public-mix-preset $neobank_spec.spec_path 1000 40 2 1337 --out-dir $toggle_dir))
    assert equal ($toggled.setup.steps | where id == authorize_keychain_users | length) 0
    assert equal ($toggled.setup.steps | where id =~ "^dex_wall_" | length) 6
}
with-env {TXGEN_NEOBANK_MODULES: "cards"} {
    assert (try { txgen-prepare-public-mix-preset $neobank_spec.spec_path 1000 40 2 1337 --out-dir $toggle_dir; false } catch { true })
}
rm -rf $toggle_dir
# neobank-multi: instances get disjoint users, sinks, portals and keychain setup, and
# their configured gas shares. Copied templates keep neobank-generic's u64 nonce bounds.
let multi_spec = (txgen-resolve-bench-spec neobank-multi)
assert ("neobank-multi" in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
assert ("neobank-multi" in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
let instances = (txgen-neobank-instances ($multi_spec.spec_path | path dirname | path join neobank instances.yml))
assert equal ($instances | get name) [full card-heavy payroll-earn remittance]
let multi_dir = (mktemp -d)
let multi_path = (txgen-prepare-public-mix-preset $multi_spec.spec_path 1000 40 6 1337 --out-dir $multi_dir)
assert equal ($multi_path | path basename) "neobank-multi.yml"
let multi = (open $multi_path)
let copies_path = ($multi_dir | path join neobank-multi-templates.yml)
let copies = (^uv run --no-project --with yq==3.4.3 yq -c '.templates | to_entries | map({name: .key, pool: .value.from.pool, setup: .value.auth.access_key.from_setup, text: (.value | tojson)})' $copies_path | from json)
assert ((open --raw $copies_path) =~ 'nonce: \{ uniform: \[0, 18446744073709551615\] \}')
assert ((open --raw $copies_path) =~ 'choice: \$\{TXGEN_TIP20_TOKENS\}')
mut user_end = 0
mut portals = []
for item in ($instances | enumerate) {
    let instance = $item.item
    let pool = ($multi.accounts | get $"users_($instance.id)")
    # Contiguous, disjoint slices covering every user.
    assert equal $pool.range.0 $user_end
    $user_end = $pool.range.1
    let mine = { |name| $name | str starts-with $"($instance.name)/" }
    let records = ($multi.templates | items { |name, template| {name: $name, template: $template} } | where { |entry| do $mine $entry.name })
    for entry in $records {
        let from = $entry.template.from
        if $from.pool == users {
            assert ($from.select.index >= $pool.range.0 and $from.select.index < $pool.range.1)
        } else {
            assert equal $from.pool $"treasury_($instance.id)"
        }
    }
    let own_copies = ($copies | where { |copy| do $mine $copy.name })
    assert (($own_copies | length) > 0)
    assert equal ($own_copies | get pool | uniq) [$"users_($instance.id)"]
    for copy in ($own_copies | where setup != null) {
        assert equal $copy.setup $"authorize_keychain_($instance.id)"
    }
    # Own sinks only: the instance number in the top two bytes.
    let texts = ($own_copies | get text | append ($records | each { |entry| $entry.template | to json -r }) | str join)
    for sink in $TXGEN_HELPER_NEOBANK_SINKS {
        for other in 0..<($instances | length) {
            if $other != $item.index { assert not ($texts =~ (txgen-neobank-sink $sink $other)) }
        }
        assert not ($texts =~ $sink)
    }
    if spend in $instance.modules {
        assert ($texts =~ (txgen-neobank-sink $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT $item.index))
    }
    let instance_portals = ($records | where { |entry| $entry.name =~ '/zone_deposit_' } | each { |entry| $entry.template.calls.0.to.var } | uniq)
    if deposit in $instance.modules { assert (($instance_portals | length) > 0) }
    assert (($portals | where { |portal| $portal in $instance_portals } | length) == 0)
    $portals = ($portals | append $instance_portals)
}
assert equal $user_end 40
assert equal (txgen-neobank-sink $TXGEN_HELPER_CARD_SETTLEMENT_ACCOUNT 1) "0x000200000000000000000000000000000000ca4d"
# Weight shares per instance match the configured shares; metadata reports instance/family.
let multi_weights = (txgen-workload-metadata-args neobank-multi $multi_path | last | str replace "workload_mix_weights=" "" | from json)
assert ("card-heavy/vault_deposit" in ($multi_weights | columns))
assert ($multi_weights | columns | all { |key| ($key | split row "/" | length) == 2 })
let multi_total = ($multi_weights | values | math sum)
let share_total = ($instances | get share | math sum)
for instance in $instances {
    let weight = ($multi_weights | items { |key, value| {key: $key, value: $value} } | where { |entry| $entry.key | str starts-with $"($instance.name)/" } | get value | math sum)
    assert ((($weight / $multi_total) - ($instance.share / $share_total) | math abs) < 0.000001)
}
assert equal ($multi_weights | columns | where { |key| $key starts-with "payroll-earn/" } | sort) [payroll-earn/cash_out payroll-earn/payroll_existing payroll-earn/payroll_new payroll-earn/public_transfer payroll-earn/reward_distribution payroll-earn/vault_deposit payroll-earn/vault_withdraw payroll-earn/zone_deposit]
# Only instances with delegated-key spend get keychain setup, over their own slice.
let keychain = (^uv run --no-project --with yq==3.4.3 yq -c '.append.setup.steps | map({id, pool: .keychain_authorize_pool.accounts.pool, keys: .keychain_authorize_pool.access_keys.range})' $multi_path | from json)
assert equal ($keychain | get id) [authorize_keychain_full authorize_keychain_card_heavy]
assert equal ($keychain.1.keys) ($multi.accounts.users_card_heavy.range | each { |user| $user + $TXGEN_HELPER_KEYCHAIN_ACCESS_KEYS_START })
assert equal ($multi.setup.steps | where id =~ "^dex_wall_" | length) 6
assert equal (txgen-prepare-public-mix-preset $multi_path 1000 40 6 1337) $multi_path
# Fewer portals than instances: instances share portals round-robin. Bad configs fail.
let config = ($multi_dir | path join instances.yml)
{instances: [{name: a, share: 3, modules: [deposit]} {name: b, share: 1, modules: "deposit,cashout"}]} | to yaml | save -f $config
with-env {TXGEN_NEOBANK_INSTANCES: $config} {
    let small = (open (txgen-prepare-public-mix-preset $multi_spec.spec_path 1000 8 1 1337 --out-dir $multi_dir))
    assert equal $small.accounts.users_a.range [0 5]
    assert equal $small.accounts.users_b.range [5 8]
    assert equal ($small.templates | columns | where { |name| $name =~ '/zone_deposit_' } | each { |name| ($small.templates | get $name).calls.0.to.var } | uniq) [setup.portal_0.address]
}
for bad in [[{name: Big, share: 1}] [{name: a, share: 0}] [{name: a, share: 1, modules: [cards]}] [{name: a, share: 1} {name: a, share: 1}]] {
    {instances: $bad} | to yaml | save -f $config
    with-env {TXGEN_NEOBANK_INSTANCES: $config} {
        assert (try { txgen-prepare-public-mix-preset $multi_spec.spec_path 1000 8 1 1337 --out-dir $multi_dir; false } catch { true })
    }
}
rm -rf $multi_dir
# Per-instance weight overrides: merged over neobank-generic's weights, zero drops a template.
let pipeline_dir = (mktemp -d)
let presets_dir = ($multi_spec.spec_path | path dirname)
let plain = (txgen-neobank-instances ($presets_dir | path join neobank instances-pipeline-plain-cards.yml))
assert equal ($plain | get name) [card-heavy earn-app remittance payroll-earn settlement]
assert equal ($plain | get share | math sum) 100
let base_mix = ((^uv run --no-project --with yq==3.4.3 yq -c .mix ($presets_dir | path join neobank-generic.yml)) | from json)
let card_mix = (txgen-neobank-instance-mix $base_mix ($plain | first))
assert not ("card_settlement" in ($card_mix | get template))
assert equal ($card_mix | where template == card_spend | get 0.weight) 13
assert equal ($card_mix | where template == cash_out | get 0.weight) 10
with-env {TXGEN_NEOBANK_INSTANCES: "contrib/bench/txgen/presets/neobank/instances-pipeline-plain-cards.yml"} {
    let path = (txgen-prepare-public-mix-preset $multi_spec.spec_path 1000 40 6 1337 --out-dir $pipeline_dir)
    let weights = (txgen-workload-metadata-args neobank-multi $path | last | str replace "workload_mix_weights=" "" | from json)
    assert not ("card-heavy/card_settlement" in ($weights | columns))
    assert ("card-heavy/card_spend" in ($weights | columns))
    let total = ($weights | values | math sum)
    for instance in $plain {
        let weight = ($weights | items { |key, value| {key: $key, value: $value} } | where { |entry| $entry.key | str starts-with $"($instance.name)/" } | get value | math sum)
        assert ((($weight / $total) - ($instance.share / 100) | math abs) < 0.000001)
    }
    # card-heavy drops card_settlement and the shard templates; others keep theirs.
    assert equal ((open $path).templates | columns | where { |name| $name =~ '/card_settlement_' } | length) 0
}
for bad in [{card_shards: 1} {card_spend: -1} {zone_deposit: 1}] {
    {instances: [{name: a, share: 1, modules: [spend], weights: $bad}]} | to yaml | save -f ($pipeline_dir | path join bad.yml)
    assert (try { txgen-neobank-instances ($pipeline_dir | path join bad.yml); false } catch { true })
}
{instances: [{name: a, share: 1, modules: [cashout], weights: {cash_out: 0}}]} | to yaml | save -f ($pipeline_dir | path join bad.yml)
assert (try { txgen-neobank-instance-mix $base_mix (txgen-neobank-instances ($pipeline_dir | path join bad.yml) | first); false } catch { true })
assert equal (txgen-neobank-instances ($presets_dir | path join neobank instances-pipeline.yml) | get share | math sum) 100
rm -rf $pipeline_dir
# Deployment shapes: a shapes file drives neobank-multi; each shape is one instance with
# its flows' weights, the modules its templates belong to and its peak-rate share.
let shapes_dir = (mktemp -d)
let shapes_path = ($presets_dir | path join shapes examples.yml)
let shapes = (txgen-deployment-shapes $shapes_path)
assert equal ($shapes | get name) [remittance-payout treasury-settlement card-earn-app agent-payments]
assert equal ((open $shapes_path).shapes | get pillar | sort) ($TXGEN_HELPER_SHAPE_PILLARS | sort)
let remittance = ($shapes | first)
assert equal $remittance.modules [account deposit transfer cashout]
assert equal $remittance.weights.payroll_new 10.0
assert equal $remittance.weights.zone_deposit 0
assert equal $remittance.share 9000000
assert (($remittance.peak_tps - (3000000 / 2592000 * 3) | math abs) < 0.000001)
assert equal ($shapes | where name == agent-payments | first | get modules) [account spend]
let schema = (open ($presets_dir | path join shapes schema.json))
assert equal ($schema | get '$defs'.shape.properties.flows.additionalProperties.properties.templates.items.enum | sort) ($TXGEN_HELPER_NEOBANK_MODULES | values | flatten | sort)
assert equal ($schema | get '$defs'.shape.properties.pillar.enum) $TXGEN_HELPER_SHAPE_PILLARS
let validated = (^uv run --no-project --with jsonschema==4.23.0 --with pyyaml==6.0.2 python3 -c "import json, sys, yaml, jsonschema; jsonschema.validate(yaml.safe_load(open(sys.argv[1])), json.load(open(sys.argv[2])))" $shapes_path ($presets_dir | path join shapes schema.json) | complete)
assert equal $validated.exit_code 0 $validated.stderr
with-env {TXGEN_NEOBANK_INSTANCES: "contrib/bench/txgen/presets/shapes/examples.yml"} {
    let path = (txgen-prepare-public-mix-preset $multi_spec.spec_path 1000 40 6 1337 --out-dir $shapes_dir)
    let rendered = (open $path)
    let weights = (txgen-workload-metadata-args neobank-multi $path | last | str replace "workload_mix_weights=" "" | from json)
    let total = ($weights | values | math sum)
    let share_total = ($shapes | get share | math sum)
    for shape in $shapes {
        let mine = ($weights | items { |key, value| {key: $key, value: $value} } | where { |entry| $entry.key | str starts-with $"($shape.name)/" })
        assert ((($mine | get value | math sum) / $total - ($shape.share / $share_total) | math abs) < 0.000001)
        # Only the shape's flow templates run.
        let flows = ($shape.weights | items { |template, weight| {template: $template, weight: $weight} } | where weight > 0 | get template | sort)
        assert equal ($mine | get key | each { |key| $key | split row "/" | last } | sort) $flows
    }
    assert equal ($weights | get "treasury-settlement/public_transfer_memo") (($weights | get "treasury-settlement/dex_swap") * 5 / 2)
    assert equal ($rendered.templates | columns | where { |name| $name =~ '^card-earn-app/card_settlement_' } | length) 18
    let keychain = (^uv run --no-project --with yq==3.4.3 yq -c '.append.setup.steps | map(.id)' $path | from json)
    assert equal $keychain [authorize_keychain_agent_payments]
}
for bad in [
    {name: a, pillar: retail, volume: {tx_per_month: 1}, flows: {x: {weight: 1, templates: [cash_out]}}}
    {name: a, pillar: agentic, volume: {tx_per_month: 0}, flows: {x: {weight: 1, templates: [cash_out]}}}
    {name: a, pillar: agentic, volume: {tx_per_month: 1, peak_factor: 0.5}, flows: {x: {weight: 1, templates: [cash_out]}}}
    {name: a, pillar: agentic, volume: {tx_per_month: 1}, flows: {}}
    {name: a, pillar: agentic, volume: {tx_per_month: 1}, flows: {x: {weight: 0, templates: [cash_out]}}}
    {name: a, pillar: agentic, volume: {tx_per_month: 1}, flows: {x: {weight: 1, templates: [mpp_open]}}}
    {name: a, pillar: agentic, volume: {tx_per_month: 1}, flows: {x: {weight: 1, templates: [cash_out]}}, presets: [no-such-preset]}
    {name: Big, pillar: agentic, volume: {tx_per_month: 1}, flows: {x: {weight: 1, templates: [cash_out]}}}
] {
    {version: 1, shapes: [$bad]} | to yaml | save -f ($shapes_dir | path join bad.yml)
    assert (try { txgen-neobank-instances ($shapes_dir | path join bad.yml); false } catch { true })
}
rm -rf $shapes_dir
# projected-pipeline: a neobank-multi style preset whose default shapes file is the pipeline
# by pillar, so the preset name alone selects it (multi-region runs pass no env).
let projected_spec = (txgen-resolve-bench-spec projected-pipeline)
for list in [$TXGEN_HELPER_PUBLIC_MIX_PRESETS $TXGEN_HELPER_ALWAYS_FUND_PRESETS ($TXGEN_HELPER_NEOBANK_MULTI_PRESETS | columns)] {
    assert ("projected-pipeline" in $list)
}
let pipeline = (txgen-deployment-shapes ($presets_dir | path join shapes pipeline.yml))
assert equal ($pipeline | get name) [embedded-finance cross-border institutional]
assert (((($pipeline | get peak_tps | math sum) - (2652435 / 2592000 * 84)) | math abs) < 0.000001)
let projected_dir = (mktemp -d)
let projected_path = (txgen-prepare-public-mix-preset $projected_spec.spec_path 1000 40 6 1337 --out-dir $projected_dir)
assert equal ($projected_path | path basename) "projected-pipeline.yml"
let projected_weights = (txgen-workload-metadata-args projected-pipeline $projected_path | last | str replace "workload_mix_weights=" "" | from json)
let projected_total = ($projected_weights | values | math sum)
for shape in $pipeline {
    let weight = ($projected_weights | items { |key, value| {key: $key, value: $value} } | where { |entry| $entry.key | str starts-with $"($shape.name)/" } | get value | math sum)
    assert ((($weight / $projected_total) - ($shape.share / ($pipeline | get share | math sum)) | math abs) < 0.000001)
}
rm -rf $projected_dir
# Batch payouts: a 16-sender treasury pays 32 recipients per transaction (the txpool's
# call limit); reward batches stop at 16 Earn deposits to fit the transaction gas cap.
let batch_dir = (mktemp -d)
let batch_spec = (txgen-resolve-bench-spec batch-payout)
assert ("batch-payout" in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
assert ("batch-payout" in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
let batch_path = (txgen-prepare-public-mix-preset $batch_spec.spec_path 1000 40 2 1337 --out-dir $batch_dir)
let batch = (open $batch_path)
assert equal ($batch.mix | get template) [payroll_existing payroll_new reward_distribution]
assert equal ($batch.templates.payroll_existing.calls | length) 32
assert equal $batch.templates.payroll_existing.gas_limit 1140000
assert equal ($batch.templates.payroll_new.calls | length) 32
assert equal ($batch.templates.payroll_new.calls | get args | uniq) [[random 1]]
let reward = $batch.templates.reward_distribution
assert equal ($reward.calls | length) 17
assert equal ($reward.calls.0.args.1) 16000000
assert ($reward.gas_limit <= $TXGEN_HELPER_TX_GAS_LIMIT_CAP)
let batch_weights = (txgen-workload-metadata-args batch-payout $batch_path | last | str replace "workload_mix_weights=" "" | from json)
assert equal ($batch_weights | columns | sort) [payroll_existing payroll_new reward_distribution]
with-env {TXGEN_BATCH_PAYOUT_RECIPIENTS: "8"} {
    let small = (open (txgen-prepare-public-mix-preset $batch_spec.spec_path 1000 40 2 1337 --out-dir $batch_dir))
    assert equal ($small.templates.payroll_new.calls | length) 8
    assert equal ($small.templates.payroll_new.gas_limit) 2740000
    assert equal ($small.templates.reward_distribution.calls | length) 9
}
rm -rf $batch_dir
# The access-key mix authorises keys in setup and inline, and pays one merchant account.
let access_spec = (txgen-resolve-bench-spec access-key-mix)
assert equal $access_spec.kind static
assert equal $access_spec.requires_keychain_setup true
assert equal (txgen-workload-metadata-args access-key-mix $access_spec.spec_path) ["-m" "workload_mix_weighting=gas"]
let access = (^uv run --no-project --with yq==3.4.3 yq -c '{mix, templates}' $access_spec.spec_path | from json)
assert equal ($access.mix | get weight | math sum) 100
assert equal ($access.mix | get template | sort) [access_key_create access_key_rotate keychain_agent_spend keychain_merchant_pull]
for name in [access_key_create access_key_rotate] {
    assert equal ($access.templates | get $name | get auth.mode) key_authorization
}
for name in [keychain_merchant_pull keychain_agent_spend] {
    assert equal ($access.templates | get $name | get auth.access_key.from_setup) authorize_keychain_users
}
assert equal ($access.templates.keychain_merchant_pull.call.args | first) "0x0000000000000000000000000000000000005e77"
# Zone -> zone: a ring of callback portals, warmed in setup; closed access returns one unit to the source.
for preset in [zone-to-zone zone-to-zone-hot] {
    let spec = (txgen-resolve-bench-spec $preset)
    assert equal ($spec.spec_path | path basename) $"($preset).yml"
    assert ($preset in $TXGEN_HELPER_ZONE_TO_ZONE_PRESETS)
    assert ($preset in $TXGEN_HELPER_ALWAYS_FUND_PRESETS)
    assert ($preset not-in $TXGEN_HELPER_PUBLIC_MIX_PRESETS)
}
let z2z_dir = (mktemp -d)
let z2z_spec = (txgen-resolve-bench-spec zone-to-zone).spec_path
let z2z = (open (txgen-prepare-zone-to-zone-preset $z2z_spec 100 4 3 --out-dir $z2z_dir))
let portals = ($z2z.setup.steps | where id =~ '^portal_')
assert equal ($portals | get id) [portal_0 portal_1 portal_2]
assert ($portals | all { |step| ($step.deploy.constructor_args | last) == true })
assert equal ($z2z.setup.steps | where id =~ '^warm_' | length) 3
assert equal ($z2z.setup.steps | where id == fund_0 | first | get tx.calls.0.args.1) 306
assert equal ($z2z.mix | get template) [zone_to_zone_0 zone_to_zone_1 zone_to_zone_2 zone_to_zone_3]
let ring = ($z2z.templates | values | each { |template| $template.calls.0.args | first 2 | each { |arg| $arg.var } })
assert equal $ring.0 [setup.portal_0.address setup.portal_1.address]
assert equal $ring.2 [setup.portal_2.address setup.portal_0.address]
assert equal $ring.3 [setup.portal_0.address setup.portal_1.address]
assert equal ($z2z.templates.zone_to_zone_0.calls.0.args | last 2) [1 $TXGEN_HELPER_ZONE_TO_ZONE_CALLBACK_GAS]
assert equal $z2z.templates.zone_to_zone_0.gas_limit $TXGEN_HELPER_ZONE_TO_ZONE_GAS_LIMIT
assert equal $z2z.templates.zone_to_zone_0.expiring_nonce true
assert equal $z2z.templates.zone_to_zone_0.valid_for_secs $TXGEN_HELPER_ZONE_TO_ZONE_VALID_FOR_SECS
assert equal $z2z.templates.zone_to_zone_0.nonce {uniform: [0 9223372036854775807]}
# Equal aggregate weight per source portal: portal 0's two users split its share.
assert equal ($z2z.mix | get weight) [100 200 200 100]
let hot = (open (txgen-prepare-zone-to-zone-preset (txgen-resolve-bench-spec zone-to-zone-hot).spec_path 100 4 9 --hot --out-dir $z2z_dir))
assert equal ($hot.setup.steps | where id =~ '^portal_' | length) 2
assert equal ($hot.setup.steps | where id =~ '^(fund|warm)_' | get id) [fund_0 warm_0]
assert ($hot.templates | values | all { |template|
    ($template.calls.0.args | first 2 | each { |arg| $arg.var }) == [setup.portal_0.address setup.portal_1.address]
})
with-env {TXGEN_ZONE_TO_ZONE_ACCESS: open, TXGEN_ZONE_TO_ZONE_SHARE: "60"} {
    let open_mix = (open (txgen-prepare-zone-to-zone-preset $z2z_spec 100 2 2 --out-dir $z2z_dir))
    assert (($open_mix.setup.steps | where id =~ '^portal_') | all { |step| ($step.deploy.constructor_args | last) == false })
    assert equal ($open_mix.templates.zone_to_zone_0.calls.0.args | get 4) 0
    assert equal ($open_mix.mix | get weight) [120 80 120 80]
    assert equal ($open_mix.templates.zone_withdraw_1.calls.0.args.2) {pool: {pool: users, select: {index: 1}}}
    assert equal $open_mix.templates.zone_withdraw_1.nonce {uniform: [0 9223372036854775807]}
    assert equal ($open_mix.setup.steps | where id == warm_0 | first | get tx.calls | length) 2
}
with-env {TXGEN_ZONE_TO_ZONE_SHARE: "60"} {
    let closed_mix = (open (txgen-prepare-zone-to-zone-preset $z2z_spec 100 2 2 --out-dir $z2z_dir))
    assert equal ($closed_mix.templates.zone_withdraw_0.calls.0.args.2) {var: setup.settlement.sender}
}
with-env {TXGEN_ZONE_TO_ZONE_ACCESS: gated} {
    assert ((try { txgen-zone-to-zone-config; false } catch { true }))
}
rm -rf $z2z_dir
# Receipt tally: the transfer marker plus WithdrawalProcessed(callbackSuccess) per receipt.
let processed = { |ok| {topics: [$TXGEN_HELPER_WITHDRAWAL_PROCESSED_TOPIC], data: $"0x(if $ok { '01' } else { '00' })"} }
let marker = {topics: [$TXGEN_HELPER_ZONE_TO_ZONE_TRANSFER_TOPIC], data: "0x"}
let tally = (txgen-zone-to-zone-tally [
    {status: "0x1", gasUsed: "0x5a550", logs: [(do $processed true) $marker]}
    {status: "0x1", gasUsed: "0x186a0", logs: [(do $processed false) $marker]}
    {status: "0x1", gasUsed: "0x30d40", logs: [(do $processed true)]}
    {status: "0x0", gasUsed: "0x10", logs: []}
])
assert equal $tally {transfers: 2, delivered: 1, bounced: 1, plain_withdrawals: 1, reverted: 1, transfer_gas: 470000}
# bench-env TXGEN_* values are read as bash's export reads them (quotes stripped, $VAR expanded).
with-env {TXGEN_TEST_BASE: "/x"} {
    assert equal (txgen-bench-env-txgen-vars "") {}
    assert equal (txgen-bench-env-txgen-vars "TXGEN_NEOBANK_MODULES='spend,cashout' BENCH_TPS_SCHEDULE=200:30s TXGEN_ZONE_COUNT=\"8\" TXGEN_NEOBANK_INSTANCES=$TXGEN_TEST_BASE/i.yml") {TXGEN_NEOBANK_MODULES: "spend,cashout", TXGEN_ZONE_COUNT: "8", TXGEN_NEOBANK_INSTANCES: "/x/i.yml"}
}
print "Preset, policy setup, state-bloat, and workload metadata checks passed"
