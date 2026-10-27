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
print "Preset, policy setup, state-bloat, and workload metadata checks passed"
