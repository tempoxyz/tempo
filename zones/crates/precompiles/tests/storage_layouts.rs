//! Programmatic conformance tests for Solidity and native Rust storage layouts.

use super::artifact;
use tempo_precompiles::{
    test_util::storage_conformance::{
        RustStorageField, RustStorageSlot, assert_foundry_slots, compare_layouts,
        compare_struct_members, load_solc_layout, panic_layout_mismatch,
    },
    zone_factory::portal,
};
use tempo_precompiles_macros::{
    gen_test_fields_layout as layout_fields, gen_test_fields_struct as struct_fields,
};

fn assert_native_layout(schema: &str, rust: &[RustStorageField]) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/solidity")
        .join(schema);
    let solidity = load_solc_layout(&path);
    if let Err(errors) = compare_layouts(&solidity, rust) {
        panic_layout_mismatch("Storage layout", errors, &path);
    }
}

#[test]
fn zone_portal_slot_constants_match_solidity() {
    let fields = [
        ("admin", portal::slots::ADMIN),
        (
            "currentDepositQueueHash",
            portal::slots::CURRENT_DEPOSIT_QUEUE_HASH,
        ),
        ("_encryptionKeys", portal::slots::ENCRYPTION_KEYS),
        ("_tokenConfigs", portal::slots::TOKEN_CONFIGS),
        ("role", portal::slots::ROLE),
        ("_isAccessEnforced", portal::slots::IS_ACCESS_ENFORCED),
        ("_isGatewayEnforced", portal::slots::IS_GATEWAY_ENFORCED),
        ("maxTempoGasRate", portal::slots::MAX_TEMPO_GAS_RATE),
        ("pauseExpiry", portal::slots::PAUSE_EXPIRY),
        ("tokenEnablementHash", portal::slots::TOKEN_ENABLEMENT_HASH),
        (
            "abdicationEffectiveAt",
            portal::slots::ABDICATION_EFFECTIVE_AT,
        ),
    ]
    .map(|(name, slot)| RustStorageSlot::new(name, slot));
    assert_foundry_slots(&artifact("ZonePortal"), &fields);
}

#[test]
fn tempo_state_layout_matches_solidity() {
    use zone_precompiles::tempo_state::slots;
    let fields = layout_fields!(tempo_block_hash, tempo_block_number);
    assert_native_layout("tempo_state.sol", &fields);
}

#[test]
fn zone_inbox_layout_matches_solidity() {
    use zone_precompiles::inbox::slots;
    let fields = layout_fields!(
        processed_deposit_queue_hash,
        processed_deposit_number,
        withdrawal_bounce_backs,
        processed_token_enablement_hash
    )
    .into_iter()
    .map(|field| match field.name {
        "withdrawalBounceBacks" => field.solidity_name("_refunds"),
        _ => field,
    })
    .collect::<Vec<_>>();
    assert_native_layout("zone_inbox.sol", &fields);
}

#[test]
fn zone_outbox_layout_matches_solidity() {
    use zone_precompiles::outbox::slots;
    let fields = layout_fields!(
        tempo_gas_rate,
        next_withdrawal_index,
        withdrawal_queue_hash,
        withdrawal_batch_index,
        max_withdrawals_per_block,
        withdrawals_this_block,
        current_block_number,
        last_finalized_timestamp,
        pending_withdrawals,
        last_fallback_nonce,
        fallback_recipients
    )
    .into_iter()
    .map(|field| match field.name {
        "withdrawalQueueHash" => field.solidity_name("_withdrawalQueueHash"),
        "withdrawalBatchIndex" => field.solidity_name("_withdrawalBatchIndex"),
        "withdrawalsThisBlock" => field.solidity_name("_withdrawalsThisBlock"),
        "currentBlockNumber" => field.solidity_name("_currentBlockNumber"),
        "pendingWithdrawals" => field.solidity_name("_pendingWithdrawals"),
        "fallbackRecipients" => field.solidity_name("_zoneFallbackRecipients"),
        _ => field,
    })
    .collect::<Vec<_>>();
    assert_native_layout("zone_outbox.sol", &fields);

    use zone_precompiles::outbox::__packing_pending_withdrawal::*;
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/solidity/zone_outbox.sol");
    let solidity = load_solc_layout(&path);
    let pending = struct_fields!(
        slots::PENDING_WITHDRAWALS,
        token,
        sender,
        tx_hash,
        to,
        amount,
        memo,
        gas_limit,
        fallback_nonce,
        callback_data,
        reveal_to
    );
    if let Err(errors) = compare_struct_members(&solidity, "_pendingWithdrawals", &pending) {
        panic_layout_mismatch("PendingWithdrawal layout", errors, &path);
    }
}
