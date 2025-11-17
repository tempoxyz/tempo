//! Tests for actual precompile contract storage layouts.
//!
//! This module verifies that the storage layouts of production precompile contracts
//! match their Solidity equivalents, ensuring compatibility with the EVM.
//!
//! Individual tests load storage layouts from the cached snapshot and compare them
//! against solc-generated Solidity layouts.

use super::*;
use utils::*;

#[test]
fn test_tip20_factory_layout() {
    let solc_layout = load_solc_layout(&testdata("tip20_factory.sol"));
    let rust_layout = load_rust_layout_from_snapshot("tip20_factory")
        .expect("Failed to load tip20_factory layout from snapshot");

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_tip20_rewards_registry_layout() {
    let solc_layout = load_solc_layout(&testdata("tip20_rewards_registry.sol"));
    let rust_layout = load_rust_layout_from_snapshot("tip20_rewards_registry")
        .expect("Failed to load tip20_rewards_registry layout from snapshot");

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_tip403_registry_layout() {
    let solc_layout = load_solc_layout(&testdata("tip403_registry.sol"));

    // Verify top-level fields
    let rust_layout = load_rust_layout_from_snapshot("tip403_registry")
        .expect("Failed to load tip403_registry layout from snapshot");
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify `PolicyData` struct members
    let rust_struct = load_rust_struct_from_snapshot("tip403_registry", "policyData")
        .expect("Failed to load policyData struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "policyData", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_fee_manager_layout() {
    let solc_layout = load_solc_layout(&testdata("fee_manager.sol"));

    // Verify top-level fields
    let rust_layout = load_rust_layout_from_snapshot("tip_fee_manager")
        .expect("Failed to load tip_fee_manager layout from snapshot");
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify `Pool` struct members
    let rust_struct = load_rust_struct_from_snapshot("tip_fee_manager", "pools")
        .expect("Failed to load pools struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "pools", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_stablecoin_exchange_layout() {
    let solc_layout = load_solc_layout(&testdata("stablecoin_exchange.sol"));

    // Verify top-level fields
    let rust_layout = load_rust_layout_from_snapshot("stablecoin_exchange")
        .expect("Failed to load stablecoin_exchange layout from snapshot");
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify `Order` struct members
    let rust_order = load_rust_struct_from_snapshot("stablecoin_exchange", "orders")
        .expect("Failed to load orders struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "orders", &rust_order) {
        panic!(
            "Order struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }

    // Verify `Orderbook` struct members
    let rust_orderbook = load_rust_struct_from_snapshot("stablecoin_exchange", "books")
        .expect("Failed to load books struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "books", &rust_orderbook) {
        panic!(
            "Orderbook struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn test_tip20_layout() {
    let solc_layout = load_solc_layout(&testdata("tip20.sol"));

    // Verify top-level fields
    let rust_layout =
        load_rust_layout_from_snapshot("tip20").expect("Failed to load tip20 layout from snapshot");
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify `RewardStream` struct members
    let rust_stream = load_rust_struct_from_snapshot("tip20", "streams")
        .expect("Failed to load streams struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "streams", &rust_stream) {
        panic!(
            "RewardStream struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }

    // Verify `UserRewardInfo` struct members
    let rust_user_info = load_rust_struct_from_snapshot("tip20", "userRewardInfo")
        .expect("Failed to load userRewardInfo struct from snapshot");
    if let Err(errors) = compare_struct_members(&solc_layout, "userRewardInfo", &rust_user_info) {
        panic!(
            "UserRewardInfo struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }
}

/// Validates storage layout consistency across changes.
///
/// This test ensures that storage layouts haven't changed unexpectedly by comparing
/// the current layout against a committed snapshot. This is critical for maintaining
/// storage compatibility and preventing accidental breaking changes.
///
/// This is the ONLY test that constructs Rust storage layouts using macros. All other
/// individual precompile tests load layouts from the snapshot generated by this test.
///
/// If storage layouts change intentionally, regenerate the snapshot:
/// ```bash
/// REGENERATE_SNAPSHOT=true cargo test -p tempo-precompiles validate_precompiles_storage_snapshot
/// ```
#[test]
fn validate_precompiles_storage_snapshot() {
    use serde_json::{Value, json};
    use std::fs;
    use tempo_precompiles_macros::{
        gen_test_fields_layout as layout_fields, gen_test_fields_struct as struct_fields,
    };

    let mut all_constants = serde_json::Map::new();

    // Helper to convert RustStorageField to JSON
    let field_to_json = |field: &utils::RustStorageField| {
        json!({
            "name": field.name,
            "slot": format!("{:#x}", field.slot),
            "offset": field.offset,
            "bytes": field.bytes
        })
    };

    // TIP20 Factory
    {
        use tempo_precompiles::tip20_factory::slots;
        let fields = layout_fields!(token_id_counter);
        all_constants.insert(
            "tip20_factory".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>()
            }),
        );
    }

    // TIP20 Rewards Registry
    {
        use tempo_precompiles::tip20_rewards_registry::slots;
        let fields = layout_fields!(last_updated_timestamp, streams_ending_at, stream_index);
        all_constants.insert(
            "tip20_rewards_registry".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>()
            }),
        );
    }

    // TIP403 Registry
    {
        use tempo_precompiles::tip403_registry::{__packing_policy_data::*, slots};

        let fields = layout_fields!(policy_id_counter, policy_data, policy_set);
        let base_slot = slots::POLICY_DATA;
        let policy_data_struct = struct_fields!(base_slot, policy_type, admin);

        all_constants.insert(
            "tip403_registry".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>(),
                "structs": {
                    "policyData": policy_data_struct.iter().map(field_to_json).collect::<Vec<_>>()
                }
            }),
        );
    }

    // Fee Manager
    {
        use tempo_precompiles::tip_fee_manager::{amm::__packing_pool::*, slots};

        let fields = layout_fields!(
            validator_tokens,
            user_tokens,
            collected_fees,
            tokens_with_fees,
            token_in_fees_array,
            pools,
            pending_fee_swap_in,
            total_supply,
            liquidity_balances
        );
        let base_slot = slots::POOLS;
        let pool_struct = struct_fields!(base_slot, reserve_user_token, reserve_validator_token);

        all_constants.insert(
            "tip_fee_manager".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>(),
                "structs": {
                    "pools": pool_struct.iter().map(field_to_json).collect::<Vec<_>>()
                }
            }),
        );
    }

    // Stablecoin Exchange
    {
        use tempo_precompiles::stablecoin_exchange::{
            order::__packing_order::*, orderbook::__packing_orderbook::*, slots,
        };

        let fields = layout_fields!(
            books,
            orders,
            balances,
            active_order_id,
            pending_order_id,
            book_keys
        );

        let order_base_slot = slots::ORDERS;
        let order_struct = struct_fields!(
            order_base_slot,
            order_id,
            maker,
            book_key,
            is_bid,
            tick,
            amount,
            remaining,
            prev,
            next,
            is_flip,
            flip_tick
        );

        let orderbook_base_slot = slots::BOOKS;
        let orderbook_struct = struct_fields!(
            orderbook_base_slot,
            base,
            quote,
            bids,
            asks,
            best_bid_tick,
            best_ask_tick,
            bid_bitmap,
            ask_bitmap
        );

        all_constants.insert(
            "stablecoin_exchange".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>(),
                "structs": {
                    "orders": order_struct.iter().map(field_to_json).collect::<Vec<_>>(),
                    "books": orderbook_struct.iter().map(field_to_json).collect::<Vec<_>>()
                }
            }),
        );
    }

    // TIP20 Token
    {
        use tempo_precompiles::tip20::{
            rewards::{__packing_reward_stream::*, __packing_user_reward_info::*},
            slots,
        };

        let fields = layout_fields!(
            // RolesAuth
            roles,
            role_admins,
            // TIP20 Metadata
            name,
            symbol,
            currency,
            domain_separator,
            quote_token,
            next_quote_token,
            transfer_policy_id,
            // TIP20 Token
            total_supply,
            balances,
            allowances,
            nonces,
            paused,
            supply_cap,
            salts,
            // TIP20 Rewards
            global_reward_per_token,
            last_update_time,
            total_reward_per_second,
            opted_in_supply,
            next_stream_id,
            streams,
            scheduled_rate_decrease,
            user_reward_info
        );

        let stream_base_slot = slots::STREAMS;
        let stream_struct = struct_fields!(
            stream_base_slot,
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total
        );

        let user_info_base_slot = slots::USER_REWARD_INFO;
        let user_info_struct = struct_fields!(
            user_info_base_slot,
            reward_recipient,
            reward_per_token,
            reward_balance
        );

        all_constants.insert(
            "tip20".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>(),
                "structs": {
                    "streams": stream_struct.iter().map(field_to_json).collect::<Vec<_>>(),
                    "userRewardInfo": user_info_struct.iter().map(field_to_json).collect::<Vec<_>>()
                }
            }),
        );
    }

    // Validator Config
    {
        use tempo_precompiles::validator_config::slots;
        let fields = layout_fields!(owner, validator_count, validators_array, validators);
        all_constants.insert(
            "validator_config".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>()
            }),
        );
    }

    // Nonce Manager
    {
        use tempo_precompiles::nonce::slots;
        let fields = layout_fields!(nonces, active_key_count);
        all_constants.insert(
            "nonce_manager".to_string(),
            json!({
                "fields": fields.iter().map(field_to_json).collect::<Vec<_>>()
            }),
        );
    }

    // TIP Account Registrar
    {
        // This contract has no storage fields, but we include it for completeness
        all_constants.insert(
            "tip_account_registrar".to_string(),
            json!({
                "fields": []
            }),
        );
    }

    // Snapshot validation and optional regeneration
    let snapshot_path = testdata("storage-layout.json");
    let current_layout = Value::Object(all_constants);
    let regenerate = std::env::var("REGENERATE_SNAPSHOT").is_ok();

    if regenerate {
        // Regenerate mode: write the current layout to the snapshot file
        let output = serde_json::to_string_pretty(&current_layout).unwrap();
        fs::write(&snapshot_path, output).unwrap();
        println!(
            "Storage layout snapshot regenerated at: {}",
            snapshot_path.display()
        );
    } else {
        // Validation mode: compare current layout with snapshot
        if !snapshot_path.exists() {
            panic!(
                "Storage layout snapshot not found at: {}\n\
                Generate it by running:\n  \
                REGENERATE_SNAPSHOT=true cargo test export_all_storage_constants",
                snapshot_path.display()
            );
        }

        let snapshot_json = fs::read_to_string(&snapshot_path)
            .unwrap_or_else(|e| panic!("Failed to read snapshot file: {e}"));

        let snapshot: Value = serde_json::from_str(&snapshot_json)
            .unwrap_or_else(|e| panic!("Failed to parse snapshot JSON: {e}"));

        if current_layout != snapshot {
            let current = serde_json::to_string_pretty(&current_layout).unwrap();
            let snapshot = serde_json::to_string_pretty(&snapshot).unwrap();

            panic!(
                r#"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ Storage layout has changed!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The current storage layout does not match the committed snapshot.
This may indicate an unintentional breaking change.
If these changes are intentional, regenerate the snapshot:
`REGENERATE_SNAPSHOT=true cargo test -p tempo-precompiles validate_precompiles_storage_snapshot`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Current layout:
{current}
Snapshot layout:
{snapshot}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"#,
            );
        }

        println!("Storage layout matches snapshot");
    }
}
