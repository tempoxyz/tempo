//! Tests for actual precompile contract storage layouts.
//!
//! This module verifies that the storage layouts of production precompile contracts
//! match their Solidity equivalents, ensuring compatibility with the EVM.

use super::*;
use tempo_precompiles_macros::{
    gen_test_fields_layout as layout_fields, gen_test_fields_struct as struct_fields,
};
use utils::*;

#[test]
fn test_tip20_factory_layout() {
    use tempo_precompiles::tip20_factory::slots;

    let sol_path = testdata("tip20_factory.sol");
    let solc_layout = load_solc_layout(&sol_path);
    let rust_layout = layout_fields!(token_id_counter);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }
}

#[test]
fn test_tip20_rewards_registry_layout() {
    use tempo_precompiles::tip20_rewards_registry::slots;

    let sol_path = testdata("tip20_rewards_registry.sol");
    let solc_layout = load_solc_layout(&sol_path);
    let rust_layout = layout_fields!(last_updated_timestamp, streams_ending_at, stream_index);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }
}

#[test]
fn test_tip403_registry_layout() {
    use tempo_precompiles::tip403_registry::{__packing_policy_data::*, slots};

    let sol_path = testdata("tip403_registry.sol");
    let solc_layout = load_solc_layout(&sol_path);

    // Verify top-level fields
    let rust_layout = layout_fields!(policy_id_counter, policy_data, policy_set);
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }

    // Verify `PolicyData` struct members
    let base_slot = slots::POLICY_DATA;
    let rust_struct = struct_fields!(base_slot, policy_type, admin);
    if let Err(errors) = compare_struct_members(&solc_layout, "policyData", &rust_struct) {
        panic_layout_mismatch("Struct member layout", errors, &sol_path);
    }
}

#[test]
fn test_fee_manager_layout() {
    use tempo_precompiles::tip_fee_manager::{
        __packing_token_pair::*, amm::__packing_pool::*, slots,
    };

    let sol_path = testdata("fee_manager.sol");
    let solc_layout = load_solc_layout(&sol_path);

    // Verify top-level fields
    let rust_layout = layout_fields!(
        validator_tokens,
        user_tokens,
        collected_fees,
        tokens_with_fees,
        token_in_fees_array,
        pools,
        pending_fee_swap_in,
        total_supply,
        liquidity_balances,
        pools_with_fees,
        pool_in_fees_array,
        validators_with_fees,
        validator_in_fees_array
    );
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }

    // Verify `Pool` struct members (used in mapping)
    let pool_base_slot = slots::POOLS;
    let rust_pool = struct_fields!(pool_base_slot, reserve_user_token, reserve_validator_token);
    if let Err(errors) = compare_struct_members(&solc_layout, "pools", &rust_pool) {
        panic_layout_mismatch("Pool struct member layout", errors, &sol_path);
    }

    // Verify `TokenPair` struct members
    let token_pair_base_slot = slots::POOLS_WITH_FEES;
    let rust_token_pair = struct_fields!(token_pair_base_slot, user_token, validator_token);
    if let Err(errors) = compare_struct_members(&solc_layout, "poolsWithFees", &rust_token_pair) {
        panic_layout_mismatch("TokenPair struct member layout", errors, &sol_path);
    }
}

#[test]
fn test_stablecoin_exchange_layout() {
    use tempo_precompiles::stablecoin_exchange::{
        order::__packing_order::*, orderbook::__packing_orderbook::*, slots,
    };

    let sol_path = testdata("stablecoin_exchange.sol");
    let solc_layout = load_solc_layout(&sol_path);

    // Verify top-level fields
    let rust_layout = layout_fields!(
        books,
        orders,
        balances,
        active_order_id,
        pending_order_id,
        book_keys
    );
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }

    // Verify `Order` struct members
    let order_base_slot = slots::ORDERS;
    let rust_order = struct_fields!(
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
    if let Err(errors) = compare_struct_members(&solc_layout, "orders", &rust_order) {
        panic_layout_mismatch("Order struct member layout", errors, &sol_path);
    }

    // Verify `Orderbook` struct members (only the non-mapping fields)
    let orderbook_base_slot = slots::BOOKS;
    let rust_orderbook = struct_fields!(
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
    if let Err(errors) = compare_struct_members(&solc_layout, "books", &rust_orderbook) {
        panic_layout_mismatch("Orderbook struct member layout", errors, &sol_path);
    }
}

#[test]
fn test_tip20_layout() {
    use tempo_precompiles::tip20::{
        rewards::{__packing_reward_stream::*, __packing_user_reward_info::*},
        slots,
    };

    let sol_path = testdata("tip20.sol");
    let solc_layout = load_solc_layout(&sol_path);

    // Verify top-level fields
    let rust_layout = layout_fields!(
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
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic_layout_mismatch("Layout", errors, &sol_path);
    }

    // Verify `RewardStream` struct members
    let stream_base_slot = slots::STREAMS;
    let rust_stream = struct_fields!(
        stream_base_slot,
        funder,
        start_time,
        end_time,
        rate_per_second_scaled,
        amount_total
    );
    if let Err(errors) = compare_struct_members(&solc_layout, "streams", &rust_stream) {
        panic_layout_mismatch("RewardStream struct member layout", errors, &sol_path);
    }

    // Verify `UserRewardInfo` struct members
    let user_info_base_slot = slots::USER_REWARD_INFO;
    let rust_user_info = struct_fields!(
        user_info_base_slot,
        reward_recipient,
        reward_per_token,
        reward_balance
    );
    if let Err(errors) = compare_struct_members(&solc_layout, "userRewardInfo", &rust_user_info) {
        panic_layout_mismatch("UserRewardInfo struct member layout", errors, &sol_path);
    }
}

/// Export all storage constants to a JSON file for comparison between branches.
///
/// This test is marked with #[ignore] so it doesn't run in CI.
/// To run it manually:
/// ```bash
/// cargo test export_all_storage_constants -- --ignored --nocapture
/// ```
///
/// The output will be written to `current_branch_constants.json` in the workspace root.
#[test]
#[ignore]
fn export_all_storage_constants() {
    use serde_json::json;
    use std::fs;

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

    // Write to file
    let output = serde_json::to_string_pretty(&all_constants).unwrap();
    let current_dir = std::env::current_dir().unwrap();
    let workspace_root = current_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").exists())
        .expect("Could not find workspace root");

    let output_path = workspace_root.join("current_branch_constants.json");
    fs::write(&output_path, output).unwrap();

    println!(
        "✅ Storage constants exported to: {}",
        output_path.display()
    );
}
