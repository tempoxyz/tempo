//! Solidity compatibility tests.
//!
//! This module tests that the `contract` macro-generated storage layouts match their
//! Solidity counterparts by comparing against the expected solc-generated outputs.

// TODO(rusowsky): add tests against the actual pre-compiles solidity-equivalent contracts

mod utils;
use super::*;
use tempo_precompiles_macros::{
    gen_test_fields_layout as layout_fields, gen_test_fields_struct as struct_fields,
};
use utils::*;

// Helper struct for struct test (defined at module level)
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
struct TestBlockInner {
    field1: U256,
    field2: U256,
    field3: u64,
}

fn testdata(filename: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("storage_tests")
        .join("solidity")
        .join("testdata")
        .join(filename)
}

#[test]
fn test_basic_types_layout() {
    #[contract]
    struct BasicTypes {
        field_a: U256,
        field_b: Address,
        field_c: bool,
        field_d: u64,
    }

    let rust_layout = layout_fields!(field_a, field_b, field_c, field_d);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("basic_types.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_mixed_slots_layout() {
    #[contract]
    struct MixedSlots {
        field_a: U256,
        field_c: U256,
    }

    let rust_layout = layout_fields!(field_a, field_c);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("mixed_slots.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_arrays_layout() {
    #[contract]
    struct Arrays {
        field_a: U256,
        large_array: [U256; 5],
        field_b: U256,
    }

    let rust_layout = layout_fields!(field_a, large_array, field_b);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("arrays.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_mappings_layout() {
    #[contract]
    struct Mappings {
        field_a: U256,
        address_mapping: Mapping<Address, U256>,
        uint_mapping: Mapping<u64, U256>,
    }

    let rust_layout = layout_fields!(field_a, address_mapping, uint_mapping);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("mappings.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

// Test struct storage layout including individual struct member verification
#[test]
fn test_structs_layout() {
    use crate::storage_tests::solidity::__packing_test_block_inner::*;

    #[contract]
    struct Structs {
        field_a: U256,
        block_data: TestBlockInner,
        field_b: U256,
    }

    let solc_layout = load_solc_layout(&testdata("structs.sol"));

    // Verify top-level fields
    let rust_layout = layout_fields!(field_a, block_data, field_b);

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify struct member slots
    let base_slot = slots::BLOCK_DATA;
    let rust_struct = struct_fields!(base_slot, field1, field2, field3);

    if let Err(errors) = compare_struct_members(&solc_layout, "block_data", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

// Test enum storage layout with packing
#[test]
fn test_enums_layout() {
    use alloy::primitives::Address;

    #[contract]
    struct Enums {
        field_a: u16,     // 2 bytes - slot 0, offset 0
        field_b: u8,      // 1 byte (enum) - slot 0, offset 2
        field_c: Address, // 20 bytes - slot 0, offset 3
    }

    let rust_layout = layout_fields!(field_a, field_b, field_c);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("enum.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_double_mappings_layout() {
    use alloy::primitives::FixedBytes;

    #[contract]
    struct DoubleMappings {
        field_a: U256,
        account_role: Mapping<Address, Mapping<FixedBytes<32>, bool>>,
        allowances: Mapping<Address, Mapping<Address, U256>>,
    }

    let rust_fields = layout_fields!(field_a, account_role, allowances);

    // Compare against expected layout from Solidity
    let solc_layout = load_solc_layout(&testdata("double_mappings.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_fields) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_tip20_factory_layout() {
    use tempo_precompiles::tip20_factory::slots;

    let rust_layout = vec![RustStorageField::new(
        "token_id_counter",
        slots::TOKEN_ID_COUNTER,
        slots::TOKEN_ID_COUNTER_OFFSET,
        slots::TOKEN_ID_COUNTER_BYTES,
    )];

    let solc_layout = load_solc_layout(&testdata("tip20_factory.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_tip20_rewards_registry_layout() {
    use tempo_precompiles::tip20_rewards_registry::slots;

    let rust_layout = vec![
        RustStorageField::new(
            "last_updated_timestamp",
            slots::LAST_UPDATED_TIMESTAMP,
            slots::LAST_UPDATED_TIMESTAMP_OFFSET,
            slots::LAST_UPDATED_TIMESTAMP_BYTES,
        ),
        RustStorageField::new(
            "streams_ending_at",
            slots::STREAMS_ENDING_AT,
            slots::STREAMS_ENDING_AT_OFFSET,
            slots::STREAMS_ENDING_AT_BYTES,
        ),
        RustStorageField::new(
            "stream_index",
            slots::STREAM_INDEX,
            slots::STREAM_INDEX_OFFSET,
            slots::STREAM_INDEX_BYTES,
        ),
    ];

    let solc_layout = load_solc_layout(&testdata("tip20_rewards_registry.sol"));

    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_tip403_registry_layout() {
    use tempo_precompiles::tip403_registry::{__packing_policy_data::*, slots};

    let rust_layout = vec![
        RustStorageField::new(
            "policy_id_counter",
            slots::POLICY_ID_COUNTER,
            slots::POLICY_ID_COUNTER_OFFSET,
            slots::POLICY_ID_COUNTER_BYTES,
        ),
        RustStorageField::new(
            "policy_data",
            slots::POLICY_DATA,
            slots::POLICY_DATA_OFFSET,
            slots::POLICY_DATA_BYTES,
        ),
        RustStorageField::new(
            "policy_set",
            slots::POLICY_SET,
            slots::POLICY_SET_OFFSET,
            slots::POLICY_SET_BYTES,
        ),
    ];

    let solc_layout = load_solc_layout(&testdata("tip403_registry.sol"));

    // Verify top-level fields
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify PolicyData struct members
    let base_slot = slots::POLICY_DATA;
    let rust_struct = vec![
        RustStorageField::new(
            "policy_type",
            base_slot + U256::from(POLICY_TYPE_SLOT),
            POLICY_TYPE_OFFSET,
            POLICY_TYPE_BYTES,
        ),
        RustStorageField::new(
            "admin",
            base_slot + U256::from(ADMIN_SLOT),
            ADMIN_OFFSET,
            ADMIN_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "policy_data", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_fee_manager_layout() {
    use tempo_precompiles::tip_fee_manager::{amm::__packing_pool::*, slots};

    let rust_layout = vec![
        RustStorageField::new(
            "validator_tokens",
            slots::VALIDATOR_TOKENS,
            slots::VALIDATOR_TOKENS_OFFSET,
            slots::VALIDATOR_TOKENS_BYTES,
        ),
        RustStorageField::new(
            "user_tokens",
            slots::USER_TOKENS,
            slots::USER_TOKENS_OFFSET,
            slots::USER_TOKENS_BYTES,
        ),
        RustStorageField::new(
            "collected_fees",
            slots::COLLECTED_FEES,
            slots::COLLECTED_FEES_OFFSET,
            slots::COLLECTED_FEES_BYTES,
        ),
        RustStorageField::new(
            "tokens_with_fees",
            slots::TOKENS_WITH_FEES,
            slots::TOKENS_WITH_FEES_OFFSET,
            slots::TOKENS_WITH_FEES_BYTES,
        ),
        RustStorageField::new(
            "token_in_fees_array",
            slots::TOKEN_IN_FEES_ARRAY,
            slots::TOKEN_IN_FEES_ARRAY_OFFSET,
            slots::TOKEN_IN_FEES_ARRAY_BYTES,
        ),
        RustStorageField::new(
            "pools",
            slots::POOLS,
            slots::POOLS_OFFSET,
            slots::POOLS_BYTES,
        ),
        RustStorageField::new(
            "pending_fee_swap_in",
            slots::PENDING_FEE_SWAP_IN,
            slots::PENDING_FEE_SWAP_IN_OFFSET,
            slots::PENDING_FEE_SWAP_IN_BYTES,
        ),
        RustStorageField::new(
            "total_supply",
            slots::TOTAL_SUPPLY,
            slots::TOTAL_SUPPLY_OFFSET,
            slots::TOTAL_SUPPLY_BYTES,
        ),
        RustStorageField::new(
            "liquidity_balances",
            slots::LIQUIDITY_BALANCES,
            slots::LIQUIDITY_BALANCES_OFFSET,
            slots::LIQUIDITY_BALANCES_BYTES,
        ),
    ];

    let solc_layout = load_solc_layout(&testdata("fee_manager.sol"));

    // Verify top-level fields
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify Pool struct members
    let base_slot = slots::POOLS;
    let rust_struct = vec![
        RustStorageField::new(
            "reserveUserToken",
            base_slot + U256::from(RESERVE_USER_TOKEN_SLOT),
            RESERVE_USER_TOKEN_OFFSET,
            RESERVE_USER_TOKEN_BYTES,
        ),
        RustStorageField::new(
            "reserveValidatorToken",
            base_slot + U256::from(RESERVE_VALIDATOR_TOKEN_SLOT),
            RESERVE_VALIDATOR_TOKEN_OFFSET,
            RESERVE_VALIDATOR_TOKEN_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "pools", &rust_struct) {
        panic!("Struct member layout mismatch:\n{}", errors.join("\n"));
    }
}

#[test]
fn test_stablecoin_exchange_layout() {
    use tempo_precompiles::stablecoin_exchange::{
        order::__packing_order::*, orderbook::__packing_orderbook::*, slots,
    };

    let rust_layout = vec![
        RustStorageField::new(
            "books",
            slots::BOOKS,
            slots::BOOKS_OFFSET,
            slots::BOOKS_BYTES,
        ),
        RustStorageField::new(
            "orders",
            slots::ORDERS,
            slots::ORDERS_OFFSET,
            slots::ORDERS_BYTES,
        ),
        RustStorageField::new(
            "balances",
            slots::BALANCES,
            slots::BALANCES_OFFSET,
            slots::BALANCES_BYTES,
        ),
        RustStorageField::new(
            "active_order_id",
            slots::ACTIVE_ORDER_ID,
            slots::ACTIVE_ORDER_ID_OFFSET,
            slots::ACTIVE_ORDER_ID_BYTES,
        ),
        RustStorageField::new(
            "pending_order_id",
            slots::PENDING_ORDER_ID,
            slots::PENDING_ORDER_ID_OFFSET,
            slots::PENDING_ORDER_ID_BYTES,
        ),
        RustStorageField::new(
            "book_keys",
            slots::BOOK_KEYS,
            slots::BOOK_KEYS_OFFSET,
            slots::BOOK_KEYS_BYTES,
        ),
    ];

    let solc_layout = load_solc_layout(&testdata("stablecoin_exchange.sol"));

    // Verify top-level fields
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify Order struct members
    let order_base_slot = slots::ORDERS;
    let rust_order = vec![
        RustStorageField::new(
            "orderId",
            order_base_slot + U256::from(ORDER_ID_SLOT),
            ORDER_ID_OFFSET,
            ORDER_ID_BYTES,
        ),
        RustStorageField::new(
            "maker",
            order_base_slot + U256::from(MAKER_SLOT),
            MAKER_OFFSET,
            MAKER_BYTES,
        ),
        RustStorageField::new(
            "bookKey",
            order_base_slot + U256::from(BOOK_KEY_SLOT),
            BOOK_KEY_OFFSET,
            BOOK_KEY_BYTES,
        ),
        RustStorageField::new(
            "isBid",
            order_base_slot + U256::from(IS_BID_SLOT),
            IS_BID_OFFSET,
            IS_BID_BYTES,
        ),
        RustStorageField::new(
            "tick",
            order_base_slot + U256::from(TICK_SLOT),
            TICK_OFFSET,
            TICK_BYTES,
        ),
        RustStorageField::new(
            "amount",
            order_base_slot + U256::from(AMOUNT_SLOT),
            AMOUNT_OFFSET,
            AMOUNT_BYTES,
        ),
        RustStorageField::new(
            "remaining",
            order_base_slot + U256::from(REMAINING_SLOT),
            REMAINING_OFFSET,
            REMAINING_BYTES,
        ),
        RustStorageField::new(
            "prev",
            order_base_slot + U256::from(PREV_SLOT),
            PREV_OFFSET,
            PREV_BYTES,
        ),
        RustStorageField::new(
            "next",
            order_base_slot + U256::from(NEXT_SLOT),
            NEXT_OFFSET,
            NEXT_BYTES,
        ),
        RustStorageField::new(
            "isFlip",
            order_base_slot + U256::from(IS_FLIP_SLOT),
            IS_FLIP_OFFSET,
            IS_FLIP_BYTES,
        ),
        RustStorageField::new(
            "flipTick",
            order_base_slot + U256::from(FLIP_TICK_SLOT),
            FLIP_TICK_OFFSET,
            FLIP_TICK_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "orders", &rust_order) {
        panic!(
            "Order struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }

    // Verify Orderbook struct members (only the non-mapping fields)
    let orderbook_base_slot = slots::BOOKS;
    let rust_orderbook = vec![
        RustStorageField::new(
            "base",
            orderbook_base_slot + U256::from(BASE_SLOT),
            BASE_OFFSET,
            BASE_BYTES,
        ),
        RustStorageField::new(
            "quote",
            orderbook_base_slot + U256::from(QUOTE_SLOT),
            QUOTE_OFFSET,
            QUOTE_BYTES,
        ),
        RustStorageField::new(
            "bids",
            orderbook_base_slot + U256::from(BIDS_SLOT),
            BIDS_OFFSET,
            BIDS_BYTES,
        ),
        RustStorageField::new(
            "asks",
            orderbook_base_slot + U256::from(ASKS_SLOT),
            ASKS_OFFSET,
            ASKS_BYTES,
        ),
        RustStorageField::new(
            "bestBidTick",
            orderbook_base_slot + U256::from(BEST_BID_TICK_SLOT),
            BEST_BID_TICK_OFFSET,
            BEST_BID_TICK_BYTES,
        ),
        RustStorageField::new(
            "bestAskTick",
            orderbook_base_slot + U256::from(BEST_ASK_TICK_SLOT),
            BEST_ASK_TICK_OFFSET,
            BEST_ASK_TICK_BYTES,
        ),
        RustStorageField::new(
            "bidBitmap",
            orderbook_base_slot + U256::from(BID_BITMAPS_SLOT),
            BID_BITMAPS_OFFSET,
            BID_BITMAPS_BYTES,
        ),
        RustStorageField::new(
            "askBitmap",
            orderbook_base_slot + U256::from(ASK_BITMAPS_SLOT),
            ASK_BITMAPS_OFFSET,
            ASK_BITMAPS_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "books", &rust_orderbook) {
        panic!(
            "Orderbook struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn test_tip20_layout() {
    use tempo_precompiles::tip20::{
        rewards::{__packing_reward_stream::*, __packing_user_reward_info::*},
        slots,
    };

    let rust_layout = vec![
        // RolesAuth
        RustStorageField::new(
            "roles",
            slots::ROLES,
            slots::ROLES_OFFSET,
            slots::ROLES_BYTES,
        ),
        RustStorageField::new(
            "role_admins",
            slots::ROLE_ADMINS,
            slots::ROLE_ADMINS_OFFSET,
            slots::ROLE_ADMINS_BYTES,
        ),
        // TIP20 Metadata
        RustStorageField::new("name", slots::NAME, slots::NAME_OFFSET, slots::NAME_BYTES),
        RustStorageField::new(
            "symbol",
            slots::SYMBOL,
            slots::SYMBOL_OFFSET,
            slots::SYMBOL_BYTES,
        ),
        RustStorageField::new(
            "currency",
            slots::CURRENCY,
            slots::CURRENCY_OFFSET,
            slots::CURRENCY_BYTES,
        ),
        RustStorageField::new(
            "domain_separator",
            slots::DOMAIN_SEPARATOR,
            slots::DOMAIN_SEPARATOR_OFFSET,
            slots::DOMAIN_SEPARATOR_BYTES,
        ),
        RustStorageField::new(
            "quote_token",
            slots::QUOTE_TOKEN,
            slots::QUOTE_TOKEN_OFFSET,
            slots::QUOTE_TOKEN_BYTES,
        ),
        RustStorageField::new(
            "next_quote_token",
            slots::NEXT_QUOTE_TOKEN,
            slots::NEXT_QUOTE_TOKEN_OFFSET,
            slots::NEXT_QUOTE_TOKEN_BYTES,
        ),
        RustStorageField::new(
            "transfer_policy_id",
            slots::TRANSFER_POLICY_ID,
            slots::TRANSFER_POLICY_ID_OFFSET,
            slots::TRANSFER_POLICY_ID_BYTES,
        ),
        // TIP20 Token
        RustStorageField::new(
            "total_supply",
            slots::TOTAL_SUPPLY,
            slots::TOTAL_SUPPLY_OFFSET,
            slots::TOTAL_SUPPLY_BYTES,
        ),
        RustStorageField::new(
            "balances",
            slots::BALANCES,
            slots::BALANCES_OFFSET,
            slots::BALANCES_BYTES,
        ),
        RustStorageField::new(
            "allowances",
            slots::ALLOWANCES,
            slots::ALLOWANCES_OFFSET,
            slots::ALLOWANCES_BYTES,
        ),
        RustStorageField::new(
            "nonces",
            slots::NONCES,
            slots::NONCES_OFFSET,
            slots::NONCES_BYTES,
        ),
        RustStorageField::new(
            "paused",
            slots::PAUSED,
            slots::PAUSED_OFFSET,
            slots::PAUSED_BYTES,
        ),
        RustStorageField::new(
            "supply_cap",
            slots::SUPPLY_CAP,
            slots::SUPPLY_CAP_OFFSET,
            slots::SUPPLY_CAP_BYTES,
        ),
        RustStorageField::new(
            "salts",
            slots::SALTS,
            slots::SALTS_OFFSET,
            slots::SALTS_BYTES,
        ),
        // TIP20 Rewards
        RustStorageField::new(
            "global_reward_per_token",
            slots::GLOBAL_REWARD_PER_TOKEN,
            slots::GLOBAL_REWARD_PER_TOKEN_OFFSET,
            slots::GLOBAL_REWARD_PER_TOKEN_BYTES,
        ),
        RustStorageField::new(
            "last_update_time",
            slots::LAST_UPDATE_TIME,
            slots::LAST_UPDATE_TIME_OFFSET,
            slots::LAST_UPDATE_TIME_BYTES,
        ),
        RustStorageField::new(
            "total_reward_per_second",
            slots::TOTAL_REWARD_PER_SECOND,
            slots::TOTAL_REWARD_PER_SECOND_OFFSET,
            slots::TOTAL_REWARD_PER_SECOND_BYTES,
        ),
        RustStorageField::new(
            "opted_in_supply",
            slots::OPTED_IN_SUPPLY,
            slots::OPTED_IN_SUPPLY_OFFSET,
            slots::OPTED_IN_SUPPLY_BYTES,
        ),
        RustStorageField::new(
            "next_stream_id",
            slots::NEXT_STREAM_ID,
            slots::NEXT_STREAM_ID_OFFSET,
            slots::NEXT_STREAM_ID_BYTES,
        ),
        RustStorageField::new(
            "streams",
            slots::STREAMS,
            slots::STREAMS_OFFSET,
            slots::STREAMS_BYTES,
        ),
        RustStorageField::new(
            "scheduled_rate_decrease",
            slots::SCHEDULED_RATE_DECREASE,
            slots::SCHEDULED_RATE_DECREASE_OFFSET,
            slots::SCHEDULED_RATE_DECREASE_BYTES,
        ),
        RustStorageField::new(
            "user_reward_info",
            slots::USER_REWARD_INFO,
            slots::USER_REWARD_INFO_OFFSET,
            slots::USER_REWARD_INFO_BYTES,
        ),
    ];

    let solc_layout = load_solc_layout(&testdata("tip20.sol"));

    // Verify top-level fields
    if let Err(errors) = compare_layouts(&solc_layout, &rust_layout) {
        panic!("Layout mismatch:\n{}", errors.join("\n"));
    }

    // Verify RewardStream struct members
    let stream_base_slot = slots::STREAMS;
    let rust_stream = vec![
        RustStorageField::new(
            "funder",
            stream_base_slot + U256::from(FUNDER_SLOT),
            FUNDER_OFFSET,
            FUNDER_BYTES,
        ),
        RustStorageField::new(
            "startTime",
            stream_base_slot + U256::from(START_TIME_SLOT),
            START_TIME_OFFSET,
            START_TIME_BYTES,
        ),
        RustStorageField::new(
            "endTime",
            stream_base_slot + U256::from(END_TIME_SLOT),
            END_TIME_OFFSET,
            END_TIME_BYTES,
        ),
        RustStorageField::new(
            "ratePerSecondScaled",
            stream_base_slot + U256::from(RATE_PER_SECOND_SCALED_SLOT),
            RATE_PER_SECOND_SCALED_OFFSET,
            RATE_PER_SECOND_SCALED_BYTES,
        ),
        RustStorageField::new(
            "amountTotal",
            stream_base_slot + U256::from(AMOUNT_TOTAL_SLOT),
            AMOUNT_TOTAL_OFFSET,
            AMOUNT_TOTAL_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "streams", &rust_stream) {
        panic!(
            "RewardStream struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }

    // Verify UserRewardInfo struct members
    let user_info_base_slot = slots::USER_REWARD_INFO;
    let rust_user_info = vec![
        RustStorageField::new(
            "rewardRecipient",
            user_info_base_slot + U256::from(DELEGATED_RECIPIENT_SLOT),
            DELEGATED_RECIPIENT_OFFSET,
            DELEGATED_RECIPIENT_BYTES,
        ),
        RustStorageField::new(
            "rewardPerToken",
            user_info_base_slot + U256::from(REWARD_PER_TOKEN_SLOT),
            REWARD_PER_TOKEN_OFFSET,
            REWARD_PER_TOKEN_BYTES,
        ),
        RustStorageField::new(
            "rewardBalance",
            user_info_base_slot + U256::from(REWARD_BALANCE_SLOT),
            REWARD_BALANCE_OFFSET,
            REWARD_BALANCE_BYTES,
        ),
    ];

    if let Err(errors) = compare_struct_members(&solc_layout, "user_reward_info", &rust_user_info) {
        panic!(
            "UserRewardInfo struct member layout mismatch:\n{}",
            errors.join("\n")
        );
    }
}
