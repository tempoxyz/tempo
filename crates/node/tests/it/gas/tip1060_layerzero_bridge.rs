use alloy::{
    hex,
    primitives::{Address, B256, Bytes, U256, address, b256},
    providers::{Provider, ProviderBuilder},
};
use serde_json::{Map, Value};
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, b256_from_hex, ensure_call_trace_succeeded, find_call_gas_used,
    mainnet_prestate_genesis_value, mapping_slot_address, print_gas_snapshot,
    successful_raw_receipt_gas_used, tip20_allowance_slot, tip20_balance_slot, upsert_storage,
};
use crate::utils::TestNodeBuilder;

// Mainnet tx 0x7b98...a3f at block 0x183c711, replayed from a prestateTracer
// fixture while forcing the local chain spec to T7.
const MAINNET_TX_HASH: B256 =
    b256!("7b98eaaf6eafb35249942e107afa2f6e7024278f147fc792b1a22d15b80b4a3f");
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_560_246;
const SMART_ACCOUNT_ADDRESS: Address = address!("4c2c0f0bb2631b02ac9299c59690914ee7a200b8");
const BRIDGE_TOKEN_ADDRESS: Address = address!("20c000000000000000000000b9537d11c60e8b50");
const PATHUSD_ADDRESS: Address = address!("20c0000000000000000000000000000000000000");
const WRAPPED_TOKEN_ADDRESS: Address = address!("0ceb237e109ee22374a567c6b09f373c73fa4cbb");
const STARGATE_ADDRESS: Address = address!("8c76e2f6c5ceda9aa7772e7eff30280226c44392");
const WRAPPER_ADDRESS: Address = WRAPPED_TOKEN_ADDRESS;
const LAYERZERO_SEND_LIB_ADDRESS: Address = address!("19ff94fe4c93d546e4db3e1fb124d45366b0b9f5");
const LAYERZERO_ENDPOINT_ADDRESS: Address = address!("20bb7c2e2f4e5ca2b4c57060d1ae2615245dcc9c");
const MESSAGING_CHANNEL_ADDRESS: Address = address!("572863d9247e52026e0892d9cd2e519b41edb73c");
const APPROVE_SELECTOR: &str = "0x095ea7b3";
const WRAP_SELECTOR: &str = "0x62355638";
const BRIDGE_SELECTOR: &str = "0xc7c7f5b3";
const LAYERZERO_SEND_SELECTOR: &str = "0xff6fb300";
const ENDPOINT_SEND_SELECTOR: &str = "0x2637a450";
const MESSAGING_CHANNEL_SEND_SELECTOR: &str = "0x4389e58f";
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_layerzero_bridge_prestate.json");
const RAW_TX: &str = "0x76f9040c821079808509502f9000832cfcc2f90378f85c9420c000000000000000000000b9537d11c60e8b5080b844095ea7b30000000000000000000000008c76e2f6c5ceda9aa7772e7eff30280226c44392000000000000000000000000000000000000000000000000000000036f9e30a0f85c9420c000000000000000000000000000000000000080b844095ea7b30000000000000000000000000ceb237e109ee22374a567c6b09f373c73fa4cbb000000000000000000000000000000000000000000000000000000000001a6fff87c940ceb237e109ee22374a567c6b09f373c73fa4cbb80b8646235563800000000000000000000000020c00000000000000000000000000000000000000000000000000000000000004c2c0f0bb2631b02ac9299c59690914ee7a200b8000000000000000000000000000000000000000000000000000000000001a6fff85c940ceb237e109ee22374a567c6b09f373c73fa4cbb80b844095ea7b30000000000000000000000008c76e2f6c5ceda9aa7772e7eff30280226c44392000000000000000000000000000000000000000000000000000000000001a6fff901dd948c76e2f6c5ceda9aa7772e7eff30280226c4439280b901c4c7c7f5b30000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000001a6ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c2c0f0bb2631b02ac9299c59690914ee7a200b800000000000000000000000000000000000000000000000000000000000075950000000000000000000000004c2c0f0bb2631b02ac9299c59690914ee7a200b8000000000000000000000000000000000000000000000000000000036f9e30a0000000000000000000000000000000000000000000000000000000036f9e30a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a3073ce809420c000000000000000000000000000000000000080c0b8413f0d6d0ace0b3874a5945cb28e69d65663188c04b9d8c82e9c3c006b3852634135f6b75c08a92c54d6523d1285aab0ad1aee01a72d611f10d548d67ea5166bc91b";

#[derive(Clone, Copy)]
enum UserState {
    New,
    Returning,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_layerzero_bridge_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_layerzero_bridge_gas_snapshot(UserState::New, "tip1060_layerzero_bridge_t7_gas")
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_layerzero_bridge_returning_user_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_layerzero_bridge_gas_snapshot(
        UserState::Returning,
        "tip1060_layerzero_bridge_returning_user_t7_gas",
    )
    .await
}

async fn test_tip1060_layerzero_bridge_gas_snapshot(
    user_state: UserState,
    snapshot_name: &'static str,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_genesis(mainnet_replay_genesis(user_state)?)
        .build_with_node_access()
        .await?;
    setup.node.payload.timestamp = MAINNET_BLOCK_TIMESTAMP;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let raw_tx = Bytes::from(hex::decode(RAW_TX.trim_start_matches("0x"))?);
    setup.node.rpc.inject_tx(raw_tx).await?;
    setup.node.advance_block().await?;

    let receipt: Option<Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), (MAINNET_TX_HASH,))
        .await?;
    let receipt =
        receipt.ok_or_else(|| eyre::eyre!("mainnet replay transaction receipt missing"))?;
    let receipt_gas_used = successful_raw_receipt_gas_used(&receipt, MAINNET_TX_HASH)?;

    let trace: Value = provider
        .raw_request(
            "debug_traceTransaction".into(),
            (
                MAINNET_TX_HASH,
                serde_json::json!({ "tracer": "callTracer" }),
            ),
        )
        .await?;
    ensure_call_trace_succeeded(&trace)?;

    let mut gas = GasSnapshot::new();
    gas.record("layerzero_bridge", receipt_gas_used);
    gas.record(
        "layerzero_bridge_bridge_token_approve",
        find_call_gas_used(&trace, BRIDGE_TOKEN_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_pathusd_approve",
        find_call_gas_used(&trace, PATHUSD_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_wrapper_wrap",
        find_call_gas_used(&trace, WRAPPED_TOKEN_ADDRESS, WRAP_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_wrapper_approve",
        find_call_gas_used(&trace, WRAPPED_TOKEN_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_stargate_send",
        find_call_gas_used(&trace, STARGATE_ADDRESS, BRIDGE_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_layerzero_send",
        find_call_gas_used(&trace, LAYERZERO_SEND_LIB_ADDRESS, LAYERZERO_SEND_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_endpoint_send",
        find_call_gas_used(&trace, LAYERZERO_ENDPOINT_ADDRESS, ENDPOINT_SEND_SELECTOR)?,
    );
    gas.record(
        "layerzero_bridge_messaging_channel_send",
        find_call_gas_used(
            &trace,
            MESSAGING_CHANNEL_ADDRESS,
            MESSAGING_CHANNEL_SEND_SELECTOR,
        )?,
    );

    print_gas_snapshot(
        match user_state {
            UserState::New => "TIP-1060 LayerZero bridge gas snapshot (T7, new user)",
            UserState::Returning => "TIP-1060 LayerZero bridge gas snapshot (T7, returning user)",
        },
        &gas,
    );

    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}

fn mainnet_replay_genesis(user_state: UserState) -> eyre::Result<String> {
    let mut genesis = mainnet_prestate_genesis_value(
        TempoHardfork::T7,
        MAINNET_CHAIN_ID,
        MAINNET_BLOCK_TIMESTAMP,
        PRESTATE_JSON,
    )?;
    let alloc = genesis["alloc"]
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("test genesis missing alloc"))?;
    apply_user_state(alloc, user_state)?;

    Ok(serde_json::to_string(&genesis)?)
}

fn apply_user_state(alloc: &mut Map<String, Value>, user_state: UserState) -> eyre::Result<()> {
    let value = match user_state {
        UserState::New => U256::ZERO,
        UserState::Returning => U256::ONE,
    };

    for (token, owner) in [
        (PATHUSD_ADDRESS, WRAPPER_ADDRESS),
        (BRIDGE_TOKEN_ADDRESS, STARGATE_ADDRESS),
    ] {
        upsert_storage(alloc, token, tip20_balance_slot(owner), value)?;
    }

    for (token, spender) in [
        (BRIDGE_TOKEN_ADDRESS, STARGATE_ADDRESS),
        (PATHUSD_ADDRESS, WRAPPER_ADDRESS),
    ] {
        upsert_storage(
            alloc,
            token,
            tip20_allowance_slot(SMART_ACCOUNT_ADDRESS, spender),
            value,
        )?;
    }

    upsert_storage(
        alloc,
        WRAPPED_TOKEN_ADDRESS,
        wrapped_token_balance_slot(SMART_ACCOUNT_ADDRESS)?,
        value,
    )?;
    upsert_storage(
        alloc,
        WRAPPED_TOKEN_ADDRESS,
        wrapped_token_balance_slot(STARGATE_ADDRESS)?,
        value,
    )?;
    upsert_storage(
        alloc,
        WRAPPED_TOKEN_ADDRESS,
        wrapped_token_allowance_slot(SMART_ACCOUNT_ADDRESS, STARGATE_ADDRESS)?,
        value,
    )?;

    Ok(())
}

fn wrapped_token_balance_slot(owner: Address) -> eyre::Result<B256> {
    Ok(mapping_slot_address(
        owner,
        wrapped_token_erc20_storage_slot()?,
    ))
}

fn wrapped_token_allowance_slot(owner: Address, spender: Address) -> eyre::Result<B256> {
    Ok(mapping_slot_address(
        spender,
        mapping_slot_address(owner, wrapped_token_erc20_allowance_slot()?),
    ))
}

fn wrapped_token_erc20_storage_slot() -> eyre::Result<B256> {
    b256_from_hex("0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00")
}

fn wrapped_token_erc20_allowance_slot() -> eyre::Result<B256> {
    b256_from_hex("0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace01")
}
