use alloy::{
    hex,
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::{SolCall, SolValue},
};
use serde_json::{Map, Value, json};
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, address_key, b256_from_hex, ensure_call_trace_succeeded, find_call_gas_used,
    hex_u64, mainnet_prestate_genesis_value, mapping_slot_address, mapping_slot_bytes32,
    print_gas_snapshot, slot_key, tip20_allowance_slot, tip20_balance_slot, upsert_balance,
    upsert_storage, word_value,
};
use crate::utils::TestNodeBuilder;

sol! {
    interface IMinimalDirectSwap {
        function swapExactOut(address _tokenIn, address _tokenOut, uint256 _amountOut) external;
    }
}

// Prototype source: tempoxyz/minimal-direct-swap, compiled with solc-js 0.8.30,
// evmVersion=cancun, optimizer=true, optimizerRuns=200. Native forge/solc was
// SIGKILLing locally, but these are the Foundry project settings.
const MINIMAL_DIRECT_SWAP_RUNTIME: &str = include_str!("fixtures/minimal_direct_swap_runtime.hex");
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_bridge_direct_swap_prestate.json");
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_563_681;
const SMART_ACCOUNT_ADDRESS: Address = address!("ea8c83b797d7dd7697858cf9d1944c84b1acb2e8");
const MINIMAL_DIRECT_SWAP_ADDRESS: Address = address!("00000000000000000000000000000000000f00d1");
const PATHUSD_ADDRESS: Address = address!("20c0000000000000000000000000000000000000");
const DLUSD_ADDRESS: Address = address!("20c0000000000000000000006fd9a167923ba194");
const RESERVE_LEDGER_ADDRESS: Address = address!("20c00000000000000000000089caf7c622ae4b0f");
const TOKEN_AUTHORITY_ADDRESS: Address = address!("8354d80eea9978faa04c3b36771c1e8b9c3e9058");
const AUTH_REGISTRY_ADDRESS: Address = address!("403c000000000000000000000000000000000000");
const AMOUNT_OUT: u64 = 4_000_000_000;
const AUTH_POLICY_ID: u64 = 469;
const TRANSFER_FROM_SELECTOR: &str = "0x23b872dd";
const IS_AUTHORIZED_SELECTOR: &str = "0x55a1179e";
const UNWRAP_SELECTOR: &str = "0x39f47693";
const WRAP_SELECTOR: &str = "0x62355638";

#[derive(Clone, Copy)]
enum UserState {
    New,
    Returning,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_minimal_direct_swap_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_minimal_direct_swap_gas_snapshot(
        UserState::New,
        "tip1060_minimal_direct_swap_t7_gas",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_minimal_direct_swap_returning_user_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_minimal_direct_swap_gas_snapshot(
        UserState::Returning,
        "tip1060_minimal_direct_swap_returning_user_t7_gas",
    )
    .await
}

async fn test_tip1060_minimal_direct_swap_gas_snapshot(
    user_state: UserState,
    snapshot_name: &'static str,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(mainnet_replay_genesis(user_state)?)
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let calldata = IMinimalDirectSwap::swapExactOutCall {
        _tokenIn: PATHUSD_ADDRESS,
        _tokenOut: DLUSD_ADDRESS,
        _amountOut: U256::from(AMOUNT_OUT),
    }
    .abi_encode();
    let call = json!({
        "from": SMART_ACCOUNT_ADDRESS.to_string(),
        "to": MINIMAL_DIRECT_SWAP_ADDRESS.to_string(),
        "gas": "0x989680",
        "gasPrice": "0x4a817c800",
        "data": format!("0x{}", hex::encode(&calldata)),
    });

    let trace: Value = provider
        .raw_request(
            "debug_traceCall".into(),
            (
                call,
                "latest",
                json!({
                    "tracer": "callTracer",
                }),
            ),
        )
        .await?;
    ensure_call_trace_succeeded(&trace)?;

    let mut gas = GasSnapshot::new();
    gas.record(
        "minimal_direct_swap",
        hex_u64(
            trace
                .get("gasUsed")
                .ok_or_else(|| eyre::eyre!("call trace missing gasUsed"))?,
        )?,
    );
    gas.record(
        "minimal_direct_swap_authorization_check",
        find_call_gas_used(&trace, AUTH_REGISTRY_ADDRESS, IS_AUTHORIZED_SELECTOR)?,
    );
    gas.record(
        "minimal_direct_swap_pathusd_transfer_from_user",
        find_call_gas_used(&trace, PATHUSD_ADDRESS, TRANSFER_FROM_SELECTOR)?,
    );
    gas.record(
        "minimal_direct_swap_unwrap_pathusd",
        find_call_gas_used(&trace, TOKEN_AUTHORITY_ADDRESS, UNWRAP_SELECTOR)?,
    );
    gas.record(
        "minimal_direct_swap_wrap_dlusd",
        find_call_gas_used(&trace, TOKEN_AUTHORITY_ADDRESS, WRAP_SELECTOR)?,
    );

    print_gas_snapshot(
        match user_state {
            UserState::New => "TIP-1060 minimal direct swap gas snapshot (T7, new user)",
            UserState::Returning => {
                "TIP-1060 minimal direct swap gas snapshot (T7, returning user)"
            }
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
    install_minimal_direct_swap(alloc)?;
    apply_user_state(alloc, user_state)?;

    Ok(serde_json::to_string(&genesis)?)
}

fn install_minimal_direct_swap(alloc: &mut Map<String, Value>) -> eyre::Result<()> {
    let route_key = keccak256((PATHUSD_ADDRESS, DLUSD_ADDRESS).abi_encode());
    let route_supported_slot = mapping_slot_bytes32(route_key, B256::from(U256::from(1)));
    let route_policy_slot = mapping_slot_bytes32(route_key, B256::from(U256::from(2)));

    let access_control_storage =
        b256_from_hex("0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800")?;
    let unwrapper_role = keccak256(b"UNWRAPPER_ROLE");
    let role_data_slot = mapping_slot_bytes32(unwrapper_role, access_control_storage);
    let role_member_slot = mapping_slot_address(MINIMAL_DIRECT_SWAP_ADDRESS, role_data_slot);

    let pathusd_user_allowance_slot =
        tip20_allowance_slot(SMART_ACCOUNT_ADDRESS, MINIMAL_DIRECT_SWAP_ADDRESS);
    let pathusd_authority_allowance_slot =
        tip20_allowance_slot(MINIMAL_DIRECT_SWAP_ADDRESS, TOKEN_AUTHORITY_ADDRESS);
    let reserve_authority_allowance_slot =
        tip20_allowance_slot(MINIMAL_DIRECT_SWAP_ADDRESS, TOKEN_AUTHORITY_ADDRESS);

    let mut minimal_storage = Map::new();
    minimal_storage.insert(slot_key(route_supported_slot), word_value(U256::ONE));
    minimal_storage.insert(
        slot_key(route_policy_slot),
        word_value(U256::from(AUTH_POLICY_ID)),
    );
    alloc.insert(
        address_key(MINIMAL_DIRECT_SWAP_ADDRESS),
        json!({
            "balance": "0x0",
            "code": MINIMAL_DIRECT_SWAP_RUNTIME.trim(),
            "storage": minimal_storage,
        }),
    );

    upsert_storage(alloc, TOKEN_AUTHORITY_ADDRESS, role_member_slot, U256::ONE)?;
    upsert_storage(
        alloc,
        PATHUSD_ADDRESS,
        pathusd_user_allowance_slot,
        U256::from(AMOUNT_OUT),
    )?;
    upsert_storage(
        alloc,
        PATHUSD_ADDRESS,
        pathusd_authority_allowance_slot,
        U256::MAX,
    )?;
    upsert_storage(
        alloc,
        RESERVE_LEDGER_ADDRESS,
        reserve_authority_allowance_slot,
        U256::MAX,
    )?;
    upsert_balance(alloc, SMART_ACCOUNT_ADDRESS, "0x3635c9adc5dea00000")?;

    Ok(())
}

fn apply_user_state(alloc: &mut Map<String, Value>, user_state: UserState) -> eyre::Result<()> {
    let returning_value = match user_state {
        UserState::New => U256::ZERO,
        UserState::Returning => U256::ONE,
    };

    for (token, owner) in [
        (PATHUSD_ADDRESS, MINIMAL_DIRECT_SWAP_ADDRESS),
        (PATHUSD_ADDRESS, TOKEN_AUTHORITY_ADDRESS),
        (RESERVE_LEDGER_ADDRESS, MINIMAL_DIRECT_SWAP_ADDRESS),
        (DLUSD_ADDRESS, SMART_ACCOUNT_ADDRESS),
    ] {
        upsert_storage(alloc, token, tip20_balance_slot(owner), returning_value)?;
    }

    Ok(())
}
