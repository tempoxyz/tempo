use alloy::{
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
};
use serde_json::{Map, Value, json};
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, ensure_call_trace_succeeded, find_call_gas_used, hex_u64,
    mainnet_prestate_genesis_value, print_gas_snapshot, tip20_balance_slot, upsert_storage,
};
use crate::utils::TestNodeBuilder;

// Mainnet tx 0x624c...b071 at block 0x183dfda, replayed from a prestateTracer fixture
// while forcing the local chain spec to T7. The test unwraps the user operation and
// traces the direct router call so the benchmark is not capped by the signed user-op gas.
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_563_681;
const SMART_ACCOUNT_ADDRESS: Address = address!("ea8c83b797d7dd7697858cf9d1944c84b1acb2e8");
const ROUTER_ADDRESS: Address = address!("73b5d86deae56497f852fd79dd6fe68c7270fb6b");
const STABLECOIN_HANDLER_ADDRESS: Address = address!("a7b1ed80a011d14a2db4a295570a72fe9cce647e");
const TOKEN_AUTHORITY_ADDRESS: Address = address!("8354d80eea9978faa04c3b36771c1e8b9c3e9058");
const PATHUSD_ADDRESS: Address = address!("20c0000000000000000000000000000000000000");
const DLUSD_ADDRESS: Address = address!("20c0000000000000000000006fd9a167923ba194");
const RESERVE_LEDGER_ADDRESS: Address = address!("20c00000000000000000000089caf7c622ae4b0f");
const SWAP_EXACT_OUT_SELECTOR: &str = "0x65149899";
const SWAP_EXACT_OUT_CALLDATA: &str = "0x6514989900000000000000000000000020c000000000000000000000000000000000000000000000000000000000000020c0000000000000000000006fd9a167923ba19400000000000000000000000000000000000000000000000000000000ee6b2800";
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_bridge_direct_swap_prestate.json");

#[derive(Clone, Copy)]
enum UserState {
    New,
    Returning,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_bridge_direct_swap_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_bridge_direct_swap_gas_snapshot(
        UserState::New,
        "tip1060_bridge_direct_swap_t7_gas",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_bridge_direct_swap_returning_user_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_bridge_direct_swap_gas_snapshot(
        UserState::Returning,
        "tip1060_bridge_direct_swap_returning_user_t7_gas",
    )
    .await
}

async fn test_tip1060_bridge_direct_swap_gas_snapshot(
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

    let call = json!({
        "from": SMART_ACCOUNT_ADDRESS.to_string(),
        "to": ROUTER_ADDRESS.to_string(),
        "gas": "0x989680",
        "gasPrice": "0x59682f000",
        "data": SWAP_EXACT_OUT_CALLDATA,
    });
    let trace: Value = provider
        .raw_request(
            "debug_traceCall".into(),
            (
                call,
                "latest",
                serde_json::json!({
                    "tracer": "callTracer",
                }),
            ),
        )
        .await?;
    ensure_call_trace_succeeded(&trace)?;

    let mut gas = GasSnapshot::new();
    gas.record(
        "bridge_direct_swap",
        hex_u64(
            trace
                .get("gasUsed")
                .ok_or_else(|| eyre::eyre!("call trace missing gasUsed"))?,
        )?,
    );
    gas.record(
        "bridge_direct_swap_swap_exact_out",
        find_call_gas_used(&trace, ROUTER_ADDRESS, SWAP_EXACT_OUT_SELECTOR)?,
    );

    print_gas_snapshot(
        match user_state {
            UserState::New => "TIP-1060 bridge direct swap gas snapshot (T7, new user)",
            UserState::Returning => "TIP-1060 bridge direct swap gas snapshot (T7, returning user)",
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
        (PATHUSD_ADDRESS, ROUTER_ADDRESS),
        (PATHUSD_ADDRESS, STABLECOIN_HANDLER_ADDRESS),
        (PATHUSD_ADDRESS, TOKEN_AUTHORITY_ADDRESS),
        (RESERVE_LEDGER_ADDRESS, ROUTER_ADDRESS),
        (RESERVE_LEDGER_ADDRESS, STABLECOIN_HANDLER_ADDRESS),
        (DLUSD_ADDRESS, SMART_ACCOUNT_ADDRESS),
        (DLUSD_ADDRESS, ROUTER_ADDRESS),
        (DLUSD_ADDRESS, STABLECOIN_HANDLER_ADDRESS),
    ] {
        upsert_storage(alloc, token, tip20_balance_slot(owner), value)?;
    }

    Ok(())
}
