use alloy::{
    primitives::{Address, address},
    providers::{Provider, ProviderBuilder},
};
use serde_json::{Value, json};
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, ensure_call_trace_succeeded, find_call_gas_used, hex_u64,
    mainnet_prestate_genesis, print_gas_snapshot,
};
use crate::utils::TestNodeBuilder;

// Mainnet tx 0x624c...b071 at block 0x183dfda, replayed from a prestateTracer fixture
// while forcing the local chain spec to T7. The test unwraps the user operation and
// traces the direct router call so the benchmark is not capped by the signed user-op gas.
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_563_681;
const SMART_ACCOUNT_ADDRESS: Address = address!("ea8c83b797d7dd7697858cf9d1944c84b1acb2e8");
const ROUTER_ADDRESS: &str = "0x73b5d86deae56497f852fd79dd6fe68c7270fb6b";
const SWAP_EXACT_OUT_SELECTOR: &str = "0x65149899";
const SWAP_EXACT_OUT_CALLDATA: &str = "0x6514989900000000000000000000000020c000000000000000000000000000000000000000000000000000000000000020c0000000000000000000006fd9a167923ba19400000000000000000000000000000000000000000000000000000000ee6b2800";
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_bridge_direct_swap_prestate.json");

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_bridge_direct_swap_t7_gas_snapshot() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .with_genesis(mainnet_replay_genesis()?)
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let call = json!({
        "from": SMART_ACCOUNT_ADDRESS.to_string(),
        "to": ROUTER_ADDRESS,
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

    print_gas_snapshot("TIP-1060 bridge direct swap gas snapshot (T7)", &gas);

    insta::assert_yaml_snapshot!("tip1060_bridge_direct_swap_t7_gas", gas);

    Ok(())
}

fn mainnet_replay_genesis() -> eyre::Result<String> {
    mainnet_prestate_genesis(
        TempoHardfork::T7,
        MAINNET_CHAIN_ID,
        MAINNET_BLOCK_TIMESTAMP,
        PRESTATE_JSON,
    )
}
