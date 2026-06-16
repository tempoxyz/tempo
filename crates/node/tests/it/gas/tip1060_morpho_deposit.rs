use alloy::{
    hex,
    primitives::{B256, Bytes, b256},
    providers::{Provider, ProviderBuilder},
};
use serde_json::Value;
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, ensure_call_trace_succeeded, find_call_gas_used, mainnet_prestate_genesis,
    print_gas_snapshot, successful_raw_receipt_gas_used,
};
use crate::utils::TestNodeBuilder;

// Mainnet tx 0x4d17...5db9 at block 0x1844940, replayed from a prestateTracer
// fixture while forcing the local chain spec to T7.
const MAINNET_TX_HASH: B256 =
    b256!("4d1767b5efe3bfdf3576e336fc5ad56bf55800e5ba071e168585538add8c5db9");
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_578_286;
const PATHUSD_ADDRESS: &str = "0x20c0000000000000000000000000000000000000";
const PRIMARY_VAULT_ADDRESS: &str = "0x83a1491f3e7f8daab8f787a631334b9ca7a87023";
const NESTED_VAULT_ADDRESS: &str = "0x9a044ae05e5e6290dcf56afd69548565e957a626";
const MORPHO_ADDRESS: &str = "0x799cd096e5ebc436daecef85392b2ecf196dfbe6";
const APPROVE_SELECTOR: &str = "0x095ea7b3";
const DEPOSIT_SELECTOR: &str = "0x6e553f65";
const MORPHO_SUPPLY_SELECTOR: &str = "0x1eadd778";
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_morpho_deposit_prestate.json");
const RAW_TX: &str = "0x76f90193821079808504a817c8008316372ff8bcf85c9420c000000000000000000000000000000000000080b844095ea7b300000000000000000000000083a1491f3e7f8daab8f787a631334b9ca7a870230000000000000000000000000000000000000000000000000000000047868c00f85c9483a1491f3e7f8daab8f787a631334b9ca7a8702380b8446e553f650000000000000000000000000000000000000000000000000000000047868c000000000000000000000000000bc95cddc7da082eef47856091c519a61c8eee9bc0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a30ba47809420c0000000000000000000000000000000000000f84301a0357f48124418ec52f37fc956e9083adb098109e53863ebd64c985cdb0de861a7a05ba6e80cfd61da3e4fa760168feabf9126a5757d352d6b915a9fd5b0dd0979b7c0b841584f5d897e9fbf2adbffe490c5e4bc681a405615fffe7b5e87fdfd90006ca9f657a796dfc131dfa95c518400d0048d83402828a19364aa63c6ee02a667a2f4481c";

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_morpho_deposit_t7_gas_snapshot() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_genesis(mainnet_replay_genesis()?)
        .build_with_node_access()
        .await?;
    setup.node.payload.timestamp = MAINNET_BLOCK_TIMESTAMP;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let raw_tx = Bytes::from(hex::decode(RAW_TX.trim_start_matches("0x"))?);
    setup.node.rpc.inject_tx(raw_tx.into()).await?;
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
    gas.record("morpho_deposit", receipt_gas_used);
    gas.record(
        "morpho_deposit_pathusd_approve",
        find_call_gas_used(&trace, PATHUSD_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_primary_vault_deposit",
        find_call_gas_used(&trace, PRIMARY_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_nested_vault_deposit",
        find_call_gas_used(&trace, NESTED_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_morpho_supply",
        find_call_gas_used(&trace, MORPHO_ADDRESS, MORPHO_SUPPLY_SELECTOR)?,
    );

    print_gas_snapshot("TIP-1060 Morpho deposit gas snapshot (T7)", &gas);

    insta::assert_yaml_snapshot!("tip1060_morpho_deposit_t7_gas", gas);

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
