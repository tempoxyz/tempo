use alloy::{
    hex,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
};
use reth_e2e_test_utils::wallet::test_signer;
use serde_json::json;
use tempo_alloy::test_utils::CallBuilderExt;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::rpc::simulate::TempoSimulateV1Response;

use crate::utils::{TestNodeBuilder, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_simulate_v1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;
    let token_addr = *token.address();

    let mint_amount = U256::from(1_000_000u64);
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .mined()
        .await?;

    // Construct a TIP20 call and insert into calls
    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();

    let payload = json!({
        "blockStateCalls": [{
            "calls": [{
                "from": format!("{caller:#x}"),
                "to": format!("{token_addr:#x}"),
                "input": hex::encode_prefixed(&calldata),
            }]
        }],
        "traceTransfers": true,
    });

    let response: TempoSimulateV1Response<serde_json::Value> = provider
        .raw_request("tempo_simulateV1".into(), (payload,))
        .await?;
    assert!(!response.blocks.is_empty());

    // Assert expected metadata
    let meta = response
        .token_metadata
        .get(&token_addr)
        .expect("Could not get metadata");

    assert_eq!(meta.name, "Test");
    assert_eq!(meta.symbol, "TEST");
    assert_eq!(meta.currency, "USD");

    // Construct calls that target a non-TIP20 address and an undeployed TIP20 address
    let undeployed_tip20 = address!("0x20C000000000000000000000ffffffffffffffff");
    let payload = json!({
        "blockStateCalls": [{
            "calls": [
                {
                    "from": format!("{:#x}", Address::ZERO),
                    "to": format!("{:#x}", Address::random()),
                },
                {
                    "from": format!("{:#x}", Address::ZERO),
                    "to": format!("{undeployed_tip20:#x}"),
                },
            ]
        }],
    });

    let response: TempoSimulateV1Response<serde_json::Value> = provider
        .raw_request("tempo_simulateV1".into(), (payload,))
        .await?;

    assert!(
        response.token_metadata.is_empty(),
        "expected empty token metadata for non-TIP-20 and undeployed TIP-20 targets"
    );

    Ok(())
}

/// `tempo_simulateV1` rejects a payload over the call limit before decoding its calls, like
/// `eth_simulateV1`.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_simulate_v1_bounds_calls() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);

    let payload = json!({ "blockStateCalls": [{ "calls": vec![json!({}); 4097] }] });
    let err = provider
        .raw_request::<_, serde_json::Value>("tempo_simulateV1".into(), (payload,))
        .await
        .unwrap_err();
    let err = err.as_error_resp().expect("JSON-RPC error");
    assert_eq!(err.code, -32602);
    assert_eq!(err.message, "too many calls in simulation payload");

    Ok(())
}
