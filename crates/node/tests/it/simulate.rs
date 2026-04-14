use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use serde_json::json;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::rpc::simulate::TempoSimulateV1Response;

use crate::utils::{TestNodeBuilder, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_simulate_v1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;
    let token_addr = *token.address();

    let mint_amount = U256::from(1_000_000u64);
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Construct a TIP20 call and insert into calls
    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();

    let payload = json!({
        "blockStateCalls": [{
            "calls": [{
                "from": format!("{caller:#x}"),
                "to": format!("{token_addr:#x}"),
                "input": format!("0x{}", alloy::hex::encode(&calldata)),
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

    // Construct a call that does not target TIP20
    let payload = json!({
        "blockStateCalls": [{
            "calls": [{
                "from": format!("{:#x}", Address::ZERO),
                "to": format!("{:#x}", Address::random()),
            }]
        }],
    });

    let response: TempoSimulateV1Response<serde_json::Value> = provider
        .raw_request("tempo_simulateV1".into(), (payload,))
        .await?;

    assert!(
        response.token_metadata.is_empty(),
        "expected empty token metadata for non-TIP-20 simulation"
    );

    Ok(())
}
