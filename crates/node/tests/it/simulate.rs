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

#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_block_gas_override_exceeds_general_limit() -> eyre::Result<()> {
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    genesis["config"]["generalGasLimit"] = json!(100_000);
    let setup = TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .with_gas_limit("0xf4240") // 1,000,000
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url.clone());
    let target = Address::repeat_byte(0x42);
    // An infinite loop consumes the call's full gas allowance.
    let payload = json!({
        "blockStateCalls": [{
            "blockOverrides": { "gasLimit": "0x1e8480" },
            "stateOverrides": { format!("{target:#x}"): { "code": "0x5b600056" } },
            "calls": [{
                "from": format!("{:#x}", Address::ZERO),
                "to": format!("{target:#x}"),
                "gas": "0x16e360"
            }]
        }],
        "validation": false
    });
    for method in ["eth_simulateV1", "tempo_simulateV1"] {
        for trace_transfers in [false, true] {
            let mut payload = payload.clone();
            payload["traceTransfers"] = json!(trace_transfers);
            let response: serde_json::Value =
                provider.raw_request(method.into(), (payload,)).await?;
            let blocks = if method == "tempo_simulateV1" {
                &response["blocks"]
            } else {
                &response
            };
            let gas_used = U256::from_str_radix(
                blocks[0]["gasUsed"]
                    .as_str()
                    .expect("simulated block gas used")
                    .trim_start_matches("0x"),
                16,
            )?;
            assert!(gas_used > U256::from(1_000_000), "{method}: {response}");
        }
    }
    Ok(())
}
