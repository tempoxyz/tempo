use alloy::{
    hex,
    primitives::{Address, Bytes, TxKind, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
    },
};
use alloy_eips::BlockNumberOrTag;
use reth_e2e_test_utils::wallet::test_signer;
use serde_json::json;
use std::num::NonZeroU64;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::rpc::simulate::TempoSimulateV1Response;
use tempo_precompiles::DEFAULT_FEE_TOKEN;
use tempo_primitives::transaction::{TEMPO_EXPIRING_NONCE_KEY, tempo_transaction::Call};

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

/// Calls on a `nonceKey` lane without a nonce simulate with the lane's nonce, not the sender's
/// protocol nonce, so validated simulation accepts them.
#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_fills_nonce_key_nonces() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    // Moves the protocol nonce past the lane nonces.
    setup_test_token(provider.clone(), caller).await?;
    assert!(provider.get_transaction_count(caller).await? > 0);
    let timestamp = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("latest block")
        .header
        .timestamp;

    let lane = U256::from(42);
    let call = |nonce_key| TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(caller),
            gas: Some(1_000_000),
            max_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(TEMPO_T1_BASE_FEE as u128),
            ..Default::default()
        },
        nonce_key: Some(nonce_key),
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    // The first simulated block is at most 12 seconds after its parent.
    let expiring = TempoTransactionRequest {
        valid_before: NonZeroU64::new(timestamp + 25),
        ..call(TEMPO_EXPIRING_NONCE_KEY)
    };
    let payload = SimulatePayload {
        block_state_calls: vec![
            SimBlock {
                block_overrides: None,
                state_overrides: None,
                calls: vec![call(lane), call(lane), expiring],
            },
            SimBlock {
                block_overrides: None,
                state_overrides: None,
                calls: vec![call(lane)],
            },
        ],
        trace_transfers: false,
        validation: true,
        return_full_transactions: true,
    };

    for method in ["eth_simulateV1", "tempo_simulateV1"] {
        let response: serde_json::Value = provider.raw_request(method.into(), (&payload,)).await?;
        let blocks = if method == "tempo_simulateV1" {
            &response["blocks"]
        } else {
            &response
        };
        let nonces = blocks
            .as_array()
            .expect("simulated blocks")
            .iter()
            .map(|block| {
                block["transactions"]
                    .as_array()
                    .expect("full transactions")
                    .iter()
                    .map(|tx| tx["nonce"].as_str().expect("nonce"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            nonces,
            [vec!["0x0", "0x1", "0x0"], vec!["0x2"]],
            "{method}: {response}"
        );
    }
    Ok(())
}
