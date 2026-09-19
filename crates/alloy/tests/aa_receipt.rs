use alloy::{
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
};
use alloy_provider::mock::Asserter;
use tempo_alloy::TempoNetwork;
use tempo_primitives::TempoTxType;

#[tokio::test]
async fn tempo_provider_deserializes_aa_receipt() {
    let asserter = Asserter::new();
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&serde_json::json!({
        "type": "0x76",
        "status": "0x1",
        "cumulativeGasUsed": "0x5208",
        "logs": [],
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": B256::ZERO,
        "transactionIndex": "0x0",
        "blockHash": B256::ZERO,
        "blockNumber": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "from": Address::ZERO,
        "to": Address::ZERO,
        "contractAddress": null,
        "feePayer": Address::ZERO,
    }));

    let receipt = provider
        .get_transaction_receipt(B256::ZERO)
        .await
        .expect("receipt request should succeed")
        .expect("receipt should be present");

    assert_eq!(receipt.inner.inner.receipt.tx_type, TempoTxType::AA);
}
