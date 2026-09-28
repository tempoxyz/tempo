use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};
use alloy::{
    consensus::Transaction,
    primitives::{Address, Bytes, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::MnemonicBuilder},
};
use alloy_network::TransactionResponse;
use reth_primitives_traits::SignerRecoverable;
use reth_rpc_eth_api::helpers::{EthTransactions, LoadState};
use reth_transaction_pool::{TransactionOrigin, TransactionPool, pool::AddedTransactionState};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::DEFAULT_FEE_TOKEN;
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::tempo_transaction::Call};

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transaction_by_sender_and_nonce() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    let nonce_before = provider.get_transaction_count(caller).await?;

    let mint_amount = U256::from(1000000u64);
    let pending_tx = token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?;

    let tx_hash = *pending_tx.tx_hash();
    let receipt = pending_tx.get_receipt().await?;
    assert!(receipt.status());

    let nonce_after = provider.get_transaction_count(caller).await?;
    assert_eq!(nonce_after, nonce_before + 1);

    let fetched_tx = provider
        .get_transaction_by_sender_nonce(caller, nonce_before)
        .await?;

    assert!(
        fetched_tx.is_some(),
        "Transaction should be found by sender and nonce"
    );

    let tx = fetched_tx.unwrap();
    assert_eq!(
        *tx.inner.tx_hash(),
        tx_hash,
        "Transaction hash should match"
    );
    assert_eq!(tx.from(), caller, "Transaction sender should match");
    assert_eq!(
        tx.inner.nonce(),
        nonce_before,
        "Transaction nonce should match"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_next_available_nonce_for_2d_key_includes_pending_txs() -> eyre::Result<()> {
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let eth_api = setup.node.rpc.inner.eth_api().clone();

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = wallet.address();
    let nonce_key = U256::from(42);

    let request = |nonce_key: U256| TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender),
            ..Default::default()
        },
        nonce_key: Some(nonce_key),
        ..Default::default()
    };

    assert_eq!(
        eth_api
            .next_available_nonce_for(&request(nonce_key))
            .await?,
        0
    );

    let tx = TempoTransaction {
        chain_id: 1337,
        nonce_key,
        nonce: 0,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    let signature = wallet.sign_hash_sync(&tx.signature_hash())?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let outcome = setup
        .node
        .inner
        .pool
        .add_consensus_transaction(envelope.try_into_recovered()?, TransactionOrigin::Local)
        .await?;
    assert!(matches!(outcome.state, AddedTransactionState::Pending));

    assert_eq!(
        eth_api
            .next_available_nonce_for(&request(nonce_key))
            .await?,
        1
    );
    assert_eq!(
        eth_api
            .next_available_nonce_for(&request(U256::from(43)))
            .await?,
        0
    );

    setup.node.advance_block().await?;
    assert!(eth_api.transaction_receipt(outcome.hash).await?.is_some());
    assert_eq!(
        eth_api
            .next_available_nonce_for(&request(nonce_key))
            .await?,
        1
    );

    Ok(())
}
