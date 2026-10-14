use crate::utils::TestNodeBuilder;
use alloy::{
    primitives::{Address, Bytes, TxKind, U256},
    rpc::types::TransactionRequest,
    signers::SignerSync,
};
use reth_e2e_test_utils::wallet::test_signer;
use reth_primitives_traits::SignerRecoverable;
use reth_rpc_eth_api::helpers::LoadState;
use reth_transaction_pool::{TransactionOrigin, TransactionPool};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::DEFAULT_FEE_TOKEN;
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::tempo_transaction::Call};

#[tokio::test(flavor = "multi_thread")]
async fn test_next_available_nonce_for_2d_key_includes_pending_txs() -> eyre::Result<()> {
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let eth_api = setup.node.rpc.inner.eth_api().clone();

    let wallet = test_signer(0);
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
    assert!(outcome.state.is_pending());

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

    setup.node.mine_pooled([outcome.hash]).await?;
    assert_eq!(
        eth_api
            .next_available_nonce_for(&request(nonce_key))
            .await?,
        1
    );

    Ok(())
}
