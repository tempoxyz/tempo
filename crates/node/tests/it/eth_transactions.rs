use crate::{
    tempo_transaction::helpers::sign_aa_tx_with_p256_access_key,
    utils::{TestNodeBuilder, setup_test_token},
};
use alloy::{
    consensus::{SignableTransaction, Transaction, TxLegacy},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::SignerSync,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TransactionResponse;
use reth_e2e_test_utils::{receipt::PendingTransactionExt, wallet::test_signer};
use reth_primitives_traits::{RecoveredBlock, SignerRecoverable};
use reth_rpc_eth_api::helpers::{EthBlocks, LoadState, LoadTransaction};
use reth_rpc_eth_types::EthApiError;
use reth_transaction_pool::{TransactionOrigin, TransactionPool};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::DEFAULT_FEE_TOKEN;
use tempo_primitives::{
    Block, TempoTransaction, TempoTxEnvelope,
    transaction::{
        envelope::TEMPO_SYSTEM_TX_SIGNATURE, tempo_transaction::Call, tt_signature::p256_keypair,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transaction_by_sender_and_nonce() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
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
    pending_tx.successful_receipt().await?;

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
        calls: vec![Call::new(Address::ZERO, Bytes::new())],
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

#[tokio::test(flavor = "multi_thread")]
async fn test_raw_pooled_transaction_recovery_rejects_system_transactions() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new().build_with_node_access().await?;
    let eth_api = setup.node.rpc.inner.eth_api();
    let tx = TxLegacy::default();
    let system_tx = TempoTxEnvelope::Legacy(tx.clone().into_signed(TEMPO_SYSTEM_TX_SIGNATURE));
    let raw = system_tx.encoded_2718();

    assert!(matches!(
        eth_api.recover_raw_pooled_transaction(&raw),
        Err(EthApiError::InvalidTransactionSignature)
    ));
    assert!(matches!(
        eth_api.recover_raw_pooled_transactions([&raw]),
        Err(EthApiError::InvalidTransactionSignature)
    ));
    // Historical system transactions must remain recoverable.
    assert!(
        eth_api
            .recover_mined_transaction(system_tx)?
            .signer()
            .is_zero()
    );

    let wallet = test_signer(0);
    let signature = wallet.sign_hash_sync(&tx.signature_hash())?;
    let signed = TempoTxEnvelope::Legacy(tx.into_signed(signature));
    let recovered = eth_api.recover_raw_pooled_transaction(&signed.encoded_2718())?;
    assert_eq!(recovered.signer(), wallet.address());
    assert_eq!(recovered.inner(), &signed);

    assert!(matches!(
        eth_api.recover_raw_pooled_transaction(&[]),
        Err(EthApiError::EmptyRawTransactionData)
    ));
    Ok(())
}

/// `convert_block` must recover keychain key IDs on the shared block, not only on the clones it
/// hands to the transaction converter, so that cached blocks keep them.
#[tokio::test(flavor = "multi_thread")]
async fn test_convert_block_caches_keychain_key_id_on_shared_block() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new().build_with_node_access().await?;
    let eth_api = setup.node.rpc.inner.eth_api().clone();

    let root = test_signer(0).address();
    let (access_key, pub_key_x, pub_key_y, access_key_address) = p256_keypair();
    let tx = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call::new(Address::ZERO, Bytes::new())],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };
    let signature =
        sign_aa_tx_with_p256_access_key(&tx, &access_key, &pub_key_x, &pub_key_y, root)?;
    let envelope = TempoTxEnvelope::from(tx.into_signed(signature));

    let new_block = || {
        let mut block = Block::default();
        block.body.transactions.push(envelope.clone());
        RecoveredBlock::new_unhashed(block, vec![root])
    };
    // Serializing the signature alone emits the cached key ID without recovering it.
    let cached_key_id = |tx: &TempoTxEnvelope| {
        let signature = tx.as_aa().expect("AA transaction").signature();
        serde_json::to_value(signature).unwrap()["keyId"].clone()
    };
    let expected = serde_json::to_value(access_key_address)?;

    // Hash-only responses don't serialize transactions, so nothing is recovered.
    let hashes_block = new_block();
    assert_eq!(
        cached_key_id(&hashes_block.body().transactions[0]),
        serde_json::Value::Null
    );
    eth_api.convert_block(&hashes_block, false)?;
    assert_eq!(
        cached_key_id(&hashes_block.body().transactions[0]),
        serde_json::Value::Null
    );

    let block = new_block();
    assert_eq!(
        cached_key_id(&block.body().transactions[0]),
        serde_json::Value::Null
    );
    let rpc_block = eth_api.convert_block(&block, true)?;
    assert_eq!(cached_key_id(&block.body().transactions[0]), expected);

    let rpc_txs = rpc_block
        .transactions
        .as_transactions()
        .expect("full transactions");
    assert_eq!(rpc_txs.len(), 1);
    assert_eq!(cached_key_id(rpc_txs[0].inner.inner()), expected);

    Ok(())
}
