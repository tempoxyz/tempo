use crate::utils::TEST_MNEMONIC;
use alloy::{
    consensus::Transaction,
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
};
use alloy_eips::Decodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, TxKind, U256};
use reth_ethereum::{
    evm::revm::primitives::hex,
    node::builder::{NodeBuilder, NodeHandle},
    pool::TransactionPool,
    primitives::SignerRecoverable,
    tasks::TaskManager,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_primitives_traits::transaction::{TxHashRef, error::InvalidTransactionError};
use reth_transaction_pool::{
    TransactionOrigin,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    pool::AddedTransactionState,
};
use std::sync::Arc;
use tempo_chainspec::spec::{TEMPO_BASE_FEE, TempoChainSpec};
use tempo_node::node::TempoNode;
use tempo_precompiles::{DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, tip_fee_manager::TipFeeManager};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope, TxFeeToken,
    transaction::{
        calc_gas_balance_spending,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn submit_pending_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch()
        .await?;

    // <cast mktx 0x20c0000000000000000000000000000000000000 'transfer(address,uint256)' 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 100000000 --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d --gas-limit 2000000 --gas-price 44000000000000 --priority-gas-price 1 --chain-id 1337 --nonce 0>
    let raw = hex!(
        "0x02f8b082053980018628048c5ec000831e84809420c000000000000000000000000000000000000080b844a9059cbb0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000000000005f5e100c001a0e7f78bca071cc3f0b41dabdee8b3b97c47ca8bfe3bf86861ba06cd97567d61f6a02ad11d6959be0eba004f1f3336c8b1c90aced228a00cbd5af990b519792e7b87"
    );

    let tx = TempoTxEnvelope::decode_2718_exact(&raw[..])?.try_into_recovered()?;
    let signer = tx.signer();
    let slot = TipFeeManager::new().user_tokens.at(signer).slot();
    println!("Submitting tx from {signer} with fee manager token slot 0x{slot:x}");

    let res = node
        .pool
        .add_consensus_transaction(tx, TransactionOrigin::Local)
        .await
        .unwrap();
    assert!(matches!(res.state, AddedTransactionState::Pending));
    let pooled_tx = node.pool.get_transactions_by_sender(signer);
    assert_eq!(pooled_tx.len(), 1);

    let best = node.pool.best_transactions().next().unwrap();
    assert_eq!(res.hash, *best.hash());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_insufficient_funds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch()
        .await?;

    let mut tx = TxFeeToken {
        chain_id: 1,
        nonce: U256::random().saturating_to(),
        // Use AlphaUSD since PathUSD is only valid post-Allegretto
        fee_token: Some(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO),
        max_priority_fee_per_gas: 74982851675,
        max_fee_per_gas: 74982851675,
        gas_limit: 1015288,
        to: Address::random().into(),
        ..Default::default()
    };
    let signer = PrivateKeySigner::random();

    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    let tx = TempoTxEnvelope::FeeToken(tx.into_signed(signature));

    let res = node
        .pool
        .add_consensus_transaction(tx.clone().try_into_recovered()?, TransactionOrigin::Local)
        .await;

    let Err(PoolError {
        hash: _,
        kind:
            PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                InvalidTransactionError::InsufficientFunds(err),
            )),
    }) = res
    else {
        panic!("Expected InvalidTransaction error, got {res:?}");
    };

    assert_eq!(err.got, U256::ZERO);
    assert_eq!(
        err.expected,
        calc_gas_balance_spending(tx.gas_limit(), tx.max_fee_per_gas())
    );

    Ok(())
}

/// Test that AA transactions with expired `valid_before` are evicted from the pool.
#[tokio::test(flavor = "multi_thread")]
async fn test_evict_expired_aa_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node, and signer
    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;
    let signer_wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let signer_addr = signer_wallet.address();

    // Cache current timestamp
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Create an AA transaction with `valid_before = current_time + 1` second
    let tx_aa = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_BASE_FEE as u128,
        gas_limit: 100_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO),
        valid_before: Some(current_time + 1),
        ..Default::default()
    };

    // Sign the AA transaction
    let sig_hash = tx_aa.signature_hash();
    let signature = signer_wallet.sign_hash_sync(&sig_hash)?;
    let aa_signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let signed_tx = AASigned::new_unhashed(tx_aa, aa_signature);

    let envelope: TempoTxEnvelope = signed_tx.into();
    let recovered = envelope.try_into_recovered()?;
    let tx_hash = *recovered.tx_hash();
    assert_eq!(recovered.signer(), signer_addr);

    // Submit tx to the pool
    let res = setup
        .node
        .inner
        .pool
        .add_consensus_transaction(recovered, TransactionOrigin::Local)
        .await?;

    // Verify transaction is in the pool + pending
    let pooled_txs = setup
        .node
        .inner
        .pool
        .get_transactions_by_sender(signer_addr);

    assert!(matches!(res.state, AddedTransactionState::Pending),);
    assert_eq!(pooled_txs.len(), 1);
    assert_eq!(*pooled_txs[0].hash(), tx_hash,);

    // Advance blocks to trigger the eviction task (new block timestamp >= valid_before)
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify tx is still there before commiting the new block
    let pooled_txs_before = setup
        .node
        .inner
        .pool
        .get_transactions_by_sender(signer_addr);
    assert_eq!(pooled_txs_before.len(), 1);

    setup.node.advance_block().await?;

    // Verify tx is evicted
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let pooled_txs_after = setup
        .node
        .inner
        .pool
        .get_transactions_by_sender(signer_addr);
    assert!(pooled_txs_after.is_empty());

    Ok(())
}
