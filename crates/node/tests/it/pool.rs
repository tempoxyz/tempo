use alloy::{
    consensus::Transaction,
    signers::{SignerSync, local::PrivateKeySigner},
};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, TxKind, U64, U256};
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::{node::Finality, wait::assert_holds_for, wallet::test_signer};
use reth_ethereum::{
    evm::revm::primitives::hex, pool::TransactionPool, primitives::SignerRecoverable,
};
use reth_node_builder::BuiltPayload;
use reth_primitives_traits::transaction::{TxHashRef, error::InvalidTransactionError};
use reth_transaction_pool::{
    TransactionOrigin,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
};
use std::{num::NonZeroU64, time::Duration};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_precompiles::{DEFAULT_FEE_TOKEN, tip_fee_manager::TipFeeManager};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{calc_gas_balance_spending, tempo_transaction::Call},
};

#[tokio::test(flavor = "multi_thread")]
async fn submit_pending_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let node = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?
        .node
        .inner;

    // <cast mktx 0x20c0000000000000000000000000000000000000 'transfer(address,uint256)' 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 100000000 --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d --gas-limit 2000000 --gas-price 44000000000000 --priority-gas-price 1 --chain-id 1337 --nonce 0>
    let raw = hex!(
        "0x02f8b082053980018628048c5ec000831e84809420c000000000000000000000000000000000000080b844a9059cbb0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000000000005f5e100c001a0e7f78bca071cc3f0b41dabdee8b3b97c47ca8bfe3bf86861ba06cd97567d61f6a02ad11d6959be0eba004f1f3336c8b1c90aced228a00cbd5af990b519792e7b87"
    );

    let tx = TempoTxEnvelope::decode_2718_exact(&raw[..])?.try_into_recovered()?;
    let signer = tx.signer();
    let slot = TipFeeManager::new().user_tokens[signer].slot();
    println!("Submitting tx from {signer} with fee manager token slot 0x{slot:x}");

    let res = node
        .pool
        .add_consensus_transaction(tx, TransactionOrigin::Local)
        .await
        .unwrap();
    assert!(res.state.is_pending());
    let pooled_tx = node.pool.get_transactions_by_sender(signer);
    assert_eq!(pooled_tx.len(), 1);

    let best = node.pool.best_transactions().next().unwrap();
    assert_eq!(res.hash, *best.hash());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_insufficient_funds() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let node = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?
        .node
        .inner;

    let tx = TempoTransaction {
        chain_id: node.chain_spec().chain_id(),
        nonce: U64::random().to(),
        fee_token: Some(DEFAULT_FEE_TOKEN),
        max_priority_fee_per_gas: 74982851675,
        max_fee_per_gas: 74982851675,
        gas_limit: 1015288,
        calls: vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        ..Default::default()
    };
    let signer = PrivateKeySigner::random();

    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let tx: TempoTxEnvelope = tx.clone().into_signed(signature.into()).into();

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
    let signer_wallet = test_signer(0);
    let signer_addr = signer_wallet.address();

    let payload = setup.node.advance_block().await?;
    let tip_timestamp = payload.block().header().inner.timestamp;

    let tx_aa = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(
            NonZeroU64::new(tip_timestamp + 5).expect("tip timestamp + 5 must be non-zero"),
        ),
        ..Default::default()
    };

    // Sign the AA transaction
    let signature = signer_wallet.sign_hash_sync(&tx_aa.signature_hash())?;
    let envelope: TempoTxEnvelope = tx_aa.into_signed(signature.into()).into();
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

    assert!(res.state.is_pending(),);
    assert_eq!(pooled_txs.len(), 1);
    assert_eq!(*pooled_txs[0].hash(), tx_hash,);

    // Verify tx stays there before committing the new block
    let pool = &setup.node.inner.pool;
    assert_holds_for(
        Duration::from_secs(2),
        "tx to stay in the pool",
        move || async move { Ok(pool.get_transactions_by_sender(signer_addr).len() == 1) },
    )
    .await?;

    // Build the next block at `valid_before`, so the tx expires instead of being mined.
    setup.node.set_next_payload_timestamp(tip_timestamp + 5)?;
    setup.node.advance_block().await?;

    // Verify tx is evicted
    setup
        .node
        .wait_for_pool(|pool| pool.get_transactions_by_sender(signer_addr).is_empty())
        .await?;

    Ok(())
}

/// Test that AA 2D nonce transactions are re-injected into the pool after a reorg.
///
/// Reth's built-in `maintain_transaction_pool` handles this — no custom reorg logic needed.
///
/// 1. Submit and mine a 2D nonce AA tx in block A at height 1
/// 2. Build an empty block B on genesis and make it the head → reorg A→B
/// 3. The orphaned tx reappears in the pool
#[tokio::test(flavor = "multi_thread")]
async fn test_2d_nonce_tx_reinjected_after_reorg() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut node = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?
        .node;
    // Keep genesis finalized, so block A can be reorged.
    node.set_finality(Finality::Keep);
    let genesis = node.block_hash(0);

    // Step 1: Submit a 2D nonce AA tx and mine it in block A
    let signer_wallet = test_signer(0);

    let tx_aa = TempoTransaction {
        chain_id: 1337,
        nonce_key: U256::from(42),
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        fee_token: Some(tempo_precompiles::DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let signature = signer_wallet.sign_hash_sync(&tx_aa.signature_hash())?;
    let envelope: TempoTxEnvelope = tx_aa.into_signed(signature.into()).into();
    let recovered = envelope.try_into_recovered()?;
    let tx_hash = *recovered.tx_hash();

    node.inner
        .pool
        .add_consensus_transaction(recovered, TransactionOrigin::Local)
        .await?;
    assert!(node.inner.pool.contains(&tx_hash), "tx should be in pool");

    node.mine_pooled([tx_hash]).await?;

    node.wait_for_pool_removal([tx_hash]).await?;

    // Step 2: Build block B on genesis and make it the head → reorg A→B. B is empty because the
    // pool no longer holds the tx.
    node.advance_block_on(genesis).await?;

    // Step 3: Wait for the orphaned tx to reappear in the pool
    node.wait_for_pooled([tx_hash]).await?;

    Ok(())
}

/// Test that transactions are NOT evicted when a non-active validator changes their
/// token preference.
///
/// Prior to the fix, any `setValidatorToken` call would trigger eviction of pending
/// transactions that lacked liquidity against the new token. An attacker could exploit
/// this by calling `setValidatorToken` with an obscure token to evict victims' transactions.
///
/// After the fix, eviction only happens if the new token is already in use by actual
/// block producers (tracked via the AMM liquidity cache).
#[tokio::test(flavor = "multi_thread")]
async fn test_evict_tx_on_validator_token_change() -> eyre::Result<()> {
    use crate::utils::TestNodeBuilder;
    use alloy_primitives::address;

    reth_tracing::init_test_tracing();

    // Setup node with direct access
    let setup = TestNodeBuilder::new().build_with_node_access().await?;

    // First signer is the validator (coinbase), we use the second for user transactions
    let user_signer = test_signer(1);
    let user_addr = user_signer.address();

    // Create a fake "new validator token" address that is NOT in the active validator set.
    // This simulates an attacker calling setValidatorToken with an obscure token.
    let attacker_token = address!("1234567890123456789012345678901234567890");

    let pool = &setup.node.inner.pool;

    // Submit a transaction that uses DEFAULT_FEE_TOKEN (PATH_USD)
    let tx_default = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let signature = user_signer.sign_hash_sync(&tx_default.signature_hash())?;
    let envelope: TempoTxEnvelope = tx_default.into_signed(signature.into()).into();
    let recovered = envelope.try_into_recovered()?;
    let tx_hash = *recovered.tx_hash();

    // Submit tx to the pool
    let res = pool
        .add_consensus_transaction(recovered, TransactionOrigin::Local)
        .await?;
    assert!(res.state.is_pending());

    // Verify transaction is in the pool
    let pooled_txs = pool.get_transactions_by_sender(user_addr);
    assert_eq!(pooled_txs.len(), 1);
    assert_eq!(*pooled_txs[0].hash(), tx_hash);

    // Simulate an attacker calling setValidatorToken with a token that:
    // 1. Has no AMM pool with PATH_USD
    // 2. Is NOT in the active validator set (never produced blocks)
    //
    // This should NOT evict the transaction because the attacker's token is not
    // used by any active block producers.
    let updates = tempo_transaction_pool::TempoPoolUpdates {
        validator_token_changes: [(user_addr, attacker_token)].into_iter().collect(),
        ..Default::default()
    };
    pool.evict_invalidated_transactions(&updates);

    // Transaction should NOT be evicted because the attacker's token is not in
    // the active validator set.
    assert_holds_for(
        Duration::from_millis(10),
        "transaction to stay in the pool when validator token change is from a non-active validator",
        move || async move {
            let pooled_txs_after = pool.get_transactions_by_sender(user_addr);
            Ok(pooled_txs_after.len() == 1 && *pooled_txs_after[0].hash() == tx_hash)
        },
    )
    .await?;

    Ok(())
}

/// Test that pending transactions are evicted when a fee token's transfer policy changes
/// from allow-all to whitelist-based, effectively invalidating all transactions using
/// that fee token — except for transactions from whitelisted senders.
///
/// 1. Two disconnected nodes start at genesis
/// 2. Node2 mines a single block containing a TempoTransaction that creates a whitelist
///    policy, whitelists one sender + the fee manager, and applies the policy to
///    DEFAULT_FEE_TOKEN
/// 3. Node1 accumulates 10 AA transactions (indices 1–9 non-whitelisted, index 10
///    whitelisted) using DEFAULT_FEE_TOKEN
/// 4. Node1 imports node2's block (with the policy change)
/// 5. The 9 non-whitelisted transactions are evicted; the whitelisted one survives
#[tokio::test(flavor = "multi_thread")]
async fn test_evict_txs_on_transfer_policy_change() -> eyre::Result<()> {
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::{ITIP20, ITIP403Registry};
    use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS};

    reth_tracing::init_test_tracing();

    // Two disconnected nodes — no tx propagation
    let mut multi = crate::utils::TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;

    let node1 = multi.nodes.remove(0);
    let mut node2 = multi.nodes.remove(0);

    let admin_signer = test_signer(0);

    // The whitelisted user is mnemonic index 10
    let whitelisted_signer = test_signer(10);
    let whitelisted_addr = whitelisted_signer.address();

    // === Step 1: On node2, mine a block with a single AA tx that creates a whitelist
    //     policy, whitelists one sender + fee manager, and applies it ===

    // The first user-created policy gets ID 2 (0=REJECT_ALL, 1=ALLOW_ALL are reserved)
    let new_policy_id = 2u64;

    let policy_tx = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 5_000_000,
        calls: vec![
            // Call 1: create a whitelist policy
            Call {
                to: TxKind::Call(TIP403_REGISTRY_ADDRESS),
                value: U256::ZERO,
                input: ITIP403Registry::createPolicyCall {
                    admin: admin_signer.address(),
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                }
                .abi_encode()
                .into(),
            },
            // Call 2: whitelist the chosen sender
            Call {
                to: TxKind::Call(TIP403_REGISTRY_ADDRESS),
                value: U256::ZERO,
                input: ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: new_policy_id,
                    account: whitelisted_addr,
                    allowed: true,
                }
                .abi_encode()
                .into(),
            },
            // Call 3: whitelist the fee manager (recipient of fee transfers)
            Call {
                to: TxKind::Call(TIP403_REGISTRY_ADDRESS),
                value: U256::ZERO,
                input: ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: new_policy_id,
                    account: TIP_FEE_MANAGER_ADDRESS,
                    allowed: true,
                }
                .abi_encode()
                .into(),
            },
            // Call 4: change DEFAULT_FEE_TOKEN's transfer policy to the new whitelist
            Call {
                to: TxKind::Call(DEFAULT_FEE_TOKEN),
                value: U256::ZERO,
                input: ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: new_policy_id,
                }
                .abi_encode()
                .into(),
            },
        ],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let sig = admin_signer.sign_hash_sync(&policy_tx.signature_hash())?;
    let envelope: TempoTxEnvelope = policy_tx.into_signed(sig.into()).into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    node2.rpc.inject_tx(encoded.into()).await?;
    let policy_payload = node2.build_and_submit_payload().await?;

    // === Step 2: On node1, add 10 AA transactions using DEFAULT_FEE_TOKEN ===
    // Indices 1–9: non-whitelisted senders (should be evicted)
    // Index 10: whitelisted sender (should survive)

    let mut evictable_hashes = Vec::new();

    for i in 1..=9u32 {
        let user_signer = test_signer(i);

        let tx_aa = TempoTransaction {
            chain_id: 1337,
            max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::new(),
            }],
            fee_token: Some(DEFAULT_FEE_TOKEN),
            ..Default::default()
        };

        let signature = user_signer.sign_hash_sync(&tx_aa.signature_hash())?;
        let envelope: TempoTxEnvelope = tx_aa.into_signed(signature.into()).into();
        let recovered = envelope.try_into_recovered()?;
        let tx_hash = *recovered.tx_hash();

        node1
            .inner
            .pool
            .add_consensus_transaction(recovered, TransactionOrigin::Local)
            .await?;

        evictable_hashes.push(tx_hash);
    }

    // Submit the whitelisted sender's transaction
    let whitelisted_tx = TempoTransaction {
        chain_id: 1337,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let wl_sig = whitelisted_signer.sign_hash_sync(&whitelisted_tx.signature_hash())?;
    let wl_envelope: TempoTxEnvelope = whitelisted_tx.into_signed(wl_sig.into()).into();
    let wl_recovered = wl_envelope.try_into_recovered()?;
    let whitelisted_hash = *wl_recovered.tx_hash();

    node1
        .inner
        .pool
        .add_consensus_transaction(wl_recovered, TransactionOrigin::Local)
        .await?;

    // Verify all 10 transactions are in node1's pool
    for hash in &evictable_hashes {
        assert!(
            node1.inner.pool.contains(hash),
            "tx should be in pool before import"
        );
    }
    assert!(
        node1.inner.pool.contains(&whitelisted_hash),
        "whitelisted tx should be in pool before import"
    );

    // === Step 3: Import node2's block into node1 — should trigger eviction ===
    node1.import_payload(policy_payload).await?;

    // Pool maintenance runs asynchronously; wait for it to evict the non-whitelisted txs
    node1
        .wait_for_pool_removal(evictable_hashes.iter().copied())
        .await?;

    // Whitelisted transaction should still be in the pool
    assert!(
        node1.inner.pool.contains(&whitelisted_hash),
        "whitelisted tx should survive the policy change"
    );

    Ok(())
}
