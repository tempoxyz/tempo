//! Local (single-node) test environment and localnet-only integration tests.
//!
//! Contains the [`Localnet`] [`TestEnv`](super::types::TestEnv) implementation
//! which spins up an in-process node with direct pool/block access, plus tests
//! that require pool introspection or controlled block mining.

use crate::utils::{ForkSchedule, SingleNodeSetup, TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    consensus::{BlockHeader, Transaction},
    network::{EthereumWallet, ReceiptResponse},
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use reth_ethereum::network::{NetworkSyncUpdater, SyncState};
use reth_node_api::BuiltPayload;
use reth_primitives_traits::transaction::TxHashRef;
use reth_transaction_pool::TransactionPool;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, account_keychain::IAccountKeychain::revokeKeyCall,
};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    tip20::ITIP20::{self},
};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        tempo_transaction::Call,
        tt_signature::{KeychainSignature, PrimitiveSignature, TempoSignature, WebAuthnSignature},
        tt_signed::AASigned,
    },
};

use super::helpers::*;

/// Single-node local test environment with direct node access.
pub(crate) struct Localnet {
    pub setup: SingleNodeSetup,
    pub provider: alloy::providers::RootProvider,
    pub chain_id: u64,
    pub funder_signer: alloy::signers::local::LocalSigner<alloy::signers::k256::ecdsa::SigningKey>,
    pub funder_addr: Address,
}

impl Localnet {
    pub(crate) async fn new() -> eyre::Result<Self> {
        Self::with_schedule(ForkSchedule::Devnet).await
    }

    pub(crate) async fn with_schedule(schedule: ForkSchedule) -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let setup = TestNodeBuilder::new()
            .with_schedule(schedule)
            .build_with_node_access()
            .await?;
        let provider = alloy::providers::RootProvider::new_http(setup.node.rpc_url());
        let chain_id = provider.get_chain_id().await?;
        let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
        let funder_addr = funder_signer.address();
        Ok(Self {
            setup,
            provider,
            chain_id,
            funder_signer,
            funder_addr,
        })
    }
}

impl super::types::TestEnv for Localnet {
    type P = alloy::providers::RootProvider;

    fn provider(&self) -> &Self::P {
        &self.provider
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn hardfork(&self) -> TempoHardfork {
        self.setup.hardfork
    }

    async fn fund_account(&mut self, addr: Address) -> eyre::Result<U256> {
        let amount = rand_funding_amount();
        fund_address_with(
            &mut self.setup,
            &self.provider,
            &self.funder_signer,
            self.funder_addr,
            addr,
            amount,
            DEFAULT_FEE_TOKEN,
            self.chain_id,
        )
        .await?;
        Ok(amount)
    }

    async fn submit_tx_expecting_rejection(
        &self,
        encoded: Vec<u8>,
        expected_reason: Option<&str>,
    ) -> eyre::Result<()> {
        // Handler-level rejection
        let handler_result = self.setup.node.rpc.inject_tx(encoded.clone().into()).await;
        assert!(handler_result.is_err(), "Handler should reject the tx");

        // RPC-level rejection
        let rpc_result = self
            .provider()
            .raw_request::<_, B256>("eth_sendRawTransaction".into(), [encoded])
            .await;
        assert!(rpc_result.is_err(), "RPC should reject the transaction");

        if let (Some(reason), Err(err)) = (expected_reason, &rpc_result) {
            let err_str = err.to_string().to_lowercase();
            assert!(
                err_str.contains(&reason.to_lowercase()),
                "Rejection error should contain '{reason}', got: {err}"
            );
        }
        Ok(())
    }

    async fn submit_tx(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;
        self.setup.node.advance_block().await?;

        let raw: Option<serde_json::Value> = self
            .provider
            .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
            .await?;
        let receipt =
            raw.ok_or_else(|| eyre::eyre!("Transaction receipt not found for {tx_hash}"))?;
        let status = receipt["status"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Receipt missing status field"))?;
        assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
        Ok(receipt)
    }

    async fn submit_tx_excluded_by_builder(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<()> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;
        assert!(
            self.setup.node.inner.pool.contains(&tx_hash),
            "Tx should be in pool after injection"
        );

        // Advance several blocks — tx should never be included by the builder.
        for _ in 0..5 {
            self.setup.node.advance_block().await?;

            let raw: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = raw {
                let status = receipt["status"].as_str().unwrap_or("?");
                panic!(
                    "Transaction {tx_hash} was mined (status={status}), \
                     expected exclusion by builder"
                );
            }
        }
        Ok(())
    }

    async fn bump_protocol_nonce(
        &mut self,
        signer: &PrivateKeySigner,
        signer_addr: Address,
        count: u64,
    ) -> eyre::Result<()> {
        let recipient = Address::random();
        let start_nonce = self.provider.get_transaction_count(signer_addr).await?;

        for i in 0..count {
            let tx = create_basic_aa_tx(
                self.chain_id,
                start_nonce + i,
                vec![Call {
                    to: recipient.into(),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                300_000,
            );

            let signature = sign_aa_tx_secp256k1(&tx, signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let tx_hash = *envelope.tx_hash();
            self.setup
                .node
                .rpc
                .inject_tx(envelope.encoded_2718().into())
                .await?;
            self.setup.node.advance_block().await?;
            wait_until_pool_not_contains(
                &self.setup.node.inner.pool,
                &tx_hash,
                "bump_protocol_nonce",
            )
            .await?;
        }

        let final_nonce = self.provider.get_transaction_count(signer_addr).await?;
        assert_eq!(
            final_nonce,
            start_nonce + count,
            "Protocol nonce should have bumped"
        );
        Ok(())
    }

    async fn current_block_timestamp(&mut self) -> eyre::Result<u64> {
        for _ in 0..3 {
            self.setup.node.advance_block().await?;
        }
        let block = self
            .provider
            .get_block_by_number(Default::default())
            .await?
            .ok_or_else(|| eyre::eyre!("latest block missing"))?;
        Ok(block.header.timestamp())
    }

    async fn submit_tx_unchecked(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        self.setup.node.rpc.inject_tx(encoded.into()).await?;

        // Try multiple blocks — the tx may not be pending in the first block
        // if pool maintenance hasn't processed the previous block yet.
        for _ in 0..3 {
            self.setup.node.advance_block().await?;

            let raw: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = raw {
                return Ok(receipt);
            }
        }
        Err(eyre::eyre!(
            "Transaction receipt not found for {tx_hash} after 3 blocks"
        ))
    }

    async fn submit_tx_sync(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        let sync_provider: alloy::providers::RootProvider =
            alloy::providers::RootProvider::new_http(self.setup.node.rpc_url());
        let encoded_for_sync = encoded;
        let mut sync_handle = tokio::spawn(async move {
            sync_provider
                .raw_request::<_, serde_json::Value>(
                    "eth_sendRawTransactionSync".into(),
                    [encoded_for_sync],
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    res = &mut sync_handle => {
                        let res = res.map_err(|err| eyre::eyre!("Sync task failed: {err}"))?;
                        let _raw_result = res.map_err(|err| eyre::eyre!("Sync request failed: {err}"))?;
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        self.setup
                            .node
                            .advance_block()
                            .await
                            .map_err(|err| eyre::eyre!("Advance block failed: {err}"))?;
                    }
                }
            }
            // Poll for receipt after sync completes (may not be immediately queryable)
            for _ in 0..10 {
                let raw: Option<serde_json::Value> = self
                    .provider
                    .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                    .await?;
                if let Some(receipt) = raw {
                    let status = receipt["status"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("Receipt missing status field for {tx_hash}"))?;
                    assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
                    return Ok(receipt);
                }
                self.setup.node.advance_block().await
                    .map_err(|err| eyre::eyre!("Advance block failed: {err}"))?;
            }
            Err(eyre::eyre!("Transaction receipt not found for {tx_hash} after sync"))
        })
        .await
        .map_err(|_| eyre::eyre!("eth_sendRawTransactionSync timed out"))?
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_pool_comprehensive() -> eyre::Result<()> {
    let localnet = Localnet::new().await?;
    let Localnet {
        mut setup,
        provider,
        chain_id,
        funder_signer: alice_signer,
        funder_addr: alice_addr,
        ..
    } = localnet;

    println!("\n=== Comprehensive 2D Nonce Pool Test ===\n");
    println!("Alice address: {alice_addr}");

    let recipient = Address::random();

    // ===========================================================================
    // Scenario 1: Pool Routing & Independence
    // ===========================================================================
    println!("\n--- Scenario 1: Pool Routing & Independence ---");

    let initial_nonce = provider.get_transaction_count(alice_addr).await?;
    println!("Initial protocol nonce: {initial_nonce}");

    // Send 3 transactions with different nonce_keys
    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            initial_nonce,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // Protocol pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            0,
            TEMPO_T1_BASE_FEE as u128,
        )
        .await?,
    ); // 2D pool

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload1.block().inner.number,
        block1_txs.len()
    );

    // Verify all submitted transactions were included in the block
    for tx_hash in &sent {
        assert!(
            block1_txs.iter().any(|tx| tx.tx_hash() == tx_hash),
            "Submitted tx {tx_hash} should be in the block"
        );
    }

    // Verify protocol nonce incremented
    let protocol_nonce_after = provider.get_transaction_count(alice_addr).await?;
    assert_eq!(
        protocol_nonce_after,
        initial_nonce + 1,
        "Protocol nonce should increment only once"
    );
    println!("  ✓ Protocol nonce: {initial_nonce} → {protocol_nonce_after}",);

    for tx_hash in &sent {
        wait_until_pool_not_contains(&setup.node.inner.pool, tx_hash, "scenario 1").await?;
    }
    println!("  ✓ All 3 transactions from different pools included in block");

    // ===========================================================================
    // Scenario 2: Priority Fee Ordering (with subsequent nonces)
    // ===========================================================================
    println!("\n--- Scenario 2: Priority Fee Ordering ---");

    // Send transactions with different priority fees
    let low_fee = 1_000_000_000u128; // 1 gwei
    let mid_fee = 5_000_000_000u128; // 5 gwei
    let high_fee = 10_000_000_000u128; // 10 gwei

    let mut sent = vec![];
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            0,
            protocol_nonce_after,
            low_fee,
        )
        .await?,
    ); // Protocol pool, low fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            1,
            1,
            high_fee,
        )
        .await?,
    ); // 2D pool, highest fee
    sent.push(
        send_tx(
            &mut setup,
            &alice_signer,
            chain_id,
            recipient,
            2,
            1,
            mid_fee,
        )
        .await?,
    ); // 2D pool, medium fee

    for tx_hash in &sent {
        // Assert that transactions are in the pool
        assert!(
            setup.node.inner.pool.contains(tx_hash),
            "Transaction should be in the pool"
        );
    }

    // Mine block
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload2.block().inner.number,
        block2_txs.len()
    );

    assert_eq!(
        provider.get_transaction_count(alice_addr).await?,
        initial_nonce + 2,
        "Protocol nonce should have incremented twice"
    );

    // Verify all submitted transactions were included in the block
    for tx_hash in &sent {
        assert!(
            block2_txs.iter().any(|tx| tx.tx_hash() == tx_hash),
            "Submitted tx {tx_hash} should be in the block"
        );
    }

    // Extract priority fees in block order, filtered to only our submitted txs
    let priority_fees: Vec<u128> = block2_txs
        .iter()
        .filter(|tx| sent.contains(tx.tx_hash()))
        .filter_map(|tx| match tx {
            TempoTxEnvelope::AA(aa_tx) => {
                println!(
                    "    TX with nonce_key={}, nonce={}, priority_fee={} gwei",
                    aa_tx.tx().nonce_key,
                    aa_tx.tx().nonce,
                    aa_tx.tx().max_priority_fee_per_gas / 1_000_000_000
                );
                Some(aa_tx.tx().max_priority_fee_per_gas)
            }
            _ => None,
        })
        .collect();

    // Verify all 3 transactions are included and ordered by descending priority fee
    assert_eq!(priority_fees.len(), 3, "Should have 3 AA transactions");
    assert!(
        priority_fees.windows(2).all(|w| w[0] >= w[1]),
        "Transactions should be ordered by descending priority fee, got: {priority_fees:?}"
    );
    println!("  ✓ All transactions included and ordered by descending priority fee");

    for tx_hash in &sent {
        wait_until_pool_not_contains(&setup.node.inner.pool, tx_hash, "scenario 2").await?;
    }

    // ===========================================================================
    // Scenario 3: Nonce Gap Handling
    // ===========================================================================
    println!("\n--- Scenario 3: Nonce Gap Handling ---");

    // Send nonce=0 for nonce_key=3 (should be pending)
    let pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        0,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=0 (should be pending)");

    // Send nonce=2 for nonce_key=3 (should be queued - gap at nonce=1)
    let queued = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        2,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("  Sent nonce_key=3, nonce=2 (should be queued - gap at nonce=1)");

    // Assert that both transactions are in the pool and tracked correctly
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .queued_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - only nonce=0 should be included
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload3.block().inner.number,
        block3_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let nonce_key_3_txs: Vec<_> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(3)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        nonce_key_3_txs.len(),
        1,
        "Only 1 transaction (nonce=0) should be included, nonce=2 should be queued"
    );
    assert_eq!(
        nonce_key_3_txs[0], 0,
        "The included transaction should have nonce=0"
    );
    println!("  ✓ Only nonce=0 included, nonce=2 correctly queued due to gap");

    // Fill the gap - send nonce=1
    let new_pending = send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        3,
        1,
        TEMPO_T1_BASE_FEE as u128,
    )
    .await?;
    println!("\n  Sent nonce_key=3, nonce=1 (fills the gap)");

    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &new_pending)
    );
    assert!(
        setup
            .node
            .inner
            .pool
            .pending_transactions()
            .iter()
            .any(|tx| tx.hash() == &queued)
    );

    // Mine block - both nonce=1 and nonce=2 should be included now
    let payload4 = setup.node.advance_block().await?;
    let block4_txs = &payload4.block().body().transactions;

    println!(
        "\n  Block {} mined with {} transactions",
        payload4.block().inner.number,
        block4_txs.len()
    );

    // Count AA transactions with nonce_key=3
    let mut nonce_key_3_txs_after: Vec<_> = block4_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(3)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    nonce_key_3_txs_after.sort();

    // After filling the gap, both nonce=1 and nonce=2 should be mined
    assert!(
        nonce_key_3_txs_after.contains(&1),
        "nonce=1 should be included after filling gap"
    );
    assert!(
        nonce_key_3_txs_after.contains(&2),
        "nonce=2 should be promoted from queue after gap is filled"
    );
    println!("  ✓ Both nonce=1 and nonce=2 included");

    wait_until_pool_not_contains(&setup.node.inner.pool, &pending, "scenario 3 pending").await?;
    wait_until_pool_not_contains(&setup.node.inner.pool, &queued, "scenario 3 queued").await?;
    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &new_pending,
        "scenario 3 new_pending",
    )
    .await?;

    Ok(())
}
/// Sign and inject a secp256k1 AA transaction with a custom nonce key and priority fee.
async fn send_tx(
    setup: &mut crate::utils::SingleNodeSetup,
    signer: &impl SignerSync,
    chain_id: u64,
    recipient: Address,
    nonce_key: u64,
    nonce: u64,
    priority_fee: u128,
) -> eyre::Result<B256> {
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.nonce_key = U256::from(nonce_key);
    tx.max_priority_fee_per_gas = priority_fee;
    tx.max_fee_per_gas = TEMPO_T1_BASE_FEE as u128 + priority_fee;
    tx.fee_token = None;

    let signature = sign_aa_tx_secp256k1(&tx, signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    println!(
        "  ✓ Sent tx: nonce_key={nonce_key}, nonce={nonce}, priority_fee={} gwei",
        priority_fee / 1_000_000_000
    );
    Ok(tx_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_aa_2d_nonce_out_of_order_arrival() -> eyre::Result<()> {
    let Localnet {
        mut setup,
        chain_id,
        funder_signer: alice_signer,
        ..
    } = Localnet::new().await?;

    let recipient = Address::random();

    println!("\n=== Out-of-Order Nonce Arrival Test ===");
    println!("Testing nonce_key=4 with nonces arriving as: [5, 0, 2]");
    println!("Expected: Only execute in order, queue out-of-order txs\n");

    // Step 1: Send nonce=5 (should be queued - large gap)
    println!("Step 1: Send nonce=5 (should be queued - gap at 0,1,2,3,4)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        5,
        10_000_000_000,
    )
    .await?;

    // Step 2: Send nonce=0 (should be pending - ready to execute)
    println!("\nStep 2: Send nonce=0 (should be pending - ready to execute)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        0,
        10_000_000_000,
    )
    .await?;

    // Step 3: Send nonce=2 (should be queued - gap at 1)
    println!("\nStep 3: Send nonce=2 (should be queued - gap at 1)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        2,
        10_000_000_000,
    )
    .await?;

    // Mine block - only nonce=0 should execute
    println!("\nMining block (should only include nonce=0)...");
    let payload1 = setup.node.advance_block().await?;
    let block1_txs = &payload1.block().body().transactions;

    let executed_nonces: Vec<u64> = block1_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(executed_nonces, vec![0], "Only nonce=0 should execute");
    println!("  ✓ Block 1: Only nonce=0 executed (nonce=2 and nonce=5 correctly queued)");

    // Step 4: Send nonce=1 (fills first gap)
    println!("\nStep 4: Send nonce=1 (fills gap before nonce=2)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        1,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonce=1 and nonce=2 should both execute (promotion!)
    println!("\nMining block (should include nonce=1 AND nonce=2 via promotion)...");
    let payload2 = setup.node.advance_block().await?;
    let block2_txs = &payload2.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block2_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&1), "nonce=1 should execute");
    assert!(
        executed_nonces.contains(&2),
        "nonce=2 should promote and execute"
    );
    println!("  ✓ Block 2: nonce=1 and nonce=2 executed (promotion worked!)");

    // Step 5: Send nonces 3 and 4 (fills remaining gaps)
    println!("\nStep 5: Send nonces 3 and 4 (fills gaps before nonce=5)");
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        3,
        10_000_000_000,
    )
    .await?;
    send_tx(
        &mut setup,
        &alice_signer,
        chain_id,
        recipient,
        4,
        4,
        10_000_000_000,
    )
    .await?;

    // Mine block - nonces 3, 4, and 5 should all execute
    println!("\nMining block (should include nonces 3, 4, AND 5 via promotion)...");
    let payload3 = setup.node.advance_block().await?;
    let block3_txs = &payload3.block().body().transactions;

    let mut executed_nonces: Vec<u64> = block3_txs
        .iter()
        .filter_map(|tx| {
            if tx.nonce_key() == Some(U256::from(4)) {
                Some(tx.nonce())
            } else {
                None
            }
        })
        .collect();
    executed_nonces.sort();

    assert!(executed_nonces.contains(&3), "nonce=3 should execute");
    assert!(executed_nonces.contains(&4), "nonce=4 should execute");
    assert!(
        executed_nonces.contains(&5),
        "nonce=5 should finally promote and execute"
    );
    Ok(())
}

#[tokio::test]
async fn test_aa_webauthn_signature_negative_cases() -> eyre::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
    };
    use sha2::{Digest, Sha256};

    reth_tracing::init_test_tracing();

    // Setup test node with direct access
    let setup = TestNodeBuilder::new().build_with_node_access().await?;

    let http_url = setup.node.rpc_url();

    // Generate the correct P256 key pair for WebAuthn
    let correct_signing_key = SigningKey::random(&mut OsRng);
    let correct_verifying_key = correct_signing_key.verifying_key();

    // Extract correct public key coordinates
    let correct_encoded_point = correct_verifying_key.to_encoded_point(false);
    let correct_pub_key_x =
        alloy::primitives::B256::from_slice(correct_encoded_point.x().unwrap().as_ref());
    let correct_pub_key_y =
        alloy::primitives::B256::from_slice(correct_encoded_point.y().unwrap().as_ref());

    // Generate a different (wrong) P256 key pair
    let wrong_signing_key = SigningKey::random(&mut OsRng);
    let wrong_verifying_key = wrong_signing_key.verifying_key();

    // Extract wrong public key coordinates
    let wrong_encoded_point = wrong_verifying_key.to_encoded_point(false);
    let wrong_pub_key_x =
        alloy::primitives::B256::from_slice(wrong_encoded_point.x().unwrap().as_ref());
    let wrong_pub_key_y =
        alloy::primitives::B256::from_slice(wrong_encoded_point.y().unwrap().as_ref());

    // Use TEST_MNEMONIC account for provider wallet
    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;

    // Create provider with funder's wallet
    let funder_wallet = EthereumWallet::from(funder_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(funder_wallet)
        .connect_http(http_url.clone());

    println!("\n=== Testing WebAuthn Negative Cases ===\n");

    // Get chain ID
    let chain_id = provider.get_chain_id().await?;

    // Create recipient address for test transactions
    let recipient = Address::random();

    let create_test_tx = |nonce_seq: u64| {
        let mut tx = create_basic_aa_tx(
            chain_id,
            nonce_seq,
            vec![Call {
                to: recipient.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        tx.fee_token = None;
        tx
    };

    // ===========================================
    // Test Case 1: Wrong Public Key
    // ===========================================
    println!("Test 1: Wrong public key in signature");

    let tx1 = create_test_tx(100);
    let sig_hash1 = tx1.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data1 = vec![0u8; 37];
    authenticator_data1[32] = 0x01; // UP flag set

    let challenge_b64url1 = URL_SAFE_NO_PAD.encode(sig_hash1.as_slice());
    let client_data_json1 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url1}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash1 = Sha256::digest(client_data_json1.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data1);
    final_hasher.update(client_data_hash1);
    let message_hash1 = final_hasher.finalize();

    // Sign with CORRECT private key
    let signature1: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash1);
    let sig_bytes1 = signature1.to_bytes();

    // But use WRONG public key in the signature
    let mut webauthn_data1 = Vec::new();
    webauthn_data1.extend_from_slice(&authenticator_data1);
    webauthn_data1.extend_from_slice(client_data_json1.as_bytes());

    let aa_signature1 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data1),
            r: alloy::primitives::B256::from_slice(&sig_bytes1[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes1[32..64]),
            pub_key_x: wrong_pub_key_x, // WRONG public key
            pub_key_y: wrong_pub_key_y, // WRONG public key
        }));

    // Try to verify - should fail
    let recovery_result1 = aa_signature1.recover_signer(&sig_hash1);
    assert!(
        recovery_result1.is_err(),
        "Should fail with wrong public key"
    );
    println!("✓ Signature recovery correctly failed with wrong public key");

    // Also verify pool rejects the transaction
    let signed_tx1 = AASigned::new_unhashed(tx1, aa_signature1);
    let envelope1: TempoTxEnvelope = signed_tx1.into();
    let mut encoded1 = Vec::new();
    envelope1.encode_2718(&mut encoded1);
    let inject_result1 = setup.node.rpc.inject_tx(encoded1.into()).await;
    assert!(
        inject_result1.is_err(),
        "Tx with wrong public key should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong public key");

    // ===========================================
    // Test Case 2: Wrong Private Key (signature doesn't match public key)
    // ===========================================
    println!("\nTest 2: Wrong private key (signature doesn't match public key)");

    let tx2 = create_test_tx(101);
    let sig_hash2 = tx2.signature_hash();

    // Create correct WebAuthn data
    let mut authenticator_data2 = vec![0u8; 37];
    authenticator_data2[32] = 0x01; // UP flag set

    let challenge_b64url2 = URL_SAFE_NO_PAD.encode(sig_hash2.as_slice());
    let client_data_json2 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url2}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash2 = Sha256::digest(client_data_json2.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data2);
    final_hasher.update(client_data_hash2);
    let message_hash2 = final_hasher.finalize();

    // Sign with WRONG private key
    let signature2: p256::ecdsa::Signature = wrong_signing_key.sign(&message_hash2);
    let sig_bytes2 = signature2.to_bytes();

    // But use CORRECT public key in the signature
    let mut webauthn_data2 = Vec::new();
    webauthn_data2.extend_from_slice(&authenticator_data2);
    webauthn_data2.extend_from_slice(client_data_json2.as_bytes());

    let aa_signature2 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data2),
            r: alloy::primitives::B256::from_slice(&sig_bytes2[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes2[32..64]),
            pub_key_x: correct_pub_key_x, // Correct public key
            pub_key_y: correct_pub_key_y, // But signature is from wrong private key
        }));

    // Try to verify - should fail
    let recovery_result2 = aa_signature2.recover_signer(&sig_hash2);
    assert!(
        recovery_result2.is_err(),
        "Should fail with wrong private key"
    );
    println!("✓ Signature recovery correctly failed with wrong private key");

    let signed_tx2 = AASigned::new_unhashed(tx2, aa_signature2);
    let envelope2: TempoTxEnvelope = signed_tx2.into();
    let mut encoded2 = Vec::new();
    envelope2.encode_2718(&mut encoded2);
    let inject_result2 = setup.node.rpc.inject_tx(encoded2.into()).await;
    assert!(
        inject_result2.is_err(),
        "Tx with wrong private key should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong private key");

    // ===========================================
    // Test Case 3: Wrong Challenge in clientDataJSON
    // ===========================================
    println!("\nTest 3: Wrong challenge in clientDataJSON");

    let tx3 = create_test_tx(102);
    let sig_hash3 = tx3.signature_hash();

    // Create WebAuthn data with WRONG challenge
    let mut authenticator_data3 = vec![0u8; 37];
    authenticator_data3[32] = 0x01; // UP flag set

    let wrong_challenge = B256::from([0xFF; 32]); // Different hash
    let wrong_challenge_b64url = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let client_data_json3 = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash3 = Sha256::digest(client_data_json3.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data3);
    final_hasher.update(client_data_hash3);
    let message_hash3 = final_hasher.finalize();

    // Sign with correct private key
    let signature3: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash3);
    let sig_bytes3 = signature3.to_bytes();

    let mut webauthn_data3 = Vec::new();
    webauthn_data3.extend_from_slice(&authenticator_data3);
    webauthn_data3.extend_from_slice(client_data_json3.as_bytes());

    let aa_signature3 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data3),
            r: alloy::primitives::B256::from_slice(&sig_bytes3[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes3[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result3 = aa_signature3.recover_signer(&sig_hash3);
    assert!(
        recovery_result3.is_err(),
        "Should fail with wrong challenge"
    );
    println!("✓ Signature recovery correctly failed with wrong challenge");

    let signed_tx3 = AASigned::new_unhashed(tx3, aa_signature3);
    let envelope3: TempoTxEnvelope = signed_tx3.into();
    let mut encoded3 = Vec::new();
    envelope3.encode_2718(&mut encoded3);
    let inject_result3 = setup.node.rpc.inject_tx(encoded3.into()).await;
    assert!(
        inject_result3.is_err(),
        "Tx with wrong challenge should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong challenge");

    // ===========================================
    // Test Case 4: Wrong Authenticator Data
    // ===========================================
    println!("\nTest 4: Wrong authenticator data (UP flag not set)");

    let tx4 = create_test_tx(103);
    let sig_hash4 = tx4.signature_hash();

    // Create WebAuthn data with UP flag NOT set
    let mut authenticator_data4 = vec![0u8; 37];
    authenticator_data4[32] = 0x00; // UP flag NOT set (should be 0x01)

    let challenge_b64url4 = URL_SAFE_NO_PAD.encode(sig_hash4.as_slice());
    let client_data_json4 = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url4}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Compute message hash
    let client_data_hash4 = Sha256::digest(client_data_json4.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&authenticator_data4);
    final_hasher.update(client_data_hash4);
    let message_hash4 = final_hasher.finalize();

    // Sign with correct private key
    let signature4: p256::ecdsa::Signature = correct_signing_key.sign(&message_hash4);
    let sig_bytes4 = signature4.to_bytes();

    let mut webauthn_data4 = Vec::new();
    webauthn_data4.extend_from_slice(&authenticator_data4);
    webauthn_data4.extend_from_slice(client_data_json4.as_bytes());

    let aa_signature4 =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(webauthn_data4),
            r: alloy::primitives::B256::from_slice(&sig_bytes4[0..32]),
            s: alloy::primitives::B256::from_slice(&sig_bytes4[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    // Try to verify - should fail during WebAuthn data validation
    let recovery_result4 = aa_signature4.recover_signer(&sig_hash4);
    assert!(
        recovery_result4.is_err(),
        "Should fail with wrong authenticator data"
    );
    println!("✓ Signature recovery correctly failed with wrong authenticator data");

    let signed_tx4 = AASigned::new_unhashed(tx4, aa_signature4);
    let envelope4: TempoTxEnvelope = signed_tx4.into();
    let mut encoded4 = Vec::new();
    envelope4.encode_2718(&mut encoded4);
    let inject_result4 = setup.node.rpc.inject_tx(encoded4.into()).await;
    assert!(
        inject_result4.is_err(),
        "Tx with wrong authenticator data should be rejected by pool"
    );
    println!("  ✓ Pool correctly rejected transaction with wrong authenticator data");

    // ===========================================
    // Test Case 5: Transaction Injection Should Fail
    // ===========================================
    println!("\nTest 5: Transaction injection with invalid signature");

    // Try to inject a transaction with wrong signature
    let bad_tx = create_test_tx(0);
    let _bad_sig_hash = bad_tx.signature_hash();

    // Create WebAuthn data with wrong challenge (like test case 3)
    let mut bad_auth_data = vec![0u8; 37];
    bad_auth_data[32] = 0x01;

    let wrong_challenge = B256::from([0xAA; 32]);
    let wrong_challenge_b64 = URL_SAFE_NO_PAD.encode(wrong_challenge.as_slice());
    let bad_client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{wrong_challenge_b64}","origin":"https://example.com","crossOrigin":false}}"#
    );

    // Sign with correct key but wrong data
    let client_hash = Sha256::digest(bad_client_data.as_bytes());

    let mut final_hasher = Sha256::new();
    final_hasher.update(&bad_auth_data);
    final_hasher.update(client_hash);
    let bad_message_hash = final_hasher.finalize();

    let bad_signature: p256::ecdsa::Signature = correct_signing_key.sign(&bad_message_hash);
    let bad_sig_bytes = bad_signature.to_bytes();

    let mut bad_webauthn_data = Vec::new();
    bad_webauthn_data.extend_from_slice(&bad_auth_data);
    bad_webauthn_data.extend_from_slice(bad_client_data.as_bytes());

    let bad_tempo_signature =
        TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: Bytes::from(bad_webauthn_data),
            r: alloy::primitives::B256::from_slice(&bad_sig_bytes[0..32]),
            s: alloy::primitives::B256::from_slice(&bad_sig_bytes[32..64]),
            pub_key_x: correct_pub_key_x,
            pub_key_y: correct_pub_key_y,
        }));

    let signed_bad_tx = AASigned::new_unhashed(bad_tx, bad_tempo_signature);
    let bad_envelope: TempoTxEnvelope = signed_bad_tx.into();
    let mut encoded_bad = Vec::new();
    bad_envelope.encode_2718(&mut encoded_bad);

    // Try to inject - should fail
    let inject_result = setup.node.rpc.inject_tx(encoded_bad.clone().into()).await;
    assert!(
        inject_result.is_err(),
        "Transaction with invalid signature should be rejected"
    );
    println!("✓ Transaction with invalid WebAuthn signature correctly rejected");

    // Verify the rejected transaction is NOT available via eth_getTransactionByHash
    verify_tx_not_in_block_via_rpc(&provider, &encoded_bad).await?;

    Ok(())
}

/// Test that verifies that we can propagate 2d transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_propagate_2d_transactions() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Create wallet from mnemonic
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;

    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;

    let node1 = setup.nodes.remove(0);
    let node2 = setup.nodes.remove(0);

    // make sure both nodes are ready to broadcast
    node1.inner.network.update_sync_state(SyncState::Idle);
    node2.inner.network.update_sync_state(SyncState::Idle);

    let mut tx_listener1 = node1.inner.pool.pending_transactions_listener();
    let mut tx_listener2 = node2.inner.pool.pending_transactions_listener();

    let provider1 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node1.rpc_url());
    let chain_id = provider1.get_chain_id().await?;

    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: 1_000_000_000u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::from(123),
        nonce: 0,
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = wallet.sign_hash_sync(&sig_hash)?;
    let signed_tx = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    let envelope: TempoTxEnvelope = signed_tx.into();
    let encoded = envelope.encoded_2718();

    // Submitting transaction to first peer
    let _ = provider1.send_raw_transaction(&encoded).await.unwrap();

    // ensure we see it as pending from the first peer
    let pending_hash1 =
        tokio::time::timeout(std::time::Duration::from_secs(30), tx_listener1.recv())
            .await
            .expect("timed out waiting for tx on node1")
            .expect("tx listener1 channel closed");
    assert_eq!(pending_hash1, *envelope.tx_hash());
    let _rpc_tx = provider1
        .get_transaction_by_hash(pending_hash1)
        .await
        .unwrap();

    // ensure we see it as pending on the second peer as well (should be broadcasted from first to second)
    let pending_hash2 =
        tokio::time::timeout(std::time::Duration::from_secs(30), tx_listener2.recv())
            .await
            .expect("timed out waiting for tx on node2")
            .expect("tx listener2 channel closed");
    assert_eq!(pending_hash2, *envelope.tx_hash());

    // check we can fetch it from the second peer now
    let provider2 =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(node2.rpc_url());
    let _rpc_tx = provider2
        .get_transaction_by_hash(pending_hash2)
        .await
        .unwrap();

    Ok(())
}

/// Verifies that transactions signed with a revoked access key cannot be executed.
#[tokio::test]
async fn test_aa_keychain_revocation_toctou_dos() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Revocation TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key
    // ========================================
    println!("\n=== STEP 1: Authorize the access key ===");

    let funded = rand_funding_amount();
    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(create_default_token_limit(funded)),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to revoke the key)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = rand_sub_amount(funded);

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient,
            transfer_amount,
        )],
        2_000_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the key is still authorized
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;
    // Note: We don't increment nonce here because the delayed tx won't be mined until valid_after.
    // The revoke tx below uses a different nonce_key (2D nonce) to be mined independently.

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Revoke the access key before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Revoke the access key ===");

    let revoke_call = revokeKeyCall {
        keyId: access_key_addr,
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    // of the delayed tx which is also using the root account but blocking on valid_after
    let mut revoke_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: revoke_call.abi_encode().into(),
        }],
        2_000_000,
    );
    revoke_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    revoke_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let revoke_sig = sign_aa_tx_secp256k1(&revoke_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, revoke_tx, revoke_sig).await?;

    // Verify the key is actually revoked by querying the keychain
    use tempo_contracts::precompiles::account_keychain::IAccountKeychain::IAccountKeychainInstance;
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, &provider);
    let key_info = keychain.getKey(root_addr, access_key_addr).call().await?;
    assert!(key_info.isRevoked, "Key should be marked as revoked");
    println!("Access key revoked");

    // The evict_revoked_keychain_txs maintenance task has a 1-second startup delay,
    // then monitors storage changes on block commits and evicts transactions signed
    // with revoked keys. We need to advance a block to trigger the commit notification,
    // then wait for the maintenance task to process it.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &delayed_tx_hash,
        "keychain eviction",
    )
    .await?;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state immediately after revocation
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance to verify if the transaction actually executed
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    assert!(
        !tx_still_in_pool,
        "DoS via AA keychain revocation TOCTOU: \
         Transaction signed with revoked key should be evicted from the mempool"
    );
    assert!(
        receipt.is_none(),
        "Transaction signed with revoked key should be evicted, not mined. \
         If it was mined (even if reverted), the eviction mechanism is not working."
    );
    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "Recipient should have no balance since transaction was evicted"
    );

    Ok(())
}

// ============================================================================
// Expiring Nonce Tests
// ============================================================================

/// Test expiring nonce replay protection - same tx hash should be rejected
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_expiring_nonce_replay_protection() -> eyre::Result<()> {
    println!("\n=== Testing Expiring Nonce Replay Protection ===\n");

    let Localnet {
        mut setup,
        provider,
        chain_id,
        funder_signer: alice_signer,
        ..
    } = Localnet::new().await?;

    let recipient = Address::random();

    // Advance a few blocks to get a meaningful timestamp
    for _ in 0..3 {
        setup.node.advance_block().await?;
    }

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();

    // Create expiring nonce transaction
    let valid_before = current_timestamp + 25;

    let tx = create_expiring_nonce_tx(chain_id, valid_before, recipient);

    let aa_signature = sign_aa_tx_secp256k1(&tx, &alice_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(aa_signature).into();
    let tx_hash = *envelope.tx_hash();
    let encoded = envelope.encoded_2718();

    println!("First submission - tx hash: {tx_hash}");

    // First submission should succeed
    setup.node.rpc.inject_tx(encoded.clone().into()).await?;
    setup.node.advance_block().await?;

    assert_receipt_status(&provider, tx_hash, true).await?;
    println!("✓ First submission succeeded");

    // Second submission with SAME encoded tx (same hash) should fail
    println!("\nSecond submission - attempting replay with same tx hash...");

    // Try to inject the same transaction again - should be rejected at pool level
    let replay_result = setup.node.rpc.inject_tx(encoded.clone().into()).await;

    // The replay MUST be rejected at pool validation (we check seen[tx_hash] in validator)
    assert!(
        replay_result.is_err(),
        "Replay should be rejected at transaction pool level"
    );
    println!("✓ Replay rejected at transaction pool level");

    Ok(())
}

/// Verifies that transactions signed with a keychain key are evicted when spending limits change.
///
/// This tests the TOCTOU vulnerability (CHAIN-444) where:
/// 1. An attacker funds and authorizes an address with balance > spending limit
/// 2. Submits transactions that pass validation
/// 3. Reduces spending limit so execution would fail
/// 4. Transactions should be evicted from the mempool
#[tokio::test]
async fn test_aa_keychain_spending_limit_toctou_dos() -> eyre::Result<()> {
    use tempo_precompiles::account_keychain::updateSpendingLimitCall;

    reth_tracing::init_test_tracing();

    println!("\n=== Testing AA Keychain Spending Limit TOCTOU DoS ===\n");

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Generate an access key for the attack
    let (access_key_signing, access_pub_x, access_pub_y, access_key_addr) =
        generate_p256_access_key();

    println!("Access key address: {access_key_addr}");

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Get current block timestamp
    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let current_timestamp = block.header.timestamp();
    println!("Current block timestamp: {current_timestamp}");

    // ========================================
    // STEP 1: Authorize the access key with a spending limit
    // ========================================
    println!("\n=== STEP 1: Authorize the access key with spending limit ===");

    let funded = rand_funding_amount();
    let initial_spending_limit = funded / U256::from(2);

    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(access_pub_x, access_pub_y),
        chain_id,
        None, // Never expires
        Some(vec![tempo_primitives::transaction::TokenLimit {
            token: DEFAULT_FEE_TOKEN,
            limit: initial_spending_limit,
        }]),
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;

    println!("Access key authorized with spending limit: {initial_spending_limit}");

    // ========================================
    // STEP 2: Submit a transaction with valid_after in the future using the access key
    // ========================================
    println!("\n=== STEP 2: Submit transaction with future valid_after using access key ===");

    // Advance a couple blocks to get a fresh timestamp
    for _ in 0..2 {
        setup.node.advance_block().await?;
    }

    let block = provider
        .get_block_by_number(Default::default())
        .await?
        .unwrap();
    let new_timestamp = block.header.timestamp();

    // Set valid_after to be 10 seconds in the future (enough time to reduce spending limit)
    let valid_after_time = new_timestamp + 10;
    println!("Setting valid_after to {valid_after_time} (current: {new_timestamp})");

    // Create a transaction that uses the access key with valid_after
    let recipient = Address::random();
    let transfer_amount = rand_sub_amount(initial_spending_limit);

    let mut delayed_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient,
            transfer_amount,
        )],
        2_000_000,
    );
    delayed_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    delayed_tx.valid_after = Some(valid_after_time);

    // Sign with the access key (wrapped in Keychain signature)
    let access_key_sig = sign_aa_tx_with_p256_access_key(
        &delayed_tx,
        &access_key_signing,
        &access_pub_x,
        &access_pub_y,
        root_addr,
    )?;

    // Submit the transaction - it should pass validation because the spending limit is still high
    let delayed_tx_envelope: TempoTxEnvelope = delayed_tx.into_signed(access_key_sig).into();
    let delayed_tx_hash = *delayed_tx_envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(delayed_tx_envelope.encoded_2718().into())
        .await?;

    println!("Delayed transaction submitted (hash: {delayed_tx_hash})");

    // Verify transaction is in the pool
    assert!(
        setup.node.inner.pool.contains(&delayed_tx_hash),
        "Delayed transaction should be in the pool"
    );
    println!("Transaction is in the mempool");

    // ========================================
    // STEP 3: Reduce the spending limit to 0 before valid_after is reached
    // ========================================
    println!("\n=== STEP 3: Reduce spending limit to 0 ===");

    let update_limit_call = updateSpendingLimitCall {
        keyId: access_key_addr,
        token: DEFAULT_FEE_TOKEN,
        newLimit: U256::ZERO, // Set to 0, making all pending transfers fail
    };

    // Use a 2D nonce (different nonce_key) so this tx can be mined independently
    let mut update_tx = create_basic_aa_tx(
        chain_id,
        0, // nonce 0 for this new nonce_key
        vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: update_limit_call.abi_encode().into(),
        }],
        2_000_000,
    );
    update_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    update_tx.nonce_key = U256::from(1); // Use a different nonce key so it's independent

    let update_sig = sign_aa_tx_secp256k1(&update_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, update_tx, update_sig).await?;

    println!("Spending limit reduced to 0");

    // The maintenance task monitors for SpendingLimitUpdated events and evicts transactions
    // signed with keys whose spending limits have changed.
    // Advance another block to trigger the commit notification
    setup.node.advance_block().await?;

    wait_until_pool_not_contains(
        &setup.node.inner.pool,
        &delayed_tx_hash,
        "spending limit eviction",
    )
    .await?;

    // ========================================
    // STEP 4: Verify transaction is evicted from the pool
    // ========================================
    println!("\n=== STEP 4: Verify transaction is evicted from pool ===");

    // Check pool state after spending limit update
    let tx_still_in_pool = setup.node.inner.pool.contains(&delayed_tx_hash);

    // Check if transaction was mined (should not be, since it had valid_after in future)
    let receipt: Option<serde_json::Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), [delayed_tx_hash])
        .await?;

    // Check the transfer recipient balance
    let recipient_balance = ITIP20::new(DEFAULT_FEE_TOKEN, &provider)
        .balanceOf(recipient)
        .call()
        .await?;

    println!("\n=== RESULTS ===");
    println!("Transaction still in pool: {tx_still_in_pool}");
    println!("Transaction mined: {}", receipt.is_some());
    println!("Recipient balance: {recipient_balance}");
    println!("Expected transfer amount: {transfer_amount}");

    assert!(
        !tx_still_in_pool,
        "DoS via AA keychain spending limit TOCTOU: \
         Transaction from key with reduced spending limit should be evicted from the mempool"
    );
    assert!(
        receipt.is_none(),
        "Transaction from key with reduced spending limit should be evicted, not mined. \
         If it was mined (even if reverted), the eviction mechanism is not working."
    );
    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "Recipient should have no balance since transaction was evicted"
    );

    println!("\n=== Test passed: Transaction was correctly evicted ===");
    Ok(())
}

/// V1 keychain signature inside `tempo_authorization_list` must be rejected post-T1C.
/// Outer sig is a normal secp256k1 primitive, only the auth list entry carries V1 keychain.
#[tokio::test(flavor = "multi_thread")]
async fn test_v1_keychain_in_auth_list_rejected_post_t1c() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let localnet = Localnet::new().await?;
    let Localnet {
        setup,
        provider,
        chain_id,
        funder_signer: sender_signer,
        funder_addr: sender_addr,
        ..
    } = localnet;

    // Build an EIP-7702 authorization and sign it with a V1 keychain sig
    let delegate_address = ACCOUNT_KEYCHAIN_ADDRESS;
    let (auth, sig_hash) = build_authorization(chain_id, delegate_address);

    let inner_signer = alloy::signers::local::PrivateKeySigner::random();
    let inner_signature = inner_signer.sign_hash_sync(&sig_hash)?;
    let v1_keychain_sig = TempoSignature::Keychain(KeychainSignature::new_v1(
        Address::random(), // arbitrary user_address
        PrimitiveSignature::Secp256k1(inner_signature),
    ));
    let auth_signed = tempo_primitives::transaction::TempoSignedAuthorization::new_unchecked(
        auth,
        v1_keychain_sig,
    );

    // Tx with primitive outer sig and V1-keychain auth list entry
    let nonce = provider.get_transaction_count(sender_addr).await?;
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(sender_addr)],
        2_000_000,
    );
    tx.tempo_authorization_list = vec![auth_signed];

    let outer_sig = sign_aa_tx_secp256k1(&tx, &sender_signer)?;
    let envelope: TempoTxEnvelope = AASigned::new_unhashed(tx, outer_sig).into();

    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await
        .expect_err("V1 keychain sig in auth list must be rejected post-T1C");

    Ok(())
}

/// V2 keychain cross-account replay prevention. A shared access key
/// authorized on Alice and Bob must not allow replaying Alice's inner sig on Bob.
/// Tests both secp256k1 and P256.
#[tokio::test]
async fn test_v2_keychain_blocks_cross_account_replay() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;

    let alice_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let alice_addr = alice_signer.address();
    let bob_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let bob_addr = bob_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(alice_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Shared access keys, same key authorized on both accounts
    let secp_access_signer = alloy::signers::local::PrivateKeySigner::random();
    let secp_access_addr = secp_access_signer.address();
    let (p256_access_signer, pub_x, pub_y, p256_access_addr) = generate_p256_access_key();

    let mut nonce_alice = provider.get_transaction_count(alice_addr).await?;

    // Fund Bob so he can receive txs
    fund_address_with(
        &mut setup,
        &provider,
        &alice_signer,
        alice_addr,
        bob_addr,
        U256::from(100e6),
        DEFAULT_FEE_TOKEN,
        chain_id,
    )
    .await?;
    nonce_alice += 1;

    let secp_mock = || {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    };
    let p256_mock = || create_mock_p256_sig(pub_x, pub_y);

    // Authorize both keys on Alice and Bob
    for (key_addr, mock_sig) in [
        (secp_access_addr, secp_mock()),
        (p256_access_addr, p256_mock()),
    ] {
        authorize_access_key(
            &mut setup,
            &alice_signer,
            alice_addr,
            key_addr,
            mock_sig,
            chain_id,
            nonce_alice,
        )
        .await?;
        nonce_alice += 1;
    }
    let mut nonce_bob = provider.get_transaction_count(bob_addr).await?;
    for (key_addr, mock_sig) in [
        (secp_access_addr, secp_mock()),
        (p256_access_addr, p256_mock()),
    ] {
        authorize_access_key(
            &mut setup,
            &bob_signer,
            bob_addr,
            key_addr,
            mock_sig,
            chain_id,
            nonce_bob,
        )
        .await?;
        nonce_bob += 1;
    }

    // secp256k1: Alice sends a valid V2 keychain tx
    let alice_tx = create_basic_aa_tx(
        chain_id,
        nonce_alice,
        vec![create_balance_of_call(alice_addr)],
        2_000_000,
    );
    let alice_sig =
        sign_aa_tx_with_secp256k1_access_key(&alice_tx, &secp_access_signer, alice_addr)?;
    submit_and_mine_aa_tx(&mut setup, alice_tx, alice_sig.clone()).await?;
    nonce_alice += 1;

    // Extract Alice's inner sig, re-wrap claiming Bob's address.
    // Pool rejects because V2 hash includes user_address, so key recovery yields a
    // different (unauthorized) key.
    let bob_tx = create_basic_aa_tx(
        chain_id,
        nonce_bob,
        vec![create_balance_of_call(bob_addr)],
        2_000_000,
    );
    let inner = alice_sig.as_keychain().unwrap().signature.clone();
    let replay_sig = TempoSignature::Keychain(KeychainSignature::new(bob_addr, inner));
    let replay_tx: TempoTxEnvelope = AASigned::new_unhashed(bob_tx, replay_sig).into();
    setup
        .node
        .rpc
        .inject_tx(replay_tx.encoded_2718().into())
        .await
        .expect_err("secp256k1 cross-account replay must be rejected at pool level");

    // P256: Alice sends a valid V2 keychain tx
    let alice_tx = create_basic_aa_tx(
        chain_id,
        nonce_alice,
        vec![create_balance_of_call(alice_addr)],
        2_000_000,
    );
    let alice_sig = sign_aa_tx_with_p256_access_key(
        &alice_tx,
        &p256_access_signer,
        &pub_x,
        &pub_y,
        alice_addr,
    )?;
    submit_and_mine_aa_tx(&mut setup, alice_tx, alice_sig.clone()).await?;

    // Same replay: extract inner sig, re-wrap for Bob, pool rejects
    let bob_tx = create_basic_aa_tx(
        chain_id,
        nonce_bob,
        vec![create_balance_of_call(bob_addr)],
        2_000_000,
    );
    let inner = alice_sig.as_keychain().unwrap().signature.clone();
    let replay_sig = TempoSignature::Keychain(KeychainSignature::new(bob_addr, inner));
    let replay_env: TempoTxEnvelope = AASigned::new_unhashed(bob_tx, replay_sig).into();
    setup
        .node
        .rpc
        .inject_tx(replay_env.encoded_2718().into())
        .await
        .expect_err("P256 cross-account replay must be rejected at pool level");

    Ok(())
}

#[tokio::test]
async fn test_v1_keychain_cross_account_replay_pre_t1c() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Pre-T1C genesis so V1 keychain sigs are accepted.
    // Set t1cTime and t2Time far in the future instead of removing them,
    // because the genesis deserializer requires all hardfork fields.
    let genesis_json = include_str!("../../assets/test-genesis.json").to_string();
    let mut genesis: serde_json::Value = serde_json::from_str(&genesis_json)?;
    let config = genesis["config"].as_object_mut().unwrap();
    let far_future = serde_json::Value::Number(serde_json::Number::from(u64::MAX));
    config.insert("t1cTime".to_string(), far_future.clone());
    config.insert("t2Time".to_string(), far_future);
    let mut setup = TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .build_with_node_access()
        .await?;

    let alice_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let alice_addr = alice_signer.address();
    let bob_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let bob_addr = bob_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(alice_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Shared access key authorized on both accounts
    let access_key_signer = alloy::signers::local::PrivateKeySigner::random();
    let access_key_addr = access_key_signer.address();

    let mut nonce_alice = provider.get_transaction_count(alice_addr).await?;

    fund_address_with(
        &mut setup,
        &provider,
        &alice_signer,
        alice_addr,
        bob_addr,
        U256::from(100e6),
        DEFAULT_FEE_TOKEN,
        chain_id,
    )
    .await?;
    nonce_alice += 1;

    let secp_mock = || {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    };

    // Authorize key on both accounts
    authorize_access_key(
        &mut setup,
        &alice_signer,
        alice_addr,
        access_key_addr,
        secp_mock(),
        chain_id,
        nonce_alice,
    )
    .await?;
    nonce_alice += 1;
    let nonce_bob = provider.get_transaction_count(bob_addr).await?;
    authorize_access_key(
        &mut setup,
        &bob_signer,
        bob_addr,
        access_key_addr,
        secp_mock(),
        chain_id,
        nonce_bob,
    )
    .await?;
    let mut nonce_bob = nonce_bob + 1;

    // Advance Bob's nonce to match Alice's — the replay needs identical sig_hash
    let dummy_tx = create_basic_aa_tx(
        chain_id,
        nonce_bob,
        vec![create_balance_of_call(bob_addr)],
        2_000_000,
    );
    let dummy_sig = sign_aa_tx_secp256k1(&dummy_tx, &bob_signer)?;
    submit_and_mine_aa_tx(&mut setup, dummy_tx, dummy_sig).await?;
    nonce_bob += 1;
    assert_eq!(nonce_alice, nonce_bob, "nonces must match for replay");

    // Alice sends a V1 keychain tx, succeeds pre-T1C
    let alice_tx = create_basic_aa_tx(
        chain_id,
        nonce_alice,
        vec![create_balance_of_call(alice_addr)],
        2_000_000,
    );
    let alice_v1_sig =
        sign_aa_tx_with_secp256k1_access_key_v1(&alice_tx, &access_key_signer, alice_addr)?;
    submit_and_mine_aa_tx(&mut setup, alice_tx.clone(), alice_v1_sig.clone()).await?;

    // Extract Alice's inner sig, re-wrap for Bob with V1
    let inner = alice_v1_sig.as_keychain().unwrap().signature.clone();
    let bob_replay_sig = TempoSignature::Keychain(KeychainSignature::new_v1(bob_addr, inner));

    // Replay Alice's EXACT tx body for Bob — V1 doesn't bind user_address in the
    // inner sig, so the same sig verifies against the same sig_hash for any user.
    let replay_env: TempoTxEnvelope = AASigned::new_unhashed(alice_tx, bob_replay_sig).into();
    setup
        .node
        .rpc
        .inject_tx(replay_env.encoded_2718().into())
        .await
        .expect("V1 cross-account replay enters pool pre-T1C");
    setup.node.advance_block().await?;
    assert_receipt_status(&provider, *replay_env.tx_hash(), true).await?;

    Ok(())
}

/// Tests keychain signature V2 e2e: authorize a key, use it with V2 signature, verify it works.
/// Also verifies that V1 signatures are rejected (current chain runs post-T1C).
#[tokio::test(flavor = "multi_thread")]
async fn test_aa_keychain_v2_signature() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let root_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let root_addr = root_signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(root_signer.clone())
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let (access_key_signing, pub_x, pub_y, access_key_addr) = generate_p256_access_key();

    let mut nonce = provider.get_transaction_count(root_addr).await?;

    // Step 1: Authorize the access key via root key
    let key_auth = create_key_authorization(
        &root_signer,
        access_key_addr,
        create_mock_p256_sig(pub_x, pub_y),
        chain_id,
        None,
        None,
    )?;

    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.fee_token = Some(DEFAULT_FEE_TOKEN);
    auth_tx.key_authorization = Some(key_auth);

    let root_sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    submit_and_mine_aa_tx(&mut setup, auth_tx, root_sig).await?;
    nonce += 1;
    println!("✓ Access key authorized");

    // Step 2: Use the access key with V2 signature — should succeed
    let recipient = Address::random();
    let mut transfer_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient,
            U256::from(1_000_000u64),
        )],
        2_000_000,
    );
    transfer_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let v2_sig = sign_aa_tx_with_p256_access_key(
        &transfer_tx,
        &access_key_signing,
        &pub_x,
        &pub_y,
        root_addr,
    )?;

    // Verify the signature is V2
    assert!(!v2_sig.is_legacy_keychain());
    assert!(v2_sig.is_keychain());

    let tx_hash = submit_and_mine_aa_tx(&mut setup, transfer_tx, v2_sig).await?;
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("receipt must exist");
    assert!(receipt.status(), "V2 keychain transfer must succeed");
    println!("✓ V2 keychain signature accepted and transfer succeeded");

    // Step 3: V1 signature should be rejected at pool level (post-T1C)
    nonce += 1;
    let mut v1_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    v1_tx.fee_token = Some(DEFAULT_FEE_TOKEN);

    let v1_sig =
        sign_aa_tx_with_p256_access_key_v1(&v1_tx, &access_key_signing, &pub_x, &pub_y, root_addr)?;

    assert!(v1_sig.is_legacy_keychain());

    let signed_v1 = AASigned::new_unhashed(v1_tx, v1_sig);
    let envelope_v1: TempoTxEnvelope = signed_v1.into();
    let inject_result = setup
        .node
        .rpc
        .inject_tx(envelope_v1.encoded_2718().into())
        .await;

    assert!(
        inject_result.is_err(),
        "V1 keychain signature should be rejected post-T1C"
    );
    println!(
        "✓ V1 keychain signature rejected post-T1C: {}",
        inject_result.unwrap_err()
    );

    Ok(())
}
