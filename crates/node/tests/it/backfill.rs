use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::{BlockNumberOrTag, Encodable2718};
use alloy_network::TxSignerSync;
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_api::{BuiltPayload, EngineApiMessageVersion};
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_primitives_traits::{AlloyBlockHeader as _, transaction::TxHashRef};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;

/// Test that verifies backfill sync works correctly.
///
/// 1. Sets up two connected nodes
/// 2. Advances the first node with enough blocks to trigger backfill
/// 3. Sends FCU to second node to trigger backfill
/// 4. Verifies the second node can sync to the first node's tip
#[tokio::test(flavor = "multi_thread")]
async fn test_backfill_sync() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Create wallet from mnemonic
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let eth_wallet = EthereumWallet::from(wallet.clone());

    // Setup two connected nodes using e2e test utilities
    println!("Setting up two connected nodes...");

    let mut multi_setup = crate::utils::TestNodeBuilder::new()
        .with_node_count(2)
        .build_multi_node()
        .await?;

    let mut node1 = multi_setup.nodes.remove(0);
    let node2 = multi_setup.nodes.remove(0);

    // Get provider for node1
    let http_url1 = node1.rpc_url();
    let provider1 = ProviderBuilder::new()
        .wallet(eth_wallet.clone())
        .connect_http(http_url1);

    // Wait for nodes to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Get the chain ID from the provider
    let chain_id = provider1.get_chain_id().await?;

    // Advance first node with blocks containing transactions
    // Use more than 32 blocks to trigger actual backfill (threshold is MIN_BLOCKS_FOR_PIPELINE_RUN = 32)
    println!("Advancing first node...");
    let target_blocks = 50;

    // Create multiple wallets for different transactions to avoid nonce issues
    let wallets = Wallet::new(target_blocks as usize)
        .with_chain_id(chain_id)
        .wallet_gen();

    // For simplicity, let's just send one transaction per block using the simple approach
    for i in 0..target_blocks {
        // Use a different wallet for each transaction to avoid nonce conflicts
        let wallet_signer = wallets[i as usize].clone();

        // Create a new transaction for this block
        let raw_tx = {
            let mut tx = TxEip1559 {
                chain_id,
                gas_limit: 300_000,
                to: Address::ZERO.into(),
                max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                ..Default::default()
            };
            let signature = wallet_signer.sign_transaction_sync(&mut tx).unwrap();
            TxEnvelope::Eip1559(tx.into_signed(signature))
                .encoded_2718()
                .into()
        };

        // Send the transaction
        let tx_hash = node1.rpc.inject_tx(raw_tx).await?;

        // Advance the block to include the transaction
        let payload = node1.advance_block().await?;

        // Verify the transaction was included
        let block_number = payload.block().number();

        let block = provider1
            .get_block(block_number.into())
            .full()
            .await?
            .unwrap();
        // Find the transaction by hash (index may vary based on system transactions)
        let txs = block.into_transactions_vec();
        assert!(
            txs.iter().any(|tx| tx.inner.tx_hash() == &tx_hash),
            "Transaction {} not found in block {}. Block has {} transactions.",
            tx_hash,
            block_number,
            txs.len()
        );

        if block_number % 10 == 0 {
            println!("Advanced to block {block_number}");
        }

        if block_number >= target_blocks {
            break;
        }
    }

    println!("Advanced {target_blocks} blocks");

    // Get the final state from node1
    let final_block = provider1
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    let final_block_number = final_block.header.number;
    let final_block_hash = final_block.header.hash;

    println!("First node advanced to block {final_block_number} (hash: {final_block_hash:?})");

    // Get provider for node2
    let http_url2 = node2.rpc_url();
    let provider2 = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(http_url2);

    // Get initial block from node2 (should be genesis)
    let initial_block2 = provider2
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    println!(
        "Second node starting at block {}",
        initial_block2.header.number
    );

    // Send Fork Choice Update to trigger backfill sync
    println!("Sending FCU to node2 with finalized block: {final_block_hash:?}");

    let forkchoice_state = ForkchoiceState {
        head_block_hash: final_block_hash.0.into(),
        safe_block_hash: final_block_hash.0.into(),
        finalized_block_hash: final_block_hash.0.into(),
    };

    let metrics_recorder = install_prometheus_recorder();
    let result = node2
        .inner
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::default())
        .await?;

    println!("FCU result: {result:?}");

    // Assert that FCU returns Syncing status, indicating backfill is triggered
    use alloy_rpc_types_engine::PayloadStatusEnum;
    assert!(
        matches!(result.payload_status.status, PayloadStatusEnum::Syncing),
        "Expected FCU to return SYNCING status for backfill, got: {:?}",
        result.payload_status.status
    );
    println!("FCU returned SYNCING status - backfill mechanism triggered correctly");

    println!("Waiting for node2 to sync with node1...");
    let mut attempts = 0;
    let max_attempts = 30; // 30 seconds timeout

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let current_block2 = provider2
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .expect("Could not get latest block");

        if current_block2.header.number >= final_block_number {
            println!(
                "Node2 successfully synced to block {}",
                current_block2.header.number
            );
            break;
        }

        attempts += 1;
        if attempts >= max_attempts {
            return Err(eyre::eyre!(
                "Node2 failed to sync to target block {} after {} seconds. Current block: {}",
                final_block_number,
                max_attempts,
                current_block2.header.number
            ));
        }

        if attempts % 5 == 0 {
            println!(
                "Sync progress: {}/{}",
                current_block2.header.number, final_block_number
            );
        }
    }

    // Verify that node2 has the same state as node1
    let final_block2 = provider2
        .get_block_by_number(BlockNumberOrTag::Number(final_block_number))
        .await?
        .expect("Could not get final block from node2");

    assert_eq!(
        final_block2.header.hash, final_block_hash,
        "Block hashes don't match after sync"
    );

    // Verify that node2 can also access intermediate blocks
    let mid_block_number = final_block_number / 2;
    let mid_block1 = provider1
        .get_block_by_number(BlockNumberOrTag::Number(mid_block_number))
        .await?
        .expect("Could not get mid block from node1");

    let mid_block2 = provider2
        .get_block_by_number(BlockNumberOrTag::Number(mid_block_number))
        .await?
        .expect("Could not get mid block from node2");

    assert_eq!(
        mid_block1.header.hash, mid_block2.header.hash,
        "Intermediate block hashes don't match"
    );

    assert!(
        tempo_e2e::get_pipeline_runs(metrics_recorder) == 1,
        "Backfill was never triggered"
    );

    Ok(())
}
