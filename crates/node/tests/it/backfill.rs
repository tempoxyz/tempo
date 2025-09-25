use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::BlockNumberOrTag;
use alloy_rpc_types_engine::ForkchoiceState;
use futures::future::join_all;
use rand::{Rng, SeedableRng, rngs::StdRng};
use reth_ethereum::{network::NetworkInfo, tasks::TaskManager};
use reth_node_api::EngineApiMessageVersion;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use reth_rpc_builder::RpcModuleSelection;
use std::sync::Arc;
use tempo_chainspec::spec::{TEMPO_BASE_FEE, TempoChainSpec};
use tempo_node::node::TempoNode;
use tempo_precompiles::contracts::{token_id_to_address, types::ITIP20};

/// Test that verifies backfill sync works correctly.
///
/// 1. Sets up a node and advances it with random transactions
/// 2. Sets up a second node
/// 3. Connects the two nodes via p2p
/// 4. Verifies the second node can sync to the first node's tip
#[tokio::test(flavor = "multi_thread")]
async fn test_backfill_sync() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Use seeded random for reproducibility
    let mut rng = StdRng::seed_from_u64(42);

    let genesis_content = include_str!("../assets/test-genesis.json").to_string();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(&genesis_content)?);

    // Create wallet from mnemonic
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let eth_wallet = EthereumWallet::from(wallet.clone());

    // Setup first node
    println!("Setting up first node...");
    let tasks1 = TaskManager::current();
    let mut node_config1 = NodeConfig::new(Arc::new(chain_spec.clone()))
        .with_unused_ports()
        .dev()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        );
    node_config1.txpool.max_account_slots = usize::MAX;

    let NodeHandle {
        node: node1,
        node_exit_future: _,
    } = NodeBuilder::new(node_config1.clone())
        .testing_node(tasks1.executor())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url1 = node1.rpc_server_handle().http_url().unwrap().parse()?;

    // Connect provider to first node
    let provider1 = ProviderBuilder::new()
        .wallet(eth_wallet.clone())
        .connect_http(http_url1);

    // Wait for node to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Get the test token
    let token_addr = token_id_to_address(0);
    let token = ITIP20::new(token_addr, provider1.clone());

    // Advance first node with random transactions
    println!("Advancing first node with random transactions...");
    let target_blocks = 20;

    // Send batches of transactions
    for batch in 0..5 {
        let mut pending_txs = vec![];

        // Send 10 transactions per batch
        for _ in 0..10 {
            let recipient = Address::from(rng.random::<[u8; 20]>());
            let amount = U256::from(rng.random_range(1..100));

            let pending_tx = token
                .transfer(recipient, amount)
                .gas_price(TEMPO_BASE_FEE as u128)
                .gas(50000)
                .send()
                .await?;
            pending_txs.push(pending_tx);
        }

        // Wait for transactions to be mined
        let receipts = join_all(pending_txs.into_iter().map(|tx| tx.get_receipt()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        // Check all receipts succeeded
        for receipt in &receipts {
            assert!(receipt.status(), "Transaction failed");
        }

        // Get latest block
        let block = provider1
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .expect("Could not get latest block");

        let block_num = block.header.number;
        println!("Batch {}: Advanced to block {}", batch + 1, block_num);

        if block_num >= target_blocks {
            break;
        }
    }

    // Get the final state from node1
    let final_block = provider1
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    let final_block_number = final_block.header.number;
    let final_block_hash = final_block.header.hash;

    println!("First node advanced to block {final_block_number} (hash: {final_block_hash:?})");

    // Setup second node with same genesis
    println!("Setting up second node...");
    let tasks2 = TaskManager::current();
    let mut node_config2 = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        );
    node_config2.txpool.max_account_slots = usize::MAX;

    let NodeHandle {
        node: node2,
        node_exit_future: _,
    } = NodeBuilder::new(node_config2.clone())
        .testing_node(tasks2.executor())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url2 = node2.rpc_server_handle().http_url().unwrap().parse()?;

    // Connect provider to second node
    let provider2 = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(http_url2);

    // Wait for node to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Get initial block from node2 (should be genesis)
    let initial_block2 = provider2
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    println!(
        "Second node starting at block {}",
        initial_block2.header.number
    );

    // Connect node2 to node1 as peer
    println!("Connecting node2 to node1...");

    let node1_peer_id = *node1.network.peer_id();
    let mut node1_addr = node1.network.local_addr();

    // Fix the address if it's 0.0.0.0 (use localhost instead)
    if node1_addr.ip().is_unspecified() {
        node1_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }

    println!("Node1 peer_id: {node1_peer_id:?}, addr: {node1_addr}");

    // Add node1 as a peer to node2
    use reth_ethereum::network::Peers;
    node2.network.add_peer(node1_peer_id, node1_addr);

    // Also add node2 as a peer to node1 for bidirectional connection
    let node2_peer_id = *node2.network.peer_id();
    let mut node2_addr = node2.network.local_addr();
    if node2_addr.ip().is_unspecified() {
        node2_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }
    node1.network.add_peer(node2_peer_id, node2_addr);

    // Wait for connections to establish
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!("Peer connections established");

    // Send Fork Choice Update to trigger backfill sync
    println!("Sending FCU to node2 with finalized block: {final_block_hash:?}");

    let forkchoice_state = ForkchoiceState {
        head_block_hash: final_block_hash.0.into(),
        safe_block_hash: final_block_hash.0.into(),
        finalized_block_hash: final_block_hash.0.into(),
    };

    let result = node2
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

    println!("Backfill sync test completed successfully!");

    Ok(())
}
