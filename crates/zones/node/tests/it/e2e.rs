//! Self-contained e2e tests using deposit-queue injection.
//!
//! These tests launch a Zone L2 node without a real L1 connection and inject
//! synthetic L1 blocks + deposits directly into the [`DepositQueue`]. The L1
//! subscriber retries a dummy URL in the background, but L2 execution is fully
//! exercised via queue injection (with the L1 state cache seeded for precompile reads).

use std::{net::TcpListener, time::Duration};

use alloy::primitives::{Address, B256, Bytes, U256, address};
use alloy_consensus::Transaction;
use alloy_eips::NumHash;
use alloy_network::{ReceiptResponse, TransactionBuilder as _};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::SolCall;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_zone_contracts::{
    IZoneInbox, IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, Withdrawal, ZONE_INBOX_ADDRESS,
    ZONE_OUTBOX_ADDRESS,
};
use zone_l1::ChainTempoStateExt;
use zone_primitives::constants::zone_chain_id;

use crate::utils::{
    DEFAULT_POLL, DEFAULT_TIMEOUT, L1Fixture, TIP20_TX_GAS, WITHDRAWAL_TX_GAS, ZoneTestNode,
    approve_outbox, leader_p2p_config, local_dev_zone_account, poll_until, seed_fixture_for_zone,
    start_chain_id_rpc, start_local_p2p_cluster, start_local_zone_with_fixture,
};

const CONTRACT_CREATION_TX_GAS: u64 = 1_000_000;
const LEADER_INCLUSION_TIMEOUT: Duration = Duration::from_secs(30);
const P2P_RECOVERY_TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::test(flavor = "multi_thread")]
async fn test_zero_fee_transactions_are_admitted_and_included() -> eyre::Result<()> {
    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, sender) = local_dev_zone_account(&zone)?;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, sender, sender, 1_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        sender,
        U256::from(1_000_000),
        DEFAULT_TIMEOUT,
    )
    .await?;

    for legacy in [true, false] {
        let token = ITIP20::new(PATH_USD_ADDRESS, &provider);
        let approval = token
            .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
            .gas(TIP20_TX_GAS);
        let approval = if legacy {
            approval.gas_price(0)
        } else {
            approval.max_fee_per_gas(0).max_priority_fee_per_gas(0)
        };
        let pending = approval.send().await?;
        fixture.inject_empty_block(zone.deposit_queue());
        let receipt = pending.get_receipt().await?;
        assert!(receipt.status(), "zero-fee approval should execute");
        assert_eq!(receipt.effective_gas_price, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sequencer_exposes_simulation_endpoints() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let cluster = start_local_p2p_cluster(10).await?;

    for method in ["eth_call", "eth_estimateGas"] {
        let response = reqwest::Client::new()
            .post(cluster.nodes[0].http_url().clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": [],
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        assert_ne!(response["error"]["code"], -32601, "{method}: {response}");
    }

    Ok(())
}

/// A follower imports the leader's executed block and exposes the resulting state over RPC.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_p2p_follower_tracks_leader_balance() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut cluster = start_local_p2p_cluster(10).await?;

    // Commonware deliberately drops messages for offline peers. Wait for
    // peer dial/handshake (loopback dials every 500ms) before producing the
    // first block. The bootstrap leader also needs tip evidence from both
    // followers before its first promotion.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut fixture = std::mem::replace(&mut cluster.fixture, L1Fixture::new());
    let [leader, follower, _third] = cluster
        .nodes
        .try_into()
        .map_err(|_| eyre::eyre!("cluster must have three nodes"))?;

    let anchor =
        fixture.inject_empty_block_into(&[leader.deposit_queue(), follower.deposit_queue()]);
    leader.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;

    // Receiving the peer block is not enough: the follower must independently
    // observe its exact L1 anchor before importing it.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        follower.provider().get_block_number().await?,
        0,
        "follower imported a block before observing its L1 anchor"
    );

    follower.l1_block_tracker().record(anchor)?;
    follower.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;

    let depositor = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x0000000000000000000000000000000000005678");
    let amount = 1_000_000_u128;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, depositor, recipient, amount);
    let observed = fixture.portal_events_from_deposits(std::slice::from_ref(&deposit));
    let anchor = fixture.inject_deposits_into(
        &[leader.deposit_queue(), follower.deposit_queue()],
        vec![deposit],
    );
    follower
        .l1_block_tracker()
        .record_with_portal_events(anchor, observed)?;

    leader
        .wait_for_balance(
            PATH_USD_ADDRESS,
            recipient,
            U256::from(amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    let follower_balance = follower
        .wait_for_balance(
            PATH_USD_ADDRESS,
            recipient,
            U256::from(amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    follower.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;
    assert_eq!(follower_balance, U256::from(amount));

    // Submit only to the follower. Its local pool admission is forwarded as canonical EIP-2718
    // bytes, then independently validated by the leader pool for the next L1-derived build.
    let (follower_wallet, sender) = local_dev_zone_account(&follower)?;
    let transfer_recipient = address!("0x0000000000000000000000000000000000009abc");
    fixture.seed_no_receive_policy(transfer_recipient)?;
    let sender_deposit = fixture.make_deposit(PATH_USD_ADDRESS, sender, sender, amount);
    let observed = fixture.portal_events_from_deposits(std::slice::from_ref(&sender_deposit));
    let anchor = fixture.inject_deposits_into(
        &[leader.deposit_queue(), follower.deposit_queue()],
        vec![sender_deposit],
    );
    follower
        .l1_block_tracker()
        .record_with_portal_events(anchor, observed)?;
    leader
        .wait_for_balance(
            PATH_USD_ADDRESS,
            sender,
            U256::from(amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    follower
        .wait_for_balance(
            PATH_USD_ADDRESS,
            sender,
            U256::from(amount),
            DEFAULT_TIMEOUT,
        )
        .await?;

    let transfer_amount = 123_456_u128;
    let pending = ITIP20::new(PATH_USD_ADDRESS, follower_wallet)
        .transfer(transfer_recipient, U256::from(transfer_amount))
        .gas_price(TEMPO_T0_BASE_FEE as u128)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    let transaction_hash = *pending.tx_hash();

    let leader_provider = leader.provider();
    poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "forwarded transaction in leader pool",
        || {
            let leader_provider = &leader_provider;
            async move {
                Ok(leader_provider
                    .get_transaction_by_hash(transaction_hash)
                    .await?)
            }
        },
    )
    .await?;
    // A transaction admitted to the pool is not guaranteed to make the very next payload under
    // load. Produce blocks one at a time until it is included, with one overall timeout rather
    // than spending the full timeout on every attempt.
    let leader_receipt = tokio::time::timeout(LEADER_INCLUSION_TIMEOUT, async {
        loop {
            let next_block = leader_provider.get_block_number().await? + 1;
            let anchor = fixture
                .inject_empty_block_into(&[leader.deposit_queue(), follower.deposit_queue()]);
            follower.l1_block_tracker().record(anchor)?;
            leader
                .wait_for_block_number(next_block, DEFAULT_TIMEOUT)
                .await?;
            if let Some(receipt) = leader_provider
                .get_transaction_receipt(transaction_hash)
                .await?
            {
                return Ok::<_, eyre::Report>(receipt);
            }
        }
    })
    .await
    .map_err(|_| eyre::eyre!("timed out producing blocks for leader transaction inclusion"))??;
    assert!(leader_receipt.status(), "leader receipt should succeed");
    let inclusion_block = leader_receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("leader receipt missing block number"))?;

    // A live broadcast can be missed while the peer reconnects. Allow enough time for the
    // follower's 30-second inactivity probe to recover the inclusion block through backfill.
    follower
        .wait_for_block_number(inclusion_block, P2P_RECOVERY_TIMEOUT)
        .await?;
    let follower_receipt = tokio::time::timeout(DEFAULT_TIMEOUT, pending.get_receipt())
        .await
        .map_err(|_| eyre::eyre!("timed out waiting for follower transaction receipt"))??;
    assert!(
        follower_receipt.status(),
        "forwarded transfer should succeed"
    );

    for zone in [&leader, &follower] {
        let balance = zone
            .wait_for_balance(
                PATH_USD_ADDRESS,
                transfer_recipient,
                U256::from(transfer_amount),
                DEFAULT_TIMEOUT,
            )
            .await?;
        assert_eq!(balance, U256::from(transfer_amount));
    }
    Ok(())
}

/// A follower must enforce a TIP-403 policy change at the *exact* L1 block its
/// imported zone block is anchored to — never one block late.
///
/// Flow:
/// 1. Zone block 1 (anchor L1#1, pathUSD still allow-all): a deposit funds Alice.
/// 2. Between blocks, pathUSD's transfer policy switches to a blacklist that
///    bans Bob as a recipient, effective at L1 block 2.
/// 3. Zone block 2 (anchor L1#2): Alice's pathUSD transfer is included and
///    reverts on the leader because policy now resolves at height 2.
/// 4. The follower imports block 2 — only possible if it, too, reads policy at
///    height 2 and reproduces the revert, matching the leader's state root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_p2p_follower_enforces_policy_change_at_anchor_block() -> eyre::Result<()> {
    use alloy_provider::ProviderBuilder;
    use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
    use tempo_contracts::precompiles::{
        ITIP20, ITIP403Registry::PolicyType, TIP_FEE_MANAGER_ADDRESS,
    };

    use crate::utils::{
        PolicySeed, TIP20_TX_GAS, seed_raw_tip403_policy, seed_raw_tip403_token_policy, signer_at,
    };

    reth_tracing::init_test_tracing();

    let mut cluster = start_local_p2p_cluster(10).await?;

    // Commonware drops messages for offline peers; wait for the dial/handshake
    // before producing the first block (mirrors the sibling P2P test).
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The block producer (fee recipient) must be covered by the seeded policy below.
    let producer = cluster.sequencer_signers[0].address();
    let mut fixture = std::mem::replace(&mut cluster.fixture, L1Fixture::new());
    let [leader, follower, _third] = cluster
        .nodes
        .try_into()
        .map_err(|_| eyre::eyre!("cluster must have three nodes"))?;

    // Alice funds the transfer; Bob becomes blacklisted at the next L1 anchor.
    let alice_signer = signer_at(1);
    let alice = alice_signer.address();
    let bob = address!("0x0000000000000000000000000000000000000B0B");

    // --- Block 1: fund Alice while pathUSD is still allow-all (anchor L1#1). ---
    let deposit_amount: u128 = 1_000_000;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, alice, alice, deposit_amount);
    let observed = fixture.portal_events_from_deposits(std::slice::from_ref(&deposit));
    let anchor = fixture.inject_deposits_into(
        &[leader.deposit_queue(), follower.deposit_queue()],
        vec![deposit],
    );
    leader
        .wait_for_balance(
            PATH_USD_ADDRESS,
            alice,
            U256::from(deposit_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;

    follower
        .l1_block_tracker()
        .record_with_portal_events(anchor, observed)?;
    follower
        .wait_for_balance(
            PATH_USD_ADDRESS,
            alice,
            U256::from(deposit_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    follower.wait_for_block_number(1, DEFAULT_TIMEOUT).await?;

    // --- Policy change effective at L1 block 2: blacklist Bob on pathUSD. ---
    // Seed identically on both nodes, mirroring each node's L1 observer having
    // made block-2 TIP-403 and TIP-20 storage available before publishing the
    // anchor. The L1-backed execution database must select these values from
    // the anchor advanced by the first `advanceTempo` transaction.
    const BLACKLIST_POLICY_ID: u64 = 7;
    const POLICY_L1_BLOCK: u64 = 2;
    let policy_block = fixture.next_block();
    assert_eq!(policy_block.header.inner.number, POLICY_L1_BLOCK);
    fixture.seed_no_receive_policy(bob)?;
    for node in [&leader, &follower] {
        seed_raw_tip403_policy(
            node.l1_state_cache(),
            POLICY_L1_BLOCK,
            &[PolicySeed::simple(
                BLACKLIST_POLICY_ID,
                PolicyType::BLACKLIST,
                &[
                    (alice, false),
                    (bob, true),
                    (producer, false),
                    (TIP_FEE_MANAGER_ADDRESS, false),
                ],
            )],
        )?;
        seed_raw_tip403_token_policy(
            &mut node.l1_state_cache().lock(),
            POLICY_L1_BLOCK,
            PATH_USD_ADDRESS,
            BLACKLIST_POLICY_ID,
        );
    }

    // --- Block 2: Alice's transfer is submitted, then the anchoring L1 block is
    // injected to trigger the build that includes it. ---
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(leader.http_url().clone());
    let tip20 = ITIP20::new(PATH_USD_ADDRESS, &alice_provider);
    let pending = tip20
        .transfer(bob, U256::from(200_000u128))
        .gas_price(TEMPO_T0_BASE_FEE as u128)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    let anchor =
        reth_primitives_traits::SealedHeader::seal_slow(policy_block.header.clone()).num_hash();
    fixture.enqueue(&policy_block, leader.deposit_queue(), vec![]);
    fixture.enqueue(&policy_block, follower.deposit_queue(), vec![]);
    leader.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;

    // The leader, resolving policy at height 2, must revert Alice's transfer
    // (proves the exact-anchor policy behavior and that the tx was included, not dropped).
    let receipt = pending.get_receipt().await?;
    assert!(
        !receipt.status(),
        "leader should revert the blacklisted transfer in the block anchored at L1#2"
    );

    // --- The follower must independently reproduce that revert at height 2. ---
    // If it read policy at height 1 (allow-all) it would replay the transfer as
    // a success, diverge from the leader's state root, reject the block, and
    // never reach block 2 — so this import succeeding proves exact-anchor policy reads.
    follower.l1_block_tracker().record(anchor)?;
    follower.wait_for_block_number(2, DEFAULT_TIMEOUT).await?;

    // Bob received nothing on the follower: the reverted transfer moved no funds.
    assert_eq!(
        follower.balance_of(PATH_USD_ADDRESS, bob).await?,
        U256::ZERO,
        "follower must reflect the reverted transfer: Bob received nothing"
    );

    Ok(())
}

/// A P2P bind failure is fatal rather than leaving the node running without P2P.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_p2p_listener_failure_stops_node() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let occupied_listener = TcpListener::bind("127.0.0.1:0")?;
    let p2p_config = leader_p2p_config(occupied_listener.local_addr()?)?;
    let l1_rpc_url = start_chain_id_rpc(1337).await?;
    let mut zone = ZoneTestNode::start_local_with_p2p(l1_rpc_url.to_string(), p2p_config).await?;

    let _exit = tokio::time::timeout(DEFAULT_TIMEOUT, zone.wait_for_node_exit())
        .await
        .expect("node did not exit after its P2P listener failed");
    Ok(())
}

/// Self-contained test: inject a deposit via the queue and verify the zone
/// mints the corresponding pathUSD balance on L2.
///
/// Flow:
/// 1. Start a zone node with no real L1 (dummy URL).
/// 2. Inject an L1 block with a deposit into the deposit queue.
/// 3. Wait for the ZoneEngine to produce L2 blocks.
/// 4. Verify the recipient's pathUSD balance increased on L2.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_via_queue_injection() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let depositor = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x0000000000000000000000000000000000005678");
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD (6 decimals)

    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, depositor, recipient, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    let balance = zone
        .wait_for_balance(
            PATH_USD_ADDRESS,
            recipient,
            U256::from(deposit_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(
        balance,
        U256::from(deposit_amount),
        "minted amount should equal deposit amount"
    );

    Ok(())
}

/// Verify a contract-creation transaction is rejected by a running zone node.
///
/// This exercises the complete public transaction path: wallet signing, HTTP RPC,
/// transaction-pool validation, and the zone contract-deployer policy.
#[tokio::test(flavor = "multi_thread")]
async fn test_contract_creation_transaction_is_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, 1_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(1_000_000u128),
        DEFAULT_TIMEOUT,
    )
    .await?;

    let request = TransactionRequest::default()
        .with_deploy_code(Bytes::from_static(&[0x00]))
        .gas_limit(CONTRACT_CREATION_TX_GAS)
        .gas_price(TEMPO_T0_BASE_FEE as u128);

    let err = provider
        .send_transaction(request)
        .await
        .expect_err("an unlisted account must not submit a contract-creation transaction");
    let error_message = format!("{err:#}");
    assert!(
        error_message.contains("error code -32000: contract creation is not supported"),
        "unexpected contract-creation rejection: {error_message}"
    );

    Ok(())
}

/// Self-contained test: inject multiple deposits across multiple L1 blocks
/// and verify all are minted on L2.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_deposits_across_blocks() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let sender = address!("0x0000000000000000000000000000000000001111");

    // Block 1: deposit to Alice
    let d1 = fixture.make_deposit(PATH_USD_ADDRESS, sender, alice, 500_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![d1]);

    // Block 2: empty block (no deposits)
    fixture.inject_empty_block(zone.deposit_queue());

    // Block 3: two deposits — one to Alice, one to Bob
    let d2 = fixture.make_deposit(PATH_USD_ADDRESS, sender, alice, 300_000);
    let d3 = fixture.make_deposit(PATH_USD_ADDRESS, sender, bob, 700_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![d2, d3]);

    // Alice should have 500k + 300k = 800k
    let alice_balance = zone
        .wait_for_balance(
            PATH_USD_ADDRESS,
            alice,
            U256::from(800_000u128),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(alice_balance, U256::from(800_000u128));

    // Bob should have 700k
    let bob_balance = zone
        .wait_for_balance(
            PATH_USD_ADDRESS,
            bob,
            U256::from(700_000u128),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(bob_balance, U256::from(700_000u128));

    Ok(())
}

/// Self-contained test: verify the zone produces blocks even for empty L1
/// blocks (no deposits). The zone must advance its TempoState for every L1
/// block to maintain chain continuity.
#[tokio::test(flavor = "multi_thread")]
async fn test_empty_l1_blocks_advance_zone() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    // Inject several empty L1 blocks
    fixture.inject_empty_blocks(zone.deposit_queue(), 5);

    // Each L1 block advances tempoBlockNumber — wait for all 5
    zone.wait_for_tempo_block_number(5, DEFAULT_TIMEOUT).await?;

    Ok(())
}

/// Cancelling the `ZoneEngine` must stop it only between zone blocks, leaving the deposit
/// queue cursor and the local head in agreement.
///
/// This is the graceful-stop invariant needed by the future leadership handoff: an advance
/// consumes an L1 block from the queue and canonicalizes the resulting zone block across several
/// awaits. Stopping partway would either replay an L1 anchor (`advanceTempo` rejects it) or skip
/// one, and either way the node could never build another block.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_engine_stops_cleanly_between_blocks() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(20).await?;

    // Produce a few blocks so the stop lands on a running engine, not an idle one.
    fixture.inject_empty_blocks(zone.deposit_queue(), 5);
    zone.wait_for_tempo_block_number(5, DEFAULT_TIMEOUT).await?;

    // Keep feeding the queue while the engine is asked to stop, so cancellation races with
    // block production instead of arriving during an idle period.
    fixture.inject_empty_blocks(zone.deposit_queue(), 10);
    let head = zone.stop_engine().await?;

    // One Zone block may checkpoint several L1 headers, but cancellation must leave the imported
    // Tempo cursor and queue front at the same atomic boundary.
    let tempo_block_number = zone.tempo_block_number().await?;
    assert!(
        tempo_block_number >= head,
        "the Tempo cursor cannot trail the Zone head: tempo={tempo_block_number}, zone={head}"
    );
    let next_anchor = zone
        .deposit_queue()
        .peek()
        .map(|block| block.header.num_hash().number);
    if let Some(next_anchor) = next_anchor {
        assert_eq!(
            next_anchor,
            tempo_block_number + 1,
            "the queue front must be the anchor of the next unbuilt zone block"
        );
    }

    // A stopped engine stays stopped, and the node keeps serving RPC.
    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        zone.provider().get_block_number().await?,
        head,
        "a cancelled engine must not resume building"
    );

    Ok(())
}

/// Two independent zones processing deposits from a shared L1 timeline.
///
/// Verifies that:
/// - Two zone nodes can run concurrently with different chain IDs.
/// - Each zone independently processes only the deposits injected into its queue.
/// - Cross-zone isolation: deposits on zone1 don't appear on zone2 and vice versa.
#[tokio::test(flavor = "multi_thread")]
async fn test_two_zones_independent_deposits() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start two zones with different chain IDs
    let zone1 = ZoneTestNode::start_local_with_chain_id(zone_chain_id(1_337, 1)?).await?;
    let zone2 = ZoneTestNode::start_local_with_chain_id(zone_chain_id(1_337, 2)?).await?;

    // Shared L1 fixture — same header timeline for both zones
    let mut fixture = L1Fixture::new();
    seed_fixture_for_zone(&fixture, &zone1, 20);
    seed_fixture_for_zone(&fixture, &zone2, 20);

    let sender = address!("0x0000000000000000000000000000000000001111");
    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");

    // L1 block 1: deposit to Alice on zone1, empty on zone2
    let b1 = fixture.next_block();
    let d1 = L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, sender, alice, 500_000);
    fixture.enqueue(&b1, zone1.deposit_queue(), vec![d1]);
    fixture.enqueue(&b1, zone2.deposit_queue(), vec![]);

    // L1 block 2: empty on zone1, deposit to Bob on zone2
    let b2 = fixture.next_block();
    let d2 = L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, sender, bob, 700_000);
    fixture.enqueue(&b2, zone1.deposit_queue(), vec![]);
    fixture.enqueue(&b2, zone2.deposit_queue(), vec![d2]);

    // L1 block 3: deposits on both zones
    let b3 = fixture.next_block();
    let d3a = L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, sender, alice, 300_000);
    let d3b = L1Fixture::make_deposit_for_block(PATH_USD_ADDRESS, sender, bob, 200_000);
    fixture.enqueue(&b3, zone1.deposit_queue(), vec![d3a]);
    fixture.enqueue(&b3, zone2.deposit_queue(), vec![d3b]);

    // Zone1: Alice should have 500k + 300k = 800k, Bob should have 0
    let zone1_alice = zone1
        .wait_for_balance(
            PATH_USD_ADDRESS,
            alice,
            U256::from(800_000u128),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(zone1_alice, U256::from(800_000u128));

    let zone1_bob = zone1.balance_of(PATH_USD_ADDRESS, bob).await?;
    assert_eq!(
        zone1_bob,
        U256::ZERO,
        "zone1: Bob should have zero — deposit was on zone2"
    );

    // Zone2: Bob should have 700k + 200k = 900k, Alice should have 0
    let zone2_bob = zone2
        .wait_for_balance(
            PATH_USD_ADDRESS,
            bob,
            U256::from(900_000u128),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(zone2_bob, U256::from(900_000u128));

    let zone2_alice = zone2.balance_of(PATH_USD_ADDRESS, alice).await?;
    assert_eq!(
        zone2_alice,
        U256::ZERO,
        "zone2: Alice should have zero — deposit was on zone1"
    );

    Ok(())
}

/// Verify that TempoState on the zone advances its tempoBlockNumber and
/// tempoBlockHash correctly as L1 blocks are injected.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_state_advances_with_l1_blocks() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, zone.provider());

    // Before injecting any blocks, tempoBlockNumber should be 0 (genesis)
    let initial_number = tempo_state.tempoBlockNumber().call().await?;
    assert_eq!(initial_number, 0, "initial tempoBlockNumber should be 0");

    let initial_hash = tempo_state.tempoBlockHash().call().await?;
    assert_ne!(
        initial_hash,
        B256::ZERO,
        "initial tempoBlockHash should be non-zero (genesis hash)"
    );

    // Inject 3 empty L1 blocks
    for _ in 0..3 {
        fixture.inject_empty_block(zone.deposit_queue());
    }

    // Wait for tempoBlockNumber to reach 3
    let final_number = zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;
    assert_eq!(
        final_number, 3,
        "tempoBlockNumber should be 3 after 3 L1 blocks"
    );

    // tempoBlockHash should have changed
    let final_hash = tempo_state.tempoBlockHash().call().await?;
    assert_ne!(
        final_hash, initial_hash,
        "tempoBlockHash should change after advancing"
    );
    assert_ne!(final_hash, B256::ZERO, "tempoBlockHash should be non-zero");

    Ok(())
}

/// Verify deposit processing emits inbox events and finalizes a batch in the same block.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_inbox_events_on_deposit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let sender = address!("0x0000000000000000000000000000000000001111");
    let recipient = address!("0x0000000000000000000000000000000000002222");
    let deposit_amount: u128 = 5_000_000;

    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, sender, recipient, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    // Wait for the deposit to be processed
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        recipient,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Query TempoAdvanced events from ZoneInbox
    let zone_inbox = IZoneInbox::new(ZONE_INBOX_ADDRESS, zone.provider());
    let tempo_advanced_filter = zone_inbox.TempoAdvanced_1_filter().from_block(0);
    let tempo_advanced_events = tempo_advanced_filter.query().await?;

    assert!(
        !tempo_advanced_events.is_empty(),
        "should have at least one TempoAdvanced event"
    );

    // Find the event for our deposit block (should have depositsProcessed == 1)
    let deposit_event = tempo_advanced_events
        .iter()
        .find(|(e, _)| e.depositsProcessed == U256::ONE);
    assert!(
        deposit_event.is_some(),
        "should have a TempoAdvanced event with depositsProcessed == 1"
    );

    let deposit_block = deposit_event.unwrap().1.block_number.unwrap();
    assert_eq!(
        deposit_block, 1,
        "deposit must precede the eight-block interval"
    );
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, zone.provider());
    let finalized = outbox
        .BatchFinalized_filter()
        .select(deposit_block)
        .query()
        .await?;
    assert_eq!(
        finalized.len(),
        1,
        "deposit-only block must finalize a batch"
    );
    assert_eq!(finalized[0].0.withdrawalQueueHash, B256::ZERO);
    assert_eq!(finalized[0].0.withdrawalBatchIndex, 1);

    // Query encrypted deposit events
    let deposit_processed_filter = zone_inbox.DepositProcessed_filter().from_block(0);
    let deposit_processed_events = deposit_processed_filter.query().await?;

    assert!(
        !deposit_processed_events.is_empty(),
        "should have at least one DepositProcessed event"
    );

    // Verify the deposit event details
    let (dp_event, _) = &deposit_processed_events[0];
    assert_eq!(dp_event.sender, sender, "deposit sender mismatch");
    assert_eq!(dp_event.to, recipient, "deposit recipient mismatch");
    assert_eq!(dp_event.amount, deposit_amount, "deposit amount mismatch");

    Ok(())
}

/// Verify a large batch of deposits in a single L1 block is processed correctly.
#[tokio::test(flavor = "multi_thread")]
async fn test_large_deposit_batch() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let sender = address!("0x0000000000000000000000000000000000001111");
    let num_deposits = 10u128;
    let amount_each: u128 = 100_000;

    // Build 10 deposits to different recipients in one L1 block
    let recipients: Vec<Address> = (0..num_deposits)
        .map(|i| Address::with_last_byte((i + 1) as u8))
        .collect();
    let deposits: Vec<_> = recipients
        .iter()
        .map(|to| fixture.make_deposit(PATH_USD_ADDRESS, sender, *to, amount_each))
        .collect();

    fixture.inject_deposits(zone.deposit_queue(), deposits);

    // Wait for the last recipient to receive their deposit
    let last_recipient = *recipients.last().unwrap();
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        last_recipient,
        U256::from(amount_each),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify all recipients received the correct amount
    for recipient in &recipients {
        let balance = zone.balance_of(PATH_USD_ADDRESS, *recipient).await?;
        assert_eq!(
            balance,
            U256::from(amount_each),
            "recipient {recipient} should have {amount_each}"
        );
    }

    Ok(())
}

/// Verify empty withdrawal batches finalize at deterministic block boundaries.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_batch_finalization() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let zone_outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, zone.provider());

    let initial_batch_index = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
    // Local test nodes finalize empty batches every eight zone blocks.
    const BATCH_INTERVAL_BLOCKS: u64 = 8;

    let before_first_boundary = fixture
        .produce_empty_zone_blocks(&zone, BATCH_INTERVAL_BLOCKS - 1)
        .await?;
    assert_eq!(before_first_boundary, BATCH_INTERVAL_BLOCKS - 1);
    assert_eq!(
        zone_outbox.lastBatch().call().await?.withdrawalBatchIndex,
        initial_batch_index,
        "withdrawalBatchIndex should not advance before a block-number boundary"
    );

    fixture.produce_empty_zone_blocks(&zone, 1).await?;
    poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "first empty withdrawal batch finalized",
        || {
            let zone_outbox = &zone_outbox;
            async move {
                let idx = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
                if idx == initial_batch_index + 1 {
                    Ok(Some(idx))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let intermediate_height = fixture
        .produce_empty_zone_blocks(&zone, BATCH_INTERVAL_BLOCKS - 1)
        .await?;
    assert_eq!(intermediate_height, (2 * BATCH_INTERVAL_BLOCKS) - 1);

    let intermediate_batch_index = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
    assert_eq!(
        intermediate_batch_index,
        initial_batch_index + 1,
        "withdrawalBatchIndex should not advance before the next block-number boundary"
    );

    fixture.produce_empty_zone_blocks(&zone, 1).await?;

    let final_batch_index = poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "withdrawalBatchIndex advanced",
        || {
            let zone_outbox = &zone_outbox;
            async move {
                let idx = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
                if idx == initial_batch_index + 2 {
                    Ok(Some(idx))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    assert_eq!(
        final_batch_index,
        initial_batch_index + 2,
        "withdrawalBatchIndex should advance at the next block-number boundary"
    );

    // lastBatch should have zero withdrawalQueueHash (no withdrawals requested)
    let last_batch = zone_outbox.lastBatch().call().await?;
    assert_eq!(
        last_batch.withdrawalQueueHash,
        B256::ZERO,
        "lastBatch.withdrawalQueueHash should be zero with no withdrawals"
    );

    Ok(())
}

async fn submit_withdrawal(
    fixture: &mut L1Fixture,
    zone: &ZoneTestNode,
    provider: &DynProvider,
    dev_address: Address,
    amount: u128,
) -> eyre::Result<u64> {
    submit_withdrawals(fixture, zone, provider, dev_address, &[amount]).await
}

async fn submit_withdrawals(
    fixture: &mut L1Fixture,
    zone: &ZoneTestNode,
    provider: &DynProvider,
    dev_address: Address,
    amounts: &[u128],
) -> eyre::Result<u64> {
    eyre::ensure!(
        !amounts.is_empty(),
        "at least one withdrawal amount is required"
    );

    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, provider.clone());
    let nonce = provider
        .get_transaction_count(dev_address)
        .pending()
        .await?;
    let mut pending = Vec::with_capacity(amounts.len());
    for (offset, amount) in amounts.iter().copied().enumerate() {
        pending.push(
            outbox
                .requestWithdrawal(
                    PATH_USD_ADDRESS,
                    dev_address,
                    amount,
                    B256::ZERO,
                    0,
                    dev_address,
                    Bytes::new(),
                    Bytes::new(),
                )
                .nonce(nonce + offset as u64)
                .gas_price(TEMPO_T0_BASE_FEE as u128)
                .send()
                .await?,
        );
    }

    fixture.inject_empty_block(zone.deposit_queue());
    let mut withdrawal_block = None;
    for pending_tx in pending {
        let receipt = pending_tx.get_receipt().await?;
        assert!(
            receipt.status(),
            "withdrawal should succeed (gas used: {})",
            receipt.gas_used
        );
        let block_number = receipt
            .block_number
            .ok_or_else(|| eyre::eyre!("withdrawal receipt missing block number"))?;
        if let Some(expected) = withdrawal_block {
            eyre::ensure!(
                block_number == expected,
                "withdrawals were included in different blocks: {expected} and {block_number}"
            );
        } else {
            withdrawal_block = Some(block_number);
        }
    }

    withdrawal_block.ok_or_else(|| eyre::eyre!("withdrawal block missing"))
}

/// Verify a withdrawal and its batch boundary are emitted in the same block.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_request_finalizes_same_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, provider.clone());

    let deposit_amount: u128 = 2_000_000;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;
    approve_outbox(&mut fixture, &zone, &provider).await?;

    let batch_index_before = outbox.lastBatch().call().await?.withdrawalBatchIndex;
    let withdrawal_block =
        submit_withdrawal(&mut fixture, &zone, &provider, dev_address, 250_000).await?;

    assert_eq!(
        outbox
            .pendingWithdrawalsCount()
            .from(Address::ZERO)
            .call()
            .await?,
        U256::ZERO,
        "withdrawal block should sweep pending withdrawals"
    );

    let requested_logs = outbox
        .WithdrawalRequested_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(requested_logs.len(), 1);
    let (requested, requested_log) = &requested_logs[0];
    let withdrawal_tx_hash = requested_log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("WithdrawalRequested log missing transaction hash"))?;
    let withdrawal = Withdrawal::from_requested_event(requested, withdrawal_tx_hash, Bytes::new());
    let expected_hash = Withdrawal::queue_hash(&[withdrawal]);

    let finalized_logs = outbox
        .BatchFinalized_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(
        finalized_logs.len(),
        1,
        "withdrawal block should emit exactly one BatchFinalized"
    );
    let (finalized, log) = &finalized_logs[0];
    assert_eq!(finalized.withdrawalQueueHash, expected_hash);
    assert_eq!(
        finalized.withdrawalBatchIndex,
        batch_index_before + 1,
        "withdrawal block should advance the batch index"
    );

    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("BatchFinalized log missing transaction hash"))?;
    let finalize_tx = provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("finalizeWithdrawalBatch tx {tx_hash} not found"))?;
    let finalize_call =
        IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(finalize_tx.input().as_ref())?;
    assert_eq!(
        finalize_call.count,
        U256::ONE,
        "builder should finalize exactly the current withdrawal"
    );
    assert_eq!(finalize_call.blockNumber, withdrawal_block);
    assert_eq!(finalize_call.encryptedSenders.len(), 1);

    let transaction_count = provider
        .get_block_transaction_count_by_number(withdrawal_block.into())
        .await?
        .ok_or_else(|| eyre::eyre!("withdrawal block {withdrawal_block} not found"))?;
    let finalize_index = log
        .transaction_index
        .ok_or_else(|| eyre::eyre!("BatchFinalized log missing transaction index"))?;
    assert_eq!(
        finalize_index + 1,
        transaction_count,
        "finalizeWithdrawalBatch should be the last transaction"
    );

    let last_batch = outbox.lastBatch().call().await?;
    assert_eq!(last_batch.withdrawalQueueHash, expected_hash);
    assert_eq!(last_batch.withdrawalBatchIndex, batch_index_before + 1);

    Ok(())
}

/// Multiple withdrawals created in one block are finalized as one batch in that block.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_withdrawals_finalize_in_one_batch() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, provider.clone());

    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, 2_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(2_000_000u128),
        DEFAULT_TIMEOUT,
    )
    .await?;
    approve_outbox(&mut fixture, &zone, &provider).await?;

    let batch_index_before = outbox.lastBatch().call().await?.withdrawalBatchIndex;
    let withdrawal_block = submit_withdrawals(
        &mut fixture,
        &zone,
        &provider,
        dev_address,
        &[250_000, 350_000],
    )
    .await?;

    let finalized_logs = outbox
        .BatchFinalized_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(
        finalized_logs.len(),
        1,
        "withdrawal block should emit one BatchFinalized"
    );

    let requested_logs = outbox
        .WithdrawalRequested_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(requested_logs.len(), 2);

    let mut withdrawals = Vec::new();
    for (requested, log) in &requested_logs {
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| eyre::eyre!("WithdrawalRequested log missing transaction hash"))?;
        withdrawals.push(Withdrawal::from_requested_event(
            requested,
            tx_hash,
            Bytes::new(),
        ));
    }
    let expected_hash = Withdrawal::queue_hash(&withdrawals);
    let (finalized, log) = &finalized_logs[0];
    assert_eq!(finalized.withdrawalQueueHash, expected_hash);
    assert_eq!(finalized.withdrawalBatchIndex, batch_index_before + 1);

    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("BatchFinalized log missing transaction hash"))?;
    let finalize_tx = provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("finalizeWithdrawalBatch tx {tx_hash} not found"))?;
    let finalize_call =
        IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(finalize_tx.input().as_ref())?;
    assert_eq!(
        finalize_call.count,
        U256::from(2),
        "one batch should cover both current-block withdrawals"
    );
    assert_eq!(finalize_call.blockNumber, withdrawal_block);
    assert_eq!(finalize_call.encryptedSenders.len(), 2);
    assert_eq!(
        outbox
            .pendingWithdrawalsCount()
            .from(Address::ZERO)
            .call()
            .await?,
        U256::ZERO,
        "batch should sweep both pending withdrawals"
    );

    Ok(())
}

/// Current-only block at a batch boundary finalizes that block's withdrawals.
#[tokio::test(flavor = "multi_thread")]
async fn test_current_only_block_finalizes_at_batch_boundary() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, provider.clone());

    // Local test nodes finalize empty batches every eight zone blocks.
    const BATCH_INTERVAL_BLOCKS: u64 = 8;

    let batch_index = outbox.lastBatch().call().await?.withdrawalBatchIndex;
    fixture.inject_empty_blocks(zone.deposit_queue(), BATCH_INTERVAL_BLOCKS);
    poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "first empty batch boundary closed",
        || {
            let outbox = &outbox;
            async move {
                let idx = outbox.lastBatch().call().await?.withdrawalBatchIndex;
                if idx == batch_index + 1 {
                    Ok(Some(idx))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, 1_000_000);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(1_000_000u128),
        DEFAULT_TIMEOUT,
    )
    .await?;
    approve_outbox(&mut fixture, &zone, &provider).await?;

    // Advance to exactly one block before the next batch boundary, then wait
    // for those quiet blocks to be built. `inject_empty_blocks` only enqueues
    // L1 blocks; without this wait the withdrawal can race into one of those
    // still-building quiet zone blocks.
    let current_block = zone.provider().get_block_number().await?;
    let quiet_blocks_until_pre_boundary =
        (BATCH_INTERVAL_BLOCKS - 1) - (current_block % BATCH_INTERVAL_BLOCKS);
    let pre_boundary_block = current_block + quiet_blocks_until_pre_boundary;
    fixture.inject_empty_blocks(zone.deposit_queue(), quiet_blocks_until_pre_boundary);
    let observed_pre_boundary = poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "quiet blocks before withdrawal boundary built",
        || {
            let provider = zone.provider();
            async move {
                let number = provider.get_block_number().await?;
                if number >= pre_boundary_block {
                    Ok(Some(number))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;
    assert_eq!(
        observed_pre_boundary, pre_boundary_block,
        "zone should be exactly one block before the withdrawal boundary"
    );
    assert_eq!((observed_pre_boundary + 1) % BATCH_INTERVAL_BLOCKS, 0);

    let batch_index_before = outbox.lastBatch().call().await?.withdrawalBatchIndex;
    // The next block is a deterministic batch boundary, so it finalizes its
    // own withdrawal rather than deferring it to the following block.
    let withdrawal_block =
        submit_withdrawal(&mut fixture, &zone, &provider, dev_address, 250_000).await?;
    assert_eq!(withdrawal_block % BATCH_INTERVAL_BLOCKS, 0);

    poll_until(
        DEFAULT_TIMEOUT,
        DEFAULT_POLL,
        "batch-boundary current-only block finalized",
        || {
            let outbox = &outbox;
            async move {
                let index = outbox.lastBatch().call().await?.withdrawalBatchIndex;
                if index == batch_index_before + 1 {
                    Ok(Some(index))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let finalized_logs = outbox
        .BatchFinalized_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(
        finalized_logs.len(),
        1,
        "batch-boundary current-only block should finalize in the same block"
    );

    let requested_logs = outbox
        .WithdrawalRequested_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    let (requested, requested_log) = &requested_logs[0];
    let withdrawal_tx_hash = requested_log
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("WithdrawalRequested log missing transaction hash"))?;
    let withdrawal = Withdrawal::from_requested_event(requested, withdrawal_tx_hash, Bytes::new());
    assert_eq!(
        finalized_logs[0].0.withdrawalQueueHash,
        Withdrawal::queue_hash(&[withdrawal])
    );

    let tx_hash = finalized_logs[0]
        .1
        .transaction_hash
        .ok_or_else(|| eyre::eyre!("BatchFinalized log missing transaction hash"))?;
    let finalize_tx = provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("finalizeWithdrawalBatch tx {tx_hash} not found"))?;
    let finalize_call =
        IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(finalize_tx.input().as_ref())?;
    assert_eq!(finalize_call.count, U256::ONE);

    Ok(())
}

/// Submit a signed L2 withdrawal request with an over-cap callback gas limit.
///
/// This exercises the RPC transaction path: the transaction is accepted into a
/// zone block, reverts in `IZoneOutbox`, and does not enter the pending
/// withdrawal queue.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_request_rejects_over_max_callback_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let (provider, dev_address) = local_dev_zone_account(&zone)?;
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &provider);

    let deposit_amount: u128 = 1_000_000;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    approve_outbox(&mut fixture, &zone, &provider).await?;

    let pending_before = outbox
        .pendingWithdrawalsCount()
        .from(Address::ZERO)
        .call()
        .await?;
    let max_callback_gas = outbox.MAX_WITHDRAWAL_GAS_LIMIT().call().await?;

    let withdrawal_pending = outbox
        .requestWithdrawal(
            PATH_USD_ADDRESS,
            dev_address,
            250_000,
            B256::ZERO,
            max_callback_gas + 1,
            dev_address,
            Bytes::from_static(b"callback"),
            Bytes::new(),
        )
        .gas_price(TEMPO_T0_BASE_FEE as u128)
        .gas(WITHDRAWAL_TX_GAS)
        .send()
        .await?;

    fixture.inject_empty_block(zone.deposit_queue());
    let withdrawal_receipt = withdrawal_pending.get_receipt().await?;
    assert!(
        !withdrawal_receipt.status(),
        "over-cap withdrawal request should revert on L2"
    );

    let pending_after = outbox
        .pendingWithdrawalsCount()
        .from(Address::ZERO)
        .call()
        .await?;
    assert_eq!(
        pending_after, pending_before,
        "reverted withdrawal must not enter the pending queue"
    );

    Ok(())
}

/// Verify that `ChainTempoStateExt` on the committed `Chain` from a canon state
/// notification returns the correct L1 block NumHash after zone blocks are mined.
#[tokio::test(flavor = "multi_thread")]
async fn test_chain_tempo_state_ext_from_canon_notification() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let mut canon_rx = zone.subscribe_to_canonical_state();

    // Pace the imports so each empty Tempo block produces a distinct Zone block and canonical
    // notification instead of being compressed into a checkpoint-only catch-up range.
    fixture.produce_empty_zone_blocks(&zone, 3).await?;

    // Drain canon notifications and collect the L1 NumHash from each committed chain.
    let mut num_hashes: Vec<NumHash> = Vec::new();
    while let Ok(notification) = canon_rx.try_recv() {
        let chain = notification.committed();
        let nh = chain.tempo_num_hash();
        if nh.number > 0 {
            num_hashes.push(nh);
        }
    }

    // We should have received notifications for blocks 1, 2, 3.
    assert!(
        num_hashes.len() >= 3,
        "expected at least 3 canon notifications with non-zero tempoBlockNumber, got {}",
        num_hashes.len()
    );

    // Verify the L1 block numbers are monotonically increasing.
    for window in num_hashes.windows(2) {
        assert!(
            window[1].number > window[0].number,
            "L1 block numbers should be increasing: {} -> {}",
            window[0].number,
            window[1].number
        );
    }

    // The last notification should match the final L1 block number (3).
    let last = num_hashes.last().unwrap();
    assert_eq!(
        last.number, 3,
        "last canon notification should have tempoBlockNumber == 3"
    );
    assert_ne!(last.hash, B256::ZERO, "tempoBlockHash should be non-zero");

    // Cross-check against the on-chain TempoState.
    let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, zone.provider());
    let on_chain_hash = tempo_state.tempoBlockHash().call().await?;
    assert_eq!(
        last.hash, on_chain_hash,
        "Chain ext hash should match on-chain tempoBlockHash"
    );

    Ok(())
}
