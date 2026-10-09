//! Full L1+L2 end-to-end tests with a real in-process Tempo L1 node.
//!
//! Unlike the injection-based tests in `e2e.rs`, these tests start a real
//! Tempo L1 dev node and a Zone L2 node connected via WebSocket. The L1
//! subscriber naturally receives blocks and deposits — no synthetic injection.

use crate::utils::{
    L1TestNode, PolicySeed, RouterCallbackArgs, RouterDepositArgs, STABLECOIN_DEX_ADDRESS,
    WithdrawalArgs, ZoneAccount, ZoneCreationConfig, ZoneTestNode, fetch_submit_batch_call,
    poll_until, seed_raw_tip403_policy, seed_raw_tip403_token_policy, spawn_sequencer,
    spawn_sequencer_with_config, start_real_p2p_cluster, start_real_p2p_cluster_with_active_nodes,
};
use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    sol_types::SolCall,
};
use alloy_consensus::Transaction;
use eyre::WrapErr as _;
use futures::future::try_join_all;
use std::{collections::HashMap, time::Duration};
use tempo_precompiles::{PATH_USD_ADDRESS, zone_factory::portal};
use tempo_zone_contracts::{
    IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS,
    ZonePortal, ZonePortal::Role as PortalRole,
};
use zone_node::dev::{ProvisionConfig, provision_zone};

/// Longer timeout for real L1 tests — the L1 dev node produces blocks every
/// 500ms and the L1Subscriber needs to connect, backfill, and subscribe.
const L1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const ROUTER_SWAP_TICK: i16 = 0;
const ROUTER_SWAP_AMOUNT: u128 = 100_000_000;
const ROUTER_DEX_LIQUIDITY: u128 = 300_000_000;

async fn wait_for_stable_zone_head(zone: &ZoneTestNode) -> eyre::Result<u64> {
    tokio::time::timeout(L1_TIMEOUT, async {
        let provider = zone.provider();
        let mut head = provider.get_block_number().await?;
        let mut unchanged = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = provider.get_block_number().await?;
            if current == head {
                unchanged += 1;
                if unchanged == 10 {
                    return Ok::<_, eyre::Report>(head);
                }
            } else {
                head = current;
                unchanged = 0;
            }
        }
    })
    .await
    .map_err(|_| eyre::eyre!("Zone head did not stop advancing"))?
}

struct SameZoneSwapFixture {
    l1: L1TestNode,
    zone: ZoneTestNode,
    portal_address: Address,
    router: Address,
    alpha: Address,
    beta: Address,
    account: ZoneAccount,
    swap_amount: u128,
}

async fn setup_same_zone_swap_fixture() -> eyre::Result<SameZoneSwapFixture> {
    let l1 = L1TestNode::start().await?;

    let alpha = l1
        .create_tip20("AlphaUSD", "aUSD", B256::with_last_byte(0xA1))
        .await?;
    let beta = l1
        .create_tip20("BetaUSD", "bUSD", B256::with_last_byte(0xB2))
        .await?;

    let mint_amount = ROUTER_DEX_LIQUIDITY + ROUTER_SWAP_AMOUNT;
    l1.mint_tip20(alpha, l1.dev_address(), mint_amount).await?;
    l1.mint_tip20(beta, l1.dev_address(), mint_amount).await?;

    let factory = l1.native_zone_factory().await?;
    let portal_address = l1.create_zone(factory).await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let router = l1
        .deploy_router_with_dex(factory, STABLECOIN_DEX_ADDRESS)
        .await?;
    let gateway_block = l1
        .set_zone_gateway_on_portal(portal_address, router, true)
        .await?;
    zone.wait_for_l2_tempo_finalized(gateway_block, L1_TIMEOUT)
        .await?;
    zone.assert_zone_gateway(router, true).await?;

    l1.enable_token_on_portal(portal_address, alpha).await?;
    l1.enable_token_on_portal(portal_address, beta).await?;
    let enable_block = l1.provider().get_block_number().await?;
    zone.wait_for_l2_tempo_finalized(enable_block, L1_TIMEOUT)
        .await?;

    l1.create_dex_pair(alpha).await?;
    l1.create_dex_pair(beta).await?;
    l1.place_dex_bid_order(alpha, ROUTER_DEX_LIQUIDITY, ROUTER_SWAP_TICK)
        .await?;
    l1.place_dex_ask_order(beta, ROUTER_DEX_LIQUIDITY, ROUTER_SWAP_TICK)
        .await?;

    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(account.address(), 10_000_000).await?;
    l1.fund_user_token(alpha, account.address(), ROUTER_SWAP_AMOUNT)
        .await?;
    account.deposit(5_000_000, L1_TIMEOUT, &zone).await?;

    let alpha_minted = account
        .deposit_token(alpha, alpha, ROUTER_SWAP_AMOUNT, L1_TIMEOUT, &zone)
        .await?;
    assert_eq!(
        alpha_minted,
        U256::from(ROUTER_SWAP_AMOUNT),
        "AlphaUSD minted balance should equal the deposited amount"
    );

    Ok(SameZoneSwapFixture {
        l1,
        zone,
        portal_address,
        router,
        alpha,
        beta,
        account,
        swap_amount: ROUTER_SWAP_AMOUNT,
    })
}

/// Start a real L1 dev node and a zone node connected to it.
/// Verify the zone advances as L1 blocks arrive — proving the full
/// L1Subscriber → DepositQueue → ZoneEngine pipeline works end-to-end.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_advances_with_real_l1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start real Tempo L1 in dev mode (500ms block time)
    let l1 = L1TestNode::start().await?;

    // Verify L1 is producing blocks
    let l1_block_0 = l1.provider().get_block_number().await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let l1_block_1 = l1.provider().get_block_number().await?;
    assert!(
        l1_block_1 > l1_block_0,
        "L1 should be producing blocks in dev mode"
    );

    // Match the normal provision flow by anchoring immediately before the portal deployment.
    // Startup must leave the registry empty at this anchor and let subscriber backfill process
    // the constructor's initial TokenEnabled event.
    let anchor_block_number = l1.provider().get_block_number().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1_at_block(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        anchor_block_number,
    )
    .await?;

    // Wait for the zone to advance past block 0 (genesis anchor)
    let zone_tempo_number = zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    assert!(
        zone_tempo_number > 0,
        "zone should have advanced past genesis anchor"
    );
    assert!(
        zone.enabled_tokens().read().contains(&PATH_USD_ADDRESS),
        "subscriber backfill should populate the initial enabled token"
    );

    // Zone should also have produced L2 blocks
    let zone_block = zone.provider().get_block_number().await?;
    assert!(zone_block > 0, "zone L2 should have blocks");

    // tempoBlockHash should be non-zero (real L1 headers)
    let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, zone.provider());
    let tempo_hash = tempo_state.tempoBlockHash().call().await?;
    assert_ne!(
        tempo_hash,
        B256::ZERO,
        "tempoBlockHash should be set from real L1 headers"
    );
    assert_eq!(
        zone.l1_block_tracker().observed_hash(zone_tempo_number),
        None,
        "the leader must prune L1 observations after consuming them"
    );

    Ok(())
}

/// The quorum path must settle a batch emitted by the real role controller, not merely accept
/// manually assembled calldata. All three nodes independently execute the boundary, then the
/// Portal accepts the leader's 2-of-3-or-more certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_three_node_quorum_settles_real_batch_boundary() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let cluster = start_real_p2p_cluster(4).await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    eyre::ensure!(
        portal.sequencerThreshold().call().await? == 2,
        "Portal threshold is not 2"
    );
    for signer in &cluster.attestation_signers {
        eyre::ensure!(
            portal.isSequencer(signer.address()).call().await?,
            "Portal did not register quorum signer {}",
            signer.address()
        );
    }

    let submitted_height: u64 = poll_until(
        L1_TIMEOUT,
        Duration::from_millis(200),
        "2-of-3 BatchSubmitted event from the real three-node cluster",
        || {
            let portal = &portal;
            async move {
                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                if events.is_empty() {
                    return Ok(None);
                }
                Ok(Some(portal.zoneHeight().call().await?))
            }
        },
    )
    .await?
    .try_into()
    .map_err(|_| eyre::eyre!("settled zone height does not fit in u64"))?;

    eyre::ensure!(
        submitted_height > 0,
        "batch submission did not advance the settled zone height"
    );
    eyre::ensure!(
        portal.withdrawalBatchIndex().call().await? >= 1,
        "real batch boundary did not advance the withdrawal batch index"
    );
    cluster.wait_all_at(submitted_height, L1_TIMEOUT).await?;
    cluster.assert_same_block(submitted_height).await?;

    Ok(())
}

/// A three-member Portal must settle as soon as its two-signature threshold is met; the missing
/// third node must neither block settlement nor appear as an unnecessary third certificate entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_online_sequencers_submit_two_signature_certificate() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // The manifest and Portal retain all three registered members, but node C never starts.
    let cluster = start_real_p2p_cluster_with_active_nodes(4, 2).await?;
    eyre::ensure!(
        cluster.nodes.len() == 2 && cluster.attestation_signers.len() == 3,
        "fixture did not retain a three-member set with exactly two online nodes"
    );
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    eyre::ensure!(
        portal.sequencerThreshold().call().await? == 2,
        "Portal threshold is not 2"
    );
    for signer in &cluster.attestation_signers {
        eyre::ensure!(
            portal.isSequencer(signer.address()).call().await?,
            "Portal did not register configured quorum signer {}",
            signer.address()
        );
    }

    let (submitted_height, tx_hash): (U256, B256) = poll_until(
        L1_TIMEOUT,
        Duration::from_millis(200),
        "BatchSubmitted event from two online members of a 2-of-3 quorum",
        || {
            let portal = &portal;
            async move {
                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                let Some((_, log)) = events.first() else {
                    return Ok(None);
                };
                let tx_hash = log
                    .transaction_hash
                    .ok_or_else(|| eyre::eyre!("BatchSubmitted log missing transaction hash"))?;
                Ok(Some((portal.zoneHeight().call().await?, tx_hash)))
            }
        },
    )
    .await?;
    let submitted_height = u64::try_from(submitted_height)
        .map_err(|_| eyre::eyre!("settled zone height does not fit in u64"))?;

    let (call, _) = fetch_submit_batch_call(&cluster.l1, tx_hash).await?;
    eyre::ensure!(
        call.signatures.len() == 2,
        "expected exactly the 2-of-3 threshold signatures, got {}",
        call.signatures.len()
    );
    eyre::ensure!(
        call.signatures[0] != call.signatures[1],
        "submitted certificate contains duplicate signature bytes"
    );
    eyre::ensure!(
        submitted_height > 0,
        "batch submission did not advance the settled zone height"
    );
    cluster.wait_all_at(submitted_height, L1_TIMEOUT).await?;
    cluster.assert_same_block(submitted_height).await?;

    Ok(())
}

/// A follower signs only after it can independently reconstruct the leader's batch statement.
/// Give both followers conflicting Portal queue hashes over the candidate operational-anchor
/// window before the boundary. The other followers are independently prevented from replacing
/// each other's share, so A remains below the 2-of-3 threshold at the configured boundary.
/// Earlier catch-up boundaries may settle normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_divergent_follower_does_not_create_quorum() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    const DIVERGENT_BOUNDARY: u64 = 20;
    const DIVERGENT_ANCHOR_WINDOW: u64 = 64;

    // Leave enough Zone blocks to install the divergent state before the configured boundary.
    let cluster = start_real_p2p_cluster(DIVERGENT_BOUNDARY).await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    // A newly started subscriber initializes its cache from the zone's L1 genesis anchor, not
    // from block zero. Its first non-contiguous coverage update resets the cache, which used to
    // race with the forged entry below and silently erase it. Wait for every member to complete
    // that initial backfill before choosing a future anchor to corrupt. Wait for the block after
    // the current tip because the current tip may be the genesis anchor, which is below the cache
    // coverage floor once the first post-genesis block is ingested.
    let covered_l1_block = cluster.l1.provider().get_block_number().await? + 1;
    for node in &cluster.nodes {
        poll_until(
            L1_TIMEOUT,
            Duration::from_millis(50),
            "initial L1 cache coverage",
            || async {
                Ok(node
                    .l1_state_cache()
                    .lock()
                    .has_coverage_at(covered_l1_block)
                    .then_some(()))
            },
        )
        .await?;
    }

    // Checkpoint-only blocks defer portal work, so a single corrupt height may be skipped before
    // the next full import selects its operational anchor. Corrupt a bounded future window to
    // guarantee that whichever finalized anchor closes the deferred range remains divergent.
    let first_divergent_anchor = cluster.l1.provider().get_block_number().await? + 2;
    let last_divergent_anchor = first_divergent_anchor + DIVERGENT_ANCHOR_WINDOW;
    for (node, queue_hash) in [
        (&cluster.nodes[1], B256::repeat_byte(0xD1)),
        (&cluster.nodes[2], B256::repeat_byte(0xD2)),
    ] {
        let mut cache = node.l1_state_cache().lock();
        for anchor in first_divergent_anchor..=last_divergent_anchor {
            cache.set(
                cluster.portal_address,
                portal::slots::CURRENT_DEPOSIT_QUEUE_HASH.into(),
                anchor,
                queue_hash,
            );
        }
    }

    cluster.nodes[0]
        .wait_for_block_number(DIVERGENT_BOUNDARY, L1_TIMEOUT)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let follower_height = cluster.nodes[1].provider().get_block_number().await?;
    eyre::ensure!(
        follower_height < DIVERGENT_BOUNDARY,
        "divergent follower unexpectedly imported the leader boundary"
    );
    eyre::ensure!(
        portal.zoneHeight().call().await? < U256::from(DIVERGENT_BOUNDARY),
        "leader settled the divergent boundary despite only its own usable signature"
    );

    Ok(())
}

/// Native factory creation permits one operator to hold both independent admin authority and the
/// stored sequencer role.
#[tokio::test(flavor = "multi_thread")]
async fn test_native_factory_allows_admin_as_sequencer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let factory = l1.native_zone_factory().await?;
    let operator = l1.dev_address();
    let portal_address = l1
        .create_zone_with_admin_sequencer_and_config(
            factory,
            operator,
            operator,
            ZoneCreationConfig::open(),
        )
        .await?;
    let portal = ZonePortal::new(portal_address, l1.provider());

    assert_eq!(portal.admin().call().await?, operator);
    assert!(portal.isSequencer(operator).call().await?);
    assert!(
        portal
            .hasRole(operator, PortalRole::Sequencer)
            .call()
            .await?
    );
    Ok(())
}

/// The dev provisioner anchors immediately before `createZone`, so the zone
/// replays the creation block and initializes a custom initial token from the
/// portal constructor's `TokenEnabled` event.
#[tokio::test(flavor = "multi_thread")]
// TODO(TIP-1091): Re-enable with a stock T9 dev chain and supply the factory-owner signer
// separately from the portal admin/sequencer signer.
#[ignore = "TODO(TIP-1091): cover stock T9 factory-owner provisioning"]
async fn test_dev_provisioner_replays_initial_token_event() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let initial_token = l1
        .create_tip20("DevUSD", "dUSD", B256::with_last_byte(0xD0))
        .await?;
    let provisioned = provision_zone(ProvisionConfig {
        l1_rpc_url: l1.ws_url().to_string(),
        dev_key: l1.dev_signer(),
        factory: None,
        initial_token,
        is_access_open: false,
        is_gateway_enforced: true,
        zone_gateways: vec![Address::repeat_byte(0x42)],
        allowed_accounts: vec![l1.user_signer().address()],
        rpc_url: String::new(),
    })
    .await?;

    let latest_l1_block = l1.provider().get_block_number().await?;
    assert!(latest_l1_block > provisioned.anchor_block_number);

    let zone = ZoneTestNode::start_from_l1_at_block(
        l1.http_url(),
        l1.ws_url(),
        provisioned.portal,
        provisioned.anchor_block_number,
    )
    .await?;
    zone.wait_for_l2_tempo_finalized(latest_l1_block, L1_TIMEOUT)
        .await?;

    let code = zone.provider().get_code_at(initial_token).await?;
    assert!(
        !code.is_empty(),
        "custom initial token should be initialized from TokenEnabled"
    );

    Ok(())
}

/// Full deposit + withdrawal flow with a real L1:
/// 1. Start L1 dev node.
/// 2. Create a zone through the native ZoneFactory (installs ZonePortal).
/// 3. Start zone node connected to L1 with the portal address.
/// 4. Deposit pathUSD on the ZonePortal to the dev account.
/// 5. Verify the zone mints the corresponding pathUSD balance on L2.
/// 6. Spawn zone sequencer background tasks (batch submitter + withdrawal processor).
/// 7. Request a withdrawal on L2 (approve + requestWithdrawal on ZoneOutbox).
/// 8. Wait for the batch to be submitted and the withdrawal to be processed on L1.
///
/// NOTE: This test requires the Foundry-compiled shared runtime artifacts.
/// Run `forge build` in `crates/contracts/` first.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_via_real_l1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start real Tempo L1 in dev mode (500ms block time)
    let l1 = L1TestNode::start().await?;

    // Deploy L1 infrastructure and create a zone
    let portal_address = l1.deploy_zone().await?;

    // Start zone node connected to L1 with the real portal
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    // Wait for the zone to advance past genesis
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // --- Deposit + withdrawal via ZoneAccount ---

    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD (6 decimals)

    // Fund the user account on L1 (separate from the sequencer/dev account)
    l1.fund_user(account.address(), deposit_amount * 2).await?;

    // Verify recipient starts with zero on L2
    let balance_before = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    assert_eq!(
        balance_before,
        U256::ZERO,
        "recipient should start with zero on L2"
    );

    // Deposit on L1, wait for mint on L2
    let minted_balance = account.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;
    assert_eq!(
        minted_balance,
        U256::from(deposit_amount),
        "minted balance should equal deposit amount (fee=0)"
    );

    // Spawn zone sequencer (batch submitter + withdrawal processor)
    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;

    // Request withdrawal on L2
    let withdrawal_amount: u128 = 500_000; // 0.5 pathUSD
    let l1_balance_before = l1.balance_of(PATH_USD_ADDRESS, account.address()).await?;
    account.withdraw(withdrawal_amount).await?;

    // Wait for the withdrawal to be fully processed on L1
    let withdrawal_timeout = std::time::Duration::from_secs(60);
    l1.wait_for_withdrawal_on_l1(
        portal_address,
        account.address(),
        l1_balance_before,
        withdrawal_amount,
        withdrawal_timeout,
    )
    .await?;

    // Verify the L2 balance decreased by at least the withdrawal amount
    let l2_balance_after = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    assert!(
        l2_balance_after <= U256::from(deposit_amount - withdrawal_amount),
        "L2 balance should decrease by at least the withdrawal amount (got {l2_balance_after})"
    );

    Ok(())
}

/// Deposit to enough independent accounts to force several gas-bounded withdrawal transactions,
/// then submit the accounts concurrently, including repeated withdrawals from half of them.
///
/// The processed events prove that withdrawals were both packed together and drained through
/// more transactions than the configured in-flight window can hold at once.
#[tokio::test(flavor = "multi_thread")]
async fn test_many_concurrent_withdrawals_are_batched() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    const ACCOUNT_COUNT: u32 = 16;
    const REPEATED_ACCOUNT_COUNT: usize = ACCOUNT_COUNT as usize / 2;
    const WITHDRAWALS_PER_REPEATED_ACCOUNT: usize = 3;
    const WITHDRAWAL_COUNT: usize =
        ACCOUNT_COUNT as usize + REPEATED_ACCOUNT_COUNT * (WITHDRAWALS_PER_REPEATED_ACCOUNT - 1);
    const MAX_WITHDRAWALS_PER_BATCH: usize = 2;
    const TEST_MAX_BATCH_GAS: u64 = 2_500_000;
    const TEST_MAX_IN_FLIGHT_BATCHES: usize = 2;
    const FIRST_ACCOUNT_INDEX: u32 = 3;
    const DEPOSIT_AMOUNT: u128 = 2_000_000;
    const WITHDRAWAL_AMOUNT: u128 = 250_000;
    const WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(120);

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let signers = (FIRST_ACCOUNT_INDEX..FIRST_ACCOUNT_INDEX + ACCOUNT_COUNT)
        .map(|index| l1.signer_at(index))
        .collect::<Vec<_>>();
    let recipients = signers
        .iter()
        .map(|signer| signer.address())
        .collect::<Vec<_>>();

    // This test exercises withdrawal batching, not access control. Opening the portal avoids one
    // L1 allowlist transaction per recipient.
    l1.set_access_mode_on_portal(portal_address, false).await?;

    // A single funded depositor keeps L1 setup deterministic while still exercising deposits to
    // many distinct zone accounts.
    let mut depositor = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let total_deposit = DEPOSIT_AMOUNT * u128::from(ACCOUNT_COUNT);
    l1.fund_user(depositor.address(), total_deposit * 2).await?;
    for recipient in &recipients {
        depositor
            .deposit_to(*recipient, DEPOSIT_AMOUNT, L1_TIMEOUT, &zone)
            .await?;
    }

    let mut accounts = signers
        .into_iter()
        .map(|signer| ZoneAccount::with_signer(signer, &l1, &zone, portal_address))
        .collect::<Vec<_>>();
    // Start the sequencer only after L1 setup so its shared signer cannot race the funding and
    // deposit transactions.
    let sequencer = spawn_sequencer_with_config(
        &l1,
        &zone,
        portal_address,
        l1.dev_signer(),
        zone_sequencer::BatchAnchorConfig::default(),
        zone_sequencer::WithdrawalBatchLimits {
            max_batch_gas: TEST_MAX_BATCH_GAS,
            max_in_flight_batches: TEST_MAX_IN_FLIGHT_BATCHES,
        },
    )
    .await;
    let withdrawal_start_block = l1.provider().get_block_number().await?;

    try_join_all(
        accounts
            .iter_mut()
            .enumerate()
            .map(|(index, account)| async move {
                let count = if index < REPEATED_ACCOUNT_COUNT {
                    WITHDRAWALS_PER_REPEATED_ACCOUNT
                } else {
                    1
                };
                for _ in 0..count {
                    account.withdraw(WITHDRAWAL_AMOUNT).await?;
                }
                Ok::<(), eyre::Report>(())
            }),
    )
    .await?;

    let portal = ZonePortal::new(portal_address, l1.provider());
    let processed = poll_until(
        WITHDRAWAL_TIMEOUT,
        Duration::from_millis(250),
        "all concurrent withdrawals to be processed on L1",
        || {
            let portal = &portal;
            let sequencer = &sequencer;
            async move {
                eyre::ensure!(
                    !sequencer.monitor_handle.is_finished(),
                    "zone monitor exited while processing concurrent withdrawals"
                );
                eyre::ensure!(
                    !sequencer.withdrawal_handle.is_finished(),
                    "withdrawal processor exited while processing concurrent withdrawals"
                );

                let events = portal
                    .WithdrawalProcessed_filter()
                    .from_block(withdrawal_start_block)
                    .query()
                    .await?;
                if events.len() < WITHDRAWAL_COUNT {
                    return Ok(None);
                }

                Ok(Some(events))
            }
        },
    )
    .await?;

    assert_eq!(
        processed.len(),
        WITHDRAWAL_COUNT,
        "each requested withdrawal should be processed exactly once"
    );

    let mut withdrawals_per_recipient = HashMap::with_capacity(ACCOUNT_COUNT as usize);
    let mut withdrawals_per_transaction = HashMap::new();

    for (event, log) in processed {
        assert_eq!(event.token, PATH_USD_ADDRESS);
        assert_eq!(event.amount, WITHDRAWAL_AMOUNT);
        assert!(event.callbackSuccess, "simple withdrawal should succeed");
        *withdrawals_per_recipient.entry(event.to).or_insert(0usize) += 1;

        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| eyre::eyre!("WithdrawalProcessed log missing transaction hash"))?;
        *withdrawals_per_transaction.entry(tx_hash).or_insert(0usize) += 1;
    }

    for (index, recipient) in recipients.iter().enumerate() {
        let expected = if index < REPEATED_ACCOUNT_COUNT {
            WITHDRAWALS_PER_REPEATED_ACCOUNT
        } else {
            1
        };
        assert_eq!(withdrawals_per_recipient.get(recipient), Some(&expected));
    }

    let zone_provider = zone.provider();
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &zone_provider);
    let finalized_batches = outbox.BatchFinalized_filter().from_block(0).query().await?;
    let mut slot_sizes = Vec::new();
    for (_, log) in finalized_batches {
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| eyre::eyre!("BatchFinalized log missing transaction hash"))?;
        let tx = zone_provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("finalizeWithdrawalBatch tx {tx_hash} not found"))?;
        let call = IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(tx.input().as_ref())?;
        slot_sizes.push(call.count.to::<usize>());
    }
    assert_eq!(
        slot_sizes.iter().sum::<usize>(),
        WITHDRAWAL_COUNT,
        "finalized slots should contain every requested withdrawal"
    );
    let largest_slot = slot_sizes.iter().copied().max().unwrap_or_default();
    assert!(
        largest_slot.div_ceil(MAX_WITHDRAWALS_PER_BATCH) > TEST_MAX_IN_FLIGHT_BATCHES,
        "at least one queue slot must require refilling the in-flight window"
    );

    assert!(
        withdrawals_per_transaction.values().any(|count| *count > 1),
        "at least one processWithdrawals transaction should contain multiple withdrawals"
    );
    assert!(
        withdrawals_per_transaction
            .values()
            .all(|count| *count <= MAX_WITHDRAWALS_PER_BATCH),
        "the configured gas limit should cap each transaction at two withdrawals"
    );
    let expected_transaction_count = slot_sizes
        .iter()
        .map(|count| count.div_ceil(MAX_WITHDRAWALS_PER_BATCH))
        .sum::<usize>();
    assert_eq!(
        withdrawals_per_transaction.len(),
        expected_transaction_count,
        "every finalized slot should be split into gas-bounded transactions"
    );
    let head_call = portal.withdrawalQueueHead();
    let tail_call = portal.withdrawalQueueTail();
    let (head, tail) = tokio::try_join!(head_call.call(), tail_call.call())?;
    assert_eq!(head, tail, "withdrawal queue should be fully drained");

    Ok(())
}

/// An open zone has no account allowlist: an unlisted account can complete the full
/// L1 deposit -> L2 mint -> L2 withdrawal -> L1 release loop.
#[tokio::test(flavor = "multi_thread")]
async fn test_open_mode_unlisted_account_roundtrip() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let factory = l1.native_zone_factory().await?;
    let portal_address = l1
        .create_zone_with_admin_sequencer_and_config(
            factory,
            l1.admin_address(),
            l1.dev_address(),
            ZoneCreationConfig::open_with_enforced_gateways(),
        )
        .await?;
    let encryption_key = k256::SecretKey::from(l1.dev_signer().credential());
    l1.set_sequencer_encryption_key(portal_address, &encryption_key)
        .await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let portal = ZonePortal::new(portal_address, l1.provider());
    let account_address = l1.user_signer().address();
    assert!(!portal.isAccessEnforced().call().await?);
    assert!(
        portal
            .hasRole(account_address, PortalRole::None)
            .call()
            .await?
    );
    zone.assert_access_enforced(false).await?;

    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount = 2_000_000u128;
    let withdrawal_amount = 400_000u128;
    l1.fund_user(account.address(), deposit_amount * 2).await?;
    account.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;

    // A second arbitrary account can also deposit without a membership update.
    let second_signer = l1.signer_at(3);
    let mut second_account =
        ZoneAccount::with_signer(second_signer.clone(), &l1, &zone, portal_address);
    l1.fund_user(second_signer.address(), 500_000).await?;
    second_account.deposit(200_000, L1_TIMEOUT, &zone).await?;

    // The encrypted recipient is also arbitrary; only the depositor/refund address is public.
    let encrypted_recipient = l1.signer_at(4).address();
    account
        .deposit_with_memo(300_000, encrypted_recipient, B256::ZERO, L1_TIMEOUT, &zone)
        .await?;

    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let arbitrary_l1_recipient = l1.signer_at(5).address();
    let mut withdrawal = WithdrawalArgs::new(withdrawal_amount);
    withdrawal.to = Some(arbitrary_l1_recipient);
    let l1_balance_before = l1
        .balance_of(PATH_USD_ADDRESS, arbitrary_l1_recipient)
        .await?;
    account.withdraw_with(withdrawal).await?;
    l1.wait_for_withdrawal_on_l1(
        portal_address,
        arbitrary_l1_recipient,
        l1_balance_before,
        withdrawal_amount,
        Duration::from_secs(60),
    )
    .await?;

    // Open mode does not weaken callback target validation.
    let router = l1.deploy_router(factory).await?;
    let unregistered = WithdrawalArgs::cross_zone_via_router(
        &l1,
        100_000,
        router,
        portal_address,
        PATH_USD_ADDRESS,
        account.address(),
        account.address(),
    )
    .await?;
    assert!(
        account.simulate_withdraw_with(unregistered).await.is_err(),
        "open mode accepted an unregistered callback target"
    );

    let gateway_block = l1
        .set_zone_gateway_on_portal(portal_address, router, true)
        .await?;
    zone.wait_for_l2_tempo_finalized(gateway_block, L1_TIMEOUT)
        .await?;
    zone.assert_zone_gateway(router, true).await?;

    let callback_amount = 150_000u128;
    let balance_before_callback = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    let callback = WithdrawalArgs::cross_zone_via_router(
        &l1,
        callback_amount,
        router,
        portal_address,
        PATH_USD_ADDRESS,
        account.address(),
        account.address(),
    )
    .await?;
    account.withdraw_with(callback).await?;
    let balance_after_callback_request = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    eyre::ensure!(
        balance_after_callback_request + U256::from(callback_amount) <= balance_before_callback,
        "callback request did not burn its withdrawal amount"
    );
    let callback_succeeded = l1
        .wait_for_withdrawal_processed_status(
            portal_address,
            router,
            PATH_USD_ADDRESS,
            callback_amount,
            Duration::from_secs(60),
        )
        .await?;
    eyre::ensure!(
        callback_succeeded,
        "registered open-zone router callback was processed as a failure"
    );
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        account.address(),
        balance_after_callback_request + U256::from(callback_amount),
        Duration::from_secs(60),
    )
    .await?;
    l1.assert_withdrawal_processed_with_status(
        portal_address,
        router,
        PATH_USD_ADDRESS,
        callback_amount,
        true,
    )
    .await?;

    Ok(())
}

/// Closed mode enforces the exact configured set for the deposit caller/refund recipient
/// and for a plain withdrawal recipient.
#[tokio::test(flavor = "multi_thread")]
async fn test_closed_mode_rejects_unlisted_deposit_and_withdrawal_recipient() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone.assert_access_enforced(true).await?;

    let outsider_signer = l1.signer_at(3);
    let outsider = outsider_signer.address();
    let portal = ZonePortal::new(portal_address, l1.provider());
    assert!(portal.hasRole(outsider, PortalRole::None).call().await?);

    let mut outsider_account =
        ZoneAccount::with_signer(outsider_signer, &l1, &zone, portal_address);
    l1.fund_user(outsider, 1_000_000).await?;
    assert!(
        outsider_account
            .simulate_deposit(500_000, outsider, outsider)
            .await
            .is_err(),
        "closed zone accepted an unlisted deposit caller/refund recipient"
    );

    let mut allowed_account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(allowed_account.address(), 1_000_000).await?;

    {
        use tempo_contracts::precompiles::ITIP20;
        let provider = l1.provider_with_signer(l1.user_signer());
        ITIP20::new(PATH_USD_ADDRESS, &provider)
            .approve(portal_address, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;
        let portal = ZonePortal::new(portal_address, &provider);
        let (key_index, encrypted) = l1
            .encrypt_deposit_for_portal(
                portal_address,
                l1.user_signer().address(),
                allowed_account.address(),
                B256::ZERO,
            )
            .await?;
        assert!(
            portal
                .deposit(PATH_USD_ADDRESS, 100_000, key_index, encrypted, outsider,)
                .call()
                .await
                .is_err(),
            "closed zone accepted an unlisted Tempo refund recipient"
        );
    }

    let add_block = l1
        .set_allowed_account_on_portal(portal_address, outsider, true)
        .await?;
    zone.wait_for_l2_tempo_finalized(add_block, L1_TIMEOUT)
        .await?;
    zone.assert_allowed_account(outsider, true).await?;
    outsider_account.deposit(500_000, L1_TIMEOUT, &zone).await?;

    let remove_block = l1
        .set_allowed_account_on_portal(portal_address, outsider, false)
        .await?;
    zone.wait_for_l2_tempo_finalized(remove_block, L1_TIMEOUT)
        .await?;
    zone.assert_allowed_account(outsider, false).await?;
    assert!(
        outsider_account
            .simulate_deposit(100_000, outsider, outsider)
            .await
            .is_err(),
        "closed zone accepted a new deposit after membership removal"
    );

    allowed_account.deposit(500_000, L1_TIMEOUT, &zone).await?;
    let mut args = WithdrawalArgs::new(100_000);
    args.to = Some(outsider);
    assert!(
        allowed_account.simulate_withdraw_with(args).await.is_err(),
        "closed zone accepted an unlisted plain withdrawal recipient"
    );

    Ok(())
}

/// Account and gateway enforcement can be changed independently without rewriting either set.
#[tokio::test(flavor = "multi_thread")]
async fn test_access_and_gateway_modes_are_mutable_and_independent() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let factory = l1.native_zone_factory().await?;
    let portal_address = l1.create_zone(factory).await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone.assert_access_enforced(true).await?;
    zone.assert_gateway_open(false).await?;

    let outsider_signer = l1.signer_at(3);
    let outsider = outsider_signer.address();
    let mut outsider_account =
        ZoneAccount::with_signer(outsider_signer, &l1, &zone, portal_address);
    l1.fund_user(outsider, 10_000_000).await?;
    assert!(
        outsider_account
            .simulate_deposit(5_000_000, outsider, outsider)
            .await
            .is_err(),
        "closed access accepted an unlisted depositor"
    );

    let open_access_block = l1.set_access_mode_on_portal(portal_address, false).await?;
    zone.wait_for_l2_tempo_finalized(open_access_block, L1_TIMEOUT)
        .await?;
    zone.assert_access_enforced(false).await?;
    zone.assert_allowed_account(outsider, true).await?;
    outsider_account
        .deposit(5_000_000, L1_TIMEOUT, &zone)
        .await?;

    let router = l1.deploy_router(factory).await?;
    let callback = WithdrawalArgs::cross_zone_via_router(
        &l1,
        100_000,
        router,
        portal_address,
        PATH_USD_ADDRESS,
        outsider,
        outsider,
    )
    .await?;
    assert!(
        outsider_account
            .simulate_withdraw_with(callback.clone())
            .await
            .is_err(),
        "open account access disabled gateway registration enforcement"
    );

    let open_gateway_block = l1.set_gateway_mode_on_portal(portal_address, false).await?;
    zone.wait_for_l2_tempo_finalized(open_gateway_block, L1_TIMEOUT)
        .await?;
    zone.assert_gateway_open(true).await?;
    outsider_account
        .withdraw_with(callback.clone())
        .await
        .wrap_err("callback should pass after opening gateway mode")?;

    let closed_access_block = l1.set_access_mode_on_portal(portal_address, true).await?;
    zone.wait_for_l2_tempo_finalized(closed_access_block, L1_TIMEOUT)
        .await?;
    zone.assert_access_enforced(true).await?;
    assert!(
        outsider_account
            .simulate_deposit(100_000, outsider, outsider)
            .await
            .is_err(),
        "re-closed access did not restore account allowlist enforcement"
    );
    outsider_account
        .withdraw_with(callback.clone())
        .await
        .wrap_err("callback should still pass after reclosing account access")?;

    let enforced_gateway_block = l1.set_gateway_mode_on_portal(portal_address, true).await?;
    zone.wait_for_l2_tempo_finalized(enforced_gateway_block, L1_TIMEOUT)
        .await?;
    assert!(
        outsider_account
            .simulate_withdraw_with(callback)
            .await
            .is_err(),
        "re-enabled gateway enforcement accepted an unregistered callback target"
    );

    Ok(())
}

/// A plain withdrawal accepted while its recipient is allowed must still drain after
/// that recipient is revoked. It bounces to the private fallback recipient and does
/// not block the next valid withdrawal in the FIFO.
#[tokio::test(flavor = "multi_thread")]
async fn test_queued_plain_withdrawal_bounces_after_recipient_revocation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let revoked_recipient = account.address();
    let trailing_recipient = l1.admin_address();
    let deposit_amount = 700_000u128;
    let bounced_amount = 200_000u128;
    let trailing_amount = 100_000u128;
    l1.fund_user(account.address(), deposit_amount).await?;
    account.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;

    account.withdraw(bounced_amount).await?;
    let mut trailing = WithdrawalArgs::new(trailing_amount);
    trailing.to = Some(trailing_recipient);
    account.withdraw_with(trailing).await?;
    let balance_after_queue = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    let trailing_l1_before = l1.balance_of(PATH_USD_ADDRESS, trailing_recipient).await?;

    let revocation_block = l1
        .set_allowed_account_on_portal(portal_address, revoked_recipient, false)
        .await?;
    zone.wait_for_l2_tempo_finalized(revocation_block, L1_TIMEOUT)
        .await?;
    zone.assert_allowed_account(revoked_recipient, false)
        .await?;

    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        account.address(),
        balance_after_queue + U256::from(bounced_amount),
        Duration::from_secs(60),
    )
    .await?;
    l1.wait_for_balance(
        PATH_USD_ADDRESS,
        trailing_recipient,
        trailing_l1_before + U256::from(trailing_amount),
        Duration::from_secs(60),
    )
    .await?;
    l1.assert_withdrawals_processed_in_order(
        portal_address,
        &[
            (revoked_recipient, PATH_USD_ADDRESS, bounced_amount, false),
            (trailing_recipient, PATH_USD_ADDRESS, trailing_amount, true),
        ],
    )
    .await?;

    Ok(())
}

/// A callback accepted while its target is registered must still drain if the
/// gateway is revoked before L1 processing. The callback bounces, and the next
/// plain withdrawal proves the failed head did not block the FIFO.
#[tokio::test(flavor = "multi_thread")]
async fn test_queued_callback_bounces_after_gateway_revocation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut fixture = setup_same_zone_swap_fixture().await?;
    let callback_amount = 200_000u128;
    let trailing_amount = 100_000u128;
    let trailing_recipient = fixture.l1.admin_address();

    let callback = WithdrawalArgs::cross_zone_via_router(
        &fixture.l1,
        callback_amount,
        fixture.router,
        fixture.portal_address,
        PATH_USD_ADDRESS,
        fixture.account.address(),
        fixture.account.address(),
    )
    .await?;
    fixture.account.withdraw_with(callback).await?;
    let mut trailing = WithdrawalArgs::new(trailing_amount);
    trailing.to = Some(trailing_recipient);
    fixture.account.withdraw_with(trailing).await?;
    let balance_after_queue = fixture
        .zone
        .balance_of(ZONE_TOKEN_ADDRESS, fixture.account.address())
        .await?;
    let trailing_l1_before = fixture
        .l1
        .balance_of(PATH_USD_ADDRESS, trailing_recipient)
        .await?;

    let revocation_block = fixture
        .l1
        .set_zone_gateway_on_portal(fixture.portal_address, fixture.router, false)
        .await?;
    fixture
        .zone
        .wait_for_l2_tempo_finalized(revocation_block, L1_TIMEOUT)
        .await?;
    fixture
        .zone
        .assert_zone_gateway(fixture.router, false)
        .await?;

    let _sequencer = spawn_sequencer(
        &fixture.l1,
        &fixture.zone,
        fixture.portal_address,
        fixture.l1.dev_signer(),
    )
    .await;
    fixture
        .zone
        .wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            fixture.account.address(),
            balance_after_queue + U256::from(callback_amount),
            Duration::from_secs(60),
        )
        .await?;
    fixture
        .l1
        .wait_for_balance(
            PATH_USD_ADDRESS,
            trailing_recipient,
            trailing_l1_before + U256::from(trailing_amount),
            Duration::from_secs(60),
        )
        .await?;
    fixture
        .l1
        .assert_withdrawals_processed_in_order(
            fixture.portal_address,
            &[
                (fixture.router, PATH_USD_ADDRESS, callback_amount, false),
                (trailing_recipient, PATH_USD_ADDRESS, trailing_amount, true),
            ],
        )
        .await?;

    Ok(())
}

/// Cross-zone withdrawal via the SwapAndDepositRouter:
///
///  1. Start L1 dev node.
///  2. Create zone_a and zone_b through the native factory, then deploy SwapAndDepositRouter.
///  3. Start both zone nodes connected to L1.
///  4. Deposit pathUSD into zone_a.
///  5. Withdraw from zone_a with a callback that deposits into zone_b via the router.
///  6. Verify the deposit arrives on zone_b.
///  7. Withdraw from zone_b with a callback that deposits into zone_a via the router.
///  8. Verify the deposit arrives on zone_a.
///
/// ```text
///  Zone A          L1 (Router)          Zone B
///    |--- withdraw 0.4 -->|                |
///    |                    |-- deposit 0.4 ->|
///    |                    |                 |
///    |                    |<- withdraw 0.2 -|
///    |<-- deposit 0.2 ----|                 |
/// ```
///
/// NOTE: Requires `forge build` in `crates/contracts/` for shared runtime and router artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_cross_zone_withdrawal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;

    // Separate sequencer keys for each zone to avoid L1 nonce conflicts
    let seq_a_signer = l1.signer_at(2);
    let seq_b_signer = l1.signer_at(3);

    // --- Step 2: Deploy L1 infrastructure (factory, two portals, router) ---
    let (portal_a, portal_b, router) = l1
        .deploy_two_open_zones_with_sequencers(seq_a_signer.clone(), seq_b_signer.clone())
        .await?;

    // --- Step 3: Start both zone nodes ---
    let zone_a = ZoneTestNode::start_from_l1_with_decryption_keys(
        l1.http_url(),
        l1.ws_url(),
        portal_a,
        vec![k256::SecretKey::from(seq_a_signer.credential())],
    )
    .await?;
    let zone_b = ZoneTestNode::start_from_l1_with_decryption_keys(
        l1.http_url(),
        l1.ws_url(),
        portal_b,
        vec![k256::SecretKey::from(seq_b_signer.credential())],
    )
    .await?;

    zone_a.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone_b.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone_a.assert_access_enforced(false).await?;
    zone_b.assert_access_enforced(false).await?;
    zone_a.assert_gateway_open(true).await?;
    zone_b.assert_gateway_open(true).await?;

    // --- Step 4: Deposit into zone_a ---
    let mut account_a = ZoneAccount::from_l1_and_zone(&l1, &zone_a, portal_a);
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD
    l1.fund_user(account_a.address(), deposit_amount * 2)
        .await?;
    account_a
        .deposit(deposit_amount, L1_TIMEOUT, &zone_a)
        .await?;

    // Spawn sequencers for both zones
    let _seq_a = spawn_sequencer(&l1, &zone_a, portal_a, seq_a_signer.clone()).await;
    let _seq_b = spawn_sequencer(&l1, &zone_b, portal_b, seq_b_signer.clone()).await;

    // --- Step 5: Cross-zone withdrawal: zone_a → router → zone_b ---
    let cross_amount: u128 = 400_000; // 0.4 pathUSD
    let args_a_to_b = WithdrawalArgs::cross_zone_via_router(
        &l1,
        cross_amount,
        router,
        portal_b,
        PATH_USD_ADDRESS,
        account_a.address(),
        account_a.address(),
    )
    .await?;
    account_a.withdraw_with(args_a_to_b).await?;

    // --- Step 6: Verify deposit arrives on zone_b ---
    let cross_timeout = std::time::Duration::from_secs(60);
    zone_b
        .wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            account_a.address(),
            U256::from(cross_amount),
            cross_timeout,
        )
        .await?;

    let zone_b_balance = zone_b
        .balance_of(ZONE_TOKEN_ADDRESS, account_a.address())
        .await?;
    assert_eq!(
        zone_b_balance,
        U256::from(cross_amount),
        "zone_b should have received the cross-zone deposit"
    );

    // zone_a balance should have decreased
    let zone_a_balance = zone_a
        .balance_of(ZONE_TOKEN_ADDRESS, account_a.address())
        .await?;
    assert!(
        zone_a_balance <= U256::from(deposit_amount - cross_amount),
        "zone_a balance should decrease by at least the cross-zone amount (got {zone_a_balance})"
    );

    // --- Step 7: Cross-zone withdrawal: zone_b → router → zone_a ---
    let mut account_b = ZoneAccount::from_l1_and_zone(&l1, &zone_b, portal_b);
    let reverse_amount: u128 = 200_000; // 0.2 pathUSD
    let args_b_to_a = WithdrawalArgs::cross_zone_via_router(
        &l1,
        reverse_amount,
        router,
        portal_a,
        PATH_USD_ADDRESS,
        account_b.address(),
        account_b.address(),
    )
    .await?;
    account_b.withdraw_with(args_b_to_a).await?;

    // --- Step 8: Verify deposit arrives on zone_a ---
    zone_a
        .wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            account_b.address(),
            zone_a_balance,
            cross_timeout,
        )
        .await?;

    let final_zone_a = zone_a
        .balance_of(ZONE_TOKEN_ADDRESS, account_b.address())
        .await?;
    assert!(
        final_zone_a > U256::ZERO,
        "zone_a should have received the reverse cross-zone deposit (got {final_zone_a})"
    );

    // zone_b balance should have decreased
    let final_zone_b = zone_b
        .balance_of(ZONE_TOKEN_ADDRESS, account_b.address())
        .await?;
    assert!(
        final_zone_b < U256::from(cross_amount),
        "zone_b balance should decrease by at least the reverse amount (got {final_zone_b})"
    );

    Ok(())
}

/// Cross-zone encrypted router deposit where Zone B accepts the L1 deposit but
/// later bounces it because the decrypted recipient violates policy.
///
/// The refund must go to the Tempo refund recipient encoded in the router payload,
/// not to the encrypted recipient and not to the router contract.
#[tokio::test(flavor = "multi_thread")]
async fn test_cross_zone_router_tempo_refund_recipient() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let seq_a_signer = l1.signer_at(2);
    let seq_b_signer = l1.signer_at(3);
    let blacklisted_recipient = l1.signer_at(4).address();
    let refund_burner = l1.signer_at(5).address();

    let (portal_a, portal_b, router) = l1
        .deploy_two_open_zones_with_sequencers(seq_a_signer.clone(), seq_b_signer.clone())
        .await?;

    let policy_id = l1.create_blacklist_policy().await?;
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, policy_id)
        .await?;
    l1.blacklist_address(policy_id, blacklisted_recipient)
        .await?;
    assert!(
        !l1.is_authorized(policy_id, blacklisted_recipient).await?,
        "recipient should be blacklisted on L1"
    );

    let zone_a = ZoneTestNode::start_from_l1_with_decryption_keys(
        l1.http_url(),
        l1.ws_url(),
        portal_a,
        vec![k256::SecretKey::from(seq_a_signer.credential())],
    )
    .await?;
    let encryption_key = k256::SecretKey::from(seq_b_signer.credential());
    let zone_b = ZoneTestNode::start_from_l1_with_decryption_keys(
        l1.http_url(),
        l1.ws_url(),
        portal_b,
        vec![encryption_key],
    )
    .await?;

    zone_a.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone_b.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone_a.assert_access_enforced(false).await?;
    zone_b.assert_access_enforced(false).await?;
    zone_a.assert_gateway_open(true).await?;
    zone_b.assert_gateway_open(true).await?;

    let mut alice = ZoneAccount::from_l1_and_zone(&l1, &zone_a, portal_a);
    let deposit_amount: u128 = 2_000_000;
    let cross_amount: u128 = 1_000_000;
    l1.fund_user(alice.address(), deposit_amount * 2).await?;
    alice.deposit(deposit_amount, L1_TIMEOUT, &zone_a).await?;

    let _seq_a = spawn_sequencer(&l1, &zone_a, portal_a, seq_a_signer.clone()).await;
    let _seq_b = spawn_sequencer(&l1, &zone_b, portal_b, seq_b_signer.clone()).await;

    let (key_index, encrypted) = l1
        .encrypt_deposit_for_portal(portal_b, router, blacklisted_recipient, B256::ZERO)
        .await?;

    let refund_before = l1.balance_of(PATH_USD_ADDRESS, refund_burner).await?;
    let router_before = l1.balance_of(PATH_USD_ADDRESS, router).await?;

    let args = WithdrawalArgs::swap_and_deposit_via_router_callback(RouterCallbackArgs {
        amount: cross_amount,
        router,
        token_out: PATH_USD_ADDRESS,
        target_portal: portal_b,
        key_index,
        encrypted,
        tempo_refund_recipient: refund_burner,
        min_amount_out: 0,
    });
    alice.withdraw_with(args).await?;

    let refund_after = l1
        .wait_for_balance(
            PATH_USD_ADDRESS,
            refund_burner,
            refund_before + U256::ONE,
            Duration::from_secs(90),
        )
        .await?;
    assert!(
        refund_after > refund_before,
        "refund burner should receive the Zone B deposit bounce-back"
    );

    let router_after = l1.balance_of(PATH_USD_ADDRESS, router).await?;
    assert_eq!(
        router_after, router_before,
        "router should not retain the bounced encrypted deposit refund"
    );

    let recipient_balance = zone_b
        .balance_of(ZONE_TOKEN_ADDRESS, blacklisted_recipient)
        .await?;
    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "blacklisted recipient should not be minted on Zone B"
    );

    l1.assert_withdrawal_processed_with_status(
        portal_a,
        router,
        PATH_USD_ADDRESS,
        cross_amount,
        true,
    )
    .await?;

    Ok(())
}

/// Same-zone routed withdrawal that takes the real swap branch:
///
///  1. Deposit AlphaUSD into the zone.
///  2. Withdraw AlphaUSD to the router.
///  3. Swap AlphaUSD -> BetaUSD via the real StablecoinDEX.
///  4. Deposit BetaUSD back into the same zone.
///  5. Verify AlphaUSD was consumed and BetaUSD was minted.
#[tokio::test(flavor = "multi_thread")]
async fn test_swap_and_deposit_into_same_zone() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut fixture = setup_same_zone_swap_fixture().await?;
    let expected_beta = fixture
        .l1
        .quote_dex_swap_exact_amount_in(fixture.alpha, fixture.beta, fixture.swap_amount)
        .await?;

    let beta_before = fixture
        .zone
        .balance_of(fixture.beta, fixture.account.address())
        .await?;
    assert_eq!(
        beta_before,
        U256::ZERO,
        "recipient should start with zero BetaUSD on the zone"
    );

    let _sequencer = spawn_sequencer(
        &fixture.l1,
        &fixture.zone,
        fixture.portal_address,
        fixture.l1.dev_signer(),
    )
    .await;

    let args = WithdrawalArgs::swap_and_deposit_via_router(
        &fixture.l1,
        RouterDepositArgs {
            amount: fixture.swap_amount,
            router: fixture.router,
            token_out: fixture.beta,
            target_portal: fixture.portal_address,
            recipient: fixture.account.address(),
            tempo_refund_recipient: fixture.account.address(),
            memo: B256::ZERO,
            min_amount_out: expected_beta,
        },
    )
    .await?;
    fixture
        .account
        .withdraw_token_with(fixture.alpha, args)
        .await?;

    let alpha_after_request = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after_request,
        U256::ZERO,
        "AlphaUSD should be burned on withdrawal before the routed deposit lands"
    );

    let timeout = Duration::from_secs(60);
    fixture
        .zone
        .wait_for_balance(
            fixture.beta,
            fixture.account.address(),
            U256::from(expected_beta),
            timeout,
        )
        .await?;

    let beta_after = fixture
        .zone
        .balance_of(fixture.beta, fixture.account.address())
        .await?;
    assert_eq!(
        beta_after,
        U256::from(expected_beta),
        "BetaUSD minted on the zone should match the routed swap quote"
    );

    let alpha_after = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after,
        U256::ZERO,
        "AlphaUSD should not be bounced back on a successful routed swap"
    );

    fixture
        .l1
        .assert_withdrawal_processed_with_status(
            fixture.portal_address,
            fixture.router,
            fixture.alpha,
            fixture.swap_amount,
            true,
        )
        .await?;

    Ok(())
}

/// Same-zone routed withdrawal where the downstream encrypted deposit fails.
///
/// Deposits for BetaUSD are paused on the target portal so the router callback
/// reverts and the original AlphaUSD withdrawal bounces back to the sender.
#[tokio::test(flavor = "multi_thread")]
async fn test_swap_and_deposit_into_same_zone_bounces_back_when_target_deposits_paused()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut fixture = setup_same_zone_swap_fixture().await?;
    let expected_beta = fixture
        .l1
        .quote_dex_swap_exact_amount_in(fixture.alpha, fixture.beta, fixture.swap_amount)
        .await?;

    fixture
        .l1
        .pause_deposits_on_portal(fixture.portal_address, fixture.beta)
        .await?;

    let _sequencer = spawn_sequencer(
        &fixture.l1,
        &fixture.zone,
        fixture.portal_address,
        fixture.l1.dev_signer(),
    )
    .await;

    let args = WithdrawalArgs::swap_and_deposit_via_router(
        &fixture.l1,
        RouterDepositArgs {
            amount: fixture.swap_amount,
            router: fixture.router,
            token_out: fixture.beta,
            target_portal: fixture.portal_address,
            recipient: fixture.account.address(),
            tempo_refund_recipient: fixture.account.address(),
            memo: B256::ZERO,
            min_amount_out: expected_beta,
        },
    )
    .await?;
    fixture
        .account
        .withdraw_token_with(fixture.alpha, args)
        .await?;

    let alpha_after_request = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after_request,
        U256::ZERO,
        "AlphaUSD should leave the zone before the bounce-back is processed"
    );

    let timeout = Duration::from_secs(60);
    fixture
        .zone
        .wait_for_balance(
            fixture.alpha,
            fixture.account.address(),
            U256::from(fixture.swap_amount),
            timeout,
        )
        .await?;

    let alpha_after = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after,
        U256::from(fixture.swap_amount),
        "AlphaUSD should bounce back after the router's encrypted deposit reverts"
    );

    let beta_after = fixture
        .zone
        .balance_of(fixture.beta, fixture.account.address())
        .await?;
    assert_eq!(
        beta_after,
        U256::ZERO,
        "BetaUSD should not be minted when the routed encrypted deposit fails"
    );

    fixture
        .l1
        .assert_withdrawal_processed_with_status(
            fixture.portal_address,
            fixture.router,
            fixture.alpha,
            fixture.swap_amount,
            false,
        )
        .await?;

    Ok(())
}

/// Same-zone routed withdrawal where the downstream encrypted deposit fails.
///
/// This pins the callback behavior for `deposit`: even with a valid
/// encrypted payload and key index, a target-portal deposit failure must revert
/// the callback and bounce the original token back to the sender.
#[tokio::test(flavor = "multi_thread")]
async fn test_swap_and_deposit_into_same_zone_bounces_back_with_explicit_payload()
-> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut fixture = setup_same_zone_swap_fixture().await?;
    let expected_beta = fixture
        .l1
        .quote_dex_swap_exact_amount_in(fixture.alpha, fixture.beta, fixture.swap_amount)
        .await?;

    fixture
        .l1
        .pause_deposits_on_portal(fixture.portal_address, fixture.beta)
        .await?;

    let (key_index, encrypted) = fixture
        .l1
        .encrypt_deposit_for_portal(
            fixture.portal_address,
            fixture.router,
            fixture.account.address(),
            B256::ZERO,
        )
        .await?;

    let _sequencer = spawn_sequencer(
        &fixture.l1,
        &fixture.zone,
        fixture.portal_address,
        fixture.l1.dev_signer(),
    )
    .await;

    let args = WithdrawalArgs::swap_and_deposit_via_router_callback(RouterCallbackArgs {
        amount: fixture.swap_amount,
        router: fixture.router,
        token_out: fixture.beta,
        target_portal: fixture.portal_address,
        key_index,
        encrypted,
        tempo_refund_recipient: fixture.account.address(),
        min_amount_out: expected_beta,
    });
    fixture
        .account
        .withdraw_token_with(fixture.alpha, args)
        .await?;

    let alpha_after_request = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after_request,
        U256::ZERO,
        "AlphaUSD should leave the zone before the router callback bounces back"
    );

    let timeout = Duration::from_secs(60);
    fixture
        .zone
        .wait_for_balance(
            fixture.alpha,
            fixture.account.address(),
            U256::from(fixture.swap_amount),
            timeout,
        )
        .await?;

    let alpha_after = fixture
        .zone
        .balance_of(fixture.alpha, fixture.account.address())
        .await?;
    assert_eq!(
        alpha_after,
        U256::from(fixture.swap_amount),
        "AlphaUSD should bounce back when the routed encrypted deposit fails"
    );

    let beta_after = fixture
        .zone
        .balance_of(fixture.beta, fixture.account.address())
        .await?;
    assert_eq!(
        beta_after,
        U256::ZERO,
        "BetaUSD should not be minted when the routed encrypted deposit fails"
    );

    fixture
        .l1
        .assert_withdrawal_processed_with_status(
            fixture.portal_address,
            fixture.router,
            fixture.alpha,
            fixture.swap_amount,
            false,
        )
        .await?;

    Ok(())
}

/// Multi-asset deposit + withdrawal test:
///
///  1. Start L1 dev node.
///  2. Create a second TIP-20 token ("ZoneUSD") on L1.
///  3. Create a zone with pathUSD through the native ZoneFactory.
///  4. Enable ZoneUSD on the portal.
///  5. Start zone node connected to L1 (ZoneUSD is auto-initialized via TokenEnabled event).
///  6. Deposit pathUSD and ZoneUSD into the zone.
///  7. Spawn sequencer, withdraw both tokens back to L1.
///  8. Verify withdrawals processed and L2 balances decreased.
///
/// ```text
///  L1 (pathUSD + ZoneUSD)          Zone L2
///    |--- deposit pathUSD -------->|  ✓ pathUSD minted
///    |--- deposit ZoneUSD -------->|  ✓ ZoneUSD minted
///    |<-- withdraw pathUSD --------|  ✓ pathUSD burned
///    |<-- withdraw ZoneUSD --------|  ✓ ZoneUSD burned
/// ```
///
/// NOTE: Requires `forge build` in `crates/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiasset_deposit_withdrawal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;

    // --- Step 2: Create a second TIP-20 token on L1 ---
    let zone_usd_salt = B256::with_last_byte(0x2a);
    let l1_zone_usd = l1.create_tip20("ZoneUSD", "zUSD", zone_usd_salt).await?;

    // Mint ZoneUSD to the dev account so we can fund the user
    let mint_amount: u128 = 100_000_000; // 100 ZoneUSD (6 decimals)
    l1.mint_tip20(l1_zone_usd, l1.dev_address(), mint_amount)
        .await?;

    // --- Step 3: Deploy L1 infrastructure and create a zone ---
    let portal_address = l1.deploy_zone().await?;

    // --- Step 4: Start zone node connected to L1 ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    // --- Step 5: Enable ZoneUSD on the portal ---
    // Must happen AFTER zone startup so the zone's L1 subscriber picks up the
    // TokenEnabled event from a live block.
    l1.enable_token_on_portal(portal_address, l1_zone_usd)
        .await?;
    let enable_block = l1.provider().get_block_number().await?;

    // Wait for the zone to finalize past the enableToken block
    zone.wait_for_l2_tempo_finalized(enable_block, L1_TIMEOUT)
        .await?;

    // L2 token address is the same as L1 by design (auto-initialized via TokenEnabled event)
    let l2_zone_usd = l1_zone_usd;

    // --- Step 6: Deposit both tokens (user account) ---
    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let pathusd_amount: u128 = 1_000_000; // 1 pathUSD
    let zoneusd_amount: u128 = 2_000_000; // 2 ZoneUSD

    // Fund user with both tokens on L1
    l1.fund_user(account.address(), pathusd_amount * 2).await?;
    l1.fund_user_token(l1_zone_usd, account.address(), zoneusd_amount * 2)
        .await?;

    // Deposit pathUSD
    let pathusd_minted = account.deposit(pathusd_amount, L1_TIMEOUT, &zone).await?;
    assert_eq!(
        pathusd_minted,
        U256::from(pathusd_amount),
        "pathUSD minted balance should equal deposit amount"
    );

    // Deposit ZoneUSD
    let zoneusd_minted = account
        .deposit_token(l1_zone_usd, l2_zone_usd, zoneusd_amount, L1_TIMEOUT, &zone)
        .await?;
    assert_eq!(
        zoneusd_minted,
        U256::from(zoneusd_amount),
        "ZoneUSD minted balance should equal deposit amount"
    );

    // --- Step 7: Spawn sequencer and withdraw both tokens ---
    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let withdrawal_timeout = std::time::Duration::from_secs(60);

    // Withdraw pathUSD
    let pathusd_withdrawal: u128 = 500_000; // 0.5 pathUSD
    let pathusd_balance_before = l1.balance_of(PATH_USD_ADDRESS, account.address()).await?;
    account.withdraw(pathusd_withdrawal).await?;

    l1.wait_for_withdrawal_on_l1(
        portal_address,
        account.address(),
        pathusd_balance_before,
        pathusd_withdrawal,
        withdrawal_timeout,
    )
    .await?;

    // Withdraw ZoneUSD
    let zoneusd_withdrawal: u128 = 1_000_000; // 1 ZoneUSD
    let zoneusd_balance_before = l1.balance_of(l1_zone_usd, account.address()).await?;
    account
        .withdraw_token(l2_zone_usd, zoneusd_withdrawal)
        .await?;

    l1.wait_for_withdrawal_on_l1_token(
        portal_address,
        l1_zone_usd,
        account.address(),
        zoneusd_balance_before,
        zoneusd_withdrawal,
        withdrawal_timeout,
    )
    .await?;

    // --- Step 8: Verify L2 balances decreased ---
    let final_pathusd = zone
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    assert!(
        final_pathusd < U256::from(pathusd_amount - pathusd_withdrawal),
        "L2 pathUSD balance should decrease by at least the withdrawal amount (got {final_pathusd})"
    );

    let final_zoneusd = zone.balance_of(l2_zone_usd, account.address()).await?;
    assert!(
        final_zoneusd <= U256::from(zoneusd_amount - zoneusd_withdrawal),
        "L2 ZoneUSD balance should decrease by at least the withdrawal amount (got {final_zoneusd})"
    );

    Ok(())
}

/// Full encrypted deposit + withdrawal flow:
///
///  1. Start L1 dev node and create a zone through the native ZoneFactory.
///  2. Generate sequencer encryption key, start zone with sequencer key.
///  3. Register encryption key on the portal via `setSequencerEncryptionKey`.
///  4. Fund depositor, call `deposit` on the portal — encrypting
///     (recipient, memo) to the sequencer's public key. The recipient is a
///     known key (mnemonic index 2) so we can withdraw later.
///     The zone processes this automatically: ECIES decrypt → CP proof →
///     AES-GCM verify → mint to recipient. `deposit_with_memo` waits for
///     the L2 balance to confirm the full pipeline succeeded.
///  5. Spawn sequencer tasks, recipient requests withdrawal on L2.
///  6. Wait for batch submission + withdrawal processing on L1.
///
/// ```text
///  L1                                       Zone L2
///   │                                         │
///   │  setSequencerEncryptionKey              │
///   │                                         │
///   │  deposit ──────────────────►    │
///   │                                         │
///   │               ECIES decrypt             │
///   │               + CP proof                │
///   │                   │                    │
///   │                   ▼                    │
///   │            advanceTempo                 │
///   │                   │                    │
///   │                   ▼                    │
///   │            CP ✓ + AES decrypt           │
///   │            → mint to recipient         │
///   │                                         │
///   │   ◄──── requestWithdrawal ───── │
///   │   ◄──── submitBatch ────────  │
///   │   processWithdrawals                     │
///   │            → tokens to L1              │
/// ```
///
/// NOTE: Requires `forge build` in `crates/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_and_withdrawal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 + deploy zone ---
    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    // --- Step 2: Start zone with the key provisioned by deploy_zone ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // --- Step 3: Encrypted deposit to a recipient we control ---
    // Use mnemonic index 2 as the recipient so we have keys for withdrawal.
    let recipient_signer = l1.signer_at(2);
    let recipient = recipient_signer.address();

    let mut depositor = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD

    l1.fund_user(depositor.address(), deposit_amount).await?;

    // deposit_with_memo waits for `balance >= deposit_amount` on L2, so success
    // here proves the full ECIES pipeline worked (decrypt → CP verify → AES → mint).
    depositor
        .deposit_with_memo(deposit_amount, recipient, B256::ZERO, L1_TIMEOUT, &zone)
        .await?;

    // --- Step 5: Spawn sequencer + withdraw from the recipient's account on L2 ---
    // Spawn sequencer after deposit to avoid L1 nonce races — the dev signer
    // is used by both fund_user and the sequencer's batch submitter.
    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;

    let mut recipient_account =
        ZoneAccount::with_signer(recipient_signer, &l1, &zone, portal_address);

    let withdrawal_amount: u128 = 500_000; // 0.5 pathUSD
    let l1_balance_before = l1.balance_of(PATH_USD_ADDRESS, recipient).await?;
    recipient_account.withdraw(withdrawal_amount).await?;

    // --- Step 6: Wait for the withdrawal to be fully processed on L1 ---
    let withdrawal_timeout = std::time::Duration::from_secs(60);
    l1.wait_for_withdrawal_on_l1(
        portal_address,
        recipient,
        l1_balance_before,
        withdrawal_amount,
        withdrawal_timeout,
    )
    .await?;

    Ok(())
}

/// A finalized portal-wide pause stops Zone block production and L1 withdrawal processing until
/// the portal resumes, while batches finalized before the pause still settle.
#[tokio::test(flavor = "multi_thread")]
async fn test_global_pause_stops_and_resumes_block_production() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let recipient_signer = l1.signer_at(2);
    let recipient = recipient_signer.address();
    let mut depositor = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let initial_deposit = 1_000_000u128;
    l1.fund_user(depositor.address(), initial_deposit).await?;
    depositor
        .deposit_with_memo(initial_deposit, recipient, B256::ZERO, L1_TIMEOUT, &zone)
        .await?;

    let admin_provider = l1.admin_provider();
    let portal = ZonePortal::new(portal_address, &admin_provider);

    // Finalize a withdrawal into a Zone batch before the pause, so settlement has pre-pause work.
    let initial_withdrawal_batch = portal.withdrawalBatchIndex().call().await?;
    let zone_outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, zone.provider());
    let initial_zone_withdrawal_batch = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
    let mut recipient_account =
        ZoneAccount::with_signer(recipient_signer, &l1, &zone, portal_address);
    recipient_account.withdraw(500_000).await?;
    poll_until(
        L1_TIMEOUT,
        Duration::from_millis(250),
        "withdrawal to be finalized into a zone batch",
        || {
            let zone_outbox = &zone_outbox;
            async move {
                let batch = zone_outbox.lastBatch().call().await?.withdrawalBatchIndex;
                Ok((batch > initial_zone_withdrawal_batch).then_some(()))
            }
        },
    )
    .await?;

    let pause_receipt = portal.pause().send().await?.get_receipt().await?;
    eyre::ensure!(pause_receipt.status(), "global pause transaction failed");
    eyre::ensure!(portal.paused().call().await?, "portal should be paused");
    let pause_block = pause_receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("pause receipt has no block number"))?;

    let _ = depositor
        .simulate_deposit(initial_deposit, depositor.address(), depositor.address())
        .await
        .expect_err("deposit simulation should revert while the portal is paused");

    let tracker = zone.l1_block_tracker().clone();
    poll_until(
        L1_TIMEOUT,
        Duration::from_millis(250),
        "pause block to be observed by the L1 subscriber",
        || {
            let latest = tracker.latest().map(|block| block.number);
            async move { Ok(latest.filter(|number| *number >= pause_block)) }
        },
    )
    .await?;

    let zone_provider = zone.provider();
    // A block already in flight may finish. Require the head to remain unchanged for a full
    // second, which spans multiple Tempo blocks in the dev chain.
    let frozen_head = wait_for_stable_zone_head(&zone).await?;
    let frozen_anchor = zone.tempo_block_number().await?;
    assert!(
        frozen_anchor < pause_block,
        "the Zone imported the pause block instead of stopping before it"
    );

    // Batches finalized before the pause still settle, but the withdrawal stays queued on L1.
    let withdrawal_start_block = l1.provider().get_block_number().await?;
    let sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    poll_until(
        L1_TIMEOUT,
        Duration::from_millis(250),
        "pre-pause withdrawal batch to settle while the portal is paused",
        || {
            let portal = &portal;
            async move {
                let batch = portal.withdrawalBatchIndex().call().await?;
                Ok((batch > initial_withdrawal_batch).then_some(()))
            }
        },
    )
    .await?;
    eyre::ensure!(
        !sequencer.withdrawal_handle.is_finished(),
        "withdrawal processor exited while the portal was paused"
    );
    assert!(
        portal
            .WithdrawalProcessed_filter()
            .from_block(withdrawal_start_block)
            .query()
            .await?
            .is_empty(),
        "withdrawal must remain queued while the portal is paused"
    );

    // Ingestion keeps following finalized L1 within its lookahead window while the Zone anchor
    // and block height remain frozen, so governance landing during the pause is applied.
    let token = l1
        .create_tip20("PausedUSD", "pUSD", B256::with_last_byte(0x7f))
        .await?;
    let governance_receipt = portal
        .enableToken(token)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        governance_receipt.status(),
        "enableToken failed while paused"
    );
    let governance_block = governance_receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("governance receipt has no block number"))?;
    poll_until(
        L1_TIMEOUT,
        Duration::from_millis(100),
        "governance update during the production pause",
        || async {
            Ok((tracker
                .latest()
                .is_some_and(|block| block.number >= governance_block)
                && zone.enabled_tokens().read().contains(&token))
            .then_some(token))
        },
    )
    .await?;
    assert_eq!(zone_provider.get_block_number().await?, frozen_head);
    assert_eq!(zone.tempo_block_number().await?, frozen_anchor);

    let resume_receipt = portal.resume().send().await?.get_receipt().await?;
    eyre::ensure!(resume_receipt.status(), "global resume transaction failed");
    eyre::ensure!(!portal.paused().call().await?, "portal should be resumed");
    let resume_block = resume_receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("resume receipt has no block number"))?;

    zone.wait_for_tempo_block_number(resume_block, L1_TIMEOUT)
        .await?;
    assert!(
        zone_provider.get_block_number().await? > frozen_head,
        "Zone block production did not restart after the portal resumed"
    );
    poll_until(
        L1_TIMEOUT,
        Duration::from_millis(250),
        "queued withdrawal to be processed after the portal resumed",
        || {
            let portal = &portal;
            async move {
                let processed = portal
                    .WithdrawalProcessed_filter()
                    .from_block(withdrawal_start_block)
                    .query()
                    .await?;
                Ok((!processed.is_empty()).then_some(()))
            }
        },
    )
    .await?;

    Ok(())
}

/// Startup reads the finalized portal snapshot before launching the producer, so a node first
/// started during an existing pause must fail closed without relying on historical event replay.
#[tokio::test(flavor = "multi_thread")]
async fn test_global_pause_snapshot_stops_startup_until_resume() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let admin_provider = l1.admin_provider();
    let portal = ZonePortal::new(portal_address, &admin_provider);
    let pause_receipt = portal.pause().send().await?.get_receipt().await?;
    eyre::ensure!(pause_receipt.status(), "global pause transaction failed");

    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    eyre::ensure!(
        zone.l1_block_tracker().portal_paused(),
        "startup did not initialize the finalized portal pause snapshot"
    );
    let frozen_head = wait_for_stable_zone_head(&zone).await?;

    let resume_receipt = portal.resume().send().await?.get_receipt().await?;
    eyre::ensure!(resume_receipt.status(), "global resume transaction failed");
    let resume_block = resume_receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("resume receipt has no block number"))?;
    zone.wait_for_tempo_block_number(resume_block, L1_TIMEOUT)
        .await?;
    assert!(
        zone.provider().get_block_number().await? > frozen_head,
        "startup-paused Zone did not begin production after resume"
    );

    Ok(())
}

/// Test that TIP-403 policy operations on L1 work correctly and the zone
/// continues to advance normally after policy changes.
///
///  1. Start L1 dev node, deploy zone.
///  2. Create a blacklist policy on L1.
///  3. Assign it to pathUSD.
///  4. Blacklist a user address.
///  5. Start zone node, verify it advances past the policy blocks.
///  6. Verify the policy state on L1 via the helpers.
///
/// NOTE: Full on-chain TIP-403 enforcement on the zone (blocking transfers)
/// requires the TIP403Registry shim precompile, which is not yet wired.
/// This test validates the L1 infrastructure and that policy changes don't
/// break zone block production.
#[tokio::test(flavor = "multi_thread")]
async fn test_l1_policy_operations_and_zone_advancement() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    // --- Create policy infrastructure on L1 ---
    let policy_id = l1.create_blacklist_policy().await?;

    // Assign the blacklist to pathUSD
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, policy_id)
        .await?;

    // Blacklist the user account
    let blacklisted_user = l1.user_signer().address();
    l1.blacklist_address(policy_id, blacklisted_user).await?;

    // Verify policy state on L1
    let auth_result = l1.is_authorized(policy_id, blacklisted_user).await?;
    assert!(
        !auth_result,
        "blacklisted user should NOT be authorized on L1"
    );

    // Non-blacklisted address should be authorized
    let clean_user = l1.signer_at(3).address();
    let clean_auth = l1.is_authorized(policy_id, clean_user).await?;
    assert!(
        clean_auth,
        "non-blacklisted user should be authorized on L1"
    );

    // --- Start zone and verify it advances past the policy blocks ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let membership_block = l1
        .set_allowed_account_on_portal(portal_address, clean_user, true)
        .await?;
    zone.wait_for_l2_tempo_finalized(membership_block, L1_TIMEOUT)
        .await?;
    zone.assert_allowed_account(clean_user, true).await?;

    // Zone should have produced blocks — policy changes on L1 don't break zone
    let zone_block = zone.provider().get_block_number().await?;
    assert!(
        zone_block > 0,
        "zone should have produced blocks after L1 policy changes"
    );

    // Deposit to a non-blacklisted user should still work.
    // Use signer_at(3) — the same `clean_user` verified above — because the default
    // user_signer (index 1) was blacklisted earlier in this test.
    let clean_signer = l1.signer_at(3);
    let mut account = ZoneAccount::with_signer(clean_signer, &l1, &zone, portal_address);
    let deposit_amount: u128 = 1_000_000;
    l1.fund_user(account.address(), deposit_amount).await?;
    let minted = account.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;
    assert_eq!(
        minted,
        U256::from(deposit_amount),
        "deposit should succeed for non-blacklisted user"
    );

    Ok(())
}

/// An encrypted deposit accepted on L1 but rejected by the zone's current token
/// policy must complete the zone -> batch -> L1 bounceback loop and refund the
/// explicitly selected Tempo recipient.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_policy_failure_bounces_to_tempo_refund_recipient() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    use tempo_contracts::precompiles::{ITIP20, ITIP403Registry::PolicyType};

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    let policy_id = l1.create_blacklist_policy().await?;
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, policy_id)
        .await?;

    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // Keep the recipient authorized on Tempo so the portal accepts and escrows
    // the deposit, while pinning the zone policy view to the rejecting state.
    let rejected_recipient = l1.admin_address();
    assert!(l1.is_authorized(policy_id, rejected_recipient).await?);
    let policy_block = l1.provider().get_block_number().await?;
    seed_raw_tip403_token_policy(
        &mut zone.l1_state_cache().lock(),
        policy_block,
        PATH_USD_ADDRESS,
        policy_id,
    );
    let blocked_members = [(rejected_recipient, true)];
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        policy_block,
        &[PolicySeed::simple(
            policy_id,
            PolicyType::BLACKLIST,
            &blocked_members,
        )],
    )?;

    let depositor = l1.user_signer();
    let tempo_refund_recipient = depositor.address();
    let deposit_amount = 1_000_000u128;
    l1.fund_user(tempo_refund_recipient, deposit_amount).await?;
    let provider = l1.provider_with_signer(depositor.clone());
    ITIP20::new(PATH_USD_ADDRESS, &provider)
        .approve(portal_address, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    let refund_balance_before = l1
        .balance_of(PATH_USD_ADDRESS, tempo_refund_recipient)
        .await?;

    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let portal = ZonePortal::new(portal_address, &provider);
    let (key_index, encrypted) = l1
        .encrypt_deposit_for_portal(
            portal_address,
            depositor.address(),
            rejected_recipient,
            B256::ZERO,
        )
        .await?;
    let receipt = portal
        .deposit(
            PATH_USD_ADDRESS,
            deposit_amount,
            key_index,
            encrypted,
            tempo_refund_recipient,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        receipt.status(),
        "encrypted L1 deposit failed before queueing"
    );

    l1.wait_for_balance(
        PATH_USD_ADDRESS,
        tempo_refund_recipient,
        refund_balance_before,
        Duration::from_secs(60),
    )
    .await?;
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, rejected_recipient)
            .await?,
        U256::ZERO,
        "policy-rejected encrypted recipient should not be minted"
    );

    let bouncebacks = portal
        .DepositBounceBack_filter()
        .from_block(0)
        .query()
        .await?;
    let bounced = bouncebacks.iter().any(|(event, _)| {
        event.tempoRefundRecipient == tempo_refund_recipient
            && event.token == PATH_USD_ADDRESS
            && event.amount + event.bouncebackFee == deposit_amount
    });
    eyre::ensure!(
        bounced,
        "expected completed encrypted deposit bounceback event"
    );

    Ok(())
}

/// Both the current key and a historical key accepted during rotation grace must decrypt.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_old_key_during_grace_mints_after_rotation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    use k256::{AffinePoint, ProjectivePoint, Scalar};
    use tempo_contracts::precompiles::ITIP20;
    use tempo_zone_contracts::DepositPayload;
    use zone_precompiles::ecies;

    let l1 = L1TestNode::start().await?;
    let current_key = k256::SecretKey::from(l1.dev_signer().credential());
    let old_key = k256::SecretKey::from_slice(&[0x42; 32])?;
    let factory = l1.native_zone_factory().await?;
    let portal_address = l1
        .create_zone_with_admin_sequencer_and_config(
            factory,
            l1.admin_address(),
            l1.dev_address(),
            ZoneCreationConfig::closed(vec![l1.admin_address(), l1.user_signer().address()]),
        )
        .await?;

    // Register both keys before startup so the node must reconstruct their index bindings from
    // the Portal snapshot at its persisted L1 anchor.
    l1.set_sequencer_encryption_key(portal_address, &old_key)
        .await?;
    l1.set_sequencer_encryption_key(portal_address, &current_key)
        .await?;

    let zone = ZoneTestNode::start_from_l1_with_decryption_keys(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        vec![old_key.clone()],
    )
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let depositor = l1.user_signer();
    let provider = l1.provider_with_signer(depositor.clone());
    let portal = ZonePortal::new(portal_address, &provider);
    assert_eq!(portal.encryptionKeyCount().call().await?, U256::from(2));
    assert!(
        portal.isEncryptionKeyValid(U256::ZERO).call().await?.valid,
        "the historical key must still be accepted during its grace period"
    );

    let current_amount = 300_000u128;
    let historical_amount = 400_000u128;
    l1.fund_user(depositor.address(), current_amount + historical_amount)
        .await?;
    ITIP20::new(PATH_USD_ADDRESS, &provider)
        .approve(portal_address, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    let current_recipient = l1.signer_at(2).address();
    let current_entry = portal.sequencerEncryptionKey().call().await?;
    let current = ecies::encrypt_deposit(
        &current_entry.x,
        current_entry.yParity,
        current_recipient,
        B256::ZERO,
        depositor.address(),
        portal_address,
        U256::ONE,
    )
    .ok_or_else(|| eyre::eyre!("current-key encryption failed"))?;
    let current_receipt = portal
        .deposit(
            PATH_USD_ADDRESS,
            current_amount,
            U256::ONE,
            DepositPayload {
                ephemeralPubkeyX: current.eph_pub_x,
                ephemeralPubkeyYParity: current.eph_pub_y_parity,
                ciphertext: current.ciphertext.into(),
                nonce: alloy_primitives::FixedBytes(current.nonce),
                tag: alloy_primitives::FixedBytes(current.tag),
            },
            depositor.address(),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(current_receipt.status(), "current-key deposit was rejected");

    let historical_recipient = l1.signer_at(3).address();
    let old_scalar: Scalar = *old_key.to_nonzero_scalar();
    let old_point = AffinePoint::from(ProjectivePoint::GENERATOR * old_scalar);
    let (old_x, old_y_parity) = ecies::compressed_x_and_parity(&old_point);
    let historical = ecies::encrypt_deposit(
        &old_x,
        old_y_parity,
        historical_recipient,
        B256::ZERO,
        depositor.address(),
        portal_address,
        U256::ZERO,
    )
    .ok_or_else(|| eyre::eyre!("historical-key encryption failed"))?;
    let historical_receipt = portal
        .deposit(
            PATH_USD_ADDRESS,
            historical_amount,
            U256::ZERO,
            DepositPayload {
                ephemeralPubkeyX: historical.eph_pub_x,
                ephemeralPubkeyYParity: historical.eph_pub_y_parity,
                ciphertext: historical.ciphertext.into(),
                nonce: alloy_primitives::FixedBytes(historical.nonce),
                tag: alloy_primitives::FixedBytes(historical.tag),
            },
            depositor.address(),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        historical_receipt.status(),
        "grace-valid historical-key deposit was rejected"
    );

    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        current_recipient,
        U256::from(current_amount),
        L1_TIMEOUT,
    )
    .await?;
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        historical_recipient,
        U256::from(historical_amount),
        L1_TIMEOUT,
    )
    .await?;

    Ok(())
}

/// Test that an encrypted deposit whose decrypted recipient is blacklisted
/// gets bounced back to the sender on L1 instead of minting to the recipient.
///
///  1. Start L1 dev node, deploy zone, register encryption key.
///  2. Create a blacklist policy, assign to pathUSD, blacklist the recipient.
///  3. Make an encrypted deposit targeting the blacklisted recipient.
///  4. Verify upstream TIP-20 mint enforcement fails and refunds the sender on L1.
///
/// `L1OverlayDB` exposes finalized L1 policy state directly to upstream Tempo execution.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_blacklisted_recipient() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 + deploy zone ---
    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    // --- Step 2: Create blacklist policy and blacklist the intended recipient ---
    let policy_id = l1.create_blacklist_policy().await?;
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, policy_id)
        .await?;

    let blacklisted_recipient = l1.signer_at(2).address();
    l1.blacklist_address(policy_id, blacklisted_recipient)
        .await?;

    // Verify on L1
    assert!(
        !l1.is_authorized(policy_id, blacklisted_recipient).await?,
        "recipient should be blacklisted"
    );

    // --- Step 3: Start zone with sequencer key ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // --- Step 4: Make an encrypted deposit targeting the blacklisted recipient ---
    let depositor = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount: u128 = 1_000_000;
    l1.fund_user(depositor.address(), deposit_amount).await?;

    // Make the encrypted deposit on L1 targeting the blacklisted recipient.
    // We don't use `deposit_with_memo` because it waits for the recipient's
    // balance to increase — which never happens since the deposit gets
    // bounced back to the sender. Instead, call the portal directly and wait
    // for the sender's L1 balance to be restored.
    {
        use tempo_contracts::precompiles::ITIP20;

        let portal = tempo_zone_contracts::ZonePortal::new(portal_address, depositor.l1_provider());

        ITIP20::new(PATH_USD_ADDRESS, depositor.l1_provider())
            .approve(portal_address, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;

        let (key_index, encrypted) = l1
            .encrypt_deposit_for_portal(
                portal_address,
                depositor.address(),
                blacklisted_recipient,
                B256::ZERO,
            )
            .await?;

        let receipt = portal
            .deposit(
                PATH_USD_ADDRESS,
                deposit_amount,
                key_index,
                encrypted,
                depositor.address(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L1 deposit tx failed");
    }

    // Wait for the bounce-back refund to arrive at the sender on L1 (not the
    // blacklisted recipient on L2).
    l1.wait_for_balance(
        PATH_USD_ADDRESS,
        depositor.address(),
        U256::from(deposit_amount),
        L1_TIMEOUT,
    )
    .await?;

    // The blacklisted recipient should NOT have received the deposit.
    let recipient_balance = zone
        .balance_of(ZONE_TOKEN_ADDRESS, blacklisted_recipient)
        .await?;

    assert_eq!(
        recipient_balance,
        U256::ZERO,
        "Blacklisted recipient should not have received the deposit"
    );

    Ok(())
}

/// Blacklisted sender cannot transfer on the zone.
///
///  1. Start L1 dev node, deploy zone.
///  2. Create a blacklist policy for senders, wrap it in a compound policy
///     (sender=blacklist, recipient=allow-all, mintRecipient=allow-all).
///  3. Assign the compound policy to pathUSD's `transferPolicyId`.
///  4. Blacklist Alice in the sender sub-policy.
///  5. Start zone connected to L1, wait for it to process the policy blocks.
///  6. Deposit pathUSD to Alice (succeeds — mint recipient is allow-all).
///  7. Alice attempts a transfer → rejected at pool level (blacklisted sender).
///
/// NOTE: The T2 hardfork must be active on L1 for compound policies and
/// directional authorization roles to work.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_blacklisted_sender_transfer_rejected() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    // --- Step 2: Create compound policy and blacklist Alice as sender ---
    let alice_signer = l1.user_signer();
    let alice = alice_signer.address();

    let sender_policy_id = l1.create_blacklist_policy().await?;
    let compound_policy_id = l1.create_compound_policy(sender_policy_id, 1, 1).await?;
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, compound_policy_id)
        .await?;
    l1.blacklist_address(sender_policy_id, alice).await?;

    // Verify on L1: Alice is NOT authorized as sender
    {
        use tempo_contracts::precompiles::ITIP403Registry;
        use tempo_precompiles::TIP403_REGISTRY_ADDRESS;
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, l1.provider());
        let authorized = registry
            .isAuthorizedSender(compound_policy_id, alice)
            .call()
            .await?;
        assert!(
            !authorized,
            "alice should NOT be authorized as sender on L1"
        );
    }

    // --- Step 3: Start zone connected to L1 ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // --- Step 4: Deposit to Alice via the dev account ---
    // Alice is blacklisted as a sender, so she can't transfer pathUSD on L1
    // herself. The dev account deposits on her behalf (recipient = allow-all).
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD
    {
        use tempo_contracts::precompiles::ITIP20;
        use tempo_zone_contracts::ZonePortal;

        let dev_provider = l1.dev_provider();
        ITIP20::new(PATH_USD_ADDRESS, &dev_provider)
            .approve(portal_address, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;

        let portal = ZonePortal::new(portal_address, &dev_provider);
        let (key_index, encrypted) = l1
            .encrypt_deposit_for_portal(portal_address, l1.dev_address(), alice, B256::ZERO)
            .await?;
        let receipt = portal
            .deposit(
                PATH_USD_ADDRESS,
                deposit_amount,
                key_index,
                encrypted,
                alice,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L1 deposit tx failed");
    }

    // Wait for the deposit to be minted on L2
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        alice,
        U256::from(deposit_amount),
        L1_TIMEOUT,
    )
    .await?;

    // --- Step 5: Alice simulates a transfer → should be rejected ---
    // Use an exact stateful call instead of waiting on pool inclusion: policy-invalid
    // transactions are allowed to remain pending, so absence of a receipt is not proof.
    let bob = Address::with_last_byte(0xBB);

    let alice_provider = alloy::providers::ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(zone.http_url().clone());

    let tip20 = tempo_contracts::precompiles::ITIP20::new(ZONE_TOKEN_ADDRESS, &alice_provider);
    let transfer = tip20
        .transfer(bob, U256::from(200_000u128))
        .from(alice)
        .call()
        .await;
    assert!(
        transfer.is_err(),
        "transfer simulation from blacklisted sender should revert"
    );

    // Bob should have zero balance
    let bob_balance = zone.balance_of(ZONE_TOKEN_ADDRESS, bob).await?;
    assert_eq!(bob_balance, U256::ZERO, "bob should have received nothing");

    Ok(())
}

/// Test that an encrypted deposit defers recipient policy enforcement to the zone.
///
///  1. Start L1 dev node, deploy zone.
///  2. Create a blacklist policy, assign to pathUSD, blacklist a user.
///  3. Fund the blacklisted user on L1.
///  4. Submit a deposit targeting the blacklisted user — L1 accepts it because the
///     recipient is encrypted and zone-side processing owns recipient enforcement.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_to_blacklisted_recipient_is_accepted_on_l1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;

    // --- Create blacklist policy and blacklist the intended deposit recipient ---
    let policy_id = l1.create_blacklist_policy().await?;
    l1.change_transfer_policy_id(PATH_USD_ADDRESS, policy_id)
        .await?;

    let blacklisted_recipient = l1.signer_at(2).address();
    l1.blacklist_address(policy_id, blacklisted_recipient)
        .await?;

    assert!(
        !l1.is_authorized(policy_id, blacklisted_recipient).await?,
        "recipient should be blacklisted"
    );

    // Fund an allowed depositor that is distinct from the blacklisted recipient.
    let depositor_signer = l1.user_signer();
    let depositor = depositor_signer.address();
    let deposit_amount: u128 = 1_000_000;
    l1.fund_user(depositor, deposit_amount).await?;

    // Build a provider for the depositor
    let depositor_provider = l1.provider_with_signer(depositor_signer);

    // Approve the portal to spend pathUSD
    use tempo_contracts::precompiles::ITIP20;
    ITIP20::new(PATH_USD_ADDRESS, &depositor_provider)
        .approve(portal_address, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;

    // The portal cannot inspect the encrypted recipient, so this is accepted on L1.
    use tempo_zone_contracts::ZonePortal;
    let portal = ZonePortal::new(portal_address, &depositor_provider);
    let (key_index, encrypted) = l1
        .encrypt_deposit_for_portal(portal_address, depositor, blacklisted_recipient, B256::ZERO)
        .await?;
    let receipt = portal
        .deposit(
            PATH_USD_ADDRESS,
            deposit_amount,
            key_index,
            encrypted,
            depositor,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    assert!(
        receipt.status(),
        "encrypted deposit should be accepted on L1"
    );

    Ok(())
}
