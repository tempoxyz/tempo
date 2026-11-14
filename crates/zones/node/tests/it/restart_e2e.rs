//! E2E tests for zone sequencer restart resilience.
//!
//! These tests verify that the zone monitor and withdrawal processor correctly
//! resume from on-chain portal state after a restart, covering:
//!
//! - Batch submission resumes from the portal's `blockHash()` (not block 0)
//! - Withdrawals continue to be processed after a sequencer restart
//! - Multiple restart cycles don't corrupt state

use crate::utils::{
    L1_TIMEOUT, L1TestNode, Network, ZoneAccount, ZoneCreationConfig, ZoneLaunch, ZoneTestNode,
    batch_count, spawn_sequencer,
};
use alloy::primitives::{Address, U256};
use tempo_contracts::zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS, ZonePortal};
use tempo_precompiles::PATH_USD_ADDRESS;

/// Timeout for waiting on withdrawals (includes batch submission + processing).
const WITHDRAWAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Read the portal's `blockHash()` — the last submitted zone block hash.
async fn portal_block_hash(
    l1: &L1TestNode,
    portal_address: Address,
) -> eyre::Result<alloy_primitives::B256> {
    let portal = ZonePortal::new(portal_address, l1.provider());
    Ok(portal.blockHash().call().await?)
}

/// Read the portal's withdrawal queue head and tail.
async fn portal_queue_state(l1: &L1TestNode, portal_address: Address) -> eyre::Result<(u64, u64)> {
    let portal = ZonePortal::new(portal_address, l1.provider());
    let head: U256 = portal.withdrawalQueueHead().call().await?;
    let tail: U256 = portal.withdrawalQueueTail().call().await?;
    Ok((head.to::<u64>(), tail.to::<u64>()))
}

/// Count `BatchSubmitted` events on the portal.
async fn batch_submitted_count(l1: &L1TestNode, portal_address: Address) -> eyre::Result<usize> {
    batch_count(&ZonePortal::new(portal_address, l1.provider())).await
}

async fn wait_for_withdrawal_requested(
    zone: &ZoneTestNode,
    sender: Address,
    amount: u128,
) -> eyre::Result<u64> {
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, zone.provider());
    let expected_amount = U256::from(amount);

    crate::utils::poll_until(
        WITHDRAWAL_TIMEOUT,
        std::time::Duration::from_millis(200),
        "WithdrawalRequested visible on zone L2",
        || {
            let outbox = &outbox;
            async move {
                let events = outbox
                    .WithdrawalRequested_filter()
                    .from_block(0)
                    .query()
                    .await?;
                Ok(events
                    .into_iter()
                    .rev()
                    .find(|(event, _)| event.sender == sender && expected_amount == event.amount)
                    .and_then(|(_, log)| log.block_number))
            }
        },
    )
    .await
}

/// Abort a sequencer task and wait for it to stop, failing if it had panicked.
async fn abort_task(handle: tokio::task::JoinHandle<()>) -> eyre::Result<()> {
    handle.abort();
    match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) if err.is_cancelled() => Ok(()),
        Ok(Err(err)) => Err(eyre::eyre!("sequencer task panicked: {err}")),
        Err(_) => Err(eyre::eyre!(
            "sequencer task did not stop within 5s of abort"
        )),
    }
}

/// Repeated sequencer restarts resume batch submission from the portal's `blockHash()`.
///
/// The first restart happens before any withdrawal, so the portal's `blockHash()` is the only
/// anchor; each later cycle restarts and then completes a withdrawal on L1. This proves the
/// monitor reads `blockHash()` on startup instead of scanning from block 0 (which would hit the
/// max block range error) and that repeated restarts don't corrupt state.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_restarts_resume_batch_submission() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let net = Network::builder()
        .zone(ZoneCreationConfig::closed(Vec::new()))
        .accounts(1, 6_000_000)
        .start()
        .await?;
    let l1 = net.l1();
    let [zone] = net.zones();
    let [user] = net.accounts();
    let deposit_amount: u128 = 5_000_000;
    zone.deposit(user, deposit_amount).await?;

    let mut seq = zone.spawn_sequencer().await;
    crate::utils::poll_until(
        WITHDRAWAL_TIMEOUT,
        std::time::Duration::from_millis(200),
        "at least one BatchSubmitted",
        || async move {
            let count = batch_submitted_count(l1, zone.portal_address()).await?;
            if count > 0 { Ok(Some(count)) } else { Ok(None) }
        },
    )
    .await?;
    assert!(
        !portal_block_hash(l1, zone.portal_address())
            .await?
            .is_zero(),
        "portal blockHash should be non-zero after first batch"
    );

    // `None` restarts without a withdrawal; each later cycle withdraws after the restart.
    let withdrawals = [None, Some(200_000u128), Some(300_000), Some(400_000)];
    for withdrawal in withdrawals {
        let hash_before = portal_block_hash(l1, zone.portal_address()).await?;
        let batches_before = batch_submitted_count(l1, zone.portal_address()).await?;

        abort_task(seq.monitor_handle).await?;
        abort_task(seq.withdrawal_handle).await?;
        seq = zone.spawn_sequencer().await;

        if let Some(amount) = withdrawal {
            zone.withdraw(user, PATH_USD_ADDRESS, amount).await?;
        }

        // The zone produces blocks as L1 blocks arrive (every 250ms in dev mode), so the
        // restarted monitor has new blocks to batch.
        crate::utils::poll_until(
            L1_TIMEOUT,
            std::time::Duration::from_millis(200),
            "new batches should be submitted after restart",
            || async move {
                let count = batch_submitted_count(l1, zone.portal_address()).await?;
                Ok((count > batches_before).then_some(()))
            },
        )
        .await?;
        assert_ne!(
            hash_before,
            portal_block_hash(l1, zone.portal_address()).await?,
            "portal blockHash should advance after restart (withdrawal: {withdrawal:?})"
        );
    }

    let total_batches = batch_submitted_count(l1, zone.portal_address()).await?;
    assert!(
        total_batches >= 3,
        "should have at least 3 batches across the restart cycles (got {total_batches})"
    );

    let total_withdrawn: u128 = withdrawals.into_iter().flatten().sum();
    let l2_balance = zone.balance_of(ZONE_TOKEN_ADDRESS, user.address()).await?;
    assert!(
        l2_balance <= U256::from(deposit_amount - total_withdrawn),
        "L2 balance should reflect all withdrawals (got {l2_balance})"
    );

    Ok(())
}

/// Sequencer restart with unprocessed withdrawal queue slots.
///
/// 1. Deposit, spawn sequencer, request withdrawal.
/// 2. Wait for the batch to be submitted (withdrawal enqueued on L1 portal).
/// 3. Abort the sequencer BEFORE the withdrawal is processed.
/// 4. Respawn the sequencer — `fetch_pending_withdrawals` restores the data.
/// 5. The OLD withdrawal from before the restart is processed on L1.
/// 6. A NEW withdrawal after restart also works.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_restart_with_pending_withdrawal_queue() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let net = Network::builder()
        .zone(ZoneCreationConfig::closed(Vec::new()))
        .accounts(1, 4_000_000)
        .start()
        .await?;
    let l1 = net.l1();
    let [zone] = net.zones();
    let [user] = net.accounts();
    let mut account = zone.account(user);
    zone.deposit(user, 3_000_000).await?;

    let zone_sequencer::ZoneSequencerHandle {
        withdrawal_handle,
        monitor_handle,
    } = zone.spawn_sequencer().await;

    // Keep batch submission running, but stop L1 processing so the portal queue
    // is guaranteed to remain pending until after the restart.
    abort_task(withdrawal_handle).await?;

    // Request withdrawal — wait for the batch to be submitted to L1
    let withdrawal_amount: u128 = 500_000;
    account.withdraw(withdrawal_amount).await?;
    wait_for_withdrawal_requested(zone, account.address(), withdrawal_amount).await?;

    // Wait for the batch to land on L1 (portal tail advances)
    crate::utils::poll_until(
        WITHDRAWAL_TIMEOUT,
        std::time::Duration::from_millis(200),
        "portal withdrawal queue tail > 0",
        || async move {
            let (_, tail) = portal_queue_state(l1, zone.portal_address()).await?;
            if tail > 0 { Ok(Some(tail)) } else { Ok(None) }
        },
    )
    .await?;

    let (head_before, tail_before) = portal_queue_state(l1, zone.portal_address()).await?;
    assert!(
        tail_before > head_before,
        "expected pending withdrawal slot: tail={tail_before} head={head_before}"
    );

    // --- Abort sequencer BEFORE the withdrawal is processed ---
    abort_task(monitor_handle).await?;

    // --- Respawn sequencer (fetch_pending_withdrawals runs during init) ---
    let seq_handle2 = zone.spawn_sequencer().await;

    // The OLD withdrawal from before the restart should be processed via
    // restored data (withdrawal processor was aborted before head advanced).
    crate::utils::poll_until(
        WITHDRAWAL_TIMEOUT,
        std::time::Duration::from_millis(200),
        "portal head advances past first withdrawal",
        || {
                        let seq_handle2 = &seq_handle2;
            async move {
                if seq_handle2.monitor_handle.is_finished() {
                    eyre::bail!("restarted monitor task exited before restoring the pending withdrawal");
                }
                if seq_handle2.withdrawal_handle.is_finished() {
                    eyre::bail!(
                        "restarted withdrawal processor exited before processing the pending withdrawal"
                    );
                }
                let (head, _) = portal_queue_state(l1, zone.portal_address()).await?;
                if head >= tail_before {
                    Ok(Some(head))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    // Request a NEW withdrawal after restart to verify normal operation continues.
    zone.withdraw(user, PATH_USD_ADDRESS, 400_000).await?;

    // Portal queue should have advanced further
    let (head_after, tail_after) = portal_queue_state(l1, zone.portal_address()).await?;
    assert!(
        tail_after > tail_before,
        "portal tail should advance after second withdrawal (before={tail_before}, after={tail_after})"
    );
    assert!(
        head_after >= tail_before,
        "portal head should have processed at least the first withdrawal"
    );

    Ok(())
}

/// Withdrawal processing survives sequencer restart after same-block batch finalization.
///
/// The batch submitter reconstructs finalized withdrawals from chain history on resume;
/// same-block finalization timing is covered by local e2e tests in `e2e.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn test_finalized_withdrawal_survives_sequencer_restart() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    // Use a long withdrawal batch interval so this live L1 restart test knows
    // finalization was triggered by the withdrawal rather than an empty-batch boundary.
    let zone = ZoneTestNode::launch(ZoneLaunch {
        withdrawal_batch_interval_blocks: 10_000,
        ..ZoneLaunch::from_l1(&l1, portal_address)
    })
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount: u128 = 2_000_000;
    l1.fund_user(account.address(), deposit_amount).await?;
    account.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;

    let seq_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;

    let withdrawal_amount: u128 = 500_000;
    let l1_balance_before = l1.balance_of(PATH_USD_ADDRESS, account.address()).await?;
    account.withdraw(withdrawal_amount).await?;
    let withdrawal_block =
        wait_for_withdrawal_requested(&zone, account.address(), withdrawal_amount).await?;

    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, zone.provider());
    let same_block_finalized = outbox
        .BatchFinalized_filter()
        .select(withdrawal_block)
        .query()
        .await?;
    assert_eq!(
        same_block_finalized.len(),
        1,
        "withdrawal block {withdrawal_block} should emit BatchFinalized"
    );

    // Restart the batch submitter after proving the request block finalized its withdrawal.
    abort_task(seq_handle.monitor_handle).await?;
    abort_task(seq_handle.withdrawal_handle).await?;
    let _seq_handle2 = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;

    l1.wait_for_withdrawal_on_l1(
        portal_address,
        account.address(),
        l1_balance_before,
        withdrawal_amount,
        WITHDRAWAL_TIMEOUT,
    )
    .await?;

    Ok(())
}
