//! Extended-gap batch submission E2E test.
//!
//! When a zone node goes down long enough that finalized batch boundaries fall
//! outside the EIP-2935 history window, the sequencer must still submit each
//! boundary successfully once it comes back. This exercises the long-downtime
//! ancestry path instead of the simpler direct-mode case.

use crate::utils::{
    L1TestNode, ZoneTestNode, fetch_submit_batch_call, poll_until, spawn_sequencer,
    spawn_sequencer_with_config,
};
use alloy::providers::Provider;
use alloy_eips::eip2935::HISTORY_SERVE_WINDOW;
use alloy_rpc_types_eth::BlockId;
use std::time::Duration;
use tempo_contracts::zones::{
    IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_OUTBOX_ADDRESS, ZonePortal,
};
use zone_sequencer::BatchAnchorConfig;

const EIP2935_SAFETY_MARGIN: u64 = 360;
const EIP2935_EFFECTIVE_WINDOW: u64 = HISTORY_SERVE_WINDOW as u64 - EIP2935_SAFETY_MARGIN;
const EXTENDED_GAP_BLOCKS: u64 = HISTORY_SERVE_WINDOW as u64 + EIP2935_EFFECTIVE_WINDOW + 64;

const SHORT_EIP2935_HISTORY_WINDOW: u64 = 10;
const SHORT_EIP2935_SAFETY_MARGIN: u64 = 4;
const SHORT_EIP2935_EFFECTIVE_WINDOW: u64 =
    SHORT_EIP2935_HISTORY_WINDOW - SHORT_EIP2935_SAFETY_MARGIN;
const SHORT_EXTENDED_GAP_BLOCKS: u64 =
    SHORT_EIP2935_HISTORY_WINDOW + SHORT_EIP2935_EFFECTIVE_WINDOW + 1;
const SHORT_MULTI_BOUNDARY_BATCH_COUNT: u64 = 3;
const SHORT_MULTI_BOUNDARY_GAP_BLOCKS: u64 = SHORT_EIP2935_HISTORY_WINDOW
    + SHORT_EIP2935_EFFECTIVE_WINDOW * SHORT_MULTI_BOUNDARY_BATCH_COUNT
    + 1;
const CURRENT_TIP_BATCH_INTERVAL: u64 = 8;

/// Extended timeout for ancestry tests — the L1 needs to mine >16k blocks and
/// the zone must replay enough history to cross the first out-of-window boundary.
const STEPPING_TIMEOUT: Duration = Duration::from_secs(300);
const BATCH_TIMEOUT: Duration = Duration::from_secs(90);
const SHORT_STEPPING_TIMEOUT: Duration = Duration::from_secs(60);

/// A transaction submitted after observing L1 head N can only execute in N+1 or later. Prove that
/// the production submitter skips latest-state estimation and settles a batch anchored to N in
/// the immediate successor block, where EIP-2935 exposes hash(N).
#[tokio::test(flavor = "multi_thread")]
async fn test_current_tip_batch_submission_lands_in_successor_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start_with(|cfg| {
        cfg.dev.block_time = None;
    })
    .await?;
    let portal_address = l1.deploy_zone().await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    let genesis_anchor = l1.provider().get_block_number().await?;
    for offset in 1..=CURRENT_TIP_BATCH_INTERVAL {
        l1.fund_user(l1.admin_address(), 1).await?;
        zone.wait_for_tempo_block_number(genesis_anchor + offset, SHORT_STEPPING_TIMEOUT)
            .await?;
    }
    let current_tip = l1.provider().get_block_number().await?;
    eyre::ensure!(
        current_tip == genesis_anchor + CURRENT_TIP_BATCH_INTERVAL,
        "instant-mining setup produced an unexpected L1 range: genesis={genesis_anchor}, tip={current_tip}"
    );

    zone.wait_for_tempo_block_number(current_tip, SHORT_STEPPING_TIMEOUT)
        .await?;
    zone.wait_for_block_number(CURRENT_TIP_BATCH_INTERVAL, SHORT_STEPPING_TIMEOUT)
        .await?;
    eyre::ensure!(
        portal
            .BatchSubmitted_1_filter()
            .from_block(0)
            .query()
            .await?
            .is_empty(),
        "batch was submitted before the current-tip precondition was established"
    );

    let seq = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let (call, inclusion_block, tx_hash) = poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(100),
        "current-tip BatchSubmitted event",
        || {
            let portal = &portal;
            let seq = &seq;
            let l1 = &l1;
            async move {
                if seq.monitor_handle.is_finished() {
                    eyre::bail!("monitor task exited before submitting the current-tip batch");
                }
                if seq.withdrawal_handle.is_finished() {
                    eyre::bail!(
                        "withdrawal processor exited before current-tip batch submission completed"
                    );
                }

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
                let (call, inclusion_block) = fetch_submit_batch_call(l1, tx_hash).await?;
                Ok(Some((call, inclusion_block, tx_hash)))
            }
        },
    )
    .await?;

    eyre::ensure!(
        call.tempoBlockNumber == current_tip,
        "batch did not anchor to the observed current tip: expected={current_tip}, actual={}",
        call.tempoBlockNumber
    );
    eyre::ensure!(
        call.recentTempoBlockNumber == 0,
        "current-tip batch unexpectedly used ancestry mode"
    );
    eyre::ensure!(
        inclusion_block == current_tip + 1,
        "current-tip settlement did not land in the immediate successor block: anchor={current_tip}, inclusion={inclusion_block}"
    );

    tracing::info!(
        %tx_hash,
        anchor_block = call.tempoBlockNumber,
        settlement_block = inclusion_block,
        "Current-tip batch settled in the immediate successor block"
    );

    Ok(())
}

/// Test that batch submission works after the zone's `tempoBlockNumber` has
/// fallen far enough behind L1 that the first finalized batch boundary lands
/// outside the EIP-2935 history window.
///
/// 1. Start L1 with 10ms block time to mine blocks quickly.
/// 2. Deploy zone portal on L1.
/// 3. Wait for L1 to advance past `history + effective window`, so the first
///    submitted boundary is still outside the history window.
/// 4. Start zone node connected to L1, anchored at the portal genesis.
/// 5. Wait for the zone to replay up to the first out-of-window boundary.
/// 6. Spawn sequencer while the zone is still far behind L1.
/// 7. Assert a `BatchSubmitted` event appears.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: mines >16k L1 blocks and replays zone history, run with --ignored or in nightly CI"]
async fn test_batch_submission_after_extended_l1_gap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 with fast block time ---
    let l1 = L1TestNode::start_with(|cfg| {
        cfg.dev.block_time = Some(Duration::from_millis(10));
    })
    .await?;

    // --- Step 2: Deploy zone portal ---
    let portal_address = l1.deploy_zone().await?;

    let genesis_block = l1.provider().get_block_number().await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let target_block = genesis_block + EXTENDED_GAP_BLOCKS;

    tracing::info!(
        genesis_block,
        target_block,
        "Waiting for L1 to advance past the extended ancestry threshold"
    );

    // Poll until L1 reaches the target — at 10ms/block this takes ~160 seconds.
    let poll_start = std::time::Instant::now();
    loop {
        let current = l1.provider().get_block_number().await?;
        if current >= target_block {
            tracing::info!(
                current,
                target_block,
                elapsed_secs = poll_start.elapsed().as_secs(),
                "L1 advanced past EIP-2935 window"
            );
            break;
        }
        if poll_start.elapsed() > STEPPING_TIMEOUT {
            return Err(eyre::eyre!(
                "Timed out waiting for L1 to reach block {target_block} (current: {current})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // --- Step 4: Start zone node connected to L1, anchored at the portal genesis ---
    let zone = ZoneTestNode::start_from_l1_genesis_block(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        genesis_block,
    )
    .await?;

    // --- Step 5: Wait for the zone to replay to the first out-of-window boundary ---
    let first_step_tempo = genesis_block + EIP2935_EFFECTIVE_WINDOW;
    zone.wait_for_tempo_block_number(first_step_tempo, STEPPING_TIMEOUT)
        .await?;

    let l1_tip = l1.provider().get_block_number().await?;
    eyre::ensure!(
        l1_tip.saturating_sub(first_step_tempo) > HISTORY_SERVE_WINDOW as u64,
        "test precondition not met: first boundary tempo {first_step_tempo} is only {} blocks behind L1 tip {l1_tip}",
        l1_tip.saturating_sub(first_step_tempo),
    );

    // --- Step 6: Spawn sequencer while the zone still has a large backlog ---
    let seq = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;

    // --- Step 7: Assert batch submission succeeds after the long gap ---
    let batch_count = poll_until(
        BATCH_TIMEOUT,
        Duration::from_millis(500),
        "BatchSubmitted event after extended L1 gap",
        || {
            let portal = &portal;
            let seq = &seq;
            async move {
                if seq.monitor_handle.is_finished() {
                    eyre::bail!("monitor task exited before submitting a batch");
                }

                if seq.withdrawal_handle.is_finished() {
                    eyre::bail!("withdrawal processor exited before batch submission completed");
                }

                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                let batch_count = events.len();
                if batch_count >= 1 {
                    Ok(Some(batch_count))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    tracing::info!(
        batch_count,
        l1_tip,
        first_step_tempo,
        first_step_gap = l1_tip.saturating_sub(first_step_tempo),
        "Batch submission succeeded after extended L1 gap"
    );

    Ok(())
}

/// Same ancestry scenario as the ignored long-gap test, but with a 10-block
/// configured EIP-2935 window so it runs in regular integration test time.
#[tokio::test(flavor = "multi_thread")]
async fn test_batch_submission_after_configured_short_l1_gap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let anchor_config =
        BatchAnchorConfig::new(SHORT_EIP2935_HISTORY_WINDOW, SHORT_EIP2935_SAFETY_MARGIN)?;

    let l1 = L1TestNode::start_with(|cfg| {
        cfg.dev.block_time = Some(Duration::from_millis(20));
    })
    .await?;

    let portal_address = l1.deploy_zone().await?;
    let genesis_block = l1.provider().get_block_number().await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let target_block = genesis_block + SHORT_EXTENDED_GAP_BLOCKS;

    poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(50),
        "L1 advanced past configured short EIP-2935 window",
        || {
            let provider = l1.provider();
            async move {
                let current = provider.get_block_number().await?;
                if current >= target_block {
                    Ok(Some(current))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let zone = ZoneTestNode::start_from_l1_genesis_block(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        genesis_block,
    )
    .await?;

    let first_step_tempo = genesis_block + SHORT_EIP2935_EFFECTIVE_WINDOW;
    zone.wait_for_tempo_block_number(first_step_tempo, SHORT_STEPPING_TIMEOUT)
        .await?;

    let l1_tip = l1.provider().get_block_number().await?;
    eyre::ensure!(
        l1_tip.saturating_sub(first_step_tempo) > SHORT_EIP2935_HISTORY_WINDOW,
        "test precondition not met: first configured boundary tempo {first_step_tempo} is only {} blocks behind L1 tip {l1_tip}",
        l1_tip.saturating_sub(first_step_tempo),
    );

    let seq = spawn_sequencer_with_config(
        &l1,
        &zone,
        portal_address,
        l1.dev_signer(),
        anchor_config,
        zone_sequencer::WithdrawalBatchLimits::default(),
    )
    .await;

    poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(250),
        "BatchSubmitted event after configured short L1 gap",
        || {
            let portal = &portal;
            let seq = &seq;
            async move {
                if seq.monitor_handle.is_finished() {
                    eyre::bail!("monitor task exited before submitting a batch");
                }

                if seq.withdrawal_handle.is_finished() {
                    eyre::bail!("withdrawal processor exited before batch submission completed");
                }

                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                if events.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(events.len()))
                }
            }
        },
    )
    .await?;

    Ok(())
}

/// Verifies that a larger configured-window gap submits multiple finalized
/// batch boundaries before the sequencer catches up.
#[tokio::test(flavor = "multi_thread")]
async fn test_configured_short_l1_gap_submits_multiple_batch_boundaries() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let anchor_config =
        BatchAnchorConfig::new(SHORT_EIP2935_HISTORY_WINDOW, SHORT_EIP2935_SAFETY_MARGIN)?;

    // Start L1 with fast blocks so the configured test window ages out quickly.
    let l1 = L1TestNode::start_with(|cfg| {
        cfg.dev.block_time = Some(Duration::from_millis(20));
    })
    .await?;

    let portal_address = l1.deploy_zone().await?;
    let genesis_block = l1.provider().get_block_number().await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let target_block = genesis_block + SHORT_MULTI_BOUNDARY_GAP_BLOCKS;

    // Mine enough L1 blocks that catching up requires several ancestry batches.
    poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(50),
        "L1 advanced far enough to require multiple configured ancestry batches",
        || {
            let provider = l1.provider();
            async move {
                let current = provider.get_block_number().await?;
                if current >= target_block {
                    Ok(Some(current))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let zone = ZoneTestNode::start_from_l1_genesis_block(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        genesis_block,
    )
    .await?;

    // Wait for the actual finalized boundaries. Checkpoint-only catch-up blocks can advance across
    // many Tempo blocks without finalizing a batch, so fixed offsets from genesis are not reliable
    // boundary anchors.
    let zone_provider = zone.provider();
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &zone_provider);
    let tempo_state = TempoState::new(TEMPO_STATE_ADDRESS, &zone_provider);
    let boundary_tempo_block_numbers = poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(50),
        "multiple finalized zone batch boundaries",
        || {
            let outbox = &outbox;
            let tempo_state = &tempo_state;
            async move {
                let events = outbox.BatchFinalized_filter().from_block(0).query().await?;
                if events.len() < SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize {
                    return Ok(None);
                }

                let mut tempo_block_numbers =
                    Vec::with_capacity(SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize);
                for (_, log) in events
                    .iter()
                    .take(SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize)
                {
                    let zone_block = log
                        .block_number
                        .ok_or_else(|| eyre::eyre!("BatchFinalized log missing block number"))?;
                    let tempo_block_number = tempo_state
                        .tempoBlockNumber()
                        .block(BlockId::number(zone_block))
                        .call()
                        .await?;
                    tempo_block_numbers.push(tempo_block_number);
                }

                Ok(Some(tempo_block_numbers))
            }
        },
    )
    .await?;

    // Age even the newest selected boundary beyond the configured history window before starting
    // the sequencer, making ancestry mode independent of zone catch-up speed.
    let newest_boundary_tempo = *boundary_tempo_block_numbers
        .last()
        .ok_or_else(|| eyre::eyre!("expected at least one finalized batch boundary"))?;
    poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(50),
        "finalized zone batch boundaries aged past configured history window",
        || {
            let provider = l1.provider();
            async move {
                let current = provider.get_block_number().await?;
                if current.saturating_sub(newest_boundary_tempo) > SHORT_EIP2935_HISTORY_WINDOW {
                    Ok(Some(current))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    // Start the sequencer only after the backlog has accumulated.
    let seq = spawn_sequencer_with_config(
        &l1,
        &zone,
        portal_address,
        l1.dev_signer(),
        anchor_config,
        zone_sequencer::WithdrawalBatchLimits::default(),
    )
    .await;

    // Wait for the boundary walk to submit the first configured catch-up batches.
    let calls = poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(250),
        "multiple boundary BatchSubmitted events",
        || {
            let portal = &portal;
            let seq = &seq;
            let l1 = &l1;
            async move {
                if seq.monitor_handle.is_finished() {
                    eyre::bail!("monitor task exited before submitting boundary batches");
                }

                if seq.withdrawal_handle.is_finished() {
                    eyre::bail!("withdrawal processor exited before boundary batches completed");
                }

                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                if events.len() < SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize {
                    return Ok(None);
                }

                let mut calls = Vec::with_capacity(SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize);
                for (_, log) in events
                    .iter()
                    .take(SHORT_MULTI_BOUNDARY_BATCH_COUNT as usize)
                {
                    let tx_hash = log.transaction_hash.ok_or_else(|| {
                        eyre::eyre!("BatchSubmitted log missing transaction hash")
                    })?;
                    let (call, _) = fetch_submit_batch_call(l1, tx_hash).await?;
                    calls.push(call);
                }

                Ok(Some(calls))
            }
        },
    )
    .await?;

    let tempo_block_numbers = calls
        .iter()
        .map(|call| call.tempoBlockNumber)
        .collect::<Vec<_>>();
    eyre::ensure!(
        tempo_block_numbers == boundary_tempo_block_numbers,
        "submitted boundaries did not match the aged zone boundaries: submitted={tempo_block_numbers:?}, expected={boundary_tempo_block_numbers:?}"
    );
    // Each boundary submission should move the portal anchor forward.
    eyre::ensure!(
        tempo_block_numbers
            .windows(2)
            .all(|window| window[0] < window[1]),
        "boundary submissions should advance tempoBlockNumber monotonically: {tempo_block_numbers:?}"
    );
    // Since these boundaries are still out of the short direct window, they use ancestry mode.
    eyre::ensure!(
        calls
            .iter()
            .all(|call| call.recentTempoBlockNumber > call.tempoBlockNumber),
        "boundary catch-up submissions should use ancestry anchors: {tempo_block_numbers:?}"
    );
    // This pre-T11 test leaves proving unconfigured, so proof bytes stay empty.
    eyre::ensure!(
        calls.iter().all(|call| call.proof.is_empty()),
        "unconfigured boundary catch-up submissions should keep proof bytes empty"
    );

    Ok(())
}

/// Verifies that the fast configured-window ancestry path submits ancestry-mode
/// calldata, not a direct `tempoBlockNumber` lookup. Proving is intentionally unconfigured, so
/// this also preserves the pre-T11 empty-proof path.
#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_ancestry_submission_uses_recent_anchor() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let anchor_config =
        BatchAnchorConfig::new(SHORT_EIP2935_HISTORY_WINDOW, SHORT_EIP2935_SAFETY_MARGIN)?;

    let l1 = L1TestNode::start_with(|cfg| {
        cfg.dev.block_time = Some(Duration::from_millis(20));
    })
    .await?;

    let portal_address = l1.deploy_zone().await?;
    let genesis_block = l1.provider().get_block_number().await?;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let target_block = genesis_block + SHORT_EXTENDED_GAP_BLOCKS;

    poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(50),
        "L1 advanced past configured short EIP-2935 window",
        || {
            let provider = l1.provider();
            async move {
                let current = provider.get_block_number().await?;
                if current >= target_block {
                    Ok(Some(current))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    let zone = ZoneTestNode::start_from_l1_genesis_block(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        genesis_block,
    )
    .await?;

    let first_step_tempo = genesis_block + SHORT_EIP2935_EFFECTIVE_WINDOW;
    zone.wait_for_tempo_block_number(first_step_tempo, SHORT_STEPPING_TIMEOUT)
        .await?;

    let l1_tip = l1.provider().get_block_number().await?;
    eyre::ensure!(
        l1_tip.saturating_sub(first_step_tempo) > SHORT_EIP2935_HISTORY_WINDOW,
        "test precondition not met: first configured boundary tempo {first_step_tempo} is only {} blocks behind L1 tip {l1_tip}",
        l1_tip.saturating_sub(first_step_tempo),
    );

    let seq = spawn_sequencer_with_config(
        &l1,
        &zone,
        portal_address,
        l1.dev_signer(),
        anchor_config,
        zone_sequencer::WithdrawalBatchLimits::default(),
    )
    .await;

    let (call, inclusion_block) = poll_until(
        SHORT_STEPPING_TIMEOUT,
        Duration::from_millis(250),
        "ancestry submitBatch calldata using recent anchor",
        || {
            let portal = &portal;
            let seq = &seq;
            let l1 = &l1;
            async move {
                if seq.monitor_handle.is_finished() {
                    eyre::bail!("monitor task exited before submitting a batch");
                }

                if seq.withdrawal_handle.is_finished() {
                    eyre::bail!("withdrawal processor exited before batch submission completed");
                }

                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                for (_, log) in events {
                    let tx_hash = log.transaction_hash.ok_or_else(|| {
                        eyre::eyre!("BatchSubmitted log missing transaction hash")
                    })?;
                    let (call, inclusion_block) = fetch_submit_batch_call(l1, tx_hash).await?;

                    if call.recentTempoBlockNumber != 0 {
                        return Ok(Some((call, inclusion_block)));
                    }
                }

                Ok(None)
            }
        },
    )
    .await?;

    eyre::ensure!(
        call.recentTempoBlockNumber > call.tempoBlockNumber,
        "ancestry submission should use a recent anchor greater than tempoBlockNumber"
    );
    eyre::ensure!(
        inclusion_block.saturating_sub(call.tempoBlockNumber) > SHORT_EIP2935_EFFECTIVE_WINDOW,
        "test did not submit an out-of-config-window tempo block: tempo={}, included_at={inclusion_block}",
        call.tempoBlockNumber,
    );
    eyre::ensure!(
        call.proof.is_empty(),
        "unconfigured ancestry submission should keep proof bytes empty"
    );

    Ok(())
}
