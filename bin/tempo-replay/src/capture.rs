use crate::{
    config::Config,
    journal::{SharedJournal, lock},
    model::*,
    rpc::{EvidenceError, Rpc, RpcError, source_subscription},
};
use alloy_primitives::B256;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn capture_once(
    c: &Config,
    rpc: &Rpc,
    journal: &SharedJournal,
    event: Option<Value>,
    to: Option<u64>,
    stop: &CancellationToken,
) -> Result<u64> {
    let value = match event {
        Some(v) => v,
        None => rpc
            .call("consensus_getLatest", json!([]))
            .await?
            .get("finalized")
            .filter(|v| !v.is_null())
            .context("no finalized source block")?
            .clone(),
    };
    let anchor = match CapturedBlock::from_certified(value.clone(), c.run.chain_id) {
        Ok(b) => b,
        Err(e) => {
            lock(journal)?.put(format!("evidence/incompatible/{}", now_ms()), &value)?;
            return Err(e);
        }
    };
    let (first, previous) = {
        let j = lock(journal)?;
        (
            j.state.first_height,
            j.state.cursors.captured_through.clone(),
        )
    };
    if let Some(prev) = &previous {
        if anchor.point.height == prev.height {
            ensure!(&anchor.point == prev, "finalized source hash changed");
            return Ok(prev.height);
        }
        if anchor.point.height < prev.height {
            if let Some(known) = lock(journal)?.block(anchor.point.height)? {
                ensure!(
                    known.point == anchor.point,
                    "delayed finalized event conflicts with canonical history"
                );
            }
            return Ok(prev.height);
        } // delayed socket event
    }
    let start = previous
        .as_ref()
        .map_or(first, |p| p.height.saturating_add(1));
    let end = to.map_or(anchor.point.height, |n| n.min(anchor.point.height));
    if end < start {
        return Ok(previous.map_or(start.saturating_sub(1), |p| p.height));
    }
    let anchor = if end == anchor.point.height {
        anchor
    } else {
        match rpc.certified(end, c.run.chain_id).await {
            Ok(block) => block,
            Err(e) if e.downcast_ref::<RpcError>().is_some() => anchor,
            Err(e) => return Err(e),
        }
    };
    ensure!(
        anchor.point.height.saturating_sub(start) < c.source.recovery_horizon_blocks,
        "backlog exceeds configured recovery horizon; extend the horizon without changing the cursor"
    );
    let mut parent = if let Some(p) = previous {
        p.hash
    } else if start == 0 {
        B256::ZERO
    } else {
        rpc.header_point(start - 1).await?.hash
    };
    let mut last_time = if start > 0 {
        lock(journal)?.block(start - 1)?.map(|b| b.timestamp_ms)
    } else {
        None
    };
    for height in start..=anchor.point.height {
        ensure!(!stop.is_cancelled(), "capture cancelled");
        let block = if height == anchor.point.height {
            anchor.clone()
        } else {
            match rpc
                .call("consensus_getFinalization", json!([{"height":height}]))
                .await
            {
                Ok(value) => match CapturedBlock::from_certified(value.clone(), c.run.chain_id) {
                    Ok(b) => b,
                    Err(e) => {
                        lock(journal)?
                            .put(format!("evidence/incompatible/{height:020}"), &value)?;
                        return Err(e);
                    }
                },
                Err(e) if e.downcast_ref::<RpcError>().is_some() => {
                    match rpc.execution(height, c.run.chain_id, true).await {
                        Ok(block) => block,
                        Err(e) => {
                            if let Some(evidence) = e.downcast_ref::<EvidenceError>() {
                                lock(journal)?.put(
                                    format!("evidence/incompatible/{height:020}"),
                                    &evidence.value,
                                )?;
                            }
                            return Err(e);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        };
        ensure!(
            block.point.height == height && block.parent == parent,
            "source ancestry mismatch at {height}"
        );
        ensure!(
            last_time.is_none_or(|t| block.timestamp_ms >= t),
            "source timestamp regressed"
        );
        ensure!(
            serde_json::to_vec(&block)?.len() as u64 <= c.limits.max_buffered_bytes,
            "decoded block exceeds byte bound"
        );
        parent = block.point.hash;
        last_time = Some(block.timestamp_ms);
        lock(journal)?.stage(&block)?;
    }
    ensure!(
        parent == anchor.point.hash,
        "recovered range does not reach finality anchor"
    );
    let end_point = lock(journal)?
        .block(end)?
        .context("verified end block missing")?
        .point;
    lock(journal)?.put("meta/finality_anchor", &anchor.point)?;
    lock(journal)?.publish(&end_point, start)?;
    Ok(end)
}
pub async fn capture_loop(
    c: Config,
    rpc: Rpc,
    journal: SharedJournal,
    to: Option<u64>,
    stop: CancellationToken,
) -> Result<()> {
    let (mut events, subscription) = source_subscription(
        c.source.consensus_ws.clone(),
        c.limits.max_buffered_bytes as usize,
        stop.child_token(),
    );
    let result: Result<()> = async {
    loop {
        if stop.is_cancelled() { break; }
        let event = if events.has_changed().unwrap_or(false) { events.borrow_and_update().clone() } else { None };
        let r = capture_once(&c, &rpc, &journal, event, to, &stop).await;
        if r.is_ok() {
            let mut j = lock(&journal)?;
            if j.state.capture_error.take().is_some() { j.save_state()?; }
        }
        match r {
            Ok(h) if to.is_some_and(|n| h >= n) => break,
            Ok(_) => {},
            Err(_) if stop.is_cancelled() => break,
            Err(e) if e.downcast_ref::<RpcError>().is_some() => {
                let mut j = lock(&journal)?; j.state.capture_error = Some(e.to_string()); j.save_state()?;
                tracing::warn!("source RPC unavailable; retaining capture cursor");
            }
            Err(e) => { lock(&journal)?.incident(&format!("capture: {e:#}"))?; return Err(e); }
        }
        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(250)) => {}, r = events.changed() => { if r.is_err() { break; } } }
    }
    Ok(())
    }.await;
    // Abort is only used for the read-only socket task. No submission future is detached.
    subscription.abort();
    let _ = subscription.await;
    result
}
