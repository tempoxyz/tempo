use crate::{
    config::Config,
    journal::{SharedJournal, lock},
    model::*,
    rpc::{Rpc, RpcError, quantity},
    timing::Pacer,
    verify::{Qualified, check_target, route},
};
use alloy_primitives::{Address, B256};
use anyhow::{Context, Result, bail, ensure};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

type Pending = FuturesUnordered<BoxFuture<'static, (String, Result<Value>)>>;
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Ambiguous,
    Capacity,
    Transport,
    Expired,
    NonceLow,
    Dependency,
    Incident,
}
pub fn classify(e: &RpcError) -> Outcome {
    let m = e.message.to_ascii_lowercase();
    if e.ambiguous {
        return Outcome::Ambiguous;
    }
    if e.code == 429 || e.code == 503 || e.code == 502 || e.code == -1 {
        return Outcome::Transport;
    }
    if e.code == 401 || e.code == 403 || e.code == -32601 {
        return Outcome::Incident;
    }
    if m.contains("already known") || m.contains("already imported") {
        return Outcome::Accepted;
    }
    if m.contains("chain id")
        || m.contains("chainid")
        || m.contains("signature")
        || m.contains("unsupported")
        || m.contains("unknown transaction type")
    {
        return Outcome::Incident;
    }
    if m.contains("capacity")
        || m.contains("pool full")
        || m.contains("spammer")
        || m.contains("exceeds maximum number")
    {
        return Outcome::Capacity;
    }
    if m.contains("expired") || m.contains("valid_before") || m.contains("valid before") {
        return Outcome::Expired;
    }
    if m.contains("nonce too low")
        || m.contains("nonce is too low")
        || m.contains("already mined")
        || m.contains("nonce has already")
    {
        return Outcome::NonceLow;
    }
    // Only recognized state/admission failures become bounded dependency gaps.
    // An unfamiliar RPC rejection is a compatibility incident, never guessed permanent.
    if [
        "insufficient",
        "nonce too high",
        "nonce gap",
        "future nonce",
        "underpriced",
        "fee token",
        "feepayer",
        "fee payer",
        "sponsor",
        "liquidity",
        "not yet valid",
        "valid_after",
        "policy",
        "authorization",
        "execution reverted",
    ]
    .iter()
    .any(|s| m.contains(s))
    {
        return Outcome::Dependency;
    }
    Outcome::Incident
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaneBlock {
    source_height: u64,
    source_index: usize,
    hash: B256,
    reason: String,
}
#[derive(Default)]
pub struct Budget {
    hashes: BTreeSet<B256>,
    senders: BTreeMap<Address, usize>,
    pub bytes: u64,
}
impl Budget {
    pub fn from_active(active: &BTreeMap<String, Occurrence>, q: &Qualified) -> Self {
        let mut b = Self::default();
        for o in active.values().filter(|o| o.state.holds_credit()) {
            b.reserve(o, q);
        }
        b
    }
    pub fn can_reserve(&self, o: &Occurrence, q: &Qualified) -> bool {
        self.hashes.contains(&o.tx.hash)
            || (self.hashes.len() < q.count_budget
                && self.senders.get(&o.tx.sender).copied().unwrap_or(0) < q.sender_budget
                && self.bytes.saturating_add(cost(o, q)) <= q.byte_budget)
    }
    fn reserve(&mut self, o: &Occurrence, q: &Qualified) {
        if self.hashes.insert(o.tx.hash) {
            *self.senders.entry(o.tx.sender).or_default() += 1;
            self.bytes = self.bytes.saturating_add(cost(o, q));
        }
    }
}
fn cost(o: &Occurrence, q: &Qualified) -> u64 {
    o.tx.raw_len()
        .saturating_mul(q.multiplier)
        .saturating_add(q.overhead)
}
fn after(o: &Occurrence, blocked: &LaneBlock) -> bool {
    (o.source.height, o.index) > (blocked.source_height, blocked.source_index)
}
fn gap(journal: &SharedJournal, o: &mut Occurrence, reason: &str) -> Result<()> {
    let mut j = lock(journal)?;
    let mut lane_update = None;
    if let Some(lane) = o.tx.lane() {
        let old: Option<LaneBlock> = j.get(format!("lane/{lane}"))?;
        if old.as_ref().is_none_or(|b| !after(o, b)) {
            lane_update = Some((
                format!("lane/{lane}"),
                LaneBlock {
                    source_height: o.source.height,
                    source_index: o.index,
                    hash: o.tx.hash,
                    reason: reason.into(),
                },
            ));
        }
    }
    o.transition(
        State::Gap {
            reason: reason.into(),
        },
        reason,
    );
    if let Some((key, block)) = lane_update {
        j.update_and_put(o, &key, &block)?;
    } else {
        j.update(o)?;
    }
    tracing::warn!(reason, "coverage degraded: user occurrence has a gap");
    Ok(())
}

pub async fn observe_target(
    c: &Config,
    rpc: &Rpc,
    journal: &SharedJournal,
    stop: &CancellationToken,
) -> Result<bool> {
    let anchor = rpc.latest_finalized(c.run.chain_id).await?;
    let checkpoint = c.checkpoint.as_ref().context("missing checkpoint")?;
    let previous = lock(journal)?
        .state
        .cursors
        .shadow_observed_through
        .clone()
        .unwrap_or(Point {
            height: checkpoint.source_height,
            hash: checkpoint.shadow_hash.parse()?,
        });
    if anchor.point.height < previous.height {
        return Ok(false);
    }
    if anchor.point.height == previous.height {
        ensure!(anchor.point == previous, "shadow finalized hash conflict");
        return Ok(false);
    }
    ensure!(
        anchor.point.height.saturating_sub(previous.height) <= c.source.recovery_horizon_blocks,
        "shadow observation backlog exceeds recovery horizon"
    );
    let mut parent = previous.hash;
    for h in previous.height + 1..=anchor.point.height {
        ensure!(!stop.is_cancelled(), "target observation cancelled");
        let b = if h == anchor.point.height {
            anchor.clone()
        } else {
            rpc.execution(h, c.run.chain_id, false).await?
        };
        ensure!(
            b.parent == parent,
            "shadow finalized ancestry conflict at {h}"
        );
        parent = b.point.hash;
        lock(journal)?.check_disk()?;
        lock(journal)?.put(format!("target/staged/{h:020}"), &b)?;
    }
    ensure!(
        parent == anchor.point.hash,
        "shadow finality anchor mismatch"
    );
    // Publish target evidence only after the range reaches the finality anchor.
    for h in previous.height + 1..=anchor.point.height {
        let b: CapturedBlock = lock(journal)?
            .get(format!("target/staged/{h:020}"))?
            .context("target staging missing")?;
        lock(journal)?.publish_target(&b)?;
    }
    Ok(true)
}
async fn finalized_receipt(
    rpc: &Rpc,
    journal: &SharedJournal,
    hash: B256,
) -> Result<Option<Value>> {
    let inclusion: Option<Inclusion> = lock(journal)?.get(format!("inclusion/{hash}"))?;
    let Some(i) = inclusion else {
        return Ok(None);
    };
    let r = rpc.call("eth_getTransactionReceipt", json!([hash])).await?;
    ensure!(
        !r.is_null(),
        "receipt missing for finalized target transaction"
    );
    ensure!(
        serde_json::from_value::<B256>(r["transactionHash"].clone())? == hash
            && serde_json::from_value::<B256>(r["blockHash"].clone())? == i.point.hash
            && quantity(&r["blockNumber"])? == i.point.height
            && quantity(&r["transactionIndex"])? == i.index as u64,
        "target receipt disagrees with finalized block"
    );
    quantity(&r["status"])?;
    quantity(&r["gasUsed"])?;
    Ok(Some(r))
}
async fn reconcile_one(
    c: &Config,
    source: &Rpc,
    target: &Rpc,
    journal: &SharedJournal,
    o: &mut Occurrence,
) -> Result<()> {
    if let Some(r) = finalized_receipt(target, journal, o.tx.hash).await? {
        let sr = source
            .call("eth_getTransactionReceipt", json!([o.tx.hash]))
            .await?;
        ensure!(
            !sr.is_null()
                && serde_json::from_value::<B256>(sr["transactionHash"].clone())? == o.tx.hash
                && serde_json::from_value::<B256>(sr["blockHash"].clone())? == o.source.hash
                && quantity(&sr["transactionIndex"])? == o.index as u64,
            "source receipt disagrees with captured occurrence"
        );
        o.receipt_mismatch = Some(
            quantity(&r["status"])? != quantity(&sr["status"])?
                || quantity(&r["gasUsed"])? != quantity(&sr["gasUsed"])?,
        );
        o.receipt = Some(r);
        o.source_receipt = Some(sr);
        o.transition(
            State::Finalized,
            "observed in verified finalized target history",
        );
        lock(journal)?.update(o)?;
        return Ok(());
    }
    if let Some(lane) = o.tx.lane() {
        let consumed: Option<B256> =
            lock(journal)?.get(format!("consumed/{lane}/{}", o.tx.nonce))?;
        ensure!(
            consumed.is_none_or(|h| h == o.tx.hash),
            "a different finalized transaction consumed the required nonce"
        );
    }
    let nonce_low = lock(journal)?
        .get::<bool>(format!("nonce_low/{}", o.tx.hash))?
        .unwrap_or(false);
    if nonce_low && !o.tx.expiring {
        let observed_point = lock(journal)?.state.cursors.shadow_observed_through.clone();
        if let Some(point) = observed_point {
            let block = json!({"blockHash": point.hash, "requireCanonical": true});
            let current = if o.tx.nonce_key.is_zero() {
                quantity(
                    &target
                        .call("eth_getTransactionCount", json!([o.tx.sender, block]))
                        .await?,
                )?
            } else {
                let selector = alloy_primitives::keccak256(b"getNonce(address,uint256)");
                let mut data = selector[..4].to_vec();
                data.extend_from_slice(&[0; 12]);
                data.extend_from_slice(o.tx.sender.as_slice());
                data.extend_from_slice(&o.tx.nonce_key.to_be_bytes::<32>());
                let v = target.call("eth_call", json!([{"to":"0x4E4F4E4345000000000000000000000000000000", "data":format!("0x{}", hex::encode(data))}, block])).await?;
                let word: alloy_primitives::U256 = serde_json::from_value(v)?;
                u64::try_from(word).context("nonce state overflow")?
            };
            ensure!(
                current <= o.tx.nonce,
                "required nonce consumed in finalized shadow state without this transaction hash"
            );
        }
    }
    if matches!(
        o.state,
        State::Unknown | State::Attempting | State::Accepted
    ) {
        let found = target
            .call("eth_getTransactionByHash", json!([o.tx.hash]))
            .await?;
        if !found.is_null() {
            ensure!(
                serde_json::from_value::<B256>(found["hash"].clone())? == o.tx.hash,
                "transaction lookup hash mismatch"
            );
            if o.state != State::Accepted {
                o.transition(
                    State::Accepted,
                    "exact hash observed on shadow; finality pending",
                );
                lock(journal)?.update(o)?;
            }
        } else if o.retry_at_ms == 0
            && !nonce_low
            && o.state != State::Accepted
            && o.ambiguous_resends < c.delivery.ambiguous_resend_limit
            && !o.tx.expired_at(lock(journal)?.state.target_tip_seconds)
        {
            o.retry_at_ms = now_ms().saturating_add(1000);
            lock(journal)?.update(o)?;
        }
        // A null lookup is not proof of pool removal, especially across validators.
        // Keep the reservation and expose a recovery incident if it cannot be resolved.
        if o.last_attempt_ms
            .is_some_and(|t| now_ms().saturating_sub(t) > c.timing.target_progress_timeout_ms)
            && o.state != State::Finalized
        {
            lock(journal)?.incident("recoverable: unresolved pool reservation; awaiting exact-hash finality/removal evidence")?;
        }
    }
    Ok(())
}
async fn reconcile_active(
    c: &Config,
    q: &Qualified,
    source: &Rpc,
    target_index: usize,
    journal: &SharedJournal,
    active: &mut BTreeMap<String, Occurrence>,
) -> Result<()> {
    // Receipt lookups are bounded by the same worker limit as submissions. Each worker
    // updates a distinct occurrence through the single journal writer.
    let target = &q.targets[target_index].rpc;
    let mut jobs = futures_util::stream::iter(active.values().cloned().map(|mut o| async move {
        if !matches!(
            o.state,
            State::GeneratedByShadowConsensus | State::Gap { .. } | State::Finalized
        ) {
            reconcile_one(c, source, target, journal, &mut o).await?;
        }
        Ok::<_, anyhow::Error>((o.key(), o))
    }))
    .buffer_unordered(c.limits.max_inflight_rpc);
    let mut refreshed = BTreeMap::new();
    while let Some(r) = jobs.next().await {
        let (key, o) = r?;
        refreshed.insert(key, o);
    }
    drop(jobs);
    *active = refreshed;
    Ok(())
}
fn load_released(c: &Config, journal: &SharedJournal) -> Result<BTreeMap<String, Occurrence>> {
    let j = lock(journal)?;
    let boundary = j.state.replay_boundary.context("journal not bound")?;
    let start = j
        .state
        .cursors
        .accounted_through
        .unwrap_or(boundary)
        .saturating_add(1);
    let end = j.state.last_release_height.unwrap_or(boundary);
    ensure!(
        end.saturating_sub(start) < c.limits.max_blocks_ahead,
        "persisted backlog exceeds configured lookahead"
    );
    let mut out = BTreeMap::new();
    let mut bytes = 0u64;
    for h in start..=end {
        for o in j.occurrences(h)? {
            if !o.state.terminal() {
                bytes += serde_json::to_vec(&o)?.len() as u64;
                ensure!(
                    bytes <= c.limits.max_buffered_bytes,
                    "persisted outstanding work exceeds memory bound"
                );
                out.insert(o.key(), o);
            }
        }
    }
    Ok(out)
}
fn record_segment(journal: &SharedJournal, pacer: &Pacer) -> Result<()> {
    let mut j = lock(journal)?;
    j.put(
        format!("phase/{:020}/{:020}", now_ms(), pacer.segment.first_height),
        &pacer.segment,
    )?;
    j.state.phase = pacer.segment.phase.clone();
    j.save_state()?;
    tracing::info!(phase = ?pacer.segment.phase, from_block = pacer.segment.first_height, speed = pacer.segment.speed, "mirror pacing phase changed");
    Ok(())
}

pub async fn replay(
    c: Config,
    q: Qualified,
    source: Rpc,
    journal: SharedJournal,
    to: Option<u64>,
    acknowledge: bool,
    stop: CancellationToken,
) -> Result<()> {
    {
        let mut j = lock(&journal)?;
        if let Some(incident) = &j.state.incident {
            ensure!(
                acknowledge || incident.starts_with("recoverable:"),
                "journal is paused: {incident}; investigate then use --acknowledge-incident or a new checkpoint"
            );
        }
        if let Some(b) = j.block(
            c.checkpoint
                .as_ref()
                .context("checkpoint missing")?
                .source_height
                .saturating_add(1),
        )? {
            ensure!(
                b.parent == c.checkpoint.as_ref().unwrap().source_hash.parse::<B256>()?,
                "captured backlog does not descend from configured source boundary"
            );
        }
        j.bind(
            c.checkpoint
                .as_ref()
                .context("checkpoint missing")?
                .source_height,
            &q.binding,
        )?;
        j.state.phase = Phase::Reconcile;
        j.state.incident = None;
        j.save_state()?;
    }
    let mut active = load_released(&c, &journal)?;
    for o in active.values_mut().filter(|o| o.state == State::Attempting) {
        o.transition(
            State::Unknown,
            "restart after durable attempt intent; response unknown",
        );
        o.retry_at_ms = 0;
        lock(&journal)?.update(o)?;
    }
    let mut pending = Pending::new();
    let mut inflight = BTreeSet::new();
    let mut available = vec![true; q.targets.len()];
    let mut observer = 0usize;
    let mut pacer: Option<Pacer> = None;
    let mut last_identity = Instant::now();
    let mut last_observe = Instant::now() - Duration::from_secs(1);
    let mut last_progress = Instant::now();
    let mut started = false;
    let work: Result<()> = async {
        loop {
            if stop.is_cancelled() { break; }
            lock(&journal)?.check_disk()?;
            if last_identity.elapsed().as_millis() >= u128::from(c.shadow.as_ref().unwrap().identity_check_interval_ms) {
                for (index, target) in q.targets.iter().enumerate() {
                    match check_target(&target.rpc, &c).await {
                        Ok(()) => available[index] = true,
                        Err(e) if e.downcast_ref::<RpcError>().is_some() => available[index] = false,
                        Err(e) => return Err(e.context("periodic target identity verification")),
                    }
                }
                last_identity = Instant::now();
            }
            // Drain submission responses before reconciliation; durable Attempting entries
            // remain reserved while their requests are on the wire.
            if last_observe.elapsed() >= Duration::from_millis(250) && pending.is_empty() {
                let mut observed = false;
                for (i, available_now) in available.iter_mut().enumerate() {
                    if !*available_now { continue; }
                    match observe_target(&c, &q.targets[i].rpc, &journal, &stop).await {
                        Ok(progress) => { observer = i; observed = true; if progress { last_progress = Instant::now(); } break; },
                        Err(_) if stop.is_cancelled() => break,
                        Err(e) if e.downcast_ref::<RpcError>().is_some() => { *available_now = false; },
                        Err(e) => return Err(e),
                    }
                }
                if observed {
                    match reconcile_active(&c, &q, &source, observer, &journal, &mut active).await {
                        Ok(()) => { started = true; },
                        Err(e) if e.downcast_ref::<RpcError>().is_some() => { started = false; },
                        Err(e) => return Err(e),
                    }
                    let mut j = lock(&journal)?;
                    let reservations_recent = active.values().filter(|o| o.state.holds_credit()).all(|o| o.last_attempt_ms.is_none_or(|ms| now_ms().saturating_sub(ms) <= c.timing.target_progress_timeout_ms));
                    if j.state.incident.as_ref().is_some_and(|i| i.starts_with("recoverable:")) && reservations_recent && last_progress.elapsed().as_millis() < u128::from(c.timing.target_progress_timeout_ms) {
                        j.state.incident = None; j.state.phase = Phase::Reconcile; pacer = None; j.save_state()?;
                    }
                } else { started = false; }
                last_observe = Instant::now();
            }
            if last_progress.elapsed().as_millis() >= u128::from(c.timing.target_progress_timeout_ms) { lock(&journal)?.incident("recoverable: target finality stalled or unavailable")?; }
            lock(&journal)?.refresh_cursors()?;
            active.retain(|_, o| !o.state.terminal());
            let state = lock(&journal)?.state.clone();
            if to.is_some_and(|h| state.cursors.accounted_through.is_some_and(|n| n >= h)) && pending.is_empty() { break; }
            if let Some(incident) = &state.incident && !incident.starts_with("recoverable:") { bail!("dispatch paused: {incident}"); }
            if started && state.incident.is_none() {
                // Load and release at most one source block per loop. The accounted frontier
                // bounds unresolved lookahead; captured backlog remains on disk.
                let boundary = state.replay_boundary.unwrap();
                let next = state.last_release_height.unwrap_or(boundary).saturating_add(1);
                if state.cursors.captured_through.as_ref().is_some_and(|p| next <= p.height) && to.is_none_or(|h| next <= h) && next <= state.cursors.accounted_through.unwrap_or(boundary).saturating_add(c.limits.max_blocks_ahead) {
                    let block = lock(&journal)?.block(next)?.context("captured dispatch block missing")?;
                    if pacer.is_none() {
                        pacer = Some(Pacer::new(&c.timing, Phase::CatchUp, next, block.timestamp_ms, "startup or recovery")); record_segment(&journal, pacer.as_ref().unwrap())?;
                    }
                    let p = pacer.as_mut().unwrap();
                    let dispatched = state.cursors.dispatch_accounted_through.unwrap_or(boundary);
                    let can_live = dispatched >= next - 1 && now_ms().saturating_sub(block.timestamp_ms) <= c.timing.target_lag_ms;
                    if p.segment.phase == Phase::CatchUp && can_live { *p = Pacer::new(&c.timing, Phase::Live, next, block.timestamp_ms, "contiguous dispatch frontier reached live lag"); record_segment(&journal, p)?; }
                    if p.segment.phase == Phase::Live && p.consecutive_slips >= c.timing.slip_window_blocks { *p = Pacer::new(&c.timing, Phase::CatchUp, next, block.timestamp_ms, "sustained live schedule slip"); record_segment(&journal, p)?; }
                    if Instant::now() >= p.release_at(block.timestamp_ms)? {
                        let entries = lock(&journal)?.occurrences(next)?;
                        let bytes: u64 = active.values().chain(entries.iter()).map(|o| serde_json::to_vec(o).map(|v| v.len() as u64)).collect::<std::result::Result<Vec<_>, _>>()?.into_iter().sum();
                        ensure!(serde_json::to_vec(&entries)?.len() as u64 <= c.limits.max_buffered_bytes, "single block cannot fit scheduler memory bound");
                        if bytes <= c.limits.max_buffered_bytes {
                            let slip = p.released(block.timestamp_ms, &c.timing)?;
                            for o in entries { if !o.state.terminal() { active.insert(o.key(), o); } }
                            let mut j = lock(&journal)?; j.state.last_release_height = Some(next); j.state.lag_ms = now_ms().saturating_sub(block.timestamp_ms); j.state.slip_ms = slip; j.save_state()?;
                        }
                    }
                }
                if last_observe.elapsed() < Duration::from_millis(250) { issue(&c, &q, &journal, &mut active, &mut pending, &mut inflight, &available)?; }
            }
            tokio::select! {
                _ = stop.cancelled() => break,
                result = pending.next(), if !pending.is_empty() => {
                    if let Some((key, result)) = result { inflight.remove(&key); handle_response(&c, &journal, &mut active, &key, result)?; }
                },
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        Ok(())
    }.await;
    // Stop issuing first, then drain every bounded HTTP request. This also handles errors.
    while let Some((key, result)) = pending.next().await {
        if let Err(e) = handle_response(&c, &journal, &mut active, &key, result) {
            tracing::error!(error = %e, "submission drain requires recovery");
        }
    }
    if let Err(e) = &work {
        lock(&journal)?.incident(&format!("replay: {e:#}"))?;
    }
    lock(&journal)?.refresh_cursors()?;
    lock(&journal)?.flush()?;
    work
}

fn issue(
    c: &Config,
    q: &Qualified,
    journal: &SharedJournal,
    active: &mut BTreeMap<String, Occurrence>,
    pending: &mut Pending,
    inflight: &mut BTreeSet<String>,
    available: &[bool],
) -> Result<()> {
    let mut budget = Budget::from_active(active, q);
    let mut lane_counts = BTreeMap::<String, usize>::new();
    let mut frozen = BTreeMap::<String, String>::new();
    for (key, o) in active.iter() {
        if let Some(lane) = o.tx.lane() {
            if o.state.holds_credit() {
                *lane_counts.entry(lane.clone()).or_default() += 1;
            }
            if matches!(o.state, State::Deferred | State::Unknown) {
                frozen.entry(lane).or_insert_with(|| key.clone());
            }
        }
    }
    let mut prepared = Vec::new();
    for (key, o) in active.iter_mut() {
        if pending.len() + prepared.len() >= c.limits.max_inflight_rpc {
            break;
        }
        if o.state.terminal()
            || inflight.contains(key)
            || matches!(o.state, State::Accepted | State::Attempting)
        {
            continue;
        }
        if o.tx.class == Class::Subblock {
            lock(journal)?.incident(
                "RequiresNativeIngress: source contains a reserved subblock transaction",
            )?;
            bail!("subblock route is unsupported; dispatch paused");
        }
        if let Some(lane) = o.tx.lane() {
            let blocked: Option<LaneBlock> = lock(journal)?.get(format!("lane/{lane}"))?;
            if blocked.as_ref().is_some_and(|b| after(o, b)) {
                if !o.state.holds_credit() {
                    gap(journal, o, "BlockedDependency")?;
                }
                continue;
            }
            if frozen.get(&lane).is_some_and(|first| first != key) {
                continue;
            }
            let window = if q
                .targets
                .iter()
                .all(|t| t.evidence.future_nonce_types.contains(&o.tx.tx_type))
            {
                c.limits.max_inflight_per_lane
            } else {
                1
            };
            if !o.state.holds_credit() && lane_counts.get(&lane).copied().unwrap_or(0) >= window {
                continue;
            }
        }
        if o.retry_at_ms > now_ms() {
            continue;
        }
        let ambiguous_resend = o.state == State::Unknown;
        if ambiguous_resend
            && (o.retry_at_ms == 0
                || o.ambiguous_resends >= c.delivery.ambiguous_resend_limit
                || o.tx.expired_at(lock(journal)?.state.target_tip_seconds))
        {
            continue;
        }
        if !budget.can_reserve(o, q) {
            continue;
        }
        let Some(index) = route(o.tx.sender, &q.targets, available) else {
            continue;
        };
        // Failover only follows the observation/reconciliation pass. Unknown outcomes
        // stay reserved, and an existing attempt is never rewritten or re-signed.
        if o.endpoint
            .as_ref()
            .is_some_and(|id| id != &q.targets[index].id)
            && ambiguous_resend
        {
            continue;
        }
        if let Some(since) = o.dependency_since_ms
            && !o.state.holds_credit()
            && now_ms().saturating_sub(since) >= c.delivery.dependency_wait_timeout_ms
        {
            gap(journal, o, "DependencyTimeout")?;
            continue;
        }
        let had_credit = o.state.holds_credit();
        budget.reserve(o, q);
        if let Some(lane) = o.tx.lane()
            && !had_credit
        {
            *lane_counts.entry(lane).or_default() += 1;
        }
        if ambiguous_resend {
            o.ambiguous_resends += 1;
        }
        o.attempts += 1;
        let now = now_ms();
        o.first_attempt_ms.get_or_insert(now);
        o.last_attempt_ms = Some(now);
        o.endpoint = Some(q.targets[index].id.clone());
        o.retry_at_ms = 0;
        let tip = lock(journal)?.state.target_tip_seconds;
        let projected_ms = tip
            .saturating_mul(1000)
            .max(now)
            .saturating_add(3000)
            .saturating_add(c.timing.expected_inclusion_latency_ms)
            .saturating_add(c.timing.expiry_safety_margin_ms)
            .saturating_add(999);
        let detail = if o.tx.expired_at(tip) {
            "initial/authorized retry attempt; exact valid_before admission risk"
        } else if o
            .tx
            .valid_before
            .is_some_and(|v| v.saturating_mul(1000) <= projected_ms)
        {
            "attempt; projected inclusion deadline risk"
        } else {
            "attempt intent persisted before network write"
        };
        o.transition(State::Attempting, detail);
        prepared.push((o.clone(), index));
    }
    if !prepared.is_empty() {
        {
            let mut j = lock(journal)?;
            ensure!(
                j.state.incident.is_none(),
                "dispatch paused before attempt batch commit"
            );
            j.update_many(&prepared.iter().map(|(o, _)| o.clone()).collect::<Vec<_>>())?;
        }
        for (o, index) in prepared {
            let rpc = q.targets[index].rpc.clone();
            let raw = o.tx.raw.clone();
            let key = o.key();
            inflight.insert(key.clone());
            pending.push(
                async move { (key, rpc.call("eth_sendRawTransaction", json!([raw])).await) }
                    .boxed(),
            );
        }
    }
    Ok(())
}
fn handle_response(
    c: &Config,
    journal: &SharedJournal,
    active: &mut BTreeMap<String, Occurrence>,
    key: &str,
    response: Result<Value>,
) -> Result<()> {
    let mut o: Occurrence = lock(journal)?
        .get(key)?
        .context("response occurrence missing")?;
    if o.state.terminal() {
        active.insert(key.into(), o);
        return Ok(());
    }
    let result = match response {
        Ok(value) => match serde_json::from_value::<B256>(value) {
            Ok(hash) if hash == o.tx.hash => {
                o.transition(
                    State::Accepted,
                    "RPC accepted exact signed transaction hash",
                );
                Ok(())
            }
            _ => {
                o.transition(
                    State::Unknown,
                    "unexpected response hash; outcome requires reconciliation",
                );
                Err(anyhow::anyhow!("submission response hash mismatch"))
            }
        },
        Err(e) => {
            let Some(rpc_error) = e.downcast_ref::<RpcError>() else {
                o.transition(
                    State::Unknown,
                    "malformed or oversized response after write",
                );
                lock(journal)?.update(&o)?;
                active.insert(key.into(), o);
                return Err(e);
            };
            let outcome = classify(rpc_error);
            // Server strings can contain addresses or payloads. Persist the bounded category
            // and numeric code; never echo arbitrary RPC messages into operational logs.
            let detail = format!("RPC code {}; category {outcome:?}", rpc_error.code);
            let had_uncertain_attempt = o.ambiguous_resends > 0
                || o.history
                    .iter()
                    .any(|h| matches!(h.state, State::Accepted | State::Unknown));
            let backoff = retry_delay(o.attempts, o.tx.hash, rpc_error.retry_ms);
            match outcome {
                Outcome::Accepted => {
                    o.transition(State::Accepted, detail);
                    Ok(())
                }
                Outcome::Ambiguous => {
                    o.transition(State::Unknown, detail);
                    o.retry_at_ms = 0;
                    Ok(())
                }
                Outcome::Capacity | Outcome::Transport => {
                    o.transition(
                        if had_uncertain_attempt {
                            State::Unknown
                        } else {
                            State::Deferred
                        },
                        detail,
                    );
                    o.retry_at_ms = now_ms().saturating_add(backoff);
                    if outcome == Outcome::Transport && o.attempts >= c.limits.max_retry_attempts {
                        lock(journal)?
                            .incident("recoverable: submission transport retry budget exhausted")?;
                    }
                    Ok(())
                }
                Outcome::Expired if !had_uncertain_attempt => {
                    gap(journal, &mut o, "ExpiredAtSubmission")?;
                    Ok(())
                }
                Outcome::Expired => {
                    o.transition(State::Unknown, "expiry rejection after earlier uncertain/accepted attempt; keep reservation");
                    o.retry_at_ms = 0;
                    Ok(())
                }
                Outcome::NonceLow => {
                    o.transition(
                        State::Unknown,
                        "nonce already consumed; reconcile exact hash and finalized state",
                    );
                    o.retry_at_ms = 0;
                    lock(journal)?.put(format!("nonce_low/{}", o.tx.hash), &true)?;
                    Ok(())
                }
                Outcome::Dependency => {
                    o.dependency_since_ms.get_or_insert(now_ms());
                    o.transition(
                        if had_uncertain_attempt {
                            State::Unknown
                        } else {
                            State::Deferred
                        },
                        detail,
                    );
                    o.retry_at_ms = now_ms().saturating_add(backoff);
                    Ok(())
                }
                Outcome::Incident => {
                    o.transition(State::Unknown, detail);
                    Err(anyhow::anyhow!(
                        "unexpected transaction rejection; compatibility or target identity incident"
                    ))
                }
            }
        }
    };
    lock(journal)?.update(&o)?;
    active.insert(key.into(), o);
    result
}
pub fn retry_delay(attempts: u32, hash: B256, server: Option<u64>) -> u64 {
    let base = 100u64.saturating_mul(1u64 << attempts.saturating_sub(1).min(8));
    let jitter = u64::from(hash[(attempts as usize) % 32]) * base / 1024;
    base.saturating_add(jitter).max(server.unwrap_or(0))
}
