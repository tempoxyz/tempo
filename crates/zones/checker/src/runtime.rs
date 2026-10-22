//! Durable notification processing and observe-only failure isolation.

use std::{collections::BTreeSet, future::Future, time::Duration};

use alloy_consensus::BlockHeader as _;
use alloy_eips::BlockNumHash;
use alloy_provider::{DynProvider, Provider as _, ProviderBuilder};
use alloy_rpc_client::{ConnectionConfig, RpcClient, WebSocketConfig};
use futures::{StreamExt as _, TryStreamExt as _, future};
use reth_chainspec::ChainSpecProvider;
use reth_evm::ConfigureEvm;
use reth_exex::{ExExContext, ExExHead, ExExNotification, ExExNotifications};
use reth_node_api::{FullNodeComponents, NodePrimitives, NodeTypes};
use reth_primitives_traits::RecoveredBlock;
use reth_storage_api::{BlockHashReader, BlockNumReader, StateProviderFactory};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TempoHardforks;
use tempo_primitives::{TempoPrimitives, TempoReceipt};
use zone_primitives::constants::MAX_WS_FRAME_AND_MESSAGE_SIZE;

use crate::{
    AttemptError, CheckerConfig,
    accounting::effects,
    bootstrap,
    l1::{L1ReadError, classify_rpc_error, collect_l1_range_at, portal_balances},
    l2::{AccountingStateError, collect_l2_block_evidence, read_accounting_state},
    latency::{self, LatencyTracker},
    persistence::{
        AppliedStatus, BlockRef, CandidateTransition, Checkpoint, Finding, Snapshot, Status, Store,
    },
    telemetry::{self, CheckerMetrics},
};

const RETRY_DELAY: Duration = Duration::from_secs(1);
/// Maximum delay between Tempo acquisition attempts.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
/// Retry bound for unavailable local Zone state.
const MAX_STATE_ATTEMPTS: u32 = 30;
/// Retry bound for Tempo acquisition.
const MAX_L1_ATTEMPTS: u32 = 10;
/// Check local history after a minute without live notifications.
const NOTIFICATION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bootstrap or open durable state, recover from its verified tip, and follow notifications.
pub(crate) async fn run<Node>(
    config: CheckerConfig,
    ctx: &mut ExExContext<Node>,
) -> eyre::Result<()>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
    <Node::Provider as ChainSpecProvider>::ChainSpec: TempoHardforks,
{
    let metrics = CheckerMetrics::default();
    metrics.disabled.set(0.0);
    let result = run_inner(config, ctx, &metrics).await;
    metrics.disabled.set(1.0);
    match result {
        Ok(()) => tracing::error!(
            target: "zone::checker",
            "checker stopped unexpectedly; Zone execution continues"
        ),
        Err(error) => tracing::error!(
            target: "zone::checker",
            %error,
            "checker disabled; Zone execution continues"
        ),
    }
    // After verification stops, drain and acknowledge notifications so the ExEx cannot block the node.
    while let Some(notification) = ctx.notifications.next().await {
        let result = notification
            .and_then(|notification| {
                notification_tip(&notification)
                    .ok_or_else(|| eyre::eyre!("received an empty ExEx notification"))
            })
            .and_then(|tip| ctx.send_finished_height(tip).map_err(Into::into));
        if let Err(error) = result {
            tracing::error!(
                target: "zone::checker",
                %error,
                "checker cannot drain notifications; parking ExEx"
            );
            break;
        }
    }
    future::pending().await
}

/// Bootstrap or open durable state, then verify each append-only notification in turn.
///
/// Transient acquisition failures are retried up to a fixed bound. An authenticated
/// divergence is persisted until the checker is rebuilt, while exhausted or
/// deterministic failures return so the outer runtime can disable and drain.
async fn run_inner<Node>(
    config: CheckerConfig,
    ctx: &mut ExExContext<Node>,
    metrics: &CheckerMetrics,
) -> eyre::Result<()>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
    <Node::Provider as ChainSpecProvider>::ChainSpec: TempoHardforks,
{
    tracing::info!(target: "zone::checker", "checker started");
    let persisted_identity = config
        .database_path
        .exists()
        .then(|| Store::inspect_identity(&config.database_path))
        .transpose()?;
    let l1 = connect(&config.l1_rpc_url).await?;
    let bootstrap = retry_transient(
        || async {
            match persisted_identity {
                Some(identity) => {
                    bootstrap::authenticate(ctx.provider(), &l1, &config, identity).await
                }
                None => bootstrap::discover(ctx.provider(), &l1, &config).await,
            }
        },
        "checker bootstrap",
    )
    .await?;
    let checkpoint = bootstrap.checkpoint();
    let (store, snapshot) = if persisted_identity.is_some() {
        Store::open(&config.database_path, bootstrap.identity())?
    } else {
        Store::open_or_create(&config.database_path, &checkpoint)?
    };
    let provider = ctx.provider().clone();
    let (mut snapshot, mut backfill_target) = recover_notifications(
        &provider,
        &mut ctx.notifications,
        &store,
        snapshot,
        &checkpoint,
        metrics,
    )?;
    metrics.update(&snapshot);
    ctx.send_finished_height(snapshot.metadata.verified_zone.into())?;

    let mut context = VerificationContext {
        config: &config,
        metrics,
        latency: LatencyTracker::default(),
    };
    loop {
        // Do not restart a slow backfill job or interrupt verification of a delivered batch.
        let notification = if let Some(timeout) = notification_idle_timeout(
            snapshot.metadata.verified_zone.number,
            &snapshot.metadata.status,
            backfill_target,
        ) {
            match tokio::time::timeout(timeout, ctx.notifications.try_next()).await {
                Ok(notification) => notification?,
                Err(_) => {
                    let head = ctx.provider().chain_info()?;
                    let verified = snapshot.metadata.verified_zone;
                    if notification_gap(
                        verified,
                        head.best_number,
                        ctx.provider().block_hash(verified.number)?,
                    ) {
                        (snapshot, backfill_target) = recover_notifications(
                            &provider,
                            &mut ctx.notifications,
                            &store,
                            snapshot,
                            &checkpoint,
                            metrics,
                        )?;
                        metrics.update(&snapshot);
                        metrics.notification_recoveries_total.increment(1);
                        tracing::warn!(
                            target: "zone::checker",
                            verified_zone = snapshot.metadata.verified_zone.number,
                            canonical_zone = head.best_number,
                            "checker notifications idle; replaying local canonical history"
                        );
                    }
                    continue;
                }
            }
        } else {
            ctx.notifications.try_next().await?
        };
        let Some(notification) = notification else {
            break;
        };
        if !matches!(&notification, ExExNotification::ChainCommitted { .. }) {
            snapshot = store.reset(&checkpoint)?;
            metrics.recovery_rebuilds_total.increment(1);
            metrics.update(&snapshot);
            (snapshot, backfill_target) = recover_notifications(
                &provider,
                &mut ctx.notifications,
                &store,
                snapshot,
                &checkpoint,
                metrics,
            )?;
            tracing::warn!(target: "zone::checker", "unexpected Zone revert; rebuilding from genesis");
            continue;
        }
        let delivered_tip = notification_tip(&notification)
            .ok_or_else(|| eyre::eyre!("received an empty ExEx notification"))?;
        if matches!(&snapshot.metadata.status, Status::Diverged { .. }) {
            snapshot = store.observe(&snapshot, delivered_tip.into())?;
            metrics.update(&snapshot);
            ctx.send_finished_height(delivered_tip)?;
            continue;
        }
        snapshot = store.observe(&snapshot, delivered_tip.into())?;
        metrics.update(&snapshot);

        let previous_verified = snapshot.metadata.verified_zone.number;
        match process_notification(
            &notification,
            ctx.provider(),
            &l1,
            &store,
            snapshot,
            &mut context,
        )
        .await
        {
            Ok(next) => {
                let next = *next;
                let verified = next
                    .metadata
                    .verified_zone
                    .number
                    .saturating_sub(previous_verified);
                snapshot = next;
                metrics.verified_zone_blocks_total.increment(verified);
                metrics.update(&snapshot);
                ctx.send_finished_height(snapshot.metadata.verified_zone.into())?;
            }
            Err(BlockError::Finding { zone, error }) => {
                snapshot = store.load()?;
                tracing::error!(target: "zone::checker", %error, zone_block = zone.number, zone_hash = %zone.hash, "checker divergence");
                snapshot = store.record_finding(
                    &snapshot,
                    Finding {
                        zone,
                        summary: error.to_string(),
                    },
                )?;
                metrics.update(&snapshot);
                ctx.send_finished_height(delivered_tip)?;
            }
            Err(BlockError::Disable(error)) => return Err(error),
        }
    }
    tracing::info!(target: "zone::checker", "checker notification stream closed");
    Ok(())
}

async fn connect(url: &str) -> eyre::Result<DynProvider<TempoNetwork>> {
    let provider = retry_transient(
        || async {
            let client = RpcClient::builder()
                .connect_with_config(url, rpc_connection_config())
                .await
                .map_err(classify_rpc_error)?;
            Ok(ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_client(client)
                .erased())
        },
        "Tempo RPC connection",
    )
    .await?;
    Ok(provider)
}

fn rpc_connection_config() -> ConnectionConfig {
    ConnectionConfig::new().with_ws_config(
        WebSocketConfig::default()
            .max_frame_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE))
            .max_message_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE)),
    )
}

/// Retry transient failures up to the acquisition bound.
async fn retry_transient<T, F, Fut>(mut attempt: F, operation: &str) -> eyre::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AttemptError>>,
{
    let mut backoff = Backoff::new();
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(AttemptError::Retry(error)) => {
                backoff.record(&error, operation)?;
                tracing::warn!(
                    target: "zone::checker",
                    %error,
                    operation,
                    attempt = backoff.attempts,
                    max_attempts = MAX_L1_ATTEMPTS,
                    "checker acquisition failed; retrying"
                );
                backoff.wait().await;
            }
            Err(AttemptError::Disable(error)) => return Err(error),
        }
    }
}

/// Return the notification's new canonical tip, or the reverted parent for a `ChainReverted`.
fn notification_tip<N: NodePrimitives>(notification: &ExExNotification<N>) -> Option<BlockNumHash> {
    match notification {
        ExExNotification::ChainCommitted { new } | ExExNotification::ChainReorged { new, .. } => {
            new.blocks()
                .values()
                .next_back()
                .map(|block| block.num_hash())
        }
        ExExNotification::ChainReverted { old } => old
            .blocks()
            .values()
            .next()
            .map(|block| block.header().parent_num_hash()),
    }
}

/// Failure processing one block.
enum BlockError {
    /// Authenticated divergence to persist as a finding.
    Finding { zone: BlockRef, error: eyre::Report },
    /// Checker-local failure that must stop verification.
    Disable(eyre::Report),
}

/// Verification inputs and state shared by every block of one checker run.
struct VerificationContext<'a> {
    config: &'a CheckerConfig,
    metrics: &'a CheckerMetrics,
    latency: LatencyTracker,
}

fn record_retry_attempt(
    attempts: &mut u32,
    max_attempts: u32,
    error: &eyre::Report,
    operation: &str,
) -> eyre::Result<()> {
    *attempts = attempts.saturating_add(1);
    if *attempts >= max_attempts {
        return Err(eyre::eyre!(
            "{operation} retry budget exhausted after {attempts} failed attempts: {error:#}"
        ));
    }
    Ok(())
}

/// Bounded backoff for Tempo acquisition.
struct Backoff {
    attempts: u32,
    delay: Duration,
}

impl Backoff {
    const fn new() -> Self {
        Self {
            attempts: 0,
            delay: RETRY_DELAY,
        }
    }

    /// Record one failed attempt.
    fn record(&mut self, error: &eyre::Report, operation: &str) -> eyre::Result<()> {
        record_retry_attempt(&mut self.attempts, MAX_L1_ATTEMPTS, error, operation)
    }

    /// Wait and increase the next delay.
    async fn wait(&mut self) {
        tokio::time::sleep(self.delay).await;
        self.delay = self.delay.saturating_mul(2).min(MAX_RETRY_DELAY);
    }
}

/// Verify one append-only notification's blocks.
async fn process_notification<P>(
    notification: &ExExNotification<TempoPrimitives>,
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    store: &Store,
    snapshot: Snapshot,
    context: &mut VerificationContext<'_>,
) -> Result<Box<Snapshot>, BlockError>
where
    P: ChainSpecProvider + StateProviderFactory,
    P::ChainSpec: TempoHardforks,
{
    let mut current = snapshot;
    let new = match notification {
        ExExNotification::ChainCommitted { new } => new,
        ExExNotification::ChainReorged { .. } | ExExNotification::ChainReverted { .. } => {
            return Err(BlockError::Disable(eyre::eyre!(
                "unexpected Zone revert reached block verification"
            )));
        }
    };
    for (block, receipts) in new.blocks_and_receipts() {
        if already_applied(&current, block.header().number(), block.hash())? {
            continue;
        }
        current = verify_block(provider, l1, store, current, context, block, receipts).await?;
    }
    Ok(Box::new(current))
}

fn already_applied(
    snapshot: &Snapshot,
    number: u64,
    hash: alloy_primitives::B256,
) -> Result<bool, BlockError> {
    let verified = snapshot.metadata.verified_zone;
    match snapshot.metadata.classify(number, hash) {
        AppliedStatus::New => Ok(false),
        AppliedStatus::Applied => Ok(true),
        AppliedStatus::Conflicts => Err(BlockError::Disable(eyre::eyre!(
            "notification block {number} ({hash}) conflicts with verified Zone block {} ({})",
            verified.number,
            verified.hash
        ))),
    }
}

/// Verify one Zone block's bridge accounting against Tempo history and Portal
/// collateral, persisting the result on success.
async fn verify_block<P>(
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    store: &Store,
    prior: Snapshot,
    context: &mut VerificationContext<'_>,
    block: &RecoveredBlock<tempo_primitives::Block>,
    receipts: &[TempoReceipt],
) -> Result<Snapshot, BlockError>
where
    P: ChainSpecProvider + StateProviderFactory,
    P::ChainSpec: TempoHardforks,
{
    let (config, metrics) = (context.config, context.metrics);
    let zone = BlockRef::from(block.num_hash());
    let fail = |error| BlockError::Finding { zone, error };
    let l2 = collect_l2_block_evidence(&block.body().transactions, receipts, zone.into())
        .map_err(fail)?;
    let tempo_parent = BlockNumHash::from(prior.metadata.imported_tempo);
    let mut l1_backoff = Backoff::new();
    let (tempo, tempo_block) = if let Some(anchor) = l2.l1_anchor() {
        let tempo = BlockNumHash::new(anchor.block_number(), anchor.block_hash());
        validate_tempo_advance(tempo_parent.number, tempo.number).map_err(fail)?;
        let evidence =
            collect_l1_range_with_retry(l1, tempo_parent, tempo, zone, context, &mut l1_backoff)
                .await?;
        (tempo, evidence)
    } else {
        // Checkpoint-only blocks perform no bridge work. Keep the accounting anchor and
        // liabilities unchanged; the next full block consumes the entire deferred L1 range.
        (tempo_parent, crate::l1::L1BlockEvidence::default())
    };
    let mut block_effects = effects::from_tempo(&tempo_block);
    block_effects.extend(effects::from_zone(&l2));
    let candidate = CandidateTransition::derive(
        prior,
        zone,
        block.header().parent_num_hash().into(),
        tempo.into(),
        &block_effects,
    )
    .map_err(|error| fail(error.into()))?;
    let state = candidate.state();
    let mut accounts = l2.accounting_candidates();
    let tokens = state
        .tokens()
        .map(|(token, _)| token)
        .collect::<BTreeSet<_>>();
    for token in &tokens {
        accounts.entry(*token).or_default();
    }
    let spec = provider
        .chain_spec()
        .tempo_hardfork_at(block.header().timestamp());
    let mut state_attempts = 0;
    let observed = loop {
        match read_accounting_state(provider, &accounts, zone.into(), spec) {
            Ok(observed) => break observed,
            Err(AccountingStateError::Unavailable(error)) => {
                metrics.acquisition_retries_total.increment(1);
                record_retry_attempt(
                    &mut state_attempts,
                    MAX_STATE_ATTEMPTS,
                    &error,
                    "local Zone state acquisition (checker requires unpruned state for notified blocks)",
                )
                .map_err(BlockError::Disable)?;
                tracing::warn!(
                    target: "zone::checker",
                    zone_block = zone.number,
                    zone_hash = %zone.hash,
                    attempt = state_attempts,
                    max_attempts = MAX_STATE_ATTEMPTS,
                    "checker local state unavailable; retrying"
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(AccountingStateError::Disable(error)) => {
                return Err(BlockError::Disable(error));
            }
        }
    };
    state
        .verify_zone_state(
            observed
                .into_iter()
                .map(|evidence| (evidence.token, evidence.total_supply, evidence.balances)),
        )
        .map_err(|error| fail(error.into()))?;

    let balances = loop {
        match portal_balances(
            l1,
            config.portal_address,
            tokens.iter().copied(),
            tempo.hash,
        )
        .await
        {
            Ok(balances) => break balances,
            Err(L1ReadError::Unavailable(error)) => {
                record_l1_retry(
                    metrics,
                    &mut l1_backoff,
                    &error,
                    "Portal balance acquisition",
                )?;
                l1_backoff.wait().await;
            }
            Err(error) => return Err(classify_block_l1_error(error, zone)),
        }
    };
    state
        .verify_portal_balances(balances)
        .map_err(|error| fail(error.into()))?;

    let next = store
        .apply(candidate)
        .map_err(|error| BlockError::Disable(error.into()))?;
    telemetry::log_verified_activity(&tempo_block, &l2, zone);
    let zone_timestamp_millis = block.header().timestamp_millis();
    let samples = context.latency.observe(
        tempo_block.blocks(),
        l2.bridge_actions(),
        zone_timestamp_millis,
    );
    if latency::is_recent(zone_timestamp_millis) {
        metrics.record_latencies(&samples);
    }
    Ok(next)
}

fn classify_block_l1_error(error: L1ReadError, zone: BlockRef) -> BlockError {
    match error {
        L1ReadError::Unavailable(error) => BlockError::Disable(error),
        L1ReadError::Finding(error) => BlockError::Finding { zone, error },
        L1ReadError::Disable(error) => BlockError::Disable(error),
    }
}

async fn collect_l1_range_with_retry(
    l1: &DynProvider<TempoNetwork>,
    parent: BlockNumHash,
    expected: BlockNumHash,
    zone: BlockRef,
    context: &VerificationContext<'_>,
    backoff: &mut Backoff,
) -> Result<crate::l1::L1BlockEvidence, BlockError> {
    let VerificationContext {
        config, metrics, ..
    } = context;
    loop {
        match collect_l1_range_at(
            l1,
            &config.l1_block_tracker,
            config.portal_address,
            parent,
            expected,
        )
        .await
        {
            Ok(block) => return Ok(block),
            Err(L1ReadError::Unavailable(error)) => {
                record_l1_retry(metrics, backoff, &error, "Tempo block acquisition")?;
                backoff.wait().await;
            }
            Err(error) => return Err(classify_block_l1_error(error, zone)),
        }
    }
}

fn record_l1_retry(
    metrics: &CheckerMetrics,
    backoff: &mut Backoff,
    error: &eyre::Report,
    operation: &str,
) -> Result<(), BlockError> {
    metrics.acquisition_retries_total.increment(1);
    backoff
        .record(error, operation)
        .map_err(BlockError::Disable)?;
    tracing::warn!(
        target: "zone::checker",
        %error,
        operation,
        attempt = backoff.attempts,
        max_attempts = MAX_L1_ATTEMPTS,
        "checker L1 acquisition failed; retrying"
    );
    Ok(())
}

fn validate_tempo_advance(parent: u64, tip: u64) -> eyre::Result<()> {
    eyre::ensure!(
        tip > parent,
        "Zone full import did not advance Tempo from block {parent} to {tip}"
    );
    Ok(())
}

/// Restart canonical replay from the durable cursor, rebuilding it if it was orphaned.
///
/// The returned target suppresses idle recovery until this backfill has made progress
/// through the captured head. Read it before resetting the stream so advancing
/// heads do not leave us waiting beyond Reth's captured target.
fn recover_notifications<TProvider, TEvm>(
    provider: &TProvider,
    notifications: &mut ExExNotifications<TProvider, TEvm>,
    store: &Store,
    mut snapshot: Snapshot,
    checkpoint: &Checkpoint,
    metrics: &CheckerMetrics,
) -> eyre::Result<(Snapshot, u64)>
where
    TProvider: BlockHashReader + BlockNumReader,
    TEvm: ConfigureEvm,
{
    let target = provider.chain_info()?.best_number;
    let verified = snapshot.metadata.verified_zone;
    if provider.block_hash(verified.number)? != Some(verified.hash) {
        tracing::warn!(
            target: "zone::checker",
            zone_block = verified.number,
            zone_hash = %verified.hash,
            "checker tip is not in local Zone history; rebuilding"
        );
        snapshot = store.reset(checkpoint)?;
        metrics.recovery_rebuilds_total.increment(1);
    }
    notifications.catch_up_with_head(ExExHead::new(snapshot.metadata.verified_zone.into()))?;
    Ok((snapshot, target))
}

/// Suppress idle recovery while replay is active or verification has stopped on a finding.
fn notification_idle_timeout(
    verified: u64,
    status: &Status,
    backfill_target: u64,
) -> Option<Duration> {
    (verified >= backfill_target && matches!(status, Status::Verifying))
        .then_some(NOTIFICATION_IDLE_TIMEOUT)
}

/// A higher canonical head or an orphaned verified cursor requires replay.
fn notification_gap(
    verified: BlockRef,
    canonical_height: u64,
    verified_canonical_hash: Option<alloy_primitives::B256>,
) -> bool {
    canonical_height > verified.number || verified_canonical_hash != Some(verified.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{collections::BTreeMap, sync::Arc};

    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256};
    use reth_ethereum_primitives::{Block, EthPrimitives};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_exex::Wal;
    use reth_primitives_traits::Block as _;
    use reth_provider::{Chain, test_utils::MockEthProvider};
    use tokio::sync::{broadcast, mpsc};

    use crate::persistence::Identity;

    #[tokio::test]
    async fn disable_error_is_not_retried() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_transient(
            || {
                attempts.set(attempts.get() + 1);
                future::ready(Err::<(), _>(AttemptError::Disable(eyre::eyre!(
                    "invalid genesis"
                ))))
            },
            "operation",
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn tempo_advance_accepts_deferred_ranges() {
        for tip in [11, 12, u64::MAX] {
            assert!(validate_tempo_advance(10, tip).is_ok());
        }
        for tip in [9, 10] {
            assert!(validate_tempo_advance(10, tip).is_err());
        }
        assert!(validate_tempo_advance(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn conflicting_verified_coordinate_disables() {
        let verified = BlockRef::new(10, alloy_primitives::B256::repeat_byte(1));
        let snapshot = Snapshot {
            metadata: crate::persistence::Metadata {
                identity: crate::persistence::Identity {
                    l1_chain_id: 1,
                    zone_chain_id: 2,
                    zone_id: 3,
                    portal: alloy_primitives::Address::repeat_byte(4),
                    creation: BlockRef::new(5, alloy_primitives::B256::repeat_byte(5)),
                },
                verified_zone: verified,
                imported_tempo: BlockRef::new(20, alloy_primitives::B256::repeat_byte(2)),
                observed_zone: verified,
                status: Status::Verifying,
            },
            state: Default::default(),
        };

        assert!(matches!(
            already_applied(&snapshot, verified.number, verified.hash),
            Ok(true)
        ));
        assert!(matches!(
            already_applied(
                &snapshot,
                verified.number,
                alloy_primitives::B256::repeat_byte(9)
            ),
            Err(BlockError::Disable(_))
        ));
    }

    #[test]
    fn acquisition_retries_are_bounded() {
        let mut attempts = 0;
        let error = eyre::eyre!("state unavailable");
        for _ in 1..MAX_STATE_ATTEMPTS {
            record_retry_attempt(
                &mut attempts,
                MAX_STATE_ATTEMPTS,
                &error,
                "local state acquisition",
            )
            .unwrap();
        }
        let error = record_retry_attempt(
            &mut attempts,
            MAX_STATE_ATTEMPTS,
            &error,
            "local state acquisition",
        )
        .expect_err("the final attempt must disable the checker");
        assert_eq!(attempts, MAX_STATE_ATTEMPTS);
        assert!(error.to_string().contains("retry budget exhausted"));
    }

    fn recovery_checkpoint(genesis: BlockRef) -> Checkpoint {
        Checkpoint {
            identity: Identity {
                l1_chain_id: 1,
                zone_chain_id: 2,
                zone_id: 3,
                portal: Address::repeat_byte(4),
                creation: BlockRef::new(5, B256::repeat_byte(5)),
            },
            zone: genesis,
            tempo: BlockRef::new(100, B256::repeat_byte(20)),
            state: Default::default(),
        }
    }

    #[tokio::test]
    async fn notification_recovery_replays_after_broadcast_lag() -> eyre::Result<()> {
        let directory = tempfile::tempdir()?;
        let provider = MockEthProvider::<EthPrimitives>::default();
        let genesis = Block::default();
        let genesis_ref = BlockRef::new(0, genesis.header.hash_slow());
        provider.add_block(genesis_ref.hash, genesis);
        let checkpoint = recovery_checkpoint(genesis_ref);
        let (store, mut snapshot) =
            Store::open_or_create(&directory.path().join("checker"), &checkpoint)?;
        let wal = Wal::new(directory.path().join("wal"))?;
        let (sender, receiver) = mpsc::channel(1024);
        // The manager remains alive after its canonical forwarding task exits.
        let _keep_alive = sender.clone();
        let mut notifications = ExExNotifications::new(
            genesis_ref.into(),
            provider.clone(),
            EthEvmConfig::mainnet(),
            receiver,
            wal.handle(),
        );
        let (canonical, mut canonical_receiver) = broadcast::channel(256);
        let (received, mut received_receiver) = mpsc::unbounded_channel();
        let bridge = tokio::spawn(async move {
            // Match the upstream bridge, including its silent exit on Lagged.
            while let Ok(notification) = canonical_receiver.recv().await {
                received.send(()).unwrap();
                sender.send(notification).await.unwrap();
            }
        });
        let mut parent = genesis_ref;
        for number in 1..=1282 {
            let block = Block {
                header: Header {
                    number,
                    parent_hash: parent.hash,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            parent = BlockRef::new(number, block.header.hash_slow());
            provider.add_block(parent.hash, block.clone());
            canonical.send(ExExNotification::ChainCommitted {
                new: Arc::new(Chain::new(
                    vec![block.seal_slow().try_recover()?],
                    Default::default(),
                    BTreeMap::new(),
                )),
            })?;
            // Notification 1025 blocks on the full downstream queue; the final
            // 257 overflow the canonical broadcast before we poll the checker.
            if number <= 1025 {
                tokio::time::timeout(Duration::from_secs(10), received_receiver.recv())
                    .await?
                    .unwrap();
            }
        }
        for expected in 1..=1025 {
            let notification =
                tokio::time::timeout(Duration::from_secs(10), notifications.try_next())
                    .await??
                    .unwrap();
            let tip = notification_tip(&notification).unwrap();
            assert_eq!(tip.number, expected);
            snapshot = store.apply(CandidateTransition::derive(
                snapshot,
                tip.into(),
                if expected == 1 {
                    genesis_ref
                } else {
                    BlockRef::new(expected - 1, provider.block_hash(expected - 1)?.unwrap())
                },
                checkpoint.tempo,
                &[],
            )?)?;
        }
        tokio::time::timeout(Duration::from_secs(10), bridge).await??;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), notifications.try_next(),)
                .await
                .is_err()
        );

        let (recovered, target) = recover_notifications(
            &provider,
            &mut notifications,
            &store,
            snapshot,
            &checkpoint,
            &CheckerMetrics::default(),
        )?;
        snapshot = recovered;
        assert_eq!(target, 1282);
        assert_eq!(snapshot.metadata.verified_zone.number, 1025);
        // No new live notification is sent. Reth must recover every missing
        // block from local history, starting strictly after the durable cursor.
        while snapshot.metadata.verified_zone.number < target {
            let notification =
                tokio::time::timeout(Duration::from_secs(10), notifications.try_next())
                    .await??
                    .unwrap();
            let ExExNotification::ChainCommitted { new } = notification else {
                panic!("expected canonical replay");
            };
            for block in new.blocks_iter() {
                assert_eq!(block.number(), snapshot.metadata.verified_zone.number + 1);
                let prior = snapshot.metadata.verified_zone;
                snapshot = store.apply(CandidateTransition::derive(
                    snapshot,
                    BlockRef::new(block.number(), block.hash()),
                    prior,
                    checkpoint.tempo,
                    &[],
                )?)?;
            }
        }
        assert_eq!(store.load()?.metadata.verified_zone, parent);
        Ok(())
    }

    #[test]
    fn notification_recovery_rebuilds_orphaned_cursor() -> eyre::Result<()> {
        let directory = tempfile::tempdir()?;
        let provider = MockEthProvider::<EthPrimitives>::default();
        let genesis = Block::default();
        let genesis_ref = BlockRef::new(0, genesis.header.hash_slow());
        provider.add_block(genesis_ref.hash, genesis);
        let checkpoint = recovery_checkpoint(genesis_ref);
        let (store, snapshot) =
            Store::open_or_create(&directory.path().join("checker"), &checkpoint)?;
        let canonical = Block {
            header: Header {
                number: 1,
                parent_hash: genesis_ref.hash,
                ..Default::default()
            },
            ..Default::default()
        };
        provider.add_block(canonical.header.hash_slow(), canonical);
        let snapshot = store.apply(CandidateTransition::derive(
            snapshot,
            BlockRef::new(1, B256::repeat_byte(1)),
            genesis_ref,
            checkpoint.tempo,
            &[],
        )?)?;
        let wal = Wal::new(directory.path().join("wal"))?;
        let (_sender, receiver) = mpsc::channel(1);
        let mut notifications = ExExNotifications::new(
            genesis_ref.into(),
            provider.clone(),
            EthEvmConfig::mainnet(),
            receiver,
            wal.handle(),
        );
        let (recovered, target) = recover_notifications(
            &provider,
            &mut notifications,
            &store,
            snapshot,
            &checkpoint,
            &CheckerMetrics::default(),
        )?;
        assert_eq!(target, 1);
        assert_eq!(recovered.metadata.verified_zone, genesis_ref);
        assert_eq!(
            notification_idle_timeout(
                recovered.metadata.verified_zone.number,
                &recovered.metadata.status,
                target
            ),
            None
        );
        assert_eq!(
            notification_idle_timeout(target, &recovered.metadata.status, target),
            Some(NOTIFICATION_IDLE_TIMEOUT)
        );
        assert_eq!(store.load()?, recovered);
        Ok(())
    }

    #[test]
    fn notification_recovery_preserves_canonical_finding() -> eyre::Result<()> {
        let directory = tempfile::tempdir()?;
        let provider = MockEthProvider::<EthPrimitives>::default();
        let genesis = Block::default();
        let genesis_ref = BlockRef::new(0, genesis.header.hash_slow());
        provider.add_block(genesis_ref.hash, genesis);
        let checkpoint = recovery_checkpoint(genesis_ref);
        let (store, snapshot) =
            Store::open_or_create(&directory.path().join("checker"), &checkpoint)?;
        let snapshot = store.record_finding(
            &snapshot,
            Finding {
                zone: BlockRef::new(1, B256::repeat_byte(1)),
                summary: "persisted divergence".into(),
            },
        )?;
        let wal = Wal::new(directory.path().join("wal"))?;
        let (_sender, receiver) = mpsc::channel(1);
        let mut notifications = ExExNotifications::new(
            genesis_ref.into(),
            provider.clone(),
            EthEvmConfig::mainnet(),
            receiver,
            wal.handle(),
        );
        let (recovered, _) = recover_notifications(
            &provider,
            &mut notifications,
            &store,
            snapshot.clone(),
            &checkpoint,
            &CheckerMetrics::default(),
        )?;
        assert_eq!(recovered, snapshot);
        assert_eq!(store.load()?, snapshot);
        Ok(())
    }

    #[test]
    fn notification_timeout_waits_for_backfill_and_preserves_findings() {
        assert_eq!(notification_idle_timeout(9, &Status::Verifying, 10), None);
        assert_eq!(
            notification_idle_timeout(10, &Status::Verifying, 10),
            Some(NOTIFICATION_IDLE_TIMEOUT)
        );
        assert_eq!(
            notification_idle_timeout(11, &Status::Verifying, 10),
            Some(NOTIFICATION_IDLE_TIMEOUT)
        );
        let status = Status::Diverged {
            finding: Finding {
                zone: BlockRef::new(10, B256::repeat_byte(1)),
                summary: "persisted finding".into(),
            },
        };
        for verified in [9, 10, 11] {
            assert_eq!(notification_idle_timeout(verified, &status, 10), None);
        }
    }

    #[test]
    fn notification_gap_requires_missing_blocks_or_an_orphaned_cursor() {
        let verified = BlockRef::new(10, B256::repeat_byte(1));
        assert!(!notification_gap(verified, 10, Some(verified.hash)));
        assert!(notification_gap(verified, 11, Some(verified.hash)));
        assert!(notification_gap(verified, 10, Some(B256::repeat_byte(2))));
        assert!(notification_gap(verified, 10, None));
        assert!(notification_gap(verified, 9, None));
    }
}
