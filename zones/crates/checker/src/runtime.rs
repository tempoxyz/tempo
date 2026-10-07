//! Durable notification processing and observe-only failure isolation.

use std::{collections::BTreeSet, future::Future, time::Duration};

use alloy_consensus::BlockHeader as _;
use alloy_eips::BlockNumHash;
use alloy_provider::{DynProvider, Provider as _, ProviderBuilder};
use alloy_rpc_client::{ConnectionConfig, RpcClient, WebSocketConfig};
use futures::{StreamExt as _, TryStreamExt as _, future};
use reth_chainspec::ChainSpecProvider;
use reth_exex::{ExExContext, ExExHead, ExExNotification};
use reth_node_api::{BlockBody as _, FullNodeComponents, NodePrimitives};
use reth_primitives_traits::RecoveredBlock;
use reth_storage_api::{BlockHashReader as _, BlockNumReader, StateProviderFactory};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TempoHardforks;

use crate::{
    AttemptError, CheckerConfig,
    accounting::effects,
    bootstrap,
    l1::{L1ReadError, classify_rpc_error, collect_l1_range_at, portal_balances},
    l2::{AccountingStateError, collect_l2_block_evidence, read_accounting_state},
    persistence::{AppliedStatus, BlockRef, CandidateTransition, Finding, Snapshot, Status, Store},
    telemetry::{self, CheckerMetrics},
};

const RETRY_DELAY: Duration = Duration::from_secs(1);
/// Maximum delay between Tempo acquisition attempts.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
/// Retry bound for unavailable local Zone state.
const MAX_STATE_ATTEMPTS: u32 = 30;
/// Retry bound for Tempo acquisition.
const MAX_L1_ATTEMPTS: u32 = 10;
const MAX_WS_FRAME_AND_MESSAGE_SIZE: usize = 128 * 1024 * 1024;

/// `NodePrimitives` whose transaction and receipt types the checker can process.
pub(crate) trait CheckedPrimitives: NodePrimitives {}

impl<N> CheckedPrimitives for N
where
    N: NodePrimitives,
    N::SignedTx: alloy_consensus::transaction::TxHashRef,
    N::Receipt: alloy_consensus::TxReceipt<Log = alloy_primitives::Log>,
{
}

/// Bootstrap or open durable state, recover from its verified tip, and follow notifications.
pub(crate) async fn run<Node>(
    config: CheckerConfig,
    ctx: &mut ExExContext<Node>,
) -> eyre::Result<()>
where
    Node: FullNodeComponents,
    Node::Provider: BlockNumReader + ChainSpecProvider + StateProviderFactory,
    <Node::Provider as ChainSpecProvider>::ChainSpec: TempoHardforks,
    <Node::Types as reth_node_api::NodeTypes>::Primitives: CheckedPrimitives,
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
    Node: FullNodeComponents,
    Node::Provider: BlockNumReader + ChainSpecProvider + StateProviderFactory,
    <Node::Provider as ChainSpecProvider>::ChainSpec: TempoHardforks,
    <Node::Types as reth_node_api::NodeTypes>::Primitives: CheckedPrimitives,
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
    let (store, mut snapshot) = if persisted_identity.is_some() {
        Store::open(&config.database_path, bootstrap.identity())?
    } else {
        Store::open_or_create(&config.database_path, &checkpoint)?
    };
    let verified = snapshot.metadata.verified_zone;
    if ctx.provider().block_hash(verified.number)? != Some(verified.hash) {
        tracing::warn!(
            target: "zone::checker",
            zone_block = verified.number,
            zone_hash = %verified.hash,
            "checker tip is not in local Zone history; rebuilding"
        );
        snapshot = store.reset(&checkpoint)?;
        metrics.recovery_rebuilds_total.increment(1);
    }
    metrics.update(&snapshot);

    ctx.catch_up_notifications_with_head(ExExHead::new(snapshot.metadata.verified_zone.into()))?;
    ctx.send_finished_height(snapshot.metadata.verified_zone.into())?;

    while let Some(notification) = ctx.notifications.try_next().await? {
        if !matches!(&notification, ExExNotification::ChainCommitted { .. }) {
            snapshot = store.reset(&checkpoint)?;
            metrics.recovery_rebuilds_total.increment(1);
            metrics.update(&snapshot);
            ctx.catch_up_notifications_with_head(ExExHead::new(bootstrap.zone().into()))?;
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
            &config,
            metrics,
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

struct VerificationContext<'a> {
    config: &'a CheckerConfig,
    metrics: &'a CheckerMetrics,
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
async fn process_notification<N, P>(
    notification: &ExExNotification<N>,
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    store: &Store,
    snapshot: Snapshot,
    config: &CheckerConfig,
    metrics: &CheckerMetrics,
) -> Result<Box<Snapshot>, BlockError>
where
    N: CheckedPrimitives,
    P: BlockNumReader + ChainSpecProvider + StateProviderFactory,
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
    let context = VerificationContext { config, metrics };
    for (block, receipts) in new.blocks_and_receipts() {
        if already_applied(&current, block.header().number(), block.hash())? {
            continue;
        }
        current =
            verify_block::<N, _>(provider, l1, store, current, &context, block, receipts).await?;
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
async fn verify_block<N, P>(
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    store: &Store,
    prior: Snapshot,
    context: &VerificationContext<'_>,
    block: &RecoveredBlock<N::Block>,
    receipts: &[N::Receipt],
) -> Result<Snapshot, BlockError>
where
    N: CheckedPrimitives,
    P: BlockNumReader + ChainSpecProvider + StateProviderFactory,
    P::ChainSpec: TempoHardforks,
{
    let VerificationContext { config, metrics } = context;
    let zone = BlockRef::from(block.num_hash());
    let fail = |error| BlockError::Finding { zone, error };
    let l2 = collect_l2_block_evidence(block.body().transactions(), receipts, zone.into())
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
    let VerificationContext { config, metrics } = context;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
