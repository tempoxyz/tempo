use std::{pin::Pin, time::Duration};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, AddressableManager, Provider};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::gauge::Gauge;
use reth_ethereum::{chainspec::EthChainSpec, network::NetworkInfo};
use reth_provider::{BlockIdReader as _, HeaderProvider as _};
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;
use tempo_telemetry_util::{display_duration, display_option};
use tracing::{Span, debug, error, info_span, instrument, warn};

use crate::{
    consensus::block::Block,
    validators::{
        read_active_and_known_peers_at_block_hash, read_active_and_known_peers_at_block_hash_v1,
    },
};

/// The interval on which the peer set is update during bootstrapping.
/// Aggressive timing to get started.
const BOOTSTRAP_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

/// The interval on which peer sets are freshed during normal operation.
/// Relaxed timing during normal operation.
const HEARTBEAT_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

use super::ingress::{Message, MessageWithCause};

pub(crate) struct Actor<TContext, TPeerManager>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    context: ContextCell<TContext>,

    oracle: TPeerManager,
    execution_node: TempoFullNode,
    executor: crate::executor::Mailbox,
    epoch_strategy: FixedEpocher,
    last_finalized_height: Height,
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,

    peers: Gauge,

    last_tracked_peer_set: Option<LastTrackedPeerSet>,

    peer_update_timer: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    pub(super) fn new(
        context: TContext,
        super::Config {
            oracle,
            execution_node,
            executor,
            epoch_strategy,
            last_finalized_height,
        }: super::Config<TPeerManager>,
        mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    ) -> Self {
        let peers = Gauge::default();
        context.register(
            "peers",
            "how many peers are registered overall for the latest epoch",
            peers.clone(),
        );
        let context = ContextCell::new(context);
        let peer_update_timer = Box::pin(context.sleep(BOOTSTRAP_UPDATE_INTERVAL));
        Self {
            context,
            oracle,
            execution_node,
            executor,
            epoch_strategy,
            last_finalized_height,
            mailbox,
            peers,
            last_tracked_peer_set: None,

            peer_update_timer,
        }
    }

    async fn run(mut self) {
        let reason = 'event_loop: loop {
            tokio::select!(
                biased;


                msg = self.mailbox.next() => {
                    match msg {
                        None => break 'event_loop eyre::eyre!("mailbox closed unexpectedly"),

                        Some(msg) => {
                            if let Err(error) = self.handle_message(msg.cause, msg.message).await {
                                break 'event_loop error;
                            }
                        }
                    }
                }

                // Perform aggressive retries if no peer set is tracked yet.
                // Otherwise just do it every minute.
                _ = &mut self.peer_update_timer => {
                    let _ = self.update_peer_set(None).await;
                    self.reset_peer_update_timer();
                }
            )
        };
        info_span!("peer_manager").in_scope(|| error!(%reason,"agent shutting down"));
    }
    pub(crate) fn start(mut self) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    #[instrument(parent = &cause, skip_all)]
    async fn handle_message(&mut self, cause: Span, message: Message) -> eyre::Result<()> {
        match message {
            Message::Track { id, peers } => {
                AddressableManager::track(&mut self.oracle, id, peers).await;
            }
            Message::Overwrite { peers } => {
                AddressableManager::overwrite(&mut self.oracle, peers).await;
            }
            Message::PeerSet { id, response } => {
                let result = Provider::peer_set(&mut self.oracle, id).await;
                let _ = response.send(result);
            }
            Message::Subscribe { response } => {
                let receiver = Provider::subscribe(&mut self.oracle).await;
                let _ = response.send(receiver);
            }
            Message::Finalized(update) => match *update {
                Update::Block(block, ack) => {
                    let _ = self.update_peer_set(Some(block)).await;
                    ack.acknowledge();
                    self.reset_peer_update_timer();
                }
                Update::Tip { .. } => {}
            },
        }
        Ok(())
    }

    /// Updates the peer set.
    #[instrument(
        skip_all,
        fields(
            block.height = block.as_ref().map(|b| tracing::field::display(b.height())),
        ),
        err,
    )]
    async fn update_peer_set(&mut self, block: Option<Block>) -> eyre::Result<()> {
        if let Some(block) = &block
            && let Err(reason) = self.executor.subscribe_finalized(block.height()).await
        {
            warn!(
                %reason,
                "unable to clarify whether the finalized block was already \
                forwarded to execution layer; will try to read validator \
                config contract, but it will likely fail",
            );
        }

        let maybe_latest_finalized_header = self.read_highest_finalized_header();
        let reference_timestamp = match &block {
            Some(block) => maybe_latest_finalized_header.ok().map_or_else(
                || block.timestamp(),
                |header| header.timestamp().max(block.timestamp()),
            ),
            None => maybe_latest_finalized_header
                .wrap_err("could not determine a timestamp to determine peer behavior")?
                .timestamp(),
        };

        // Post T2 behavior: do a best-effort update of the peerset, to whatever
        // is available as long as it is newer than what we are already tracking.
        //
        // Also run this if we do not yet have any peer set available.
        if self
            .execution_node
            .chain_spec()
            .is_t2_active_at_timestamp(reference_timestamp)
            || self.last_tracked_peer_set.is_none()
        {
            self.refresh_peers()
                .await
                .wrap_err("failed refreshing peer set")?;
        } else if let Some(block) = block {
            let height = block.number();
            if let Some(peers) = read_peer_set_if_boundary(
                &self.context,
                &self.epoch_strategy,
                &self.execution_node,
                block,
            )
            .await
            {
                self.track_or_overwrite(height, peers).await;
            }
        }
        Ok(())
    }

    /// Reads the peers given the latest finalized state.
    /// and finalized state.
    #[instrument(skip_all, err)]
    async fn refresh_peers(&mut self) -> eyre::Result<()> {
        // Always take whatever is higher: the last finalized height as per
        // consensus layer (greater than 0 only on restarts with populated
        // consensus state), or the highest finalized block number from the
        // execution layer.
        //
        // This works even if the execution layer was replaced with a snapshot.
        //
        // There is no point taking an outdated state because the network has
        // moved on and there is no guarantee that older peers are even around.
        //
        // Compare this to the DKG actor, which boots into older DKG epochs
        // because it attempts to replay older rounds.
        let highest_finalized = self
            .execution_node
            .provider
            .finalized_block_number()
            .wrap_err("unable to read highest finalized block from execution layer")?
            .unwrap_or(self.last_finalized_height.get())
            .max(self.last_finalized_height.get());

        // Short circuit - no need to read the same state if there is no new data.
        if self
            .last_tracked_peer_set
            .as_ref()
            .is_some_and(|tracked| tracked.height >= highest_finalized)
        {
            return Ok(());
        }

        let epoch_info = self
            .epoch_strategy
            .containing(Height::new(highest_finalized))
            .expect("epoch strategy covers all heights");

        // If we're exactly on a boundary, use it; otherwise use the previous
        // epoch's last block (or genesis).
        //
        // This height is guaranteed to be finalized.
        let latest_boundary = if epoch_info.last().get() == highest_finalized {
            highest_finalized
        } else {
            epoch_info
                .epoch()
                .previous()
                .map_or_else(Height::zero, |prev| {
                    self.epoch_strategy
                        .last(prev)
                        .expect("epoch strategy covers all epochs")
                })
                .get()
        };

        let latest_boundary_header = read_header_at_height(&self.execution_node, latest_boundary)
            .wrap_err("failed reading latest boundary header")?;
        let highest_finalized_header =
            read_header_at_height(&self.execution_node, highest_finalized)
                .wrap_err("failed reading highest finalized header")?;

        let onchain_outcome =
            OnchainDkgOutcome::read(&mut latest_boundary_header.extra_data().as_ref())
                .wrap_err_with(|| {
                    format!(
                        "boundary block at `{latest_boundary}` did not contain a valid DKG outcome"
                    )
                })?;

        let peers_as_per_dkg = ordered::Set::from_iter_dedup(
            onchain_outcome
                .players()
                .iter()
                .cloned()
                .chain(onchain_outcome.next_players().iter().cloned()),
        );
        let peers = read_active_and_known_peers_at_block_hash(
            &self.execution_node,
            &peers_as_per_dkg,
            highest_finalized_header.hash_slow(),
        )
        .wrap_err("unable to read initial peer set from execution layer")?;

        self.track_or_overwrite(highest_finalized_header.number(), peers)
            .await;

        Ok(())
    }

    async fn track_or_overwrite(
        &mut self,
        height: u64,
        peers: ordered::Map<PublicKey, commonware_p2p::Address>,
    ) {
        if let Some(tracked) = &self.last_tracked_peer_set {
            // Overwrite the addresses if only the addresses are changed.
            if peers.keys() == tracked.peers.keys() {
                if peers.values() != tracked.peers.values() {
                    self.oracle.overwrite(peers.clone()).await;
                }
            // Otherwise track the new peers.
            } else {
                self.oracle.track(height, peers.clone()).await;
            }
        } else {
            self.oracle.track(height, peers.clone()).await;
        }

        // Always bump the last-tracked peer set. If the peers are unchanged
        // this only updates the height, but we use the height to determine if
        // state should be read or not.
        self.last_tracked_peer_set
            .replace(LastTrackedPeerSet { height, peers });

        if let Some(tracked) = &self.last_tracked_peer_set {
            self.peers.set(tracked.peers.len() as i64);
        }

        debug!(
            last_tracked_peer_set = ?self.last_tracked_peer_set.as_ref().expect("just set it"),
            "latest tracked peerset",
        );
    }

    fn reset_peer_update_timer(&mut self) {
        // Perform aggressive retries if no peer set is tracked yet.
        // Otherwise just do it every minute.
        self.peer_update_timer = Box::pin(
            self.context.sleep(
                self.last_tracked_peer_set
                    .as_ref()
                    .map_or(BOOTSTRAP_UPDATE_INTERVAL, |_| HEARTBEAT_UPDATE_INTERVAL),
            ),
        );
    }
    #[instrument(skip_all, fields(height), err)]
    fn read_highest_finalized_header(&self) -> eyre::Result<TempoHeader> {
        let highest_finalized = match self.execution_node.provider.finalized_block_hash() {
            Ok(Some(highest_finalized)) => Ok(highest_finalized),
            Ok(None) if self.last_finalized_height == Height::zero() => {
                Ok(self.execution_node.chain_spec().genesis_hash())
            }
            Ok(None) => Err(eyre::eyre!(
                "execution layer has no record of any finalization hashes"
            )),
            Err(err) => Err(eyre::Report::new(err)),
        }
        .wrap_err("failed reading latest finalizhed hash from execution layer")?;
        self.execution_node
            .provider
            .header_by_hash_or_number(highest_finalized.into())
            .map_err(eyre::Report::new)
            .and_then(|h| {
                h.ok_or_eyre(
                    "execution layer did not have the header for the advertised finalized hash",
                )
            })
            .wrap_err_with(|| format!("failed reading header for hash `{highest_finalized}`"))
    }
}

#[derive(Debug)]
struct LastTrackedPeerSet {
    height: u64,
    peers: ordered::Map<PublicKey, commonware_p2p::Address>,
}

#[instrument(skip_all, fields(height), err)]
fn read_header_at_height(execution_node: &TempoFullNode, height: u64) -> eyre::Result<TempoHeader> {
    execution_node
        .provider
        .header_by_number(height)
        .map_err(eyre::Report::new)
        .and_then(|h| h.ok_or_eyre("execution layer did not have a header at the requested height"))
        .wrap_err_with(|| format!("failed reading header at height `{height}`"))
}

async fn read_peer_set_if_boundary(
    context: &impl commonware_runtime::Clock,
    epoch_strategy: &FixedEpocher,
    node: &TempoFullNode,
    block: Block,
) -> Option<ordered::Map<PublicKey, Address>> {
    let mut attempts = 0;
    const MIN_RETRY: Duration = Duration::from_secs(1);
    const MAX_RETRY: Duration = Duration::from_secs(30);

    if epoch_strategy
        .containing(block.height())
        .expect("valid for all heights")
        .last()
        != block.height()
    {
        return None;
    }

    let onchain_outcome = OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref())
        .expect("invariant: boundary blocks must contain DKG outcome");

    let peers_as_per_dkg = ordered::Set::from_iter_dedup(
        onchain_outcome
            .players()
            .iter()
            .cloned()
            .chain(onchain_outcome.next_players().iter().cloned()),
    );

    loop {
        attempts += 1;
        if let Ok(peers) =
            read_active_and_known_peers_at_block_hash_v1(node, &peers_as_per_dkg, block.hash())
        {
            return Some(peers);
        }

        let retry_after = MIN_RETRY.saturating_mul(attempts).min(MAX_RETRY);
        let is_syncing = node.network.is_syncing();
        let best_finalized = node.provider.finalized_block_number().ok().flatten();
        let blocks_behind = best_finalized
            .as_ref()
            .map(|best| block.height().get().saturating_sub(*best));
        tracing::warn_span!("read_peer_set_if_boundary").in_scope(|| {
            warn!(
                attempts,
                retry_after = %display_duration(retry_after),
                is_syncing,
                best_finalized = %display_option(&best_finalized),
                target_height = %block.height(),
                blocks_behind = %display_option(&blocks_behind),
                "reading validator config from contract failed; will retry",
            );
        });
        context.sleep(retry_after).await;
    }
}
