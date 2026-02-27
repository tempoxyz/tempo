use std::time::Duration;

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
use futures::{StreamExt as _, channel::mpsc, future::join};
use prometheus_client::metrics::gauge::Gauge;
use reth_ethereum::{network::NetworkInfo, rpc::eth::primitives::BlockNumHash};
use reth_provider::{BlockIdReader as _, HeaderProvider as _};
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;
use tracing::{Level, Span, debug, error, info, info_span, instrument, warn};

use crate::{
    consensus::block::Block,
    validators::{
        read_active_and_known_peers_at_block_hash, read_active_and_known_peers_at_block_hash_v1,
    },
};

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
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    /// Returns the last tracked peer set.
    ///
    /// Must only be called after bootstrapping the initial peer set. Will
    /// panic otherwise.
    fn last_tracked_peer_set(&self) -> &LastTrackedPeerSet {
        self.last_tracked_peer_set
            .as_ref()
            .expect("set after bootstrap")
    }

    /// Returns a mutable borrow of the last tracked peer set.
    ///
    /// Must be called only after bootstrapping the initial peer set. Will
    /// panic otherwise.
    fn last_tracked_peer_set_mut(&mut self) -> &mut LastTrackedPeerSet {
        self.last_tracked_peer_set
            .as_mut()
            .expect("set after bootstrap")
    }

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
        Self {
            context: ContextCell::new(context),
            oracle,
            execution_node,
            executor,
            epoch_strategy,
            last_finalized_height,
            mailbox,
            peers,
            last_tracked_peer_set: None,
        }
    }

    async fn run(mut self) {
        if let Err(error) = self.bootstrap_initial_peers().await {
            info_span!("peer_manager").in_scope(|| {
                error!(
                    %error,
                    "failed to bootstrap initial peers on startup, cannot continue",
                );
            });
            return;
        }

        let reason = 'event_loop: loop {
            match self.mailbox.next().await {
                None => break 'event_loop eyre::eyre!("mailbox closed unexpectedly"),
                Some(msg) => {
                    if let Err(error) = self.handle_message(msg.cause, msg.message).await {
                        break 'event_loop error;
                    }
                }
            }
        };
        info_span!("peer_manager").in_scope(|| error!(%reason,"agent shutting down"));
    }

    /// Bootstraps and registers initial peer set from the latest DKG outcome
    /// and finalized state.
    ///
    ///
    #[instrument(skip_all, err)]
    async fn bootstrap_initial_peers(&mut self) -> eyre::Result<()> {
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

        // NOTE: retry relies on the knowledge that `last_finalized_block` is
        // passed to the executor actor to backfill finalized blocks that might
        // have been lost on restart because the execution layer did not persist
        // them in time.
        //
        // If the execution layer has been deleted then this loop will never
        // complete.
        let (latest_boundary_header, highest_finalized_header) = join(
            read_header_at_height_with_retry(&self.context, &self.execution_node, latest_boundary),
            read_header_at_height_with_retry(
                &self.context,
                &self.execution_node,
                highest_finalized,
            ),
        )
        .await;

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

        self.peers.set(peers.len() as i64);

        info!(
            epoch = %onchain_outcome.epoch,
            %latest_boundary,
            %highest_finalized,
            ?peers,
            "bootstrapped initial peer set from DKG outcome on latest boundary \
            and block state from highest finalized block",
        );

        let last_tracked_peer_set = LastTrackedPeerSet {
            height: highest_finalized,
            peers,
        };
        self.oracle
            .track(
                last_tracked_peer_set.height,
                last_tracked_peer_set.peers.clone(),
            )
            .await;
        self.last_tracked_peer_set = Some(last_tracked_peer_set);

        Ok(())
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
                    self.update_peer_set(block).await;
                    ack.acknowledge();
                }
                Update::Tip { .. } => {}
            },
        }
        Ok(())
    }

    #[instrument(
        skip_all,
        fields(
            block.height = %block.height(),
        ),
    )]
    async fn update_peer_set(&mut self, block: Block) {
        if let Err(reason) = self.executor.subscribe_finalized(block.height()).await {
            warn!(
                %reason,
                "unable to clarify whether the finalized block was already \
                forwarded to execution layer; will try to read validator \
                config contract, but it will likely fail",
            );
        }

        // Post T2 behavior: do a best-effort update of the peerset, to whatever
        // is available as long as it is newer than what we are already tracking.
        let (height, peers) = if self
            .execution_node
            .chain_spec()
            .is_t2_active_at_timestamp(block.timestamp())
        {
            let highest_finalized = match self.execution_node.provider.finalized_block_num_hash() {
                Err(error) => {
                    warn!(
                        reason = %eyre::Report::new(error),
                        "failed reading latest finalized block number and hash \
                        from execution layer ",
                    );
                    return;
                }
                Ok(None) => {
                    debug!("no finalized block block state set; returning");
                    return;
                }
                Ok(Some(num_hash)) => num_hash,
            };
            let peers = if highest_finalized.number > self.last_tracked_peer_set().height {
                read_peers_at_block_num_hash(
                    &self.execution_node,
                    &self.epoch_strategy,
                    highest_finalized,
                )
                .ok()
            } else {
                None
            };
            (highest_finalized.number, peers)

        // Pre T2 behavior: wait until the boundary is available.
        } else {
            let height = block.number();
            let peers = read_peer_set_if_boundary(
                &self.context,
                &self.epoch_strategy,
                &self.execution_node,
                block,
            )
            .await;
            (height, peers)
        };

        if let Some(peers) = &peers {
            // Overwrite the addresses if the peers are unchanged.
            if peers.keys() == self.last_tracked_peer_set().peers.keys() {
                if peers.values() != self.last_tracked_peer_set().peers.values() {
                    self.oracle.overwrite(peers.clone()).await;
                }
            // Otherwise track the new peers.
            } else {
                self.oracle.track(height, peers.clone()).await;
            }
        }

        // Always bump the last-tracked peer set. If the peers are unchanged
        // this only updates the height, but we use the height to determine if
        // state should be read or not.
        self.last_tracked_peer_set_mut().height = height;
        if let Some(peers) = peers {
            self.last_tracked_peer_set_mut().peers = peers;
        }

        if let Some(tracked) = &self.last_tracked_peer_set {
            self.peers.set(tracked.peers.len() as i64);
        }

        debug!(
            last_tracked_peer_set = ?self.last_tracked_peer_set,
            "latest tracked peerset",
        );
    }
}

#[derive(Debug)]
struct LastTrackedPeerSet {
    height: u64,
    peers: ordered::Map<PublicKey, commonware_p2p::Address>,
}

async fn read_header_at_height_with_retry(
    context: &impl Clock,
    execution_node: &TempoFullNode,
    height: u64,
) -> TempoHeader {
    let mut attempts = 0u32;
    const MIN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
    const MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
    loop {
        attempts += 1;
        match execution_node
            .provider
            .header_by_number(height)
            .map_err(eyre::Report::new)
            .and_then(|h| h.ok_or_eyre("no header at boundary height"))
        {
            Ok(header) => break header,
            Err(error) => {
                let retry_after = MIN_RETRY.saturating_mul(attempts).min(MAX_RETRY);
                warn!(
                    %error,
                    %height,
                    attempts,
                    retry_after = %tempo_telemetry_util::display_duration(retry_after),
                    "header not yet available for height; will retry",
                );
                context.sleep(retry_after).await;
            }
        }
    }
}

#[instrument(
    skip_all,
    fields(block.hash = %num_hash.hash, block.number = %num_hash.number),
    err(level = Level::WARN),
)]
fn read_peers_at_block_num_hash(
    execution_node: &TempoFullNode,
    epoch_strategy: &FixedEpocher,
    num_hash: BlockNumHash,
) -> eyre::Result<ordered::Map<PublicKey, Address>> {
    let epoch_info = epoch_strategy
        .containing(Height::new(num_hash.number))
        .expect("epoch strategy covers all heights");
    let latest_boundary = if epoch_info.last().get() == num_hash.number {
        num_hash.number
    } else {
        epoch_info.epoch().previous().map_or(0, |prev| {
            epoch_strategy
                .last(prev)
                .expect("valid for all epochs")
                .get()
        })
    };

    let boundary_header = execution_node
        .provider
        .header_by_number(latest_boundary)
        .map_err(eyre::Report::new)
        .and_then(|maybe| maybe.ok_or_eyre("unknown header"))
        .wrap_err_with(|| {
            format!("failed reading header for last boundary height `{latest_boundary}`")
        })?;

    let onchain_outcome = OnchainDkgOutcome::read(&mut boundary_header.extra_data().as_ref())
        .expect("invariant: boundary blocks must contain DKG outcome");

    let peers_as_per_dkg = ordered::Set::from_iter_dedup(
        onchain_outcome
            .players()
            .iter()
            .cloned()
            .chain(onchain_outcome.next_players().iter().cloned()),
    );

    let peers =
        read_active_and_known_peers_at_block_hash(execution_node, &peers_as_per_dkg, num_hash.hash)
            .wrap_err("failed reading peers from on-chain state")?;
    Ok(peers)
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
                retry_after = %tempo_telemetry_util::display_duration(retry_after),
                is_syncing,
                best_finalized = %tempo_telemetry_util::display_option(&best_finalized),
                target_height = %block.height(),
                blocks_behind = %tempo_telemetry_util::display_option(&blocks_behind),
                "reading validator config from contract failed; will retry",
            );
        });
        context.sleep(retry_after).await;
    }
}
