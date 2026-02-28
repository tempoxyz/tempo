use std::net::SocketAddr;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{AddressableManager, Provider};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, ordered};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use futures::{StreamExt as _, channel::mpsc};
use itertools::Either;
use prometheus_client::metrics::gauge::Gauge;
use reth_ethereum::network::NetworkInfo;
use reth_provider::{BlockNumReader as _, HeaderProvider as _};
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;
use tracing::{Level, Span, debug, error, info, info_span, instrument, warn};

use crate::{
    consensus::block::Block,
    validators::{self, Validators},
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

    /// Bootstraps the initial peer set from the last boundary block's DKG
    /// outcome and the validator config at the best available block.
    ///
    /// This is necessary because the DKG may have failed, so the on-chain
    /// outcome is the authoritative source for which dealers and players are
    /// actually running in the current epoch.
    ///
    /// Uses `last_finalized_height` from the consensus layer (marshal) rather
    /// than the execution layer's best block, because the execution layer may
    /// be behind and missing boundary blocks.
    #[instrument(skip_all, err)]
    async fn bootstrap_initial_peers(&mut self) -> eyre::Result<()> {
        let epoch_info = self
            .epoch_strategy
            .containing(self.last_finalized_height)
            .expect("epoch strategy covers all heights");

        // If we're exactly on a boundary, use it; otherwise use the previous
        // epoch's last block (or genesis).
        let last_boundary = if epoch_info.last() == self.last_finalized_height {
            self.last_finalized_height
        } else {
            epoch_info
                .epoch()
                .previous()
                .map_or_else(Height::zero, |prev| {
                    self.epoch_strategy
                        .last(prev)
                        .expect("epoch strategy covers all epochs")
                })
        };

        let header = {
            let mut attempts = 0u32;
            const MIN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
            const MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
            loop {
                attempts += 1;
                match self
                    .execution_node
                    .provider
                    .header_by_number(last_boundary.get())
                    .map_err(eyre::Report::new)
                    .and_then(|h| h.ok_or_eyre("no header at boundary height"))
                {
                    Ok(header) => break header,
                    Err(error) => {
                        let retry_after = MIN_RETRY.saturating_mul(attempts).min(MAX_RETRY);
                        warn!(
                            %error,
                            %last_boundary,
                            attempts,
                            retry_after = %tempo_telemetry_util::display_duration(retry_after),
                            "header not yet available at boundary height; will retry",
                        );
                        self.context.sleep(retry_after).await;
                    }
                }
            }
        };

        let onchain_outcome = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
            .wrap_err_with(|| {
                format!("boundary block at `{last_boundary}` did not contain a valid DKG outcome")
            })?;

        let (read_height, read_hash, all_validators) =
            read_validator_config(&self.execution_node, &header)
                .wrap_err("unable to read initial peer set from execution layer")?;

        let source = match &all_validators {
            Validators::V1(_) => "Validator Config V1",
            Validators::V2(_) => "Validator Config V2",
        };
        debug!(source, "read validators from chain");
        let peers = construct_peer_set(&onchain_outcome, &all_validators);
        self.peers.set(peers.len() as i64);

        let is_syncing = self.execution_node.network.is_syncing();
        info!(
            epoch = %onchain_outcome.epoch,
            %last_boundary,
            is_syncing,
            read_height,
            %read_hash,
            ?peers,
            "bootstrapped initial peer set from last boundary block and best execution layer block",
        );

        let header = self
            .execution_node
            .provider
            .header(read_hash)
            .expect("must be access execution layer to get header - just read validator config for")
            .expect("execution layer must have the header - just read validator config for it");
        let last_tracked_peer_set = LastTrackedPeerSet {
            from_height: header.number(),
            peers,
        };
        self.oracle
            .track(
                last_tracked_peer_set.from_height,
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
                    self.handle_finalized_block(block)
                        .await
                        .wrap_err("failed handling finalized block")?;
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
        err,
    )]
    async fn handle_finalized_block(&mut self, block: Block) -> eyre::Result<()> {
        let epoch_info = self
            .epoch_strategy
            .containing(block.height())
            .expect("epoch strategy covers all heights");

        // Always validator state on the boundary, and if we are past the hardfork.
        if block.height() == epoch_info.last()
            || self
                .execution_node
                .chain_spec()
                .is_t2_active_at_timestamp(block.timestamp())
        {
            // Intentionally bail on parse failure: the last block of every epoch
            // must contain a valid DKG outcome. If it doesn't, something is
            // fundamentally wrong and we surface the error rather than silently
            // running with a stale peer set.
            let header;
            let extra_data = if block.height() == epoch_info.last() {
                block.header().extra_data()
            } else {
                let last_boundary = epoch_info.epoch().previous().map_or(0, |epoch| {
                    self.epoch_strategy
                        .last(epoch)
                        .expect("valid for all epochs")
                        .get()
                });
                header = self
                    .execution_node
                    .provider
                    .header_by_number(last_boundary)
                    .map_err(eyre::Report::new)
                    .and_then(|maybe| maybe.ok_or_eyre("unknown header"))
                    .wrap_err_with(|| {
                        format!("failed reading header for last boundary height `{last_boundary}`")
                    })?;
                header.extra_data()
            };
            let onchain_outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
                .wrap_err("could not read DKG outcome from boundary block")?;

            if let Err(reason) = self.executor.subscribe_finalized(block.height()).await {
                warn!(
                    %reason,
                    "unable to clarify whether the finalized block was already \
                    forwarded to execution layer; will try to read validator \
                    config contract, but it will likely fail",
                );
            }

            let (_read_height, _read_hash, all_validators) =
                match read_validator_config_at_hash(&self.execution_node, block.hash()) {
                    Ok(ret) => ret,
                    Err(reason) => {
                        warn!(
                            %reason,
                            execution_layer.status = self.execution_node.network.is_syncing(),
                            "unable to read validator config; will retry on next block",
                        );
                        return Ok(());
                    }
                };

            let peers = construct_peer_set(&onchain_outcome, &all_validators);

            if let Some(last_tracked_peer_set) = &mut self.last_tracked_peer_set {
                if peers.keys() == last_tracked_peer_set.peers.keys() {
                    if peers.values() != last_tracked_peer_set.peers.values() {
                        self.oracle.overwrite(peers.clone()).await;
                        last_tracked_peer_set.peers = peers;
                    }
                } else {
                    *last_tracked_peer_set = LastTrackedPeerSet {
                        from_height: block.height().get(),
                        peers,
                    };
                    self.oracle
                        .track(
                            last_tracked_peer_set.from_height,
                            last_tracked_peer_set.peers.clone(),
                        )
                        .await;
                }
            } else {
                self.oracle.track(block.height().get(), peers.clone()).await;
                self.last_tracked_peer_set = Some(LastTrackedPeerSet {
                    from_height: block.height().get(),
                    peers,
                })
            }

            if let Some(tracked) = &self.last_tracked_peer_set {
                self.peers.set(tracked.peers.len() as i64);
            }

            debug!(
                last_tracked_peer_set = ?self.last_tracked_peer_set,
                "latest tracked peerset",
            );
        }
        Ok(())
    }
}

pub(crate) fn construct_peer_set(
    outcome: &OnchainDkgOutcome,
    validators: &Validators,
) -> commonware_utils::ordered::Map<PublicKey, commonware_p2p::Address> {
    // Dealers are output.players() from the previous epoch's DKG output.
    // Players are outcome.next_players.
    let all_keys = outcome
        .players()
        .iter()
        .chain(outcome.next_players().iter())
        .chain(match validators {
            Validators::V1(validators) => Either::Left(
                validators
                    .iter_pairs()
                    .filter_map(|(k, v)| v.is_active().then_some(k)),
            ),
            Validators::V2(validators) => Either::Right(
                validators
                    .iter_pairs()
                    .filter_map(|(k, v)| v.is_active().then_some(k)),
            ),
        });

    commonware_utils::ordered::Map::from_iter_dedup(all_keys.map(|key| {
        let addr = match validators {
            Validators::V1(vals) => commonware_p2p::Address::Symmetric(
                vals.get_value(key)
                    .expect(
                        "all DKG participants must have an entry in the \
                         unfiltered, contract validator set",
                    )
                    .outbound,
            ),
            Validators::V2(vals) => {
                let val = vals.get_value(key).expect(
                    "all DKG participants must have an entry in the \
                     unfiltered, contract validator set",
                );
                commonware_p2p::Address::Asymmetric {
                    ingress: commonware_p2p::Ingress::Socket(val.ingress()),
                    egress: SocketAddr::new(val.egress(), 0),
                }
            }
        };
        (key.clone(), addr)
    }))
}

#[derive(Debug)]
struct LastTrackedPeerSet {
    from_height: u64,
    peers: ordered::Map<PublicKey, commonware_p2p::Address>,
}

/// Reads the smart contract at `reference_header.number` or higher, if
/// available.
#[instrument(skip_all, err(level = Level::INFO))]
fn read_validator_config(
    node: &TempoFullNode,
    reference_header: &TempoHeader,
) -> eyre::Result<(u64, B256, Validators)> {
    // TODO: is this too harsh? Should we wait until there is a best block
    // available at a later point?
    let best_block_number = node
        .provider
        .best_block_number()
        .wrap_err("provider does not have best block available")?;

    ensure!(
        best_block_number >= reference_header.number(),
        "best_block_number `{best_block_number}` is below reference header {}",
        reference_header.number(),
    );

    validators::read_from_contract_at_height(1, node, best_block_number, reference_header)
        .wrap_err("unable to read validators from best block")
}

#[instrument(skip_all, err(level = Level::INFO))]
fn read_validator_config_at_hash(
    node: &TempoFullNode,
    block_hash: B256,
) -> eyre::Result<(u64, B256, Validators)> {
    validators::read_from_contract_at_block_hash(1, node, block_hash)
        .wrap_err("unable to read validators from best block")
}
