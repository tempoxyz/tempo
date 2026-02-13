use alloy_consensus::BlockHeader as _;
use commonware_codec::ReadExt as _;
use commonware_consensus::Heightable as _;
use commonware_consensus::marshal::Update;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{AddressableManager, Provider};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use commonware_utils::Acknowledgement;
use commonware_utils::acknowledgement::Exact;
use eyre::{OptionExt as _, WrapErr as _};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use reth_ethereum::network::NetworkInfo;
use reth_provider::BlockNumReader as _;
use reth_provider::HeaderProvider;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tracing::{Span, error, info, info_span, instrument, warn};

use crate::consensus::block::Block;
use crate::validators::{self, DecodedValidator, read_validator_config_with_retry};

use super::ingress::{Message, MessageWithCause};

pub(crate) struct Actor<TContext, TPeerManager>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    context: ContextCell<TContext>,

    oracle: TPeerManager,
    execution_node: TempoFullNode,
    epoch_strategy: FixedEpocher,
    last_finalized_height: Height,
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,

    contract_read_attempts: Counter,
    peers: Gauge,
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
            epoch_strategy,
            last_finalized_height,
        }: super::Config<TPeerManager>,
        mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    ) -> Self {
        let contract_read_attempts = Counter::default();
        context.register(
            "contract_read_attempts",
            "how often the actor tried reading the validator config contract",
            contract_read_attempts.clone(),
        );
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
            epoch_strategy,
            last_finalized_height,
            mailbox,
            contract_read_attempts,
            peers,
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

        let all_validators = read_validator_config_with_retry(
            &self.context,
            &self.execution_node,
            validators::ReadTarget::AtLeast {
                height: last_boundary,
            },
            &self.contract_read_attempts,
        )
        .await;

        let peers = construct_peer_set(&onchain_outcome, &all_validators);
        self.peers.set(peers.len() as i64);

        let is_syncing = self.execution_node.network.is_syncing();
        let best_block = self.execution_node.provider.best_block_number();
        info!(
            epoch = %onchain_outcome.epoch,
            %last_boundary,
            is_syncing,
            best_block = %tempo_telemetry_util::display_result(&best_block),
            peers = peers.len(),
            "bootstrapped initial peer set from boundary block",
        );

        AddressableManager::track(&mut self.oracle, onchain_outcome.epoch.get(), peers).await;

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
                    self.handle_finalized_block(block, ack)
                        .await
                        .wrap_err("failed handling finalized block")?;
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
    async fn handle_finalized_block(&mut self, block: Block, ack: Exact) -> eyre::Result<()> {
        let height = commonware_consensus::Heightable::height(&block);
        let epoch_info = self
            .epoch_strategy
            .containing(height)
            .expect("epoch strategy covers all heights");

        if is_past_hardfork(&block) {
            // TODO: After the hardfork, read Val Config V2 getActiveValidators()
            // from the execution node, build ordered::Map<PublicKey, Address>
            // using Address::Asymmetric { ingress, egress }, and call
            // oracle.overwrite(peers).
            warn!("hardfork detected but V2 peer management not yet implemented");
        } else if height == epoch_info.last() {
            // Intentionally bail on parse failure: the last block of every epoch
            // must contain a valid DKG outcome. If it doesn't, something is
            // fundamentally wrong and we surface the error rather than silently
            // running with a stale peer set.
            let extra_data = block.header().extra_data();
            let onchain_outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
                .wrap_err("could not read DKG outcome from boundary block")?;

            let all_validators = read_validator_config_with_retry(
                &self.context,
                &self.execution_node,
                validators::ReadTarget::AtLeast {
                    height: block.height(),
                },
                &self.contract_read_attempts,
            )
            .await;

            let peers = construct_peer_set(&onchain_outcome, &all_validators);
            self.peers.set(peers.len() as i64);

            info!(
                epoch = %onchain_outcome.epoch,
                ?peers,
                "tracking peers for new epoch from boundary block",
            );

            AddressableManager::track(&mut self.oracle, onchain_outcome.epoch.get(), peers).await;
        }
        ack.acknowledge();
        Ok(())
    }
}

/// Stub to implement hardfork logic.
fn is_past_hardfork(_block: &Block) -> bool {
    false
}

fn construct_peer_set(
    outcome: &OnchainDkgOutcome,
    validators: &commonware_utils::ordered::Map<PublicKey, DecodedValidator>,
) -> commonware_utils::ordered::Map<PublicKey, commonware_p2p::Address> {
    // Dealers are output.players() from the previous epoch's DKG output.
    // Players are outcome.next_players (the players for the next DKG round).
    // Syncers are all currently active validators.
    let all_keys = outcome
        .dealers()
        .iter()
        .chain(outcome.next_players().iter())
        .chain(
            validators
                .iter_pairs()
                .filter(|(_, v)| v.active)
                .map(|(k, _)| k),
        );

    commonware_utils::ordered::Map::from_iter_dedup(all_keys.map(|key| {
        let addr = validators
            .get_value(key)
            .expect(
                "all DKG participants must have an entry in the \
                 unfiltered, contract validator set",
            )
            .outbound;
        (key.clone(), commonware_p2p::Address::Symmetric(addr))
    }))
}
