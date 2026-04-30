//! Follower sync driver.
//!
//! Subscribes to upstream finalization events and processes epoch boundary
//! blocks for DKG scheme extraction. Non-boundary blocks are synced by Reth
//! via P2P and fetched by marshal's gap-repair resolver on demand.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::{
    Epochable, Heightable as _, Reporter, marshal,
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::variant::MinSig,
    ed25519::{self, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, vec::NonEmptyVec};
use rand_08::{CryptoRng, Rng};

use eyre::{OptionExt as _, Report, WrapErr as _};
use reth_node_core::primitives::SealedBlock;
use reth_provider::HeaderProvider as _;
use tempo_node::{TempoFullNode, rpc::consensus::Event};
use tokio::{select, sync::mpsc};
use tracing::instrument;

use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    feed,
};

pub(super) fn try_init<TContext>(
    context: TContext,
    config: Config,
) -> eyre::Result<(Driver<TContext>, Mailbox)> {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = Mailbox(tx);

    // Use the last boundary block available in the execution layer as the
    // trusted starting point.
    //
    // TODO: Provide a certificate with the latest boundary to not just trust
    // but also verify.
    let last_finalized_number = config
        .execution_node
        .provider
        .canonical_in_memory_state()
        .get_finalized_num_hash()
        .map_or(0u64, |num_hash| num_hash.number);

    let epoch_info = config
        .epoch_strategy
        .containing(Height::new(last_finalized_number))
        .expect("strategy valid for all heights and epochs");

    let last_boundary = if epoch_info.last().get() == last_finalized_number {
        epoch_info.last()
    } else if let Some(previous) = epoch_info.epoch().previous() {
        config
            .epoch_strategy
            .last(previous)
            .expect("strategy valid for all heights and epochs")
    } else {
        Height::zero()
    };
    let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
        &mut config
            .execution_node
            .provider
            .header_by_number(last_boundary.get())
            .map_err(Report::new)
            .and_then(|maybe_header| maybe_header.ok_or_eyre("execution layer did not have header"))
            .wrap_err_with(|| {
                format!(
                    "cannot establish baseline - unable to read the header from \
                the last boundary block at height `{last_boundary}` from the \
                excecution layer"
                )
            })?
            .extra_data()
            .as_ref(),
    )
    .wrap_err("the genesis header did not contain a DKG outcome")?;

    config.scheme_provider.register(
        onchain_outcome.epoch,
        Scheme::certificate_verifier(
            crate::config::NAMESPACE,
            *onchain_outcome.sharing().public(),
        ),
    );

    let actor = Driver {
        context: ContextCell::new(context),
        config,
        mailbox: rx,
        current_epoch: epoch_info.epoch(),
        last_boundary,
    };
    Ok((actor, mailbox))
}

pub(super) struct Config {
    pub(super) execution_node: Arc<TempoFullNode>,
    pub(super) scheme_provider: SchemeProvider,

    // TODO: What to do with this information?
    pub(super) last_finalized_height: Height,

    pub(super) marshal: crate::alias::marshal::Mailbox,
    pub(super) feed: feed::Mailbox,
    pub(super) epoch_strategy: FixedEpocher,
}

enum Message {
    Event(Event),
    Finalized(marshal::Update<Block>),
}

impl From<Event> for Message {
    fn from(value: Event) -> Self {
        Self::Event(value)
    }
}

impl From<marshal::Update<Block>> for Message {
    fn from(value: marshal::Update<Block>) -> Self {
        Self::Finalized(value)
    }
}

#[derive(Clone)]
pub(super) struct Mailbox(mpsc::UnboundedSender<Message>);

impl Mailbox {
    pub(super) fn to_event_reporter(&self) -> EventReporter {
        EventReporter(self.clone())
    }

    pub(super) fn to_marshal_reporter(&self) -> MarshalReporter {
        MarshalReporter(self.clone())
    }

    fn send(&self, msg: impl Into<Message>) {
        let _ = self.0.send(msg.into());
    }
}

#[derive(Clone)]
pub(super) struct EventReporter(Mailbox);

impl Reporter for EventReporter {
    type Activity = Event;

    async fn report(&mut self, activity: Self::Activity) {
        self.0.send(activity);
    }
}

#[derive(Clone)]
pub(super) struct MarshalReporter(Mailbox);

impl Reporter for MarshalReporter {
    type Activity = marshal::Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        self.0.send(activity);
    }
}

pub(super) struct Driver<TContext> {
    context: ContextCell<TContext>,
    config: Config,
    mailbox: mpsc::UnboundedReceiver<Message>,

    last_boundary: Height,
    current_epoch: Epoch,
}

impl<C: Clock + Rng + CryptoRng> Driver<C>
where
    C: Spawner,
{
    pub(super) fn start(mut self) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        self.config.marshal.set_floor(self.last_boundary).await;
        if self.heal_gap().await.is_err() {
            return;
        };

        loop {
            select!(
                biased;

                Some(message) = self.mailbox.recv() => {
                    match message {
                        Message::Event(event) => {
                            // Emits an event on error.
                            let _ = self.process_event(event);
                        }
                        Message::Finalized(update) => {
                            self.process_update(update).await;
                        }
                    }
                }
            );
        }
    }

    /// Fills in the missing scheme if the execution layer did not persist.
    #[instrument(skip_all, err(Display))]
    async fn heal_gap(&mut self) -> eyre::Result<()> {
        let current_consensus_epoch = self
            .config
            .epoch_strategy
            .containing(self.config.last_finalized_height)
            .expect("strategy is valid for all heights and epochs");
        let current_execution_epoch = self
            .config
            .epoch_strategy
            .containing(self.last_boundary)
            .expect("strategy is valid for all heights and epochs");

        if let Some(previous) = current_consensus_epoch.epoch().previous()
            && previous > current_execution_epoch.epoch()
        {
            let last_consensus_boundary = self
                .config
                .epoch_strategy
                .last(previous)
                .expect("strategy is valid for all heights and epochs");
            let boundary_block = self
                .config
                .marshal
                .get_block(last_consensus_boundary)
                .await
                .ok_or_else(|| {
                    eyre::eyre!(
                        "cannot heal finalization gap; consensus layer is \
                        ahead of execution layer, but consensus layer does not \
                        have boundary block at height \
                        `{last_consensus_boundary}`"
                    )
                })?;

            let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
                &mut boundary_block.header().extra_data().as_ref(),
            )
            .wrap_err_with(|| {
                format!(
                    "the boundary block at height `{last_consensus_boundary}` \
                contained no or a malformed DKG outcome"
                )
            })?;

            self.config.scheme_provider.register(
                onchain_outcome.epoch,
                Scheme::certificate_verifier(
                    crate::config::NAMESPACE,
                    *onchain_outcome.sharing().public(),
                ),
            );
        }

        Ok(())
    }

    #[instrument(skip_all)]
    async fn process_event(&mut self, event: Event) -> eyre::Result<()> {
        let Event::Finalized {
            block: certified, ..
        } = event
        else {
            return Ok(());
        };

        // TODO: ensure well-formedness at the type level so we don't need extra
        // decoding here.
        let finalization = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(Report::new)
            .and_then(|bytes| {
                Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(&*bytes)
                    .map_err(Report::new)
            })
            .wrap_err("event contained a malformed finalization certificate")?;

        if finalization.epoch() > self.current_epoch {
            let boundary_height = self
                .config
                .epoch_strategy
                .last(self.current_epoch)
                .expect("strategy is valid for all epochs and heights");
            self.config
                .marshal
                .hint_finalized(
                    boundary_height,
                    // XXX: we know for a fact that the resolver used by the marshal
                    // actor ignores the target, so we just give it a dummy key.
                    NonEmptyVec::new(ed25519::PrivateKey::random(&mut self.context).public_key()),
                )
                .await;

            return Ok(());
        }

        let consensus_block = Block::from_execution_block(SealedBlock::seal_slow(certified.block));

        // Store the Finalized Block
        let round = Round::new(Epoch::new(certified.epoch), View::new(certified.view));
        let activity = Activity::Finalization(finalization);
        self.config.marshal.verified(round, consensus_block).await;
        self.config.marshal.report(activity.clone()).await;
        self.config.feed.report(activity).await;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn process_update(&mut self, update: marshal::Update<Block>) {
        let marshal::Update::Block(block, ack) = update else {
            return;
        };
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(block.height())
            .expect("strategy valid for all heights");
        if epoch_info.last() == block.height() {
            let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
                &mut block.header().extra_data().as_ref(),
            )
            .expect("boundary blocks must contain DKG outcomes");
            self.config.scheme_provider.register(
                onchain_outcome.epoch,
                Scheme::certificate_verifier(
                    crate::config::NAMESPACE,
                    *onchain_outcome.network_identity(),
                ),
            );
            self.current_epoch = onchain_outcome.epoch;
        }
        ack.acknowledge();
    }
}
