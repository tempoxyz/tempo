use std::{collections::HashMap, sync::Arc};

use commonware_consensus::{Block as _, simplex::signing_scheme::bls12381_threshold, types::Epoch};
use commonware_cryptography::bls12381::dkg::player::Output;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_p2p::{Receiver, Sender, utils::mux};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use eyre::WrapErr as _;
use eyre::eyre;
use futures::{StreamExt as _, channel::mpsc};
use rand_core::CryptoRngCore;
use tracing::info;
use tracing::{Span, instrument, warn};

use crate::dkg::ceremony::DealOutcome;
use crate::dkg::ceremony::RoundResult;
use crate::dkg::manager::ingress::GetCeremonyDeal;
use crate::dkg::manager::ingress::GetCeremonyOutcome;
use crate::{
    dkg::{
        ceremony::{self, Ceremony},
        manager::ingress::Finalize,
    },
    epoch,
};

pub(crate) struct Actor<TContext> {
    pub(super) config: super::Config,
    pub(super) context: ContextCell<TContext>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::Message>,
    pub(super) schemes_per_epoch:
        Arc<std::sync::Mutex<HashMap<Epoch, Arc<bls12381_threshold::Scheme<MinSig>>>>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + governor::clock::Clock + CryptoRngCore + Metrics + Spawner + Storage,
{
    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let (mux, mut ceremony_mux) = mux::Muxer::new(
            self.context.with_label("ceremony_mux"),
            sender,
            receiver,
            100,
        );
        mux.start();

        // Can't know the some of the types of ceremony until after receiving
        // Sender and Receiver and so must make it an ephemeral variable.

        let mut ceremony = None;

        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
                super::Command::GetCeremonyDeal(get_ceremony_deal) => {
                    let _: Result<_, _> = self
                        .handle_get_ceremony_deal(cause, get_ceremony_deal, &mut ceremony)
                        .await;
                }
                super::Command::GetCeremonyOutcome(get_ceremony_outcome) => {
                    let _: Result<_, _> = self
                        .handle_get_ceremony_outcome(cause, get_ceremony_outcome, &mut ceremony)
                        .await;
                }
                super::Command::Finalize(finalize) => {
                    let _: Result<_, _> = self
                        .handle_finalize(cause, finalize, &mut ceremony, &mut ceremony_mux)
                        .await;
                }
                super::Command::GetScheme(get_scheme) => todo!(),
            }
        }
    }

    pub(crate) fn start(
        mut self,
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(dkg_channel).await)
    }

    #[instrument(
        parent = cause,
        skip_all,
        fields(
            request.epoch = epoch,
        ),
        err,
    )]
    async fn handle_get_ceremony_deal<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetCeremonyDeal { epoch, response }: GetCeremonyDeal,
        ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut outcome = None;

        'get_outcome: {
            let Some(ceremony) = ceremony else {
                warn!("no dkg ceremony currently active");
                break 'get_outcome;
            };
            if ceremony.epoch() != epoch {
                warn!(
                    ceremony.epoch = %ceremony.epoch(),
                    "deal outcome for ceremony of different epoch requested",
                );
                break 'get_outcome;
            }
            outcome = ceremony.deal_outcome().cloned();
        }

        response
            .send(outcome)
            .map_err(|_| eyre!("failed returning outcome because requester went away"))
    }

    #[instrument(
        parent = cause,
        skip_all,
        fields(
            request.epoch = epoch,
        ),
        err,
    )]
    async fn handle_get_ceremony_outcome<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetCeremonyOutcome { epoch, response }: GetCeremonyOutcome,
        ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut outcome = None;

        'get_outcome: {
            let Some(ceremony) = ceremony else {
                warn!("no dkg ceremony currently active");
                break 'get_outcome;
            };
            if ceremony.epoch() != epoch {
                warn!(
                    ceremony.epoch = %ceremony.epoch(),
                    "deal outcome for ceremony of different epoch requested",
                );
                break 'get_outcome;
            }
            outcome = ceremony.deal_outcome().cloned();
        }

        response
            .send(outcome)
            .map_err(|_| eyre!("failed returning outcome because requester went away"))
    }

    #[instrument(
        parent = cause,
        skip_all,
        fields(
            derived_epoch = epoch::of_height(block.height(), self.config.heights_per_epoch),
        ),
        err,
    )]
    async fn handle_finalize<TReceiver, TSender>(
        &mut self,
        cause: Span,
        Finalize { block, response }: Finalize,
        ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        mux: &mut mux::MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        match epoch::relative_position(block.height(), self.config.heights_per_epoch) {
            epoch::RelativePosition::FirstHalf => {
                if ceremony.is_none() {
                    let epoch = epoch::of_height(block.height(), self.config.heights_per_epoch)
                        .expect("genesis block with height == 0 must never be finalized and all other blocks belong to an epoch");

                    let (sender, receiver) = mux
                        .register(epoch as u32)
                        .await
                        .wrap_err("mux subchannel already running for epoch; this is a problem")?;

                    let config = ceremony::Config {
                        namespace: self.config.namespace.clone(),
                        me: self.config.me.clone(),
                        public: self.config.public.clone(),
                        share: self.config.share.clone(),
                        epoch,
                        dealers: self.config.participants.clone(),
                        players: self.config.participants.clone(),
                        send_rate_limit: self.config.rate_limit,
                        receiver,
                        sender,
                        partition_prefix: format!(
                            "{}_ceremny",
                            self.config.partition_prefix.clone()
                        ),
                    };

                    let new_ceremony = ceremony::Ceremony::init(&mut self.context, config)
                        .await
                        .wrap_err(
                            "failed initializing a new ceremony on the first height of the epoch",
                        )?;
                    if let Some(old) = ceremony.replace(new_ceremony) {
                        warn!(
                            epoch = old.epoch(),
                            "an old ceremony was still running on the first height of the new epoch",
                        );
                    }
                }

                let ceremony = ceremony
                    .as_mut()
                    .expect("ceremony is initialized immediately above");

                let _ = ceremony.request_acks().await;
                let _ = ceremony.process_messages().await;
            }
            epoch::RelativePosition::Middle => {
                let Some(ceremony) = ceremony else {
                    return Err(eyre!(
                        "no dkg ceremony was running at the midpoint of the epoch"
                    ));
                };
                let _ = ceremony.process_messages().await;

                let _ = ceremony.construct_deal_outcome().await;
            }
            epoch::RelativePosition::SecondHalf => {
                let Some(ceremony) = ceremony else {
                    return Err(eyre!(
                        "no dkg ceremony was running during the second half of the epoch"
                    ));
                };
                let _ = ceremony.process_block(&block).await;
            }
        }

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes availaboe on the last height and can be
        // stored on chain.
        if epoch::is_last_height(
            block.height().saturating_add(1),
            self.config.heights_per_epoch,
        ) {
            let Some(ceremony) = ceremony.take() else {
                return Err(eyre!(
                    "no dkg ceremony was running on the pre-to-last block of the epoch"
                ));
            };
            let (next_participants, next_public_polynomial, next_share, success) =
                match ceremony.finalize().await {
                    (next_participants, RoundResult::Output(Output { public, share }), success) => {
                        (next_participants, public, Some(share), success)
                    }
                    (next_participants, RoundResult::Polynomial(public), success) => {
                        (next_participants, public, None, success)
                    }
                };

            // TODO(janis): add metrics
            // if !success {
            //     self.failed_rounds.inc();
            // }

            // TODO(janis): add display formatting to the polynomial
            info!(
                success,
                ?next_public_polynomial,
                "finalized dkg reshare ceremony; instructing reconfiguration after reshare.",
            );
            // let next_epoch = epoch + 1;

            // // Persist the next epoch information
            // let epoch_state = EpochState {
            //     epoch: next_epoch,
            //     public: next_public.clone(),
            //     share: next_share.clone(),
            // };
            // self.epoch_metadata
            //     .put_sync(EPOCH_METADATA_KEY, epoch_state)
            //     .await
            //     .expect("epoch metadata must update");
        }
        Ok(())
    }
}
