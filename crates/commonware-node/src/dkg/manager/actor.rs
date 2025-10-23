use std::sync::Arc;

use commonware_consensus::Block as _;
use commonware_consensus::Reporter;
use commonware_cryptography::bls12381::dkg::player::Output;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::utils::mux::MuxHandle;
use commonware_p2p::{Receiver, Sender, utils::mux};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::Metadata;
use commonware_utils::sequence::U64;
use eyre::eyre;
use futures::lock::Mutex;
use futures::{StreamExt as _, channel::mpsc};
use rand_core::CryptoRngCore;
use tracing::{Span, instrument, warn};

use crate::dkg::EpochState;
use crate::dkg::ceremony::RoundInfo;
use crate::dkg::ceremony::{PublicOutcome, RoundResult};
use crate::dkg::manager::ingress::GetCeremonyDeal;
use crate::dkg::manager::ingress::GetPublicCeremonyOutcome;
use crate::{
    dkg::{
        ceremony::{self, Ceremony},
        manager::ingress::Finalize,
    },
    epoch,
};

const EPOCH_KEY: u64 = 0;

pub(crate) struct Actor<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    config: super::Config,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    ceremony_metadata: Arc<Mutex<Metadata<ContextCell<TContext>, U64, RoundInfo>>>,
    epoch_metadata: Metadata<ContextCell<TContext>, U64, EpochState>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + CryptoRngCore + Metrics + Spawner + Storage,
{
    pub(super) async fn init(
        config: super::Config,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> Self {
        let context = ContextCell::new(context);

        // let initial_scheme = bls12381_threshold::Scheme::new(
        //     config.participants.as_ref(),
        //     &config.public,
        //     config.share.clone(),
        // );

        let ceremony_metadata = Metadata::init(
            context.with_label("ceremony_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_ceremony", config.partition_prefix),
                // XXX: commonware suggested to use usize::MAX.
                codec_config: usize::MAX,
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let epoch_metadata = Metadata::init(
            context.with_label("epoch_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        Self {
            config,
            context,
            mailbox,
            ceremony_metadata: Arc::new(Mutex::new(ceremony_metadata)),
            epoch_metadata,
        }
    }

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
            self.config.mailbox_size,
        );
        mux.start();

        let epoch_state = self
            .epoch_metadata
            .get(&EPOCH_KEY.into())
            .cloned()
            .unwrap_or_else(|| EpochState {
                epoch: 0,
                participants: self.config.initial_participants.clone(),
                public: self.config.initial_public.clone(),
                share: self.config.initial_share.clone(),
            });

        self.config
            .epoch_manager
            .report(
                epoch::Enter {
                    epoch: epoch_state.epoch,
                    public: epoch_state.public.clone(),
                    share: epoch_state.share.clone(),
                    participants: epoch_state.participants.clone(),
                }
                .into(),
            )
            .await;

        let mut ceremony = {
            let config = ceremony::Config {
                namespace: self.config.namespace.clone(),
                me: self.config.me.clone(),
                public: epoch_state.public.clone(),
                share: epoch_state.share.clone(),
                epoch: epoch_state.epoch,
                dealers: epoch_state.participants.clone(),
                players: epoch_state.participants.clone(),
            };
            Some(
                ceremony::Ceremony::init(
                    &mut self.context,
                    &mut ceremony_mux,
                    self.ceremony_metadata.clone(),
                    config,
                )
                .await
                .expect("must be able to initialize the first dkg ceremony; can't recover if not"),
            )
        };

        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
                super::Command::GetCeremonyDeal(get_ceremony_deal) => {
                    let _: Result<_, _> = self
                        .handle_get_ceremony_deal(
                            cause,
                            get_ceremony_deal,
                            ceremony
                                .as_mut()
                                .expect("there must be a ceremony active at all times"),
                        )
                        .await;
                }
                super::Command::GetCeremonyOutcome(get_ceremony_outcome) => {
                    let _: Result<_, _> = self
                        .handle_get_public_ceremony_outcome(
                            cause,
                            get_ceremony_outcome,
                            ceremony
                                .as_mut()
                                .expect("there must be a ceremony active at all times"),
                        )
                        .await;
                }
                super::Command::Finalize(finalize) => {
                    self.handle_finalize(cause, finalize, &mut ceremony, &mut ceremony_mux)
                        .await;
                }
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
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut outcome = None;

        'get_outcome: {
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
    async fn handle_get_public_ceremony_outcome<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetPublicCeremonyOutcome { epoch, response }: GetPublicCeremonyOutcome,
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut outcome = None;

        'get_outcome: {
            if epoch.saturating_add(1) != ceremony.epoch() {
                warn!(
                    request.epoch = epoch,
                    ceremony.epoch = ceremony.epoch(),
                    "current ceremony can return the outcome of its immediate \
                    predecessor ceremony, but the requested outcome is for \
                    another epoch",
                );
                break 'get_outcome;
            }

            outcome = Some(PublicOutcome {
                public: ceremony.config().public.clone(),
                participants: ceremony.config().dealers.clone(),
            });
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
    )]
    async fn handle_finalize<TReceiver, TSender>(
        &mut self,
        cause: Span,
        Finalize { block, response }: Finalize,
        ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut this_ceremony = ceremony
            .take()
            .expect("there must be a ceremony active at all times");

        if let Some(block_epoch) = epoch::of_height(block.height(), self.config.heights_per_epoch)
            && block_epoch == this_ceremony.epoch()
        {
            if epoch::is_first_height(block.height(), self.config.heights_per_epoch) {
                // Notify the epoch manager that the first height of the new epoch
                // was entered and the previous epoch can be exited.
                self.config
                    .epoch_manager
                    .report(
                        epoch::Exit {
                            epoch: this_ceremony.epoch().saturating_sub(1),
                        }
                        .into(),
                    )
                    .await;
            }

            match epoch::relative_position(block.height(), self.config.heights_per_epoch) {
                epoch::RelativePosition::FirstHalf => {
                    let _ = this_ceremony.request_acks().await;
                    let _ = this_ceremony.process_messages().await;
                }
                epoch::RelativePosition::Middle => {
                    let _ = this_ceremony.process_messages().await;
                    let _ = this_ceremony.construct_deal_outcome().await;
                }
                epoch::RelativePosition::SecondHalf => {
                    let _ = this_ceremony.process_block(&block).await;
                }
            }
        }

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes available on the last height and can be
        // stored on chain.
        let new_ceremony = if epoch::is_last_height(
            block.height().saturating_add(1),
            self.config.heights_per_epoch,
        ) {
            let next_epoch = this_ceremony.epoch().saturating_add(1);

            let (next_participants, next_public, next_share, success) =
                match this_ceremony.finalize().await {
                    (next_participants, RoundResult::Output(Output { public, share }), success) => {
                        (next_participants, public, Some(share), success)
                    }
                    (next_participants, RoundResult::Polynomial(public), success) => {
                        (next_participants, public, None, success)
                    }
                };

            let epoch_state = EpochState {
                epoch: next_epoch,
                participants: next_participants,
                public: next_public,
                share: next_share,
            };
            self.epoch_metadata
                .put_sync(EPOCH_KEY.into(), epoch_state.clone())
                .await
                .expect("must always be able to write epoch state to disk");

            if let Some(epoch) = epoch_state.epoch.checked_sub(2) {
                let mut ceremony_metadata = self.ceremony_metadata.lock().await;
                ceremony_metadata.remove(&epoch.into());
                ceremony_metadata.sync().await.expect("metadata must sync");
            }

            self.config
                .epoch_manager
                .report(
                    epoch::Enter {
                        epoch: epoch_state.epoch,
                        public: epoch_state.public.clone(),
                        share: epoch_state.share.clone(),
                        participants: epoch_state.participants.clone(),
                    }
                    .into(),
                )
                .await;

            // TODO(janis): add metrics
            if !success {
                ()
                //     self.failed_rounds.inc();
            }

            // TODO(janis): prune old ceremony metadata?
            let config = ceremony::Config {
                namespace: self.config.namespace.clone(),
                me: self.config.me.clone(),
                public: epoch_state.public.clone(),
                share: epoch_state.share.clone(),
                epoch: epoch_state.epoch,
                dealers: epoch_state.participants.clone(),
                players: epoch_state.participants.clone(),
            };
            ceremony::Ceremony::init(
                &mut self.context,
                ceremony_mux,
                self.ceremony_metadata.clone(),
                config,
            )
            .await
            .expect("must always be able to initialize ceremony")
        } else {
            this_ceremony
        };

        ceremony.replace(new_ceremony);

        if let Err(()) = response.send(()) {
            warn!("could not confirm finalization because recipient already went away");
        }
    }
}
