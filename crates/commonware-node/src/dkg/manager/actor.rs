use commonware_consensus::{Block as _, Reporter, utils};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{
    Receiver, Sender,
    utils::{mux, mux::MuxHandle},
};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics as _, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::Metadata;
use commonware_utils::Acknowledgement as _;
use eyre::eyre;
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use tracing::{Span, debug, info, instrument, warn};

use crate::{
    db::{CeremonyStore, DkgEpochStore, MetadataDatabase, Tx},
    dkg::{
        EpochState,
        ceremony::{self, Ceremony, PublicOutcome},
        manager::ingress::{Finalize, GetIntermediateDealing, GetOutcome},
    },
    epoch,
};

pub(crate) struct Actor<TContext>
where
    TContext: Clock + commonware_runtime::Metrics + Storage,
{
    config: super::Config,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    /// Unified database for storing both ceremony and epoch state.
    db: MetadataDatabase<ContextCell<TContext>>,

    metrics: Metrics,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
{
    pub(super) async fn init(
        config: super::Config,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> Self {
        let context = ContextCell::new(context);

        let db = init_db(&context, &config.partition_prefix)
            .await
            .expect("must be able to initialize metadata on disk to function");

        let ceremony_failures = Counter::default();
        let ceremony_successes = Counter::default();

        let ceremony_dealers = Gauge::default();
        let ceremony_players = Gauge::default();

        context.register(
            "ceremony_failures",
            "the number of failed ceremonies a node participated in",
            ceremony_failures.clone(),
        );
        context.register(
            "ceremony_successes",
            "the number of successful ceremonies a node participated in",
            ceremony_successes.clone(),
        );
        context.register(
            "ceremony_dealers",
            "the number of dealers in the currently running ceremony",
            ceremony_dealers.clone(),
        );
        context.register(
            "ceremony_players",
            "the number of players in the currently running ceremony",
            ceremony_players.clone(),
        );

        let metrics = Metrics {
            ceremony_failures,
            ceremony_successes,
            ceremony_dealers,
            ceremony_players,
        };

        Self {
            config,
            context,
            mailbox,
            db,
            metrics,
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

        let mut tx = self.db.read_write().expect("should create tx");
        let epoch_state = match tx.get_epoch().expect("should be able to query") {
            Some(state) => state,
            None => {
                let state = EpochState {
                    epoch: 0,
                    participants: self.config.initial_participants.clone(),
                    public: self.config.initial_public.clone(),
                    share: self.config.initial_share.clone(),
                };
                tx.set_epoch(state.clone())
                    .expect("must be able to write epoch");
                state
            }
        };

        // Only start the current epoch if the marshal actor has the "genesis"
        // block for it.
        let has_genesis_block_for_epoch =
            if let Some(previous_epoch) = epoch_state.epoch.checked_sub(1) {
                self.config
                    .marshal
                    .get_info(utils::last_block_in_epoch(
                        self.config.epoch_length,
                        previous_epoch,
                    ))
                    .await
                    .is_some()
            } else {
                true
            };
        if has_genesis_block_for_epoch {
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
        }

        if let Some(previous_epoch_state) = tx
            .get_previous_epoch()
            .expect("must be able to read previous epoch")
        {
            // NOTE: PREVIOUS_EPOCH_KEY is only set if the node was shut down
            // before the first height of the incoming epoch was observed (which
            // would have subsequently deleted PREVIOUS_EPOCH_KEY).
            self.config
                .epoch_manager
                .report(
                    epoch::Enter {
                        epoch: previous_epoch_state.epoch,
                        public: previous_epoch_state.public.clone(),
                        share: previous_epoch_state.share.clone(),
                        participants: previous_epoch_state.participants.clone(),
                    }
                    .into(),
                )
                .await;
        }

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
            self.metrics
                .ceremony_dealers
                .set(epoch_state.participants.len() as i64);
            self.metrics
                .ceremony_players
                .set(epoch_state.participants.len() as i64);
            ceremony::Ceremony::init(&mut self.context, &mut ceremony_mux, &mut tx, config)
                .await
                .expect("must be able to initialize the first dkg ceremony; can't recover if not")
        };
        tx.commit().await.expect("must be able to commit changes");

        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
                super::Command::GetIntermediateDealing(get_ceremony_deal) => {
                    let _: Result<_, _> = self
                        .handle_get_intermediate_dealing(cause, get_ceremony_deal, &mut ceremony)
                        .await;
                }
                super::Command::GetOutcome(get_ceremony_outcome) => {
                    let _: Result<_, _> = self
                        .handle_get_outcome(cause, get_ceremony_outcome, &mut ceremony)
                        .await;
                }
                super::Command::Finalize(finalize) => {
                    let mut tx = self
                        .db
                        .read_write()
                        .expect("must be able to create transaction");
                    ceremony = self
                        .handle_finalize(cause, finalize, ceremony, &mut ceremony_mux, &mut tx)
                        .await;
                    tx.commit().await.expect("must be able to commit finalize");
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
    async fn handle_get_intermediate_dealing<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetIntermediateDealing { epoch, response }: GetIntermediateDealing,
        ceremony: &mut Ceremony<TReceiver, TSender>,
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
            current_ceremony.epoch = ceremony.epoch(),
        ),
        err,
    )]
    async fn handle_get_outcome<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetOutcome { epoch, response }: GetOutcome,
        ceremony: &mut Ceremony<TReceiver, TSender>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let outcome = if epoch.saturating_add(1) == ceremony.epoch() {
            Some(PublicOutcome {
                epoch: ceremony.epoch(),
                public: ceremony.config().public.clone(),
                participants: ceremony.config().dealers.clone(),
            })
        } else {
            warn!(
                predecessor_ceremony.epoch = ceremony.epoch().checked_sub(1),
                "currently active ceremony contains the outcome of its
                predecessor ceremony, but the request was for a different
                ceremony: cannot return the outcome of even older ceremonies,
                nor the outcome of the currently running ceremony",
            );
            None
        };

        response
            .send(outcome)
            .map_err(|_| eyre!("failed returning outcome because requester went away"))
    }

    /// Handles a finalized block.
    ///
    /// Depending on which height of an epoch the block is, this method exhibits
    /// different behavior:
    ///
    /// + first height of an epoch: notify the epoch manager that the previous
    /// epoch can be shut down.
    /// + first half of an epoch: distribute the shares generated during the
    /// DKG ceremony and collect shares from other dealers, and acks from other
    /// players.
    /// + exact middle of an epoch: generate the intermediate outcome of the
    /// ceremony.
    /// + second half of an epoch: read intermediate outcomes from blocks.
    /// + pre-to-last height of an epoch: generate the overall ceremony outcome,
    /// start a new ceremony with the outcome of the last ceremony.
    /// + last height of an epoch: notify the epoch manager that a new epoch can
    /// be started, using the outcome of the last epoch.
    #[instrument(
        parent = cause,
        skip_all,
        fields(
            block.derived_epoch = utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            ceremony.epoch = ceremony.epoch(),
        ),
    )]
    async fn handle_finalize<TReceiver, TSender>(
        &mut self,
        cause: Span,
        Finalize {
            block,
            acknowledgment,
        }: Finalize,
        mut ceremony: Ceremony<TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut Tx<ContextCell<TContext>>,
    ) -> Ceremony<TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        if block.height() == 0 {
            acknowledgment.acknowledge();
            return ceremony;
        }

        let block_epoch = utils::epoch(self.config.epoch_length, block.height());

        // Special case the last height of the previous epoch: remember that we
        // can only enter the new epoch once the last height of outgoing was
        // reached, because that's what provides the genesis.
        if ceremony.epoch().saturating_sub(1) == block_epoch
            && utils::is_last_block_in_epoch(self.config.epoch_length, block.height())
                .is_some_and(|e| e == block_epoch)
        {
            debug!(
                "reached last height of outgoing epoch; reporting that a \
                new epoch can be entered"
            );
            self.config
                .epoch_manager
                .report(
                    epoch::Enter {
                        epoch: ceremony.config().epoch,
                        public: ceremony.config().public.clone(),
                        share: ceremony.config().share.clone(),
                        participants: ceremony.config().dealers.clone(),
                    }
                    .into(),
                )
                .await;
        }

        if ceremony.epoch() != block_epoch {
            debug!(
                "block was for a different epoch; not including it in the \
                ceremony"
            );
            acknowledgment.acknowledge();
            return ceremony;
        };

        // Notify the epoch manager that the first height of the new epoch
        // was entered and the previous epoch can be exited.
        //
        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        if block.height().is_multiple_of(self.config.epoch_length)
            && let Some(old_epoch_state) = tx
                .get_previous_epoch()
                .expect("must be able to read previous epoch")
        {
            self.config
                .epoch_manager
                .report(
                    epoch::Exit {
                        epoch: old_epoch_state.epoch,
                    }
                    .into(),
                )
                .await;
            tx.remove_previous_epoch()
                .expect("must be able to remove previous epoch");
        }

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares(tx).await;
                let _ = ceremony.process_messages(tx).await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages(tx).await;
                let _ = ceremony.construct_intermediate_outcome(tx).await;
            }
            epoch::RelativePosition::SecondHalf => {
                let _ = ceremony.process_dealings_in_block(tx, &block).await;
            }
        }

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes available on the last height and can be
        // stored on chain.
        //
        // This starts a new ceremony.
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height().saturating_add(1))
            .is_some_and(|e| e == block_epoch)
        {
            info!("on pre-to-last height of epoch; finalizing ceremony");

            let next_epoch = ceremony.epoch().saturating_add(1);

            let ceremony_outcome = match ceremony.finalize() {
                Ok(outcome) => {
                    self.metrics.ceremony_successes.inc();
                    info!(
                        "ceremony was successful; using the new participants, polynomial and secret key"
                    );
                    outcome
                }
                Err(outcome) => {
                    self.metrics.ceremony_failures.inc();
                    warn!(
                        "ceremony was a failure; using the old participants, polynomial and secret key"
                    );
                    outcome
                }
            };
            let (public, share) = ceremony_outcome.role.into_key_pair();

            let old_epoch_state = tx
                .get_epoch()
                .expect("must be able to read epoch")
                .expect("a current epoch state must always exist");

            tx.set_previous_epoch(old_epoch_state)
                .expect("must be able to write previous epoch");

            let new_epoch_state = EpochState {
                epoch: next_epoch,
                participants: ceremony_outcome.participants,
                public,
                share,
            };

            // Update epoch state and prune older ceremony using the provided transaction
            tx.set_epoch(new_epoch_state.clone())
                .expect("must be able to write epoch");

            // Prune older ceremony
            if let Some(epoch) = new_epoch_state.epoch.checked_sub(2) {
                tx.remove_ceremony(epoch)
                    .expect("must be able to remove ceremony");
            }

            let config = ceremony::Config {
                namespace: self.config.namespace.clone(),
                me: self.config.me.clone(),
                public: new_epoch_state.public.clone(),
                share: new_epoch_state.share.clone(),
                epoch: new_epoch_state.epoch,
                dealers: new_epoch_state.participants.clone(),
                players: new_epoch_state.participants.clone(),
            };
            self.metrics
                .ceremony_dealers
                .set(new_epoch_state.participants.len() as i64);
            self.metrics
                .ceremony_players
                .set(new_epoch_state.participants.len() as i64);

            ceremony = ceremony::Ceremony::init(&mut self.context, ceremony_mux, tx, config)
                .await
                .expect("must always be able to initialize ceremony");
        }

        acknowledgment.acknowledge();

        ceremony
    }
}

#[derive(Clone)]
struct Metrics {
    ceremony_failures: Counter,
    ceremony_successes: Counter,
    ceremony_dealers: Gauge,
    ceremony_players: Gauge,
}

/// Initialize the database and perform migration if needed.
async fn init_db<TContext>(
    context: &ContextCell<TContext>,
    partition_prefix: &str,
) -> eyre::Result<MetadataDatabase<ContextCell<TContext>>>
where
    TContext: Clock + commonware_runtime::Metrics + Storage,
{
    let db_metadata = Metadata::init(
        context.with_label("dkg_db"),
        commonware_storage::metadata::Config {
            partition: format!("{}_db", partition_prefix),
            codec_config: commonware_codec::RangeCfg::from(0..=usize::MAX),
        },
    )
    .await?;
    let db = MetadataDatabase::new(db_metadata);

    // Migrate data from old stores to new database (if needed)
    let mut tx = db.read_write()?;
    super::migrate::maybe_migrate_to_db(context, partition_prefix, &mut tx).await?;
    tx.set_node_version(env!("CARGO_PKG_VERSION").to_string())?;
    tx.commit().await?;

    Ok(db)
}
