use std::{collections::HashMap, sync::Arc};

use commonware_consensus::{Block as _, simplex::signing_scheme::bls12381_threshold, types::Epoch};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_p2p::{Receiver, Sender, utils::mux};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use eyre::WrapErr as _;
use eyre::eyre;
use futures::{StreamExt as _, channel::mpsc};
use rand_core::CryptoRngCore;
use tracing::{Span, instrument, warn};

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
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + governor::clock::Clock + CryptoRngCore + Metrics + Spawner + Storage,
{
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
                let _ = ceremony.process_block(block).await;
            }
        }
        Ok(())
    }
}
