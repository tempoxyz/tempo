use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{Block as _, simplex::signing_scheme::bls12381_threshold, types::Epoch};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::{StreamExt as _, channel::mpsc};
use tracing::{Span, instrument};

use crate::{dkg::manager::ingress::Finalize, epoch};

pub(crate) struct Actor<TContext> {
    pub(super) config: super::Config,
    pub(super) context: ContextCell<TContext>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::Message>,
    pub(super) per_epoch_schemes:
        Arc<Mutex<HashMap<Epoch, Arc<bls12381_threshold::Scheme<MinSig>>>>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Spawner,
{
    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
                super::Command::Finalize(finalize) => {
                    let _: Result<_, _> = self.handle_finalize(cause, finalize).await;
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
        fields(),
        err,
    )]
    async fn handle_finalize(
        &mut self,
        cause: Span,
        Finalize { block, response }: Finalize,
    ) -> eyre::Result<()> {
        match epoch::relative_position(block.height(), self.config.heights_per_epoch) {
            epoch::RelativePosition::FirstHalf => todo!(),
            epoch::RelativePosition::Middle => todo!(),
            epoch::RelativePosition::SecondHalf => todo!(),
        }
        Ok(())
    }
}
