use std::sync::{Arc, Mutex};

use commonware_consensus::{
    Block as _, Reporter, marshal::SchemeProvider, simplex::signing_scheme::bls12381_threshold,
    types::Epoch,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::p2p::Coordinator;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tracing::{Span, warn};

use crate::consensus::{Digest, block::Block};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,

    // TODO(janis): unclear if this is a good idea providing the scheme via mutex.
    //
    // This is done in this way because marshal requires a S: SchemeProvider.
    // On the other hand in the epoch manager we should be able to just await?
    pub(super) per_epoch_schemes:
        Arc<Mutex<std::collections::HashMap<Epoch, Arc<bls12381_threshold::Scheme<MinSig>>>>>,
}

impl Mailbox {
    pub(crate) async fn get_scheme(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Arc<bls12381_threshold::Scheme<MinSig>>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetScheme { epoch, response }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with scheme")
    }
}

pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) command: Command,
}

impl Message {
    fn in_current_span(cmd: impl Into<Command>) -> Self {
        Self {
            cause: Span::current(),
            command: cmd.into(),
        }
    }
}

pub(super) enum Command {
    Finalize(Finalize),
    GetScheme(GetScheme),
}

impl From<Finalize> for Command {
    fn from(value: Finalize) -> Self {
        Self::Finalize(value)
    }
}

impl From<GetScheme> for Command {
    fn from(value: GetScheme) -> Self {
        Self::GetScheme(value)
    }
}

pub(super) struct Finalize {
    pub(super) block: Block,
    pub(super) response: oneshot::Sender<()>,
}

pub(super) struct GetScheme {
    epoch: Epoch,
    response: oneshot::Sender<Arc<bls12381_threshold::Scheme<MinSig>>>,
}

impl Reporter for Mailbox {
    type Activity = Block;

    async fn report(&mut self, block: Self::Activity) {
        let (response, rx) = oneshot::channel();
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Finalize { block, response }))
            .wrap_err("dkg manager no longer running")
        {
            warn!(%error, "failed to report finalized block to dkg manager")
        }
        let _ = rx.await;
    }
}

impl SchemeProvider for Mailbox {
    type Scheme = bls12381_threshold::Scheme<MinSig>;

    fn scheme(&self, epoch: Epoch) -> Option<std::sync::Arc<Self::Scheme>> {
        self.per_epoch_schemes
            .lock()
            .expect("locks must not be held such that they can panick")
            .get(&epoch)
            .cloned()
    }
}
