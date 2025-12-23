use commonware_consensus::{Reporter, marshal::Update, types::Epoch};
use commonware_cryptography::{
    bls12381::{dkg::SignedDealerLog, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::acknowledgement::Exact;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tracing::{Span, warn};

use crate::consensus::{Digest, block::Block};

/// A mailbox to handle finalized blocks.
///
/// It implements the `Reporter` trait with associated
/// `type Activity = Update<Block, Exact>` and is passed to the marshal actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }

    /// Returns the intermediate dealing of this node's ceremony.
    ///
    /// Returns `None` if this node was not a dealer, or if the request is
    /// for a different epoch than the ceremony that's currently running.
    pub(crate) async fn get_dealer_log(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Option<SignedDealerLog<MinSig, PrivateKey>>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetDealerLog { epoch, response }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with signed dealer log")
    }

    pub(crate) async fn get_dkg_outcome(
        &self,
        digest: Digest,
        height: u64,
    ) -> eyre::Result<OnchainDkgOutcome> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetDkgOutcome {
                digest,
                height,
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony deal outcome")
    }

    /// Verifies the `dealing` based on the current status of the DKG actor.
    ///
    /// This method is intended to be called by the application when verifying
    /// the dealing found in a proposal.
    pub(crate) async fn verify_dealer_log(
        &self,
        epoch: Epoch,
        bytes: Vec<u8>,
    ) -> eyre::Result<PublicKey> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(VerifyDealerLog {
                bytes,
                epoch,
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony info")
            // TODO: replace by Result::flatten once MRSV >= 1.89
            .and_then(|res| res)
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
    Finalized(Finalized),

    // From application
    GetDealerLog(GetDealerLog),
    GetDkgOutcome(GetDkgOutcome),
    VerifyDealerLog(VerifyDealerLog),
}

impl From<Finalized> for Command {
    fn from(value: Finalized) -> Self {
        Self::Finalized(value)
    }
}

impl From<GetDealerLog> for Command {
    fn from(value: GetDealerLog) -> Self {
        Self::GetDealerLog(value)
    }
}

impl From<VerifyDealerLog> for Command {
    fn from(value: VerifyDealerLog) -> Self {
        Self::VerifyDealerLog(value)
    }
}

impl From<GetDkgOutcome> for Command {
    fn from(value: GetDkgOutcome) -> Self {
        Self::GetDkgOutcome(value)
    }
}

pub(super) struct Finalized {
    pub(super) block: Box<Block>,
    pub(super) acknowledgment: Exact,
}

pub(super) struct GetDealerLog {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<SignedDealerLog<MinSig, PrivateKey>>>,
}

pub(super) struct GetDkgOutcome {
    pub(super) digest: Digest,
    pub(super) height: u64,
    pub(super) response: oneshot::Sender<OnchainDkgOutcome>,
}

pub(super) struct VerifyDealerLog {
    pub(super) bytes: Vec<u8>,
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<eyre::Result<PublicKey>>,
}

impl Reporter for Mailbox {
    type Activity = Update<Block, Exact>;

    async fn report(&mut self, update: Self::Activity) {
        let Update::Block(block, acknowledgment) = update else {
            return;
        };
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Finalized {
                block: Box::new(block),
                acknowledgment,
            }))
            .wrap_err("dkg manager no longer running")
        {
            warn!(%error, "failed to report finalized block to dkg manager")
        }
    }
}
