use std::sync::Arc;

use alloy_primitives::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, types::Epoch};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{Output, SignedDealerLog},
        primitives::variant::MinSig,
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::acknowledgement::Exact;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tracing::{Span, warn};

use crate::consensus::block::Block;

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

    /// Returns the dealer log of the node to include in a proposal.
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

    /// Registers a subscription for the ceremony output that the DKG outcome
    /// of a boundary block on top of `parent` must contain, returning its
    /// receiver immediately.
    ///
    /// If the actor must fetch `parent` from peers, it uses the round in the
    /// consensus context of `parent`. The actor responds once it has the
    /// blocks that it needs from the ancestry of `parent`. It does not read
    /// chain state, so a caller can subscribe before the engine has executed
    /// `parent`. Dropping the receiver cancels the subscription. The channel
    /// closes without a value if the actor cannot serve the request or shuts
    /// down.
    pub(crate) fn subscribe_dkg_ceremony(
        &self,
        parent: Arc<Block>,
    ) -> oneshot::Receiver<Output<MinSig, PublicKey>> {
        let (response, rx) = oneshot::channel();
        // A closed mailbox drops the sender, so the receiver reports cancellation.
        let _ = self
            .inner
            .unbounded_send(Message::in_current_span(SubscribeDkgCeremony {
                parent,
                response,
            }));
        rx
    }

    /// Verifies the `dealing` based on the current status of the DKG actor.
    ///
    /// This method is intended to be called by the application when verifying
    /// the dealing found in a proposal.
    /// Returns `None` for an invalid log and an error if verification is unavailable.
    pub(crate) async fn verify_dealer_log(
        &self,
        epoch: Epoch,
        bytes: Bytes,
    ) -> eyre::Result<Option<PublicKey>> {
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
    Update(Box<Update<Block>>),

    // From application
    GetDealerLog(GetDealerLog),
    SubscribeDkgCeremony(SubscribeDkgCeremony),
    VerifyDealerLog(VerifyDealerLog),
}

impl From<Update<Block>> for Command {
    fn from(value: Update<Block>) -> Self {
        Self::Update(Box::new(value))
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

impl From<SubscribeDkgCeremony> for Command {
    fn from(value: SubscribeDkgCeremony) -> Self {
        Self::SubscribeDkgCeremony(value)
    }
}

pub(super) struct GetDealerLog {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<SignedDealerLog<MinSig, PrivateKey>>>,
}

pub(super) struct SubscribeDkgCeremony {
    pub(super) parent: Arc<Block>,
    pub(super) response: oneshot::Sender<Output<MinSig, PublicKey>>,
}

pub(super) struct VerifyDealerLog {
    pub(super) bytes: Bytes,
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<PublicKey>>,
}

impl Reporter for Mailbox {
    type Activity = Update<Block, Exact>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self
            .inner
            .unbounded_send(Message::in_current_span(activity))
            .wrap_err("dkg manager no longer running")
        {
            Ok(()) => Feedback::Ok,
            Err(error) => {
                warn!(%error, "failed to report finalization activity to dkg manager");
                Feedback::Closed
            }
        }
    }
}
