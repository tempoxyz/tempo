//! Mailbox for the shard buffer engine.

use crate::{
    marshal::coding::types::CodedBlock,
    types::{coding::Commitment, Round},
    CertifiableBlock,
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};

/// A message that can be sent to the coding [`Engine`].
///
/// [`Engine`]: super::Engine
pub(crate) enum Message<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// A request to broadcast a proposed [`CodedBlock`] to all peers.
    Proposed {
        /// The erasure coded block.
        block: Arc<CodedBlock<B, C, H>>,
        /// The round in which the block was proposed.
        round: Round,
    },
    /// A notification from consensus that a [`Commitment`] has been discovered.
    Discovered {
        /// The [`Commitment`] of the proposed block.
        commitment: Commitment,
        /// The leader's public key.
        leader: P,
        /// The round in which the commitment was proposed.
        round: Round,
    },
    /// A notification from consensus that a [`Commitment`] has been notarized.
    ///
    /// This may arrive before the engine knows the round leader. It allows the
    /// engine to reconstruct from sender-indexed gossip shards already buffered
    /// for the commitment, but it does not satisfy assigned shard verification.
    Notarized {
        /// The [`Commitment`] of the notarized block.
        commitment: Commitment,
        /// The round in which the commitment was notarized.
        round: Round,
    },
    /// A request to get a reconstructed block, if available.
    GetByCommitment {
        /// The [`Commitment`] of the block to get.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C, H>>>>,
    },
    /// A request to get a reconstructed block by its digest, if available.
    GetByDigest {
        /// The digest of the block to get.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C, H>>>>,
    },
    /// A request to open a subscription for assigned shard verification.
    ///
    /// For participants, this resolves once the leader-delivered shard for
    /// the local participant index has been verified. Reconstructing the full
    /// block from gossiped shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    SubscribeAssignedShardVerified {
        /// The block's commitment.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<()>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its [`Commitment`].
    SubscribeByCommitment {
        /// The block's digest.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its digest.
    SubscribeByDigest {
        /// The block's digest.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    },
    /// A request to prune all caches at and below the given commitment.
    Prune {
        /// Inclusive prune target [`Commitment`].
        through: Commitment,
    },
}

impl<B, C, H, P> Message<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetByCommitment { response, .. } | Self::GetByDigest { response, .. } => {
                response.is_closed()
            }
            Self::SubscribeAssignedShardVerified { response, .. } => response.is_closed(),
            Self::SubscribeByCommitment { response, .. }
            | Self::SubscribeByDigest { response, .. } => response.is_closed(),
            Self::Proposed { .. }
            | Self::Discovered { .. }
            | Self::Notarized { .. }
            | Self::Prune { .. } => false,
        }
    }
}

pub(crate) struct Pending<B, C, H, P>(VecDeque<Message<B, C, H, P>>)
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey;

impl<B, C, H, P> Default for Pending<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<B, C, H, P> Overflow<Message<B, C, H, P>> for Pending<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<B, C, H, P>) -> Option<Message<B, C, H, P>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<B, C, H, P> Policy for Message<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type Overflow = Pending<B, C, H, P>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        overflow.0.push_back(message);
    }
}

/// A mailbox for sending messages to the [`Engine`].
///
/// [`Engine`]: super::Engine
#[derive(Clone)]
pub struct Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    pub(super) sender: Sender<Message<B, C, H, P>>,
}

impl<B, C, H, P> Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Create a new [`Mailbox`] with the given sender.
    pub(crate) const fn new(sender: Sender<Message<B, C, H, P>>) -> Self {
        Self { sender }
    }

    /// Broadcast a proposed erasure coded block's shards to the participants.
    pub fn proposed(&self, round: Round, block: CodedBlock<B, C, H>) {
        self.proposed_shared(round, Arc::new(block));
    }

    pub(crate) fn proposed_shared(&self, round: Round, block: Arc<CodedBlock<B, C, H>>) {
        let _ = self.sender.enqueue(Message::Proposed { block, round });
    }

    /// Inform the engine of an externally proposed [`Commitment`].
    pub fn discovered(&self, commitment: Commitment, leader: P, round: Round) {
        let _ = self.sender.enqueue(Message::Discovered {
            commitment,
            leader,
            round,
        });
    }

    /// Inform the engine that a [`Commitment`] was notarized.
    ///
    /// This is the leaderless reconstruction signal used by certification. It
    /// lets the engine drain sender-indexed gossip shards from its peer buffers
    /// for the commitment. Leader-specific validation and assigned shard
    /// verification still require a later [`Self::discovered`] call.
    pub fn notarized(&self, commitment: Commitment, round: Round) {
        let _ = self
            .sender
            .enqueue(Message::Notarized { commitment, round });
    }

    /// Request a reconstructed block by its [`Commitment`].
    pub async fn get(&self, commitment: Commitment) -> Option<Arc<CodedBlock<B, C, H>>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetByCommitment {
            commitment,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Request a reconstructed block by its digest.
    pub async fn get_by_digest(&self, digest: B::Digest) -> Option<Arc<CodedBlock<B, C, H>>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetByDigest { digest, response });
        receiver.await.ok().flatten()
    }

    /// Subscribe to assigned shard verification for a commitment.
    ///
    /// For participants, this resolves once the leader-delivered shard for
    /// the local participant index has been verified. Reconstructing the full
    /// block from gossiped shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    pub fn subscribe_assigned_shard_verified(
        &self,
        commitment: Commitment,
    ) -> oneshot::Receiver<()> {
        let (responder, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::SubscribeAssignedShardVerified {
                commitment,
                response: responder,
            });
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its [`Commitment`].
    pub fn subscribe(&self, commitment: Commitment) -> oneshot::Receiver<Arc<CodedBlock<B, C, H>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByCommitment {
            commitment,
            response: responder,
        });
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its digest.
    pub fn subscribe_by_digest(
        &self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C, H>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByDigest {
            digest,
            response: responder,
        });
        receiver
    }

    /// Request to prune all caches at and below the given commitment.
    pub fn prune(&self, through: Commitment) {
        let _ = self.sender.enqueue(Message::Prune { through });
    }
}
