//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    marshal::{
        ancestry::BlockProvider,
        core::{Buffer, CommitmentFallback, Mailbox, Variant},
    },
    simplex::scheme::Scheme as SimplexScheme,
    types::Round,
    Block,
};
use commonware_broadcast::buffered;
use commonware_codec::Read;
use commonware_cryptography::{certificate::Scheme, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: Block,
{
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Standard variant commitment is exactly the block digest.
        block.digest()
    }

    fn stored_commitment(block: &Self::StoredBlock) -> Self::Commitment {
        block.digest()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // Trivial left-inverse: digest == commitment in this variant.
        commitment
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // In standard mode, commitments are digests, so parent commitment is parent digest.
        block.parent()
    }

    fn check_payload<S>(_scheme: &S, _payload: Self::Commitment) -> bool
    where
        S: SimplexScheme<Self::Commitment>,
    {
        true
    }

    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        _expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg {
        block_cfg.clone()
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block
    }

    fn into_inner_shared(block: Arc<Self::Block>) -> Arc<Self::ApplicationBlock> {
        block
    }

    fn owned_into_inner_shared(block: Self::Block) -> Arc<Self::ApplicationBlock> {
        Arc::new(block)
    }

    fn from_application_block(
        block: Self::ApplicationBlock,
        _payload: Self::Commitment,
    ) -> Self::Block {
        block
    }
}

impl<B, K> Buffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block,
    K: PublicKey,
{
    type PublicKey = K;

    async fn find_by_digest(&self, digest: B::Digest) -> Option<Arc<B>> {
        self.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: B::Digest) -> Option<Arc<B>> {
        self.find_by_digest(commitment).await
    }

    fn subscribe_by_digest(&self, digest: B::Digest) -> Option<oneshot::Receiver<Arc<B>>> {
        Some(self.subscribe(digest))
    }

    fn subscribe_by_commitment(&self, commitment: B::Digest) -> Option<oneshot::Receiver<Arc<B>>> {
        self.subscribe_by_digest(commitment)
    }

    fn finalized(&self, _commitment: B::Digest) {
        // No cleanup needed in standard mode - the buffer handles its own pruning
    }

    fn send(&self, _round: Round, block: Arc<B>, recipients: Recipients<K>) {
        self.broadcast_shared(recipients, block);
    }
}

impl<S, B> BlockProvider for Mailbox<S, Standard<B>>
where
    S: Scheme,
    B: Block,
{
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
        let receiver = block.height().previous().map(|parent_height| {
            self.subscribe_by_commitment(
                block.parent(),
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
        });
        async move { receiver?.await.ok() }
    }
}
