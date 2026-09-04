//! Marshal variant and buffer traits.
//!
//! This module defines the core abstractions that allow the marshal actor to work
//! with different block dissemination strategies:
//!
//! - [`Variant`]: Describes the types used by a marshal variant
//! - [`Buffer`]: Abstracts over block dissemination strategies
//!
//! The [`Variant`] trait expects a 1:1 mapping between the [`Variant::Commitment`] and the
//! block digest, with the commitment being a superset of the digest. The commitment may
//! contain extra information that can be used for optimized retrieval or variant-specific
//! mechanisms, though it is required that the digest can be extracted from the commitment
//! for lookup purposes.

use crate::{simplex::scheme::Scheme, types::Round, Block};
use commonware_codec::{Codec, Read};
use commonware_cryptography::{Digest, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{future::Future, marker::PhantomData, sync::Arc};

/// A marker trait describing the types used by a variant of Marshal.
pub trait Variant: Clone + Send + Sync + 'static {
    /// The working block type of marshal, supporting the consensus commitment.
    ///
    /// Must be convertible to `StoredBlock` via `Into` for archival.
    type Block: Block<Digest = <Self::ApplicationBlock as Digestible>::Digest>
        + Into<Self::StoredBlock>;

    /// The application block type.
    type ApplicationBlock: Block;

    /// The type of block stored in the archive.
    ///
    /// Must be convertible back to the working block type via `Into`.
    type StoredBlock: Block<Digest = <Self::Block as Digestible>::Digest>
        + Into<Self::Block>
        + Codec<Cfg = <Self::ApplicationBlock as Read>::Cfg>;

    /// The [`Digest`] type used by consensus.
    type Commitment: Digest;

    /// Computes the consensus commitment for a block.
    ///
    /// The commitment is what validators sign over during consensus.
    ///
    /// Together with [`Variant::commitment_to_inner`], implementations must satisfy:
    /// `commitment_to_inner(commitment(block)) == block.digest()`.
    fn commitment(block: &Self::Block) -> Self::Commitment;

    /// Computes the consensus commitment for a stored block.
    ///
    /// The stored representation carries enough information to derive the
    /// commitment without reconstructing a working block.
    fn stored_commitment(block: &Self::StoredBlock) -> Self::Commitment;

    /// Extracts the block digest from a consensus commitment.
    ///
    /// For blocks/certificates accepted by marshal in this variant instance, the digest
    /// must uniquely determine the commitment. In other words, there should not be two accepted
    /// commitments with the same inner digest.
    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest;

    /// Returns the parent commitment referenced by `block`.
    fn parent_commitment(block: &Self::Block) -> Self::Commitment;

    /// Validates a certificate payload against the active consensus scheme.
    fn check_payload<S>(scheme: &S, payload: Self::Commitment) -> bool
    where
        S: Scheme<Self::Commitment>;

    /// Returns the codec configuration used to decode [`Self::Block`] received over the wire.
    ///
    /// The returned configuration may bind `expected_commitment` so that decoding rejects
    /// blocks that do not match the expected commitment.
    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg;

    /// Converts a working block to an application block.
    ///
    /// This conversion cannot use `Into` due to orphan rules when `Block` wraps
    /// `ApplicationBlock` (e.g., `CodedBlock<B, C, H> -> B`).
    fn into_inner(block: Self::Block) -> Self::ApplicationBlock;

    /// Converts a shared working block to a shared application block.
    fn into_inner_shared(block: Arc<Self::Block>) -> Arc<Self::ApplicationBlock>;

    /// Converts an owned working block to a shared application block.
    fn owned_into_inner_shared(block: Self::Block) -> Arc<Self::ApplicationBlock>;

    /// Reconstructs a working block from an application block and trusted payload.
    fn from_application_block(
        block: Self::ApplicationBlock,
        payload: Self::Commitment,
    ) -> Self::Block;
}

/// A buffer for block storage and retrieval, abstracting over different
/// dissemination strategies.
///
/// The trait is generic over a [`Variant`] which provides the block, commitment,
/// and recipient types.
///
/// Lookup operations come in two forms:
/// - By digest: Simple lookup using only the block hash
/// - By commitment: Lookup using the full consensus commitment, which may enable
///   additional retrieval mechanisms depending on the variant
pub trait Buffer<V: Variant>: Clone + Send + Sync + 'static {
    /// The public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Attempt to find a block by its digest.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    fn find_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<Arc<V::Block>>> + Send;

    /// Attempt to find a block by its commitment.
    ///
    /// Returns `Some(block)` if the block is immediately available in the buffer,
    /// or `None` if it is not currently cached.
    ///
    /// This is a non-blocking lookup that does not trigger network fetches.
    /// Having the full commitment may enable additional retrieval mechanisms
    /// depending on the variant implementation.
    fn find_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> impl Future<Output = Option<Arc<V::Block>>> + Send;

    /// Subscribe to a block's availability by its digest.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_digest(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<Arc<V::Block>>>;

    /// Subscribe to a block's availability by its commitment.
    ///
    /// Returns a receiver that will resolve when the block becomes available.
    /// If the block is already cached, the receiver may resolve immediately.
    /// Returns `None` when the buffer cannot provide availability notifications.
    ///
    /// Having the full commitment may enable additional retrieval mechanisms
    /// depending on the variant implementation.
    ///
    /// The returned receiver can be dropped to cancel the subscription.
    fn subscribe_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> Option<oneshot::Receiver<Arc<V::Block>>>;

    /// Notify the buffer that a block has been finalized.
    ///
    /// This allows the buffer to perform variant-specific cleanup operations.
    fn finalized(&self, commitment: V::Commitment);

    /// Send a block to peers.
    fn send(&self, round: Round, block: Arc<V::Block>, recipients: Recipients<Self::PublicKey>);
}

/// A buffer implementation that never stores, subscribes, finalizes, or sends blocks.
pub(super) struct NoBuffer<P> {
    _public_key: PhantomData<fn() -> P>,
}

impl<P> NoBuffer<P> {
    pub(super) const fn new() -> Self {
        Self {
            _public_key: PhantomData,
        }
    }
}

impl<P> Clone for NoBuffer<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for NoBuffer<P> {}

impl<V, P> Buffer<V> for NoBuffer<P>
where
    V: Variant,
    P: PublicKey,
{
    type PublicKey = P;

    async fn find_by_digest(&self, _: <V::Block as Digestible>::Digest) -> Option<Arc<V::Block>> {
        None
    }

    async fn find_by_commitment(&self, _: V::Commitment) -> Option<Arc<V::Block>> {
        None
    }

    fn subscribe_by_digest(
        &self,
        _: <V::Block as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<Arc<V::Block>>> {
        None
    }

    fn subscribe_by_commitment(
        &self,
        _: V::Commitment,
    ) -> Option<oneshot::Receiver<Arc<V::Block>>> {
        None
    }

    fn finalized(&self, _: V::Commitment) {}

    fn send(&self, _: Round, _: Arc<V::Block>, _: Recipients<Self::PublicKey>) {}
}
