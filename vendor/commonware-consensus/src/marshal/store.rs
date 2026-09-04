//! Interfaces for stores of finalized certificates and blocks.

use crate::{simplex::types::Finalization, types::Height, Block};
use commonware_cryptography::{certificate::Scheme, Digest, Digestible};
use commonware_runtime::{BufferPooler, Clock, Handle, Metrics, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive, Identifier},
    translator::Translator,
};
use std::{error::Error, future::Future};

/// Durable store for [Finalizations](Finalization) keyed by height and block digest.
pub trait Certificates: Send + Sync + 'static {
    /// The type of [Digest] used for block digests.
    type BlockDigest: Digest;

    /// The type of [Digest] included in consensus certificates.
    type Commitment: Digest;

    /// The type of signing [Scheme] used by consensus.
    type Scheme: Scheme;

    /// The type of error returned when storing, retrieving, or pruning finalizations.
    type Error: Error + Send + Sync + 'static;

    /// Buffer a finalization certificate for storage, keyed by height and block digest.
    ///
    /// The write is not durable until [sync](Self::sync) is called.
    ///
    /// Implementations must ignore overwrites for an existing finalization at the same
    /// height or commitment.
    ///
    /// # Arguments
    ///
    /// * `height`: The application height associated with the finalization.
    /// * `digest`: The block digest associated with the finalization.
    /// * `finalization`: The finalization certificate to store.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err` if the write fails.
    fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<Self::Scheme, Self::Commitment>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Buffer a finalization certificate and start syncing the resulting write.
    ///
    /// If the finalization already exists (making the put a no-op), the returned handle still
    /// reports the durability of all previously accepted writes, including the original write
    /// if its sync is still in flight.
    fn put_start_sync(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<Self::Scheme, Self::Commitment>,
    ) -> impl Future<Output = Result<Handle<()>, Self::Error>> + Send {
        async move {
            self.put(height, digest, finalization).await?;
            self.start_sync().await
        }
    }

    /// Flush all buffered writes to durable storage.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Request that all buffered writes are flushed to durable storage.
    ///
    /// The returned handle completes once every write accepted before this call is durable,
    /// including writes covered by a sync that is still in flight. Implementations without a
    /// non-blocking sync path may complete the sync before returning an already-finished handle.
    fn start_sync(&mut self) -> impl Future<Output = Result<Handle<()>, Self::Error>> + Send {
        async move {
            self.sync().await?;
            Ok(Handle::ready(Ok(())))
        }
    }

    /// Retrieve a [Finalization] by height or corresponding block digest.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the application height or
    /// its corresponding block digest.
    ///
    /// # Arguments
    ///
    /// * `id`: The finalization identifier (height or digest) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(finalization))` if present, `Ok(None)` if missing, or `Err` on read failure.
    #[allow(clippy::type_complexity)]
    fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> impl Future<
        Output = Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error>,
    > + Send;

    /// Check whether a finalization is stored at `height` without fetching it.
    fn has(&self, height: Height) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Prune the store to the provided minimum height (inclusive).
    ///
    /// # Arguments
    ///
    /// * `min`: The lowest height that must remain after pruning.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is applied or unnecessary; `Err` if pruning fails.
    fn prune(&mut self, min: Height) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the highest stored finalization's application height.
    ///
    /// # Returns
    /// `Some(height)` if there are any stored finalizations, or `None` if the store is empty.
    fn last_index(&self) -> Option<Height>;

    /// Retrieve an iterator over ranges that overlap or follow `from`.
    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)>;
}

/// Durable store for finalized [Blocks](Block) keyed by height and block digest.
pub trait Blocks: Send + Sync + 'static {
    /// The type of [Block] that is stored.
    type Block: Block;

    /// The type of error returned when storing, retrieving, or pruning blocks.
    type Error: Error + Send + Sync + 'static;

    /// Buffer a finalized block for storage, keyed by height and block digest.
    ///
    /// The write is not durable until [sync](Self::sync) is called.
    ///
    /// Implementations must ignore overwrites for an existing block at the same
    /// height or commitment.
    ///
    /// # Arguments
    ///
    /// * `block`: The finalized block, which provides its `height()` and `digest()`.
    fn put(&mut self, block: Self::Block) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Buffer a finalized block and start syncing the resulting write.
    ///
    /// If the block already exists (making the put a no-op), the returned handle still reports
    /// the durability of all previously accepted writes, including the original write if its
    /// sync is still in flight.
    fn put_start_sync(
        &mut self,
        block: Self::Block,
    ) -> impl Future<Output = Result<Handle<()>, Self::Error>> + Send {
        async move {
            self.put(block).await?;
            self.start_sync().await
        }
    }

    /// Flush all buffered writes to durable storage.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Request that all buffered writes are flushed to durable storage.
    ///
    /// The returned handle completes once every write accepted before this call is durable,
    /// including writes covered by a sync that is still in flight. Implementations without a
    /// non-blocking sync path may complete the sync before returning an already-finished handle.
    fn start_sync(&mut self) -> impl Future<Output = Result<Handle<()>, Self::Error>> + Send {
        async move {
            self.sync().await?;
            Ok(Handle::ready(Ok(())))
        }
    }

    /// Retrieve a finalized block by height or block digest.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the block height or
    /// its block digest.
    ///
    /// # Arguments
    ///
    /// * `id`: The block identifier (height or digest) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(block))` if present, `Ok(None)` if missing, or `Err` on read failure.
    fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> impl Future<Output = Result<Option<Self::Block>, Self::Error>> + Send;

    /// Prune the store to the provided minimum height (inclusive).
    ///
    /// # Arguments
    ///
    /// * `min`: The lowest height that must remain after pruning.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is applied or unnecessary; `Err` if pruning fails.
    fn prune(&mut self, min: Height) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    ///
    /// # Arguments
    ///
    /// * `start`: The height to start searching from (inclusive).
    /// * `max`: The maximum number of missing items to return.
    ///
    /// # Returns
    ///
    /// A vector containing up to `max` missing heights from gaps between ranges.
    /// The vector may contain fewer than `max` items if there aren't enough gaps.
    /// If there are no more ranges after the current position, no items are returned.
    fn missing_items(&self, start: Height, max: usize) -> Vec<Height>;

    /// Finds the end of the range containing `value` and the start of the
    /// range succeeding `value`. This method is useful for identifying gaps around a given point.
    ///
    /// # Arguments
    ///
    /// - `value`: The height to query around.
    ///
    /// # Behavior
    ///
    /// - If `value` falls within an existing range `[r_start, r_end]`, `current_range_end` will be `Some(r_end)`.
    /// - If `value` falls in a gap between two ranges `[..., prev_end]` and `[next_start, ...]`,
    ///   `current_range_end` will be `None` and `next_range_start` will be `Some(next_start)`.
    /// - If `value` is before all ranges in the store, `current_range_end` will be `None`.
    /// - If `value` is after all ranges in the store (or within the last range), `next_range_start` will be `None`.
    /// - If the store is empty, both will be `None`.
    ///
    /// # Returns
    ///
    /// A tuple `(Option<Height>, Option<Height>)` where:
    /// - The first element (`current_range_end`) is `Some(end)` of the range that contains `value`. It's `None` if `value` is before all ranges, the store is empty, or `value` is not in any range.
    /// - The second element (`next_range_start`) is `Some(start)` of the first range that begins strictly after `value`. It's `None` if no range starts after `value` or the store is empty.
    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>);

    /// Retrieve the last (highest) index in the store.
    ///
    /// # Returns
    /// `Some(height)` if there are any stored blocks, or `None` if the store is empty.
    fn last_index(&self) -> Option<Height>;
}

impl<E, B, C, S> Certificates for immutable::Archive<E, B, Finalization<S, C>>
where
    E: BufferPooler + Storage + Metrics + Clock,
    B: Digest,
    C: Digest,
    S: Scheme,
{
    type BlockDigest = B;
    type Commitment = C;
    type Scheme = S;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<S, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        Archive::put(self, height.get(), digest, finalization).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        Archive::start_sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn has(&self, height: Height) -> Result<bool, Self::Error> {
        <Self as Archive>::has(self, Identifier::Index(height.get())).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }

    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
        <Self as Archive>::ranges_from(self, from.get())
            .map(|(s, e)| (Height::new(s), Height::new(e)))
    }
}

impl<E, B> Blocks for immutable::Archive<E, B::Digest, B>
where
    E: BufferPooler + Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        Archive::put(self, block.height().get(), block.digest(), block).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        Archive::start_sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        <Self as Archive>::missing_items(self, start.get(), max)
            .into_iter()
            .map(Height::new)
            .collect()
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        (a.map(Height::new), b.map(Height::new))
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }
}

impl<T, E, B, C, S> Certificates for prunable::Archive<T, E, B, Finalization<S, C>>
where
    T: Translator,
    E: BufferPooler + Storage + Metrics + Clock,
    B: Digest,
    C: Digest,
    S: Scheme,
{
    type BlockDigest = B;
    type Commitment = C;
    type Scheme = S;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<S, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        Archive::put(self, height.get(), digest, finalization).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        Archive::start_sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn has(&self, height: Height) -> Result<bool, Self::Error> {
        <Self as Archive>::has(self, Identifier::Index(height.get())).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }

    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
        <Self as Archive>::ranges_from(self, from.get())
            .map(|(s, e)| (Height::new(s), Height::new(e)))
    }
}

impl<T, E, B> Blocks for prunable::Archive<T, E, B::Digest, B>
where
    T: Translator,
    E: BufferPooler + Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        Archive::put(self, block.height().get(), block.digest(), block).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn start_sync(&mut self) -> Result<Handle<()>, Self::Error> {
        Archive::start_sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        <Self as Archive>::missing_items(self, start.get(), max)
            .into_iter()
            .map(Height::new)
            .collect()
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        (a.map(Height::new), b.map(Height::new))
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }
}
