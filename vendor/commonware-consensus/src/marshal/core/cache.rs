use crate::{
    marshal::core::Variant,
    simplex::types::{Finalization, Notarization},
    types::{Epoch, Height, Round, View},
};
use commonware_codec::{CodecShared, Read};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::boxed;
use commonware_runtime::{
    buffer::paged::CacheRef, BufferPooler, Clock, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::{
    archive::{self, prunable, Archive as _, Identifier, MultiArchive as _},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use rand_core::Rng;
use std::{
    cmp::max,
    collections::BTreeMap,
    num::{NonZero, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

// The key used to store the current epoch in the metadata store.
const CACHED_EPOCHS_KEY: u8 = 0;

/// Configuration parameters for prunable archives.
pub(crate) struct Config {
    pub partition_prefix: String,
    pub prunable_items_per_section: NonZero<u64>,
    pub replay_buffer: NonZeroUsize,
    pub key_write_buffer: NonZeroUsize,
    pub value_write_buffer: NonZeroUsize,
    pub key_page_cache: CacheRef,
}

/// Prunable archives for a single epoch.
#[allow(clippy::type_complexity)]
struct Cache<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, V::StoredBlock>,
    /// Notarized blocks stored by view
    notarized_blocks:
        prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, V::StoredBlock>,
    /// Certified blocks indexed by height and keyed by digest.
    certified_blocks:
        prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, V::StoredBlock>,
    /// Notarizations stored by view
    notarizations: prunable::Archive<
        TwoCap,
        R,
        <V::Block as Digestible>::Digest,
        Notarization<S, V::Commitment>,
    >,
    /// Finalizations stored by view
    finalizations: prunable::Archive<
        TwoCap,
        R,
        <V::Block as Digestible>::Digest,
        Finalization<S, V::Commitment>,
    >,
}

impl<R, V, S> Cache<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Prune view-indexed archives to the given view.
    async fn prune_by_view(&mut self, min_view: View) {
        match futures::try_join!(
            self.verified_blocks.prune(min_view.get()),
            self.notarized_blocks.prune(min_view.get()),
            self.notarizations.prune(min_view.get()),
            self.finalizations.prune(min_view.get()),
        ) {
            Ok(_) => debug!(min_view = %min_view, "pruned archives"),
            Err(e) => panic!("failed to prune archives: {e}"),
        }
    }

    /// Prune height-indexed archives to the given height.
    async fn prune_by_height(&mut self, min_height: Height) {
        self.certified_blocks
            .prune(min_height.get())
            .await
            .expect("failed to prune certified blocks");
    }
}

/// Manages prunable caches and their metadata.
pub(crate) struct Manager<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Context
    context: R,

    /// Configuration for underlying prunable archives
    cfg: Config,

    /// Codec configuration for block type
    block_codec_config: <V::ApplicationBlock as Read>::Cfg,

    /// Metadata store for recording which epochs may have data. The value is a tuple of the floor
    /// and ceiling, the minimum and maximum epochs (inclusive) that may have data.
    metadata: Metadata<R, u8, (Epoch, Epoch)>,

    /// A map from epoch to its cache
    caches: BTreeMap<Epoch, Cache<R, V, S>>,
}

impl<R, V, S> Manager<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Initialize the cache manager and its metadata store.
    #[boxed]
    pub(crate) async fn init(
        context: R,
        cfg: Config,
        block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    ) -> Self {
        // Initialize metadata
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", cfg.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize metadata");

        // We don't eagerly initialize any epoch caches here, they will be
        // initialized on demand, otherwise there could be coordination issues
        // around the scheme provider.
        Self {
            context,
            cfg,
            block_codec_config,
            metadata,
            caches: BTreeMap::new(),
        }
    }

    /// Load all persisted epoch caches so that `find_block` can discover
    /// blocks written before the last shutdown.
    pub(crate) async fn load_persisted_epochs(&mut self) {
        let (floor, ceiling) = self.get_metadata();
        for e in floor.get()..=ceiling.get() {
            let epoch = Epoch::new(e);
            if !self.caches.contains_key(&epoch) {
                self.init_epoch(epoch).await;
            }
        }
    }

    /// Retrieve the epoch range that may have data.
    fn get_metadata(&self) -> (Epoch, Epoch) {
        self.metadata
            .get(&CACHED_EPOCHS_KEY)
            .cloned()
            .unwrap_or((Epoch::zero(), Epoch::zero()))
    }

    /// Set the epoch range that may have data.
    async fn set_metadata(&mut self, floor: Epoch, ceiling: Epoch) {
        self.metadata
            .put_sync(CACHED_EPOCHS_KEY, (floor, ceiling))
            .await
            .expect("failed to write metadata");
    }

    /// Get the cache for the given epoch, initializing it if it doesn't exist.
    ///
    /// If the epoch is less than the minimum cached epoch, then it has already been pruned,
    /// and this will return `None`.
    async fn get_or_init_epoch(&mut self, epoch: Epoch) -> Option<&mut Cache<R, V, S>> {
        // If the cache exists, return it
        if self.caches.contains_key(&epoch) {
            return self.caches.get_mut(&epoch);
        }

        // If the epoch is less than the epoch floor, then it has already been pruned
        let (floor, ceiling) = self.get_metadata();
        if epoch < floor {
            return None;
        }

        // Update the metadata (metadata-first is safe; init is idempotent)
        if epoch > ceiling {
            self.set_metadata(floor, epoch).await;
        }

        // Initialize and return the epoch
        self.init_epoch(epoch).await;
        self.caches.get_mut(&epoch) // Should always be Some
    }

    /// Helper to initialize the cache for a given epoch.
    #[boxed]
    async fn init_epoch(&mut self, epoch: Epoch) {
        let context = self.context.child("cache").with_attribute("epoch", epoch);
        let (verified_blocks, notarized_blocks, certified_blocks, notarizations, finalizations) = futures::join!(
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "verified",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "notarized",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "certified",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "notarizations",
                S::certificate_codec_config_unbounded(),
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "finalizations",
                S::certificate_codec_config_unbounded(),
            ),
        );
        let existing = self.caches.insert(
            epoch,
            Cache {
                verified_blocks,
                notarized_blocks,
                certified_blocks,
                notarizations,
                finalizations,
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    /// Helper to initialize an archive.
    async fn init_archive<T: CodecShared>(
        ctx: &R,
        cfg: &Config,
        epoch: Epoch,
        name: &'static str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, T> {
        let start = ctx.current();
        let archive_cfg = prunable::Config {
            translator: TwoCap,
            key_partition: format!("{}-cache-{epoch}-{name}-key", cfg.partition_prefix),
            key_page_cache: cfg.key_page_cache.clone(),
            value_partition: format!("{}-cache-{epoch}-{name}-value", cfg.partition_prefix),
            items_per_section: cfg.prunable_items_per_section,
            compression: None,
            codec_config,
            replay_buffer: cfg.replay_buffer,
            key_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
        };
        let archive = prunable::Archive::init(ctx.child(name), archive_cfg)
            .await
            .unwrap_or_else(|_| panic!("failed to initialize {name} archive"));
        info!(elapsed = ?ctx.current().duration_since(start).unwrap_or(Duration::ZERO), "restored {name} archive");
        archive
    }

    /// Add a verify-stage candidate block to the prunable archive and start syncing it.
    ///
    /// The archive name is historical: callers may start this durability work
    /// after structural validation and before the application verdict is known.
    /// Consensus must not treat presence in this cache as application validity.
    ///
    /// No certificate pins a round to a single candidate at this stage: an
    /// equivocating leader can land one block at this view (possibly before a
    /// crash) while consensus later verifies a different one. Candidates are
    /// stored with multi-put semantics so a same-view collision cannot silently
    /// drop the new block while the returned handle vouches only for the old
    /// one. A digest already stored at this view is not duplicated, and the
    /// covering handle reports the durability of its existing write.
    pub(crate) async fn put_verified(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::StoredBlock,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let view = round.view().get();

        // Deduplicate against this view only: the same digest may legitimately
        // be stored again at a later view (boundary re-proposal), and each view
        // needs its own copy to survive per-view retention pruning.
        match cache.verified_blocks.has_at(view, &digest).await {
            Ok(true) => {
                return Self::handle_start_result(
                    cache.verified_blocks.start_sync().await,
                    round,
                    "verified",
                );
            }
            Ok(false) => {}
            Err(e) => panic!("failed to check verified blocks: {e}"),
        }

        let result = cache
            .verified_blocks
            .put_multi_start_sync(view, digest, block)
            .await;
        Self::handle_start_result(result, round, "verified")
    }

    /// Add a certified block to the height-indexed archive.
    pub(crate) async fn put_certified(
        &mut self,
        epoch: Epoch,
        height: Height,
        digest: <V::Block as Digestible>::Digest,
        block: V::StoredBlock,
    ) {
        let Some(cache) = self.get_or_init_epoch(epoch).await else {
            return;
        };

        // A digest determines its height, so scoping the dedup to this height
        // is exact and avoids fetching values.
        match cache.certified_blocks.has_at(height.get(), &digest).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => panic!("failed to check certified block: {e}"),
        }

        match cache
            .certified_blocks
            .put_multi_sync(height.get(), digest, block)
            .await
        {
            Ok(()) => debug!(%height, "cached certified block"),
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(%height, "certified block already pruned");
            }
            Err(e) => panic!("failed to insert certified block: {e}"),
        }
    }

    /// Add a notarized block to the prunable archive and start syncing it.
    pub(crate) async fn put_notarized(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::StoredBlock,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };

        let result = cache
            .notarized_blocks
            .put_start_sync(round.view().get(), digest, block)
            .await;
        Self::handle_start_result(result, round, "notarized")
    }

    /// Returns a handle covering every write accepted by the round's verified-block
    /// archive before this call, including writes whose sync is still in flight.
    ///
    /// An absent epoch has nothing to observe (it never accepted a write or was
    /// pruned below the epoch floor), so its handle resolves immediately.
    pub(crate) async fn start_sync_verified(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        Self::handle_start_result(cache.verified_blocks.start_sync().await, round, "verified")
    }

    /// Returns a handle covering every write accepted by the round's notarization
    /// archive before this call, including writes whose sync is still in flight.
    ///
    /// An absent epoch has nothing to observe (it never accepted a write or was
    /// pruned below the epoch floor), so its handle resolves immediately.
    pub(crate) async fn start_sync_notarizations(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        Self::handle_start_result(
            cache.notarizations.start_sync().await,
            round,
            "notarization",
        )
    }

    /// Add a notarization to the prunable archive and start syncing it.
    pub(crate) async fn put_notarization(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        notarization: Notarization<S, V::Commitment>,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let result = cache
            .notarizations
            .put_start_sync(round.view().get(), digest, notarization)
            .await;
        Self::handle_start_result(result, round, "notarization")
    }

    /// Add a finalization to the prunable archive.
    ///
    /// The blocking sync is intentional. A downstream application may write to
    /// an external store once it observes a finalization's effects and then
    /// assume the certificate is still readable from marshal after a restart.
    /// Deferring this sync would silently break that recovery pattern.
    pub(crate) async fn put_finalization(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        finalization: Finalization<S, V::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        match cache
            .finalizations
            .put_sync(round.view().get(), digest, finalization)
            .await
        {
            Ok(()) => debug!(?round, "cached finalization"),
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, "finalization already pruned");
            }
            Err(e) => panic!("failed to insert finalization: {e}"),
        }
    }

    /// Helper to debug cache sync start results.
    ///
    /// `AlreadyPrunedTo` only arises from the put step of `put_start_sync` callers; a
    /// bare `start_sync` cannot return it.
    fn handle_start_result(
        result: Result<Handle<()>, archive::Error>,
        round: Round,
        name: &str,
    ) -> Handle<()> {
        match result {
            Ok(handle) => {
                debug!(?round, name, "cache sync started");
                handle
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, name, "already pruned");
                Handle::ready(Ok(()))
            }
            Err(e) => {
                panic!("failed to persist {name}: {e}");
            }
        }
    }

    /// Get a notarization from the prunable archive by round.
    pub(crate) async fn get_notarization(
        &self,
        round: Round,
    ) -> Option<Notarization<S, V::Commitment>> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .notarizations
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get notarization")
    }

    /// Returns whether the verified archive holds `digest` at `round`.
    pub(crate) async fn has_verified(
        &self,
        round: Round,
        digest: &<V::Block as Digestible>::Digest,
    ) -> bool {
        let Some(cache) = self.caches.get(&round.epoch()) else {
            return false;
        };
        cache
            .verified_blocks
            .has_at(round.view().get(), digest)
            .await
            .expect("failed to check verified blocks")
    }

    /// Get the block previously persisted in the verified archive for `round`.
    ///
    /// The archive can hold multiple candidates at one view (an equivocating
    /// leader can land one before a crash and another after), and this returns
    /// the first stored. Callers must not assume it is the most recently
    /// verified candidate: check context/digest before reuse, or look up by
    /// digest.
    pub(crate) async fn get_verified(&self, round: Round) -> Option<V::StoredBlock> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .verified_blocks
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get verified block")
    }

    /// Get a finalization from the prunable archive by block digest.
    ///
    /// SAFETY: For blocks/certificates admitted by marshal verification, a block digest
    /// maps to exactly one consensus payload commitment for the active marshal
    /// [`Variant`] instance.
    pub(crate) async fn get_finalization_for(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<Finalization<S, V::Commitment>> {
        for cache in self.caches.values().rev() {
            match cache.finalizations.get(Identifier::Key(&digest)).await {
                Ok(Some(finalization)) => return Some(finalization),
                Ok(None) => continue,
                Err(e) => panic!("failed to get cached finalization: {e}"),
            }
        }
        None
    }

    /// Looks for a block (certified by height, verified, or notarized) that matches `predicate`.
    pub(crate) async fn find_block_matching(
        &self,
        digest: <V::Block as Digestible>::Digest,
        mut predicate: impl FnMut(&V::StoredBlock) -> bool,
    ) -> Option<V::StoredBlock> {
        // Check in reverse order
        for cache in self.caches.values().rev() {
            // Check verified blocks
            if let Some(block) = cache
                .verified_blocks
                .get(Identifier::Key(&digest))
                .await
                .expect("failed to get verified block")
            {
                if predicate(&block) {
                    return Some(block);
                }
            }

            // Check notarized blocks
            if let Some(block) = cache
                .notarized_blocks
                .get(Identifier::Key(&digest))
                .await
                .expect("failed to get notarized block")
            {
                if predicate(&block) {
                    return Some(block);
                }
            }

            // Check certified blocks
            if let Some(block) = cache
                .certified_blocks
                .get(Identifier::Key(&digest))
                .await
                .expect("failed to get certified block")
            {
                if predicate(&block) {
                    return Some(block);
                }
            }
        }
        None
    }

    /// Prune the view-indexed caches below the given round.
    pub(crate) async fn prune_by_view(&mut self, round: Round) {
        // Remove and close prunable archives from older epochs
        let new_floor = round.epoch();
        let old_epochs: Vec<Epoch> = self
            .caches
            .keys()
            .copied()
            .filter(|epoch| *epoch < new_floor)
            .collect();
        for epoch in old_epochs.iter() {
            let Cache {
                verified_blocks: vb,
                notarized_blocks: nb,
                certified_blocks: cb,
                notarizations: nv,
                finalizations: fv,
            } = self.caches.remove(epoch).unwrap();
            vb.destroy().await.expect("failed to destroy vb");
            nb.destroy().await.expect("failed to destroy nb");
            cb.destroy().await.expect("failed to destroy cb");
            nv.destroy().await.expect("failed to destroy nv");
            fv.destroy().await.expect("failed to destroy fv");
        }

        // Update metadata if necessary
        let (floor, ceiling) = self.get_metadata();
        if new_floor > floor {
            let new_ceiling = max(ceiling, new_floor);
            self.set_metadata(new_floor, new_ceiling).await;
        }

        // Prune archives for the given epoch
        let min_view = round.view();
        if let Some(prunable) = self.caches.get_mut(&round.epoch()) {
            prunable.prune_by_view(min_view).await;
        }
    }

    /// Prune height-indexed certified blocks below the given height.
    pub(crate) async fn prune_by_height(&mut self, height: Height) {
        for cache in self.caches.values_mut() {
            cache.prune_by_height(height).await;
        }
    }
}
