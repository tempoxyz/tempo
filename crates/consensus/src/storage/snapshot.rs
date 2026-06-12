//! Persisted-cache extraction for `tempo snapshot-manifest`.
//!
//! A snapshot of a node ships the execution layer's state up to its
//! finalized watermark plus a consensus floor certificate. To let a
//! restored node replay the execution layer up to the digest recorded in
//! that certificate without round-tripping to peers, the snapshot also
//! carries a *minimized* copy of the consensus layer's hybrid storage
//! ("persisted cache"): exactly the finalized blocks in
//! `(execution_finalized, certificate_height]`.
//!
//! Blocks at or below the execution layer's finalized watermark are
//! already durable in the execution layer snapshot and are served from
//! there by [`super::Hybrid`]'s fallback path, so they are dead weight in
//! a snapshot. Blocks above the certificate height are not required to
//! reach the certificate digest. Everything else is dropped.
//!
//! [`collect_persisted_cache`] determines the certificate and reads the
//! covered blocks out of the node's consensus storage;
//! [`write_persisted_cache`] writes them into a fresh prunable archive
//! rooted at a staging directory using the production storage layout, so
//! a restored node can open it as its own persisted cache.

use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier};
use eyre::{Context as _, OptionExt as _, ensure};
use reth_provider::{BlockIdReader, BlockReader};

use super::{
    BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
    init_prunable_finalized_blocks_archive,
};
use crate::consensus::{Digest, block::Block};

type TempoFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;

/// Narrow view of the execution layer needed to anchor the persisted
/// cache: the finalized watermark and canonical block digests at or below
/// it.
///
/// Exists to make unit testing easier; production callers go through the
/// [`RethAnchor`] adapter over reth's provider traits.
pub(crate) trait ExecutionAnchor {
    /// The execution layer's last finalized block height, or `None` if
    /// nothing has been finalized yet.
    fn finalized_height(&self) -> eyre::Result<Option<u64>>;

    /// Digest (block hash) of the canonical block at `height`.
    fn block_digest(&self, height: u64) -> eyre::Result<Option<Digest>>;
}

/// [`ExecutionAnchor`] adapter over reth's provider traits.
struct RethAnchor<'a, P: ?Sized>(&'a P);

impl<P> ExecutionAnchor for RethAnchor<'_, P>
where
    P: BlockIdReader + BlockReader<Block = tempo_primitives::Block> + ?Sized,
{
    fn finalized_height(&self) -> eyre::Result<Option<u64>> {
        self.0
            .finalized_block_number()
            .wrap_err("failed reading finalized block number from execution provider")
    }

    fn block_digest(&self, height: u64) -> eyre::Result<Option<Digest>> {
        use alloy_consensus::Sealable as _;

        let block = self
            .0
            .block_by_number(height)
            .wrap_err_with(|| format!("failed reading execution block at height {height}"))?;
        Ok(block.map(|block| Digest(block.header.hash_slow())))
    }
}

/// The minimal persisted-cache payload extracted from a node's consensus
/// storage for a snapshot.
///
/// Holds the highest finalization certificate that the cached blocks can
/// reach from the execution layer's finalized watermark, plus the blocks
/// `(execution_height, height]` themselves (opaque outside this crate).
#[derive(Debug)]
pub struct PersistedCache {
    /// The execution layer's finalized height the cache builds on.
    pub execution_height: u64,
    /// Digest of the execution layer's finalized block at
    /// [`Self::execution_height`].
    pub execution_digest: Digest,
    /// Height of [`Self::finalization`]. At most
    /// [`Self::execution_height`] + the number of cached blocks.
    pub height: u64,
    /// The target finalization certificate. Its payload is the digest the
    /// execution layer can be brought up to by replaying the cached
    /// blocks.
    pub finalization: TempoFinalization,
    /// Blocks `(execution_height, height]`, oldest first. Verified to be
    /// parent-linked from the execution anchor up to the certificate
    /// digest.
    blocks: Vec<Block>,
}

impl PersistedCache {
    /// Digest recorded in the certificate.
    pub fn digest(&self) -> Digest {
        self.finalization.proposal.payload
    }

    /// Number of blocks in the minimized cache.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Inclusive height range of the cached blocks, or `None` when the
    /// certificate is already covered by the execution layer snapshot.
    pub fn block_range(&self) -> Option<(u64, u64)> {
        (!self.blocks.is_empty()).then(|| (self.execution_height + 1, self.height))
    }
}

/// Determines the snapshot's target finalization certificate and collects
/// the minimal set of persisted-cache blocks needed to reach it.
///
/// Reads the node's consensus storage rooted at `context`'s storage
/// directory. The target is the highest finalization certificate whose
/// height is contiguously covered by cached blocks above the execution
/// layer's finalized watermark (searching at most `max_depth` certificate
/// heights downwards). The covered blocks are verified to be parent-linked
/// from the execution layer's finalized block up to the certificate
/// digest.
///
/// The blocks are buffered in memory; the range is bounded by how far the
/// consensus layer ran ahead of the execution layer when the node was
/// stopped (at most the persisted cache itself).
///
/// Returns `None` when the execution layer has no finalized state, when no
/// finalization certificates are persisted, or when no certificate within
/// `max_depth` matches the available state.
pub async fn collect_persisted_cache<TContext, P>(
    context: &TContext,
    execution_provider: &P,
    max_depth: u64,
) -> eyre::Result<Option<PersistedCache>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: BlockIdReader + BlockReader<Block = tempo_primitives::Block> + Send + Sync + ?Sized,
{
    collect_persisted_cache_inner(context, &RethAnchor(execution_provider), max_depth).await
}

/// Implementation of [`collect_persisted_cache`] generic over the
/// [`ExecutionAnchor`] seam so tests can stub the execution layer.
async fn collect_persisted_cache_inner<TContext, P>(
    context: &TContext,
    execution_provider: &P,
    max_depth: u64,
) -> eyre::Result<Option<PersistedCache>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: ExecutionAnchor + ?Sized,
{
    let Some(execution_height) = execution_provider.finalized_height()? else {
        return Ok(None);
    };
    let execution_digest = execution_provider
        .block_digest(execution_height)?
        .ok_or_eyre(format!(
            "finalized execution block at height `{execution_height}` is missing"
        ))?;

    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let finalizations =
        init_finalizations_archive(context, crate::PARTITION_PREFIX, page_cache.clone())
            .await
            .wrap_err("failed to open finalizations-by-height archive")?;
    let Some(last_finalization) = finalizations.last_index() else {
        return Ok(None);
    };

    let blocks_archive =
        init_prunable_finalized_blocks_archive(context, crate::PARTITION_PREFIX, page_cache)
            .await
            .wrap_err("failed to open prunable finalized blocks archive")?;

    // Highest cached height contiguously reachable from the execution
    // anchor. Anything above a gap cannot be replayed into the execution
    // layer and is useless to a restored node.
    let (coverage_end, _) = blocks_archive.next_gap(execution_height.saturating_add(1));
    let coverage_end = coverage_end.unwrap_or(execution_height);

    let upper = last_finalization.min(coverage_end);
    let lower = upper.saturating_sub(max_depth);
    for height in (lower..=upper).rev() {
        let Some(finalization) = finalizations
            .get(Identifier::Index(height))
            .await
            .wrap_err_with(|| format!("failed reading finalization at height {height}"))?
        else {
            continue;
        };

        // Collect the cached blocks `(execution_height, height]` and walk
        // the parent linkage from the execution anchor.
        let mut blocks = Vec::new();
        let mut parent = execution_digest;
        for cached in execution_height + 1..=height {
            let block = blocks_archive
                .get(Identifier::Index(cached))
                .await
                .wrap_err_with(|| format!("failed reading cached block at height {cached}"))?
                .ok_or_eyre(format!(
                    "cached block at height `{cached}` disappeared during extraction"
                ))?;
            ensure!(
                block.parent_digest() == parent,
                "cached block at height `{cached}` does not extend digest {parent}",
            );
            parent = block.digest();
            blocks.push(block);
        }

        // The digest the certificate must commit to: the last cached
        // block, or the execution layer's block when the certificate sits
        // at or below the finalized watermark.
        let tip_digest = match blocks.last() {
            Some(block) => block.digest(),
            None if height == execution_height => execution_digest,
            None => execution_provider
                .block_digest(height)?
                .ok_or_eyre(format!(
                    "execution block at certificate height `{height}` is missing"
                ))?,
        };

        let finalization_digest = finalization.proposal.payload;
        ensure!(
            finalization_digest == tip_digest,
            "digest mismatch at height `{height}`. finalization: {finalization_digest}, block: {tip_digest}",
        );

        return Ok(Some(PersistedCache {
            execution_height,
            execution_digest,
            height,
            finalization,
            blocks,
        }));
    }

    Ok(None)
}

/// Writes the minimized persisted cache into a fresh prunable
/// finalized-blocks archive rooted at `context`'s storage directory.
///
/// The archive uses the production storage layout (same partition names
/// and section sizing), so extracting the staged files into a node's
/// consensus datadir yields a persisted cache the node opens as its own.
///
/// The target storage directory must not already contain a finalized
/// blocks archive.
pub async fn write_persisted_cache<TContext>(
    context: &TContext,
    cache: &PersistedCache,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let mut archive =
        init_prunable_finalized_blocks_archive(context, crate::PARTITION_PREFIX, page_cache)
            .await
            .wrap_err("failed to initialize minimized persisted cache archive")?;

    ensure!(
        archive.last_index().is_none(),
        "minimized persisted cache target directory is not empty",
    );

    for block in &cache.blocks {
        let height = block.height().get();
        archive
            .put(height, block.digest(), block.clone())
            .await
            .wrap_err_with(|| format!("failed writing cached block at height {height}"))?;
    }

    archive
        .sync()
        .await
        .wrap_err("failed to sync minimized persisted cache archive")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use commonware_consensus::{
        simplex::types::{Finalize, Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use rand_08::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::storage::hybrid::test::utils::{fresh_page_cache, make_chain};

    const NAMESPACE: &[u8] = b"snapshot-test";

    /// Stub [`ExecutionAnchor`]: a finalized watermark plus canonical
    /// digests by height.
    #[derive(Default)]
    struct StubAnchor {
        finalized: Option<u64>,
        digests: HashMap<u64, Digest>,
    }

    impl StubAnchor {
        fn with_chain(finalized: u64, chain: &[Block]) -> Self {
            Self {
                finalized: Some(finalized),
                digests: chain
                    .iter()
                    .map(|block| (block.height().get(), block.digest()))
                    .collect(),
            }
        }
    }

    impl ExecutionAnchor for StubAnchor {
        fn finalized_height(&self) -> eyre::Result<Option<u64>> {
            Ok(self.finalized)
        }

        fn block_digest(&self, height: u64) -> eyre::Result<Option<Digest>> {
            // Mirror the production provider: only canonical blocks at or
            // below the finalized watermark matter for anchoring.
            Ok(self.digests.get(&height).copied())
        }
    }

    fn scheme_fixture() -> Fixture<Scheme<PublicKey, MinSig>> {
        let mut rng = StdRng::seed_from_u64(42);
        commonware_consensus::simplex::scheme::bls12381_threshold::vrf::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        )
    }

    fn make_finalization(
        fixture: &Fixture<Scheme<PublicKey, MinSig>>,
        height: u64,
        digest: Digest,
    ) -> TempoFinalization {
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(height)),
            View::new(height.saturating_sub(1)),
            digest,
        );
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect();
        Finalization::from_finalizes(&fixture.schemes[0], &finalizes, &Sequential)
            .expect("assemble finalization")
    }

    /// Populate the production-prefix archives with `chain` blocks and
    /// finalization certificates at `cert_heights`.
    async fn seed_storage<TContext>(
        context: &TContext,
        chain: &[Block],
        cert_heights: &[u64],
        skip_block_heights: &[u64],
    ) where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    {
        let fixture = scheme_fixture();
        let page_cache = fresh_page_cache(context);

        let mut finalizations =
            init_finalizations_archive(context, crate::PARTITION_PREFIX, page_cache.clone())
                .await
                .expect("init finalizations archive");
        for block in chain {
            let height = block.height().get();
            if cert_heights.contains(&height) {
                let finalization = make_finalization(&fixture, height, block.digest());
                finalizations
                    .put(height, block.digest(), finalization)
                    .await
                    .expect("put finalization");
            }
        }
        finalizations.sync().await.expect("sync finalizations");

        let mut blocks =
            init_prunable_finalized_blocks_archive(context, crate::PARTITION_PREFIX, page_cache)
                .await
                .expect("init blocks archive");
        for block in chain {
            let height = block.height().get();
            if skip_block_heights.contains(&height) {
                continue;
            }
            blocks
                .put(height, block.digest(), block.clone())
                .await
                .expect("put block");
        }
        blocks.sync().await.expect("sync blocks");
    }

    #[test_traced]
    fn collects_blocks_up_to_highest_covered_certificate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let anchor = StubAnchor::with_chain(10, &chain);
            seed_storage(&context.with_label("seed"), &chain, &[5, 10, 15, 20], &[]).await;

            let cache = collect_persisted_cache_inner(&context.with_label("collect"), &anchor, 100)
                .await
                .expect("collect")
                .expect("cache");

            assert_eq!(cache.execution_height, 10);
            assert_eq!(cache.height, 20);
            assert_eq!(cache.block_count(), 10);
            assert_eq!(cache.block_range(), Some((11, 20)));
            assert_eq!(cache.digest(), chain[20].digest());
            assert_eq!(cache.execution_digest, chain[10].digest());
        });
    }

    #[test_traced]
    fn coverage_gap_limits_certificate_selection() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let anchor = StubAnchor::with_chain(10, &chain);
            // Block 15 is missing from the cache: certificates above it
            // are unreachable.
            seed_storage(&context.with_label("seed"), &chain, &[14, 20], &[15]).await;

            let cache = collect_persisted_cache_inner(&context.with_label("collect"), &anchor, 100)
                .await
                .expect("collect")
                .expect("cache");

            assert_eq!(cache.height, 14);
            assert_eq!(cache.block_range(), Some((11, 14)));
            assert_eq!(cache.digest(), chain[14].digest());
        });
    }

    #[test_traced]
    fn certificate_below_execution_floor_yields_empty_cache() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let anchor = StubAnchor::with_chain(10, &chain);
            // Only a certificate below the execution watermark exists.
            seed_storage(&context.with_label("seed"), &chain, &[8], &[]).await;

            let cache = collect_persisted_cache_inner(&context.with_label("collect"), &anchor, 100)
                .await
                .expect("collect")
                .expect("cache");

            assert_eq!(cache.height, 8);
            assert_eq!(cache.block_count(), 0);
            assert_eq!(cache.block_range(), None);
            assert_eq!(cache.digest(), chain[8].digest());
        });
    }

    #[test_traced]
    fn errors_on_certificate_digest_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let anchor = StubAnchor::with_chain(10, &chain);
            seed_storage(&context.with_label("seed"), &chain, &[], &[]).await;

            // A certificate at height 20 committing to the wrong digest.
            let fixture = scheme_fixture();
            let bogus = make_finalization(&fixture, 20, chain[19].digest());
            let page_cache = fresh_page_cache(&context);
            let mut finalizations = init_finalizations_archive(
                &context.with_label("rewrite"),
                crate::PARTITION_PREFIX,
                page_cache,
            )
            .await
            .expect("init finalizations archive");
            finalizations
                .put(20, chain[19].digest(), bogus)
                .await
                .expect("put finalization");
            finalizations.sync().await.expect("sync");
            drop(finalizations);

            let err = collect_persisted_cache_inner(&context.with_label("collect"), &anchor, 100)
                .await
                .expect_err("digest mismatch must error");
            assert!(err.to_string().contains("digest mismatch"), "{err}");
        });
    }

    #[test_traced]
    fn returns_none_without_finalizations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let anchor = StubAnchor::with_chain(10, &chain);
            seed_storage(&context.with_label("seed"), &chain, &[], &[]).await;

            let cache = collect_persisted_cache_inner(&context.with_label("collect"), &anchor, 100)
                .await
                .expect("collect");
            assert!(cache.is_none());
        });
    }

    /// Build a [`PersistedCache`] covering `(10, 20]` of `chain` directly
    /// (tests share the module, so the private `blocks` field is in
    /// reach). Lets write-path tests run against an empty storage root
    /// without seeding source archives first.
    fn make_cache(chain: &[Block]) -> PersistedCache {
        let fixture = scheme_fixture();
        PersistedCache {
            execution_height: 10,
            execution_digest: chain[10].digest(),
            height: 20,
            finalization: make_finalization(&fixture, 20, chain[20].digest()),
            blocks: chain[11..=20].to_vec(),
        }
    }

    #[test_traced]
    fn write_round_trips_through_fresh_archive() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let cache = make_cache(&chain);

            write_persisted_cache(&context.with_label("write"), &cache)
                .await
                .expect("write");

            let page_cache = fresh_page_cache(&context);
            let archive = init_prunable_finalized_blocks_archive(
                &context.with_label("reopen"),
                crate::PARTITION_PREFIX,
                page_cache,
            )
            .await
            .expect("reopen archive");

            assert_eq!(archive.first_index(), Some(11));
            assert_eq!(archive.last_index(), Some(20));
            for (height, expected) in (11..=20u64).zip(&chain[11..=20]) {
                let block = archive
                    .get(Identifier::Index(height))
                    .await
                    .expect("get")
                    .expect("block present");
                assert_eq!(block.digest(), expected.digest());
            }
        });
    }

    #[test_traced]
    fn write_rejects_non_empty_target() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let chain = make_chain(0, 21);
            let cache = make_cache(&chain);

            write_persisted_cache(&context.with_label("first"), &cache)
                .await
                .expect("write");

            // The target now already contains a finalized blocks archive.
            let err = write_persisted_cache(&context.with_label("second"), &cache)
                .await
                .expect_err("non-empty target must be rejected");
            assert!(err.to_string().contains("not empty"), "{err}");
        });
    }
}
