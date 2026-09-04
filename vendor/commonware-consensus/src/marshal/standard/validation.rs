use crate::{
    marshal::{
        application::validation::{
            has_contiguous_height, is_block_in_expected_epoch, is_valid_reproposal_at_verify,
        },
        core::Mailbox,
        standard::Standard,
    },
    simplex::types::Context,
    types::Epocher,
    Application, Block, Epochable,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{
    telemetry::{metrics::histogram::Timed, traces::TracedExt as _},
    Clock, Metrics, Spawner,
};
use commonware_utils::channel::oneshot;
use rand_core::Rng;
use std::sync::Arc;
use tracing::{debug, info_span, Instrument as _};

/// Validation failures for standard verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    ParentDigest,
    ExpectedParentDigest,
    Height,
}

/// Consolidated validation for standard verification.
#[inline]
pub(crate) fn validate_block<B>(
    block: &B,
    parent: &B,
    parent_digest: B::Digest,
) -> Result<(), Error>
where
    B: Block,
{
    if block.parent() != parent.digest() {
        return Err(Error::ParentDigest);
    }
    if parent.digest() != parent_digest {
        return Err(Error::ExpectedParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(Error::Height);
    }
    Ok(())
}

/// Result of the shared epoch / re-proposal pre-check step.
///
/// `Complete(valid)` indicates verification can terminate immediately with `valid`.
/// `Continue(block)` indicates full parent + application verification should continue.
pub(super) enum Decision<B> {
    Complete(bool),
    Continue(B),
}

/// Performs shared pre-checks used by both inline and deferred verification paths.
///
/// This enforces:
/// - Block height belongs to the expected epoch.
/// - Re-proposal validation when `digest == context.parent.1`.
///
/// Valid re-proposals are immediately marked verified in marshal and return `Complete(true)`.
#[inline]
pub(super) async fn precheck_epoch_and_reproposal<ES, S, B>(
    epocher: &ES,
    marshal: &Mailbox<S, Standard<B>>,
    context: &Context<B::Digest, S::PublicKey>,
    digest: B::Digest,
    block: Arc<B>,
) -> Option<Decision<Arc<B>>>
where
    ES: Epocher,
    S: Scheme,
    B: Block + Clone,
{
    // Block heights must map to the expected epoch.
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        debug!(
            height = %block.height(),
            "block height not in expected epoch"
        );
        return Some(Decision::Complete(false));
    }

    // Re-proposals are signaled by `digest == context.parent.1`.
    // They skip normal parent/height checks because:
    // 1. The block was already verified when originally proposed.
    // 2. Parent-child checks would fail by construction when parent == block.
    if digest == context.parent.1 {
        if !is_valid_reproposal_at_verify(epocher, block.height(), context.epoch()) {
            debug!(
                height = %block.height(),
                "re-proposal is not at epoch boundary"
            );
            return Some(Decision::Complete(false));
        }

        if !marshal.verified(context.round, block).await {
            return None;
        }
        return Some(Decision::Complete(true));
    }

    Some(Decision::Continue(block))
}

/// Outcome of awaiting the parent and validating structural ancestry invariants.
pub(super) enum ParentCheck<B> {
    /// Structurally valid. Carries the parent for application verification.
    Valid(B),
    /// Structurally invalid (bad parent linkage or non-contiguous height); the verdict is
    /// `false` and the block must not be stored.
    Invalid,
}

/// Awaits the parent subscription and validates standard ancestry invariants (parent linkage
/// and contiguous height) against `parent_commitment`, the expected parent commitment from
/// the context the block is verified under.
///
/// The `parent_request` must be a subscription to `parent_commitment` started by the caller,
/// so the parent fetch can overlap earlier work (e.g., waiting for the candidate block to
/// become available).
///
/// Returns `None` when work should stop early (receiver dropped or parent unavailable).
#[inline]
pub(super) async fn await_and_validate_parent<B>(
    parent_commitment: B::Digest,
    block: &B,
    parent_request: oneshot::Receiver<Arc<B>>,
    tx: &mut oneshot::Sender<bool>,
) -> Option<ParentCheck<Arc<B>>>
where
    B: Block,
{
    // If consensus drops the receiver, we can stop work early.
    let parent = select! {
        _ = tx.closed() => {
            debug!(
                reason = "consensus dropped receiver",
                "skipping verification"
            );
            return None;
        },
        result = parent_request => match result {
            Ok(parent) => parent,
            Err(_) => {
                debug!(
                    ?parent_commitment,
                    reason = "failed to fetch parent block",
                    "skipping verification"
                );
                return None;
            }
        },
    };

    // Validate parent linkage and contiguous child height before application logic.
    if let Err(err) = validate_block(block, &parent, parent_commitment) {
        debug!(
            ?err,
            expected_parent = %parent.digest(),
            block_parent = %block.parent(),
            parent_height = %parent.height(),
            block_height = %block.height(),
            "block failed standard invariant validation"
        );
        return Some(ParentCheck::Invalid);
    }

    Some(ParentCheck::Valid(parent))
}

/// Runs application verification over the two-block ancestry prefix.
///
/// The block must already have passed [`await_and_validate_parent`]. Returns `None` when
/// work should stop early (receiver dropped). The store is intentionally separate so callers
/// can run it concurrently with this verification (durability is independent of validity).
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_app_verify<E, S, A, B>(
    runtime_context: E,
    context: Context<B::Digest, S::PublicKey>,
    block: Arc<B>,
    parent: Arc<B>,
    application: &mut A,
    marshal: &Mailbox<S, Standard<B>>,
    tx: &mut oneshot::Sender<bool>,
    ancestor_fetch_duration: Timed,
) -> Option<bool>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, SigningScheme = S, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
{
    let (parent_view, parent_commitment) = context.parent;
    let ancestry_stream = marshal.ancestor_stream(
        Arc::new(runtime_context.child("ancestor_stream")),
        [Arc::clone(&block), parent],
        ancestor_fetch_duration,
    );
    let validity_request = application
        .verify(
            (runtime_context.child("app_verify"), context.clone()),
            ancestry_stream,
        )
        .instrument(info_span!(
            "marshal.standard.application.verify",
            round = %context.round,
            digest = %block.digest(),
            parent_view = parent_view.traced(),
            parent = %parent_commitment
        ));
    // If consensus drops the receiver, we can stop work early.
    select! {
        _ = tx.closed() => {
            debug!(
                reason = "consensus dropped receiver",
                "skipping verification"
            );
            None
        },
        valid = validity_request => Some(valid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Height;
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digestible, Hasher, Sha256};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.digest.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.digest.encode_size() + self.parent.encode_size() + self.height.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let digest = Sha256Digest::read(buf)?;
            let parent = Sha256Digest::read(buf)?;
            let height = Height::read(buf)?;
            Ok(Self {
                digest,
                parent,
                height,
            })
        }
    }

    impl Digestible for TestBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl crate::Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl crate::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            self.parent
        }
    }

    fn baseline_blocks() -> (TestBlock, TestBlock) {
        let parent_digest = Sha256::hash(b"parent");
        let parent = TestBlock {
            digest: parent_digest,
            parent: Sha256::hash(b"grandparent"),
            height: Height::new(6),
        };
        let block = TestBlock {
            digest: Sha256::hash(b"block"),
            parent: parent_digest,
            height: Height::new(7),
        };
        (parent, block)
    }

    #[test]
    fn test_validate_block_ok() {
        let (parent, block) = baseline_blocks();
        assert_eq!(validate_block(&block, &parent, parent.digest()), Ok(()));
    }

    #[test]
    fn test_validate_block_parent_digest_error() {
        let (parent, mut block) = baseline_blocks();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_block(&block, &parent, parent.digest()),
            Err(Error::ParentDigest)
        );
    }

    #[test]
    fn test_validate_block_expected_parent_digest_error() {
        let (parent, block) = baseline_blocks();
        assert_eq!(
            validate_block(&block, &parent, Sha256::hash(b"wrong_expected_parent")),
            Err(Error::ExpectedParentDigest)
        );
    }

    #[test]
    fn test_validate_block_height_error() {
        let (parent, mut block) = baseline_blocks();
        block.height = Height::new(9);
        assert_eq!(
            validate_block(&block, &parent, parent.digest()),
            Err(Error::Height)
        );
    }
}
