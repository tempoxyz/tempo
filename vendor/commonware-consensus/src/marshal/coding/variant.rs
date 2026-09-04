use crate::{
    marshal::{
        ancestry::BlockProvider,
        coding::{
            shards,
            types::{coding_config_for_participants, CodedBlock, CodedBlockCfg, StoredCodedBlock},
        },
        core::{Buffer, CommitmentFallback, Mailbox, Variant},
    },
    simplex::{scheme::Scheme as SimplexScheme, types::Context},
    types::{coding::Commitment, Round},
    CertifiableBlock,
};
use commonware_codec::Read;
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{certificate::Scheme, Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{future::Future, sync::Arc};

/// The coding variant of Marshal, which uses erasure coding for block dissemination.
///
/// This variant distributes blocks as erasure-coded shards, allowing reconstruction
/// from a subset of shards. This reduces bandwidth requirements for block propagation.
#[derive(Default, Clone, Copy)]
pub struct Coding<B, C, H, P>(std::marker::PhantomData<(B, C, H, P)>)
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey;

impl<B, C, H, P> Variant for Coding<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type ApplicationBlock = B;
    type Block = CodedBlock<B, C, H>;
    type StoredBlock = StoredCodedBlock<B, C, H>;
    type Commitment = Commitment;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Commitment is deterministic from the coded block contents.
        block.commitment()
    }

    fn stored_commitment(block: &Self::StoredBlock) -> Self::Commitment {
        block.commitment()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // The inner digest is embedded in the coding commitment.
        commitment.block()
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // Parent commitment is embedded in the consensus context.
        block.context().parent.1
    }

    fn check_payload<S>(scheme: &S, payload: Self::Commitment) -> bool
    where
        S: SimplexScheme<Self::Commitment>,
    {
        let n_participants = u16::try_from(scheme.participants().len())
            .expect("scheme must have at most 2^16-1 participants");
        payload.config() == coding_config_for_participants(n_participants)
    }

    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg {
        CodedBlockCfg {
            inner: block_cfg.clone(),
            expected,
        }
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }

    fn into_inner_shared(block: Arc<Self::Block>) -> Arc<Self::ApplicationBlock> {
        block.inner_shared()
    }

    fn owned_into_inner_shared(block: Self::Block) -> Arc<Self::ApplicationBlock> {
        block.into_inner_shared()
    }

    fn from_application_block(
        block: Self::ApplicationBlock,
        payload: Self::Commitment,
    ) -> Self::Block {
        CodedBlock::new_trusted(block, payload)
    }
}

impl<B, C, H, P> Buffer<Coding<B, C, H, P>> for shards::Mailbox<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type PublicKey = P;

    async fn find_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<Arc<CodedBlock<B, C, H>>> {
        self.get_by_digest(digest).await
    }

    async fn find_by_commitment(&self, commitment: Commitment) -> Option<Arc<CodedBlock<B, C, H>>> {
        self.get(commitment).await
    }

    fn subscribe_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<Arc<CodedBlock<B, C, H>>>> {
        Some(self.subscribe_by_digest(digest))
    }

    fn subscribe_by_commitment(
        &self,
        commitment: Commitment,
    ) -> Option<oneshot::Receiver<Arc<CodedBlock<B, C, H>>>> {
        Some(self.subscribe(commitment))
    }

    fn finalized(&self, commitment: Commitment) {
        self.prune(commitment);
    }

    fn send(&self, round: Round, block: Arc<CodedBlock<B, C, H>>, _recipients: Recipients<P>) {
        // Targeted forwarding is not supported by the coding variant.
        self.proposed_shared(round, block);
    }
}

impl<S, B, C, H, P> BlockProvider for Mailbox<S, Coding<B, C, H, P>>
where
    S: Scheme,
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
        let receiver = block.height().previous().map(|parent_height| {
            self.subscribe_by_commitment(
                block.context().parent.1,
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
        });
        async move { receiver?.await.ok().map(|block| block.inner_shared()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{coding::types::StoredCodedBlock, mocks::block::Block as MockBlock},
        types::{Epoch, Height, View},
    };
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error, Read, Write};
    use commonware_coding::{Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
        Digest as _, Digestible, Signer as _,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, NZU16};

    type TestContext = Context<Commitment, PublicKey>;
    type InnerBlock = MockBlock<Sha256Digest, TestContext>;

    struct NoCloneBlock {
        inner: InnerBlock,
    }

    impl Clone for NoCloneBlock {
        fn clone(&self) -> Self {
            panic!("stored commitment lookup must not clone the inner block");
        }
    }

    impl Write for NoCloneBlock {
        fn write(&self, writer: &mut impl BufMut) {
            self.inner.write(writer);
        }
    }

    impl Read for NoCloneBlock {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
            Ok(Self {
                inner: InnerBlock::read_cfg(reader, cfg)?,
            })
        }
    }

    impl EncodeSize for NoCloneBlock {
        fn encode_size(&self) -> usize {
            self.inner.encode_size()
        }
    }

    impl Digestible for NoCloneBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.inner.digest()
        }
    }

    impl crate::Heightable for NoCloneBlock {
        fn height(&self) -> Height {
            self.inner.height
        }
    }

    impl crate::Block for NoCloneBlock {
        fn parent(&self) -> Self::Digest {
            self.inner.parent
        }
    }

    impl CertifiableBlock for NoCloneBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.inner.context.clone()
        }
    }

    fn no_clone_block(config: CodingConfig) -> NoCloneBlock {
        let mut rng = test_rng();
        let leader = PrivateKey::random(&mut rng).public_key();
        let parent_commitment = Commitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            config,
        ));
        let context = Context {
            round: Round::new(Epoch::new(1), View::new(2)),
            leader,
            parent: (View::new(1), parent_commitment),
        };
        let inner =
            InnerBlock::new::<Sha256>(context, Sha256::hash(b"parent"), Height::new(7), 1_234_567);
        NoCloneBlock { inner }
    }

    #[test]
    fn stored_commitment_does_not_clone_coding_block() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        type TestScheme = ReedSolomon<Sha256>;
        type TestVariant = Coding<NoCloneBlock, TestScheme, Sha256, PublicKey>;

        let block = no_clone_block(CONFIG);
        let coded = CodedBlock::<NoCloneBlock, TestScheme, Sha256>::new(block, CONFIG, &Sequential);
        let expected = coded.commitment();
        let stored = StoredCodedBlock::new(coded);

        assert_eq!(TestVariant::stored_commitment(&stored), expected);
    }
}
