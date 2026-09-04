//! Coding-specific validation helpers for marshal verification and reconstruction.
//!
//! This module contains pure invariant checks for coding-mode proposal verification,
//! block verification, and reconstruction.

use crate::{
    marshal::{
        application::validation::{has_contiguous_height, is_block_in_expected_epoch},
        coding::types::hash_context,
    },
    types::{coding::Commitment, Epocher},
    CertifiableBlock, Epochable,
};
use commonware_codec::{EncodeSize, Write};
use commonware_coding::Config as CodingConfig;
use commonware_cryptography::{Committable, Digest, Hasher};

/// Validation failures for coding proposal verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalError {
    CodingConfig,
    ContextDigest,
}

/// Validation failures for coding block verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockError {
    Commitment,
    ParentCommitment,
    Epoch,
    ParentDigest,
    Height,
    ContextDigest,
    Context,
}

/// Validation failures for coded block reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconstructionError<D: Digest> {
    BlockDigest,
    CodingConfig,
    ContextDigest(D, D),
}

/// Consolidated validation for coding proposal checks.
///
/// If `context` is `None`, only coding-config validation is applied.
pub(crate) fn validate_proposal<H: Hasher, C: EncodeSize + Write>(
    payload: Commitment,
    expected_config: CodingConfig,
    context: Option<&C>,
) -> Result<(), ProposalError> {
    if payload.config() != expected_config {
        return Err(ProposalError::CodingConfig);
    }
    if let Some(context) = context {
        if payload.context::<H::Digest>() != hash_context::<H, _>(context) {
            return Err(ProposalError::ContextDigest);
        }
    }
    Ok(())
}

/// Consolidated validation for coding block verification.
pub(crate) fn validate_block<H, ES, B>(
    epocher: &ES,
    block: &B,
    parent: &B,
    context: &B::Context,
    commitment: Commitment,
    parent_commitment: Commitment,
) -> Result<(), BlockError>
where
    H: Hasher,
    ES: Epocher,
    B: CertifiableBlock + Committable<Commitment = Commitment>,
    B::Context: Epochable + EncodeSize + Write + PartialEq,
{
    if block.commitment() != commitment {
        return Err(BlockError::Commitment);
    }
    if parent.commitment() != parent_commitment {
        return Err(BlockError::ParentCommitment);
    }
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        return Err(BlockError::Epoch);
    }
    if block.parent() != parent.digest() {
        return Err(BlockError::ParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(BlockError::Height);
    }
    let block_context = block.context();
    if commitment.context::<H::Digest>() != hash_context::<H, _>(&block_context) {
        return Err(BlockError::ContextDigest);
    }
    if block_context != *context {
        return Err(BlockError::Context);
    }
    Ok(())
}

/// Consolidated validation for reconstructed coded blocks.
pub(crate) fn validate_reconstruction<H, B>(
    block: &B,
    config: CodingConfig,
    commitment: Commitment,
) -> Result<(), ReconstructionError<H::Digest>>
where
    H: Hasher,
    B: CertifiableBlock,
    B::Context: EncodeSize + Write,
{
    if block.digest() != commitment.block() {
        return Err(ReconstructionError::BlockDigest);
    }
    if config != commitment.config() {
        return Err(ReconstructionError::CodingConfig);
    }
    let commitment_context = commitment.context::<H::Digest>();
    let block_context = hash_context::<H, _>(&block.context());
    if commitment_context != block_context {
        return Err(ReconstructionError::ContextDigest(
            commitment_context,
            block_context,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::coding::types::coding_config_for_participants,
        types::{Epoch, FixedEpocher, Height, Round, View},
    };
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{
        sha256::Digest as Sha256Digest, Committable, Digestible, Hasher, Sha256,
    };
    use commonware_utils::NZU64;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
        context: Round,
        commitment: Commitment,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.digest.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.context.write(buf);
            self.commitment.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.digest.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.context.encode_size()
                + self.commitment.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let digest = Sha256Digest::read(buf)?;
            let parent = Sha256Digest::read(buf)?;
            let height = Height::read(buf)?;
            let context = Round::read(buf)?;
            let commitment = Commitment::read(buf)?;
            Ok(Self {
                digest,
                parent,
                height,
                context,
                commitment,
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

    impl crate::CertifiableBlock for TestBlock {
        type Context = Round;

        fn context(&self) -> Self::Context {
            self.context
        }
    }

    impl Committable for TestBlock {
        type Commitment = Commitment;

        fn commitment(&self) -> Self::Commitment {
            self.commitment
        }
    }

    struct Fixture {
        epocher: FixedEpocher,
        block: TestBlock,
        parent: TestBlock,
        context: Round,
        commitment: Commitment,
        parent_commitment: Commitment,
        config: CodingConfig,
    }

    fn commitment_for(
        digest: Sha256Digest,
        context: Round,
        config: CodingConfig,
        root_label: &[u8],
    ) -> Commitment {
        Commitment::from((
            digest,
            Sha256::hash(root_label),
            hash_context::<Sha256, _>(&context),
            config,
        ))
    }

    fn baseline_fixture() -> Fixture {
        let config = coding_config_for_participants(4);
        let epocher = FixedEpocher::new(NZU64!(10));

        let parent_context = Round::new(Epoch::new(0), View::new(6));
        let context = Round::new(Epoch::new(0), View::new(7));

        let parent_digest = Sha256::hash(b"parent");
        let digest = Sha256::hash(b"block");

        let parent_commitment =
            commitment_for(parent_digest, parent_context, config, b"parent_root");
        let commitment = commitment_for(digest, context, config, b"block_root");

        let parent = TestBlock {
            digest: parent_digest,
            parent: Sha256::hash(b"grandparent"),
            height: Height::new(6),
            context: parent_context,
            commitment: parent_commitment,
        };
        let block = TestBlock {
            digest,
            parent: parent_digest,
            height: Height::new(7),
            context,
            commitment,
        };

        Fixture {
            epocher,
            block,
            parent,
            context,
            commitment,
            parent_commitment,
            config,
        }
    }

    #[test]
    fn test_validate_block_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_proposal_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_proposal::<Sha256, _>(
                fixture.commitment,
                fixture.config,
                Some(&fixture.context)
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_reconstruction_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_reconstruction::<Sha256, _>(
                &fixture.block,
                fixture.config,
                fixture.commitment
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_block_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_block"),
            fixture.context,
            fixture.config,
            b"other_root",
        );
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                wrong,
                fixture.parent_commitment,
            ),
            Err(BlockError::Commitment)
        );
    }

    #[test]
    fn test_validate_block_parent_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_parent"),
            fixture.parent.context,
            fixture.config,
            b"other_parent_root",
        );
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                wrong,
            ),
            Err(BlockError::ParentCommitment)
        );
    }

    #[test]
    fn test_validate_block_epoch_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(1), View::new(7));
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Epoch)
        );
    }

    #[test]
    fn test_validate_block_parent_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_block_height_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.height = Height::new(9);
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Height)
        );
    }

    #[test]
    fn test_validate_block_context_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        let wrong_context = Round::new(Epoch::new(0), View::new(9));
        let wrong_commitment =
            commitment_for(block.digest(), wrong_context, fixture.config, b"block_root");
        block.commitment = wrong_commitment;
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                wrong_commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::ContextDigest)
        );
    }

    #[test]
    fn test_validate_block_context_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_block::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Context)
        );
    }

    #[test]
    fn test_validate_proposal_coding_config_error() {
        let fixture = baseline_fixture();
        let wrong = coding_config_for_participants(7);
        assert_eq!(
            validate_proposal::<Sha256, _>(fixture.commitment, wrong, Some(&fixture.context)),
            Err(ProposalError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_proposal_context_digest_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_proposal::<Sha256, _>(
                fixture.commitment,
                fixture.config,
                Some(&wrong_context)
            ),
            Err(ProposalError::ContextDigest)
        );
    }

    #[test]
    fn test_validate_proposal_none_context_skips_context_digest_check() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        let payload_with_wrong_context = commitment_for(
            fixture.block.digest(),
            wrong_context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_proposal::<Sha256, Round>(payload_with_wrong_context, fixture.config, None),
            Ok(())
        );
    }

    #[test]
    fn test_validate_proposal_none_context_still_enforces_coding_config() {
        let fixture = baseline_fixture();
        let wrong = coding_config_for_participants(7);
        assert_eq!(
            validate_proposal::<Sha256, Round>(fixture.commitment, wrong, None),
            Err(ProposalError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_reconstruction_block_digest_error() {
        let fixture = baseline_fixture();
        let wrong_commitment = commitment_for(
            Sha256::hash(b"wrong_block_digest"),
            fixture.context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionError::BlockDigest)
        );
    }

    #[test]
    fn test_validate_reconstruction_coding_config_error() {
        let fixture = baseline_fixture();
        let wrong_config = coding_config_for_participants(7);
        let wrong_commitment = commitment_for(
            fixture.block.digest(),
            fixture.context,
            wrong_config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_reconstruction_context_digest_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        let wrong_commitment = commitment_for(
            fixture.block.digest(),
            wrong_context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionError::ContextDigest(
                wrong_commitment.context(),
                hash_context::<Sha256, _>(&fixture.block.context),
            ))
        );
    }
}
