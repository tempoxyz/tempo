//! The foundational data structure the Tempo network comes to consensus over.
//!
//! The Tempo [`Block`] contains the execution-layer block plus
//! consensus-layer validation data that is transmitted over commonware p2p.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes, keccak256};
use bytes::{Buf, BufMut};
#[cfg(feature = "bal")]
use commonware_codec::RangeCfg;
use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{
    Heightable,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Committable, Digestible, Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use reth_consensus::ConsensusError;
use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
use std::fmt::Display;
use tempo_payload_types::EncodedBlock;
use tempo_primitives::TempoConsensusContext;
use tracing::warn;

use crate::consensus::Digest;
use tempo_evm::consensus::validate_body_against_header;

/// Error returned when a BAL sidecar does not match the execution block header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum BlockAccessListError {
    /// The header commits to a BAL, but no BAL bytes were provided.
    #[error("block access list hash {expected} is present but block access list is missing")]
    Missing { expected: B256 },
    /// BAL bytes were provided for a block that does not commit to a BAL.
    #[error("block access list is present but block access list hash is missing")]
    Unexpected,
    /// The BAL bytes do not hash to the value committed in the header.
    #[error("block access list hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: B256, actual: B256 },
}

impl BlockAccessListError {
    fn codec_error(self) -> commonware_codec::Error {
        match self {
            Self::Missing { .. } => {
                commonware_codec::Error::Invalid("block access list", "missing for header hash")
            }
            Self::Unexpected => {
                commonware_codec::Error::Invalid("block access list", "present without header hash")
            }
            Self::HashMismatch { .. } => {
                commonware_codec::Error::Invalid("block access list", "hash does not match header")
            }
        }
    }
}

/// Error returned when an execution block or its consensus sidecars are invalid.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The execution block body does not match the commitments in its header.
    #[error("execution block body does not match its header")]
    Body(#[from] ConsensusError),
    /// The BAL sidecar does not match the commitment in the execution block header.
    #[error("block access list does not match its header commitment")]
    BlockAccessList(#[from] BlockAccessListError),
}

impl Error {
    fn codec_error(self) -> commonware_codec::Error {
        match self {
            Self::Body(error) => commonware_codec::Error::Wrapped(
                "validating execution block body against header",
                error.into(),
            ),
            Self::BlockAccessList(error) => error.codec_error(),
        }
    }
}

/// Consensus block shared through commonware.
///
/// This wraps the execution-layer block Tempo commits to, plus any consensus sidecars that are not
/// part of the EL block body. Locally built blocks keep recovered senders so follow-up validation
/// paths can avoid recovery work; blocks received from the network or storage may only be sealed.
///
/// The shared encoded-byte cache lets payload building, proposal broadcast, and commonware
/// `EncodeSize` reuse the same execution-block RLP bytes once any path has encoded them.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    /// The execution-layer block, either sealed-only or fully recovered when built locally.
    execution_block: SealedOrRecoveredBlock<tempo_primitives::Block>,
    /// Cached execution-layer RLP bytes when already encoded by the caller or a payload clone.
    execution_block_encoded: EncodedBlock,
    /// Optional block access list. Only provided if the network supports BALs.
    #[cfg(feature = "bal")]
    block_access_list: Option<Bytes>,
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.execution_block == other.execution_block && {
            #[cfg(feature = "bal")]
            {
                self.block_access_list == other.block_access_list
            }
            #[cfg(not(feature = "bal"))]
            {
                true
            }
        }
    }
}

impl Eq for Block {}

impl Block {
    /// Creates a block after validating its body and optional BAL against the header.
    pub(crate) fn try_from_execution_block<T>(
        execution_block: T,
        block_access_list: Option<Bytes>,
    ) -> Result<Self, Error>
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        let execution_block = execution_block.into();
        validate_body_against_header(execution_block.body(), execution_block.header())?;
        validate_block_access_list_hash(
            execution_block.block_access_list_hash(),
            block_access_list.as_ref(),
        )?;

        Ok(Self::from_execution_block_unchecked(
            execution_block,
            block_access_list,
        ))
    }

    /// Creates a validated block with a shared execution-layer RLP byte cache.
    pub(crate) fn try_from_execution_block_with_encoded_cache<T>(
        execution_block: T,
        block_access_list: Option<Bytes>,
        execution_block_encoded: EncodedBlock,
    ) -> Result<Self, Error>
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        let mut block = Self::try_from_execution_block(execution_block, block_access_list)?;
        block.execution_block_encoded = execution_block_encoded;
        Ok(block)
    }

    /// Creates a block without checking that BAL bytes match the header.
    ///
    /// This is for reconstructing blocks from persisted EL data that does not include
    /// commonware sidecars. Callers must not encode or broadcast a block whose header
    /// commits to a BAL unless the corresponding BAL bytes have been restored.
    pub(crate) fn from_execution_block_unchecked<T>(
        execution_block: T,
        block_access_list: Option<Bytes>,
    ) -> Self
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        Self::from_execution_block_unchecked_with_encoded_cache(
            execution_block,
            block_access_list,
            EncodedBlock::default(),
        )
    }

    fn from_execution_block_unchecked_with_encoded_cache<T>(
        execution_block: T,
        block_access_list: Option<Bytes>,
        execution_block_encoded: EncodedBlock,
    ) -> Self
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        #[cfg(not(feature = "bal"))]
        let _ = block_access_list;

        Self {
            execution_block: execution_block.into(),
            execution_block_encoded,
            #[cfg(feature = "bal")]
            block_access_list,
        }
    }

    /// Consumes the block and returns the wrapped execution block handle.
    pub(crate) fn into_execution_block(self) -> SealedOrRecoveredBlock<tempo_primitives::Block> {
        self.execution_block
    }

    /// Consumes the block and returns the execution-layer block handle plus optional BAL.
    pub(crate) fn into_parts(
        self,
    ) -> (
        SealedOrRecoveredBlock<tempo_primitives::Block>,
        Option<Bytes>,
    ) {
        (
            self.execution_block,
            #[cfg(feature = "bal")]
            {
                self.block_access_list
            },
            #[cfg(not(feature = "bal"))]
            {
                None
            },
        )
    }

    /// Returns the (eth) hash of the wrapped block.
    pub(crate) fn block_hash(&self) -> B256 {
        self.execution_block.hash()
    }

    /// Returns the hash of the wrapped block as a commonware [`Digest`].
    pub(crate) fn digest(&self) -> Digest {
        Digest(self.execution_block.hash())
    }

    /// Returns the parent hash of the wrapped block as a commonware [`Digest`].
    pub(crate) fn parent_digest(&self) -> Digest {
        Digest(self.execution_block.parent_hash())
    }

    /// Returns the wrapped block.
    pub(crate) fn block(&self) -> &SealedBlock<tempo_primitives::Block> {
        self.execution_block.sealed_block()
    }

    /// Returns the block access list of the wrapped block.
    pub(crate) fn block_access_list(&self) -> Option<&Bytes> {
        #[cfg(feature = "bal")]
        {
            self.block_access_list.as_ref()
        }
        #[cfg(not(feature = "bal"))]
        {
            None
        }
    }

    fn encoded_execution_block(&self) -> &Bytes {
        self.execution_block_encoded
            .get_or_encode(self.execution_block.sealed_block())
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "digest: {}, height: {}",
            self.digest(),
            self.height()
        ))
    }
}

impl std::ops::Deref for Block {
    type Target = SealedBlock<tempo_primitives::Block>;

    fn deref(&self) -> &Self::Target {
        self.execution_block.sealed_block()
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.encoded_execution_block());
        #[cfg(feature = "bal")]
        if self.execution_block.block_access_list_hash().is_some() {
            // FIXME: Blocks reconstructed from persisted EL data can carry a BAL hash
            // without the commonware BAL sidecar. Encoding one will panic here, which
            // can crash follower nodes and validators that request blocks over p2p.
            let block_access_list = self
                .block_access_list
                .as_ref()
                .expect("BAL bytes must be present when header contains a BAL hash");
            block_access_list.write(buf);
        }
    }
}

impl Read for Block {
    // TODO: Figure out what this is for/when to use it. This is () for both alto and summit.
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        // XXX: this does not advance `buf`. Also, it assumes that the rlp
        // header is fully contained in the first chunk of `buf`. As per
        // `bytes::Buf::chunk`'s documentation, the first slice should never be
        // empty is there are remaining bytes. We hence don't worry about edge
        // cases where the very tiny rlp header is spread over more than one
        // chunk.
        let header = alloy_rlp::Header::decode(&mut buf.chunk()).map_err(|rlp_err| {
            commonware_codec::Error::Wrapped("reading RLP header", rlp_err.into())
        })?;

        if header.length_with_payload() > buf.remaining() {
            // TODO: it would be nice to report more information here, but commonware_codex::Error does not
            // have the fidelity for it (outside abusing Error::Wrapped).
            return Err(commonware_codec::Error::EndOfBuffer);
        }
        let execution_block_encoded_size = header.length_with_payload();
        let bytes = buf.copy_to_bytes(execution_block_encoded_size);

        let inner = <tempo_primitives::Block as reth_primitives_traits::Block>::decode_sealed(
            &mut bytes.as_ref(),
        )
        .map_err(|rlp_err| {
            commonware_codec::Error::Wrapped("reading RLP encoded block", rlp_err.into())
        })?;

        #[cfg(feature = "bal")]
        let block_access_list = {
            if inner.block_access_list_hash().is_some() {
                let block_access_list: Bytes = bytes::Bytes::read_cfg(buf, &RangeCfg::from(..))
                    .map_err(|err| {
                        commonware_codec::Error::Wrapped("reading block access list", err.into())
                    })?
                    .into();
                Some(block_access_list)
            } else {
                None
            }
        };
        #[cfg(not(feature = "bal"))]
        let block_access_list = None;

        let execution_block_encoded = EncodedBlock::new(bytes.into());
        Self::try_from_execution_block_with_encoded_cache(
            inner,
            block_access_list,
            execution_block_encoded,
        )
        .map_err(|err| err.codec_error())
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        let execution_block_size = self.encoded_execution_block().len();

        #[cfg(feature = "bal")]
        {
            execution_block_size
                + if self.execution_block.block_access_list_hash().is_some() {
                    self.block_access_list
                        .as_ref()
                        .expect("BAL bytes must be present when header contains a BAL hash")
                        .encode_size()
                } else {
                    0
                }
        }
        #[cfg(not(feature = "bal"))]
        {
            execution_block_size
        }
    }
}

impl Committable for Block {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        self.digest()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        self.digest()
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        Height::new(self.execution_block.number())
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent_digest()
    }
}

impl commonware_consensus::CertifiableBlock for Block {
    type Context = Context<Digest, PublicKey>;

    fn context(&self) -> Self::Context {
        match self.consensus_context {
            Some(ctx) => Context {
                leader: ctx.proposer.to_inner(),
                round: round_from_context(ctx),
                parent: (View::new(ctx.parent_view), self.parent_digest()),
            },
            None => {
                // Returns a deterministic sentinel `Context`.
                //
                // All consensus-produced blocks must carry a `consensus_context`, so
                // reaching this branch indicates a malformed block. The sentinel
                // intentionally does not match any real consensus values, so it will
                // fail verification rather than panic.
                warn!(
                    "context request for block `{}` with no consensus context",
                    self.digest()
                );

                let leader = PublicKey::from(PrivateKey::from_seed(0));
                Context {
                    leader,
                    round: Round::new(Epoch::new(0), View::new(0)),
                    parent: (View::new(0), Digest(B256::ZERO)),
                }
            }
        }
    }
}

pub(crate) fn round_from_context(context: TempoConsensusContext) -> Round {
    Round::new(Epoch::new(context.epoch), View::new(context.view))
}

fn validate_block_access_list_hash(
    expected: Option<B256>,
    block_access_list: Option<&Bytes>,
) -> Result<(), BlockAccessListError> {
    match (expected, block_access_list) {
        (Some(expected), Some(block_access_list)) => {
            let actual = keccak256(block_access_list.as_ref());
            if actual == expected {
                Ok(())
            } else {
                Err(BlockAccessListError::HashMismatch { expected, actual })
            }
        }
        (Some(expected), None) => Err(BlockAccessListError::Missing { expected }),
        (None, Some(_)) => Err(BlockAccessListError::Unexpected),
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "bal")]
    use alloy_consensus::BlockHeader as _;
    use alloy_consensus::{BlockBody, EMPTY_ROOT_HASH};
    use alloy_primitives::{B256, bytes, keccak256};
    #[cfg(not(feature = "bal"))]
    use commonware_codec::Write as _;
    use commonware_codec::{Encode, Read as _};
    use reth_node_core::primitives::SealedBlock;
    use tempo_primitives::{Block as TempoBlock, TempoHeader};

    #[cfg(feature = "bal")]
    use super::BlockAccessListError;
    use super::{Block, Error};

    fn execution_block_with_block_access_list_hash(
        block_access_list_hash: B256,
    ) -> SealedBlock<TempoBlock> {
        SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    base_fee_per_gas: Some(0),
                    withdrawals_root: Some(EMPTY_ROOT_HASH),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    block_access_list_hash: Some(block_access_list_hash),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        })
    }

    // required unit tests:
    //
    // 1. roundtrip block write -> read -> equality
    // 2. encode size for block.
    // 3. roundtrip notarized write -> read -> equality
    // 4. encode size for notarized
    // 5. roundtrip finalized write -> read -> equality
    // 6. encode size for finalized
    //
    //
    // desirable snapshot tests:
    //
    // 1. block write -> stable hex or rlp representation
    // 2. block digest -> stable hex
    // 3. notarized write -> stable hex (necessary? good to guard against commonware xyz changes?)
    // 4. finalized write -> stable hex (necessary? good to guard against commonware xyz changes?)

    #[test]
    fn reads_block_without_block_access_list_bytes() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    number: 42,
                    gas_limit: 30_000_000,
                    timestamp: 1_700_000_000,
                    base_fee_per_gas: Some(1_000_000_000),
                    withdrawals_root: Some(EMPTY_ROOT_HASH),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        });
        let expected = Block::try_from_execution_block(execution_block.clone(), None)
            .expect("block has no BAL side data");
        let mut block_bytes = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut block_bytes);

        let decoded = Block::read_cfg(&mut block_bytes.as_ref(), &()).unwrap();
        assert_eq!(decoded, expected);
        assert!(decoded.block_access_list().is_none());

        let encoded = decoded.encode();

        assert_eq!(encoded.as_ref(), block_bytes.as_slice());
    }

    #[test]
    fn read_rejects_execution_body_that_does_not_match_header() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    base_fee_per_gas: Some(0),
                    withdrawals_root: Some(B256::ZERO),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        });
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut encoded);

        let err = Block::read_cfg(&mut encoded.as_slice(), &()).unwrap_err();

        assert!(
            matches!(
                err,
                commonware_codec::Error::Wrapped(
                    "validating execution block body against header",
                    _
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn constructor_rejects_execution_body_that_does_not_match_header() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    withdrawals_root: Some(B256::ZERO),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        });

        let err = Block::try_from_execution_block(execution_block, None).unwrap_err();

        assert!(matches!(err, Error::Body(_)));
    }

    #[cfg(not(feature = "bal"))]
    #[test]
    fn read_rejects_block_access_list_hash_when_bal_feature_disabled() {
        let block_access_list = bytes!("0xc0");
        let execution_block =
            execution_block_with_block_access_list_hash(keccak256(block_access_list.as_ref()));
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut encoded);
        block_access_list.write(&mut encoded);

        let err = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap_err();

        assert!(matches!(
            err,
            commonware_codec::Error::Invalid("block access list", "missing for header hash")
        ));
    }

    #[cfg(feature = "bal")]
    #[test]
    fn rejects_block_access_list_without_header_hash() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader::default(),
            body: Default::default(),
        });
        assert!(execution_block.block_access_list_hash().is_none());

        let block_access_list = bytes!("0xc0");
        let err =
            Block::try_from_execution_block(execution_block, Some(block_access_list)).unwrap_err();

        assert!(matches!(
            err,
            Error::BlockAccessList(BlockAccessListError::Unexpected)
        ));
    }

    #[cfg(feature = "bal")]
    #[test]
    fn rejects_missing_block_access_list_with_header_hash() {
        let execution_block = execution_block_with_block_access_list_hash(B256::ZERO);
        let err = Block::try_from_execution_block(execution_block, None).unwrap_err();

        assert!(matches!(
            err,
            Error::BlockAccessList(BlockAccessListError::Missing {
                expected: B256::ZERO
            })
        ));
    }

    #[cfg(feature = "bal")]
    #[test]
    fn reads_wraps_missing_block_access_list_error() {
        let execution_block = execution_block_with_block_access_list_hash(B256::ZERO);
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut encoded);

        let err = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap_err();

        assert!(matches!(
            err,
            commonware_codec::Error::Wrapped("reading block access list", _)
        ));
    }

    #[cfg(feature = "bal")]
    #[test]
    fn roundtrips_block_access_list_with_matching_header_hash() {
        let block_access_list = bytes!("0xc0");
        let execution_block =
            execution_block_with_block_access_list_hash(keccak256(block_access_list.as_ref()));
        let block =
            Block::try_from_execution_block(execution_block, Some(block_access_list.clone()))
                .unwrap();

        let encoded = block.encode();
        let decoded = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap();

        assert_eq!(decoded, block);
        assert_eq!(
            decoded.block_access_list().map(|bytes| bytes.as_ref()),
            Some(block_access_list.as_ref())
        );
    }

    #[cfg(feature = "bal")]
    #[test]
    fn rejects_block_access_list_with_mismatched_header_hash() {
        let block_access_list = bytes!("0xc0");
        let execution_block = execution_block_with_block_access_list_hash(B256::ZERO);
        let err =
            Block::try_from_execution_block(execution_block, Some(block_access_list)).unwrap_err();

        assert!(matches!(
            err,
            Error::BlockAccessList(BlockAccessListError::HashMismatch {
                expected: B256::ZERO,
                actual,
            }) if actual == keccak256(bytes!("0xc0").as_ref())
        ));
    }

    #[cfg(feature = "bal")]
    #[test]
    fn reads_reject_block_access_list_with_mismatched_header_hash() {
        let block_access_list = bytes!("0xc0");
        let execution_block = execution_block_with_block_access_list_hash(B256::ZERO);
        let block = Block::from_execution_block_unchecked(execution_block, Some(block_access_list));
        let encoded = block.encode();
        let err = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap_err();

        assert!(matches!(
            err,
            commonware_codec::Error::Invalid("block access list", "hash does not match header")
        ));
    }
}
