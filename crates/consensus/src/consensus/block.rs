//! The foundational data structure the Tempo network comes to consensus over.
//!
//! The Tempo [`Block`] contains the execution-layer block plus
//! consensus-layer validation data that is transmitted over commonware p2p.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes};
use bytes::{Buf, BufMut};
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

/// Error returned for unsupported BAL headers or sidecars.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum BlockAccessListError {
    /// BALs cannot represent configurable account extensions.
    #[error("block access lists are unsupported with configurable account extensions")]
    Unsupported,
}

impl BlockAccessListError {
    fn codec_error(self) -> commonware_codec::Error {
        commonware_codec::Error::Invalid("block access list", "unsupported with account extensions")
    }
}

/// Error returned when an execution block or its consensus sidecars are invalid.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The execution block body does not match the commitments in its header.
    #[error("execution block body does not match its header")]
    Body(#[from] ConsensusError),
    /// A BAL header or sidecar was supplied to this extension-enabled build.
    #[error("unsupported block access list")]
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
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.execution_block == other.execution_block
    }
}

impl Eq for Block {}

impl Block {
    /// Creates a block after validating its body and rejecting BAL headers or sidecars.
    pub(crate) fn try_from_execution_block<T>(
        execution_block: T,
        block_access_list: Option<Bytes>,
    ) -> Result<Self, Error>
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        let execution_block = execution_block.into();
        validate_body_against_header(execution_block.body(), execution_block.header())?;
        reject_block_access_list(
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

    /// Creates a block without validating its header or sidecars.
    ///
    /// This is for reconstructing blocks from persisted EL data that does not include
    /// commonware sidecars. Callers must only use execution blocks already validated for
    /// this no-BAL build; this constructor does not enforce that precondition.
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
        let _ = block_access_list;

        Self {
            execution_block: execution_block.into(),
            execution_block_encoded,
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
        (self.execution_block, None)
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
        None
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
        self.encoded_execution_block().len()
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

fn reject_block_access_list(
    expected: Option<B256>,
    block_access_list: Option<&Bytes>,
) -> Result<(), BlockAccessListError> {
    if expected.is_some() || block_access_list.is_some() {
        Err(BlockAccessListError::Unsupported)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{BlockBody, EMPTY_ROOT_HASH};
    use alloy_primitives::{B256, bytes, keccak256};
    use commonware_codec::{Encode, Read as _, Write as _};
    use reth_node_core::primitives::SealedBlock;
    use tempo_primitives::{Block as TempoBlock, TempoHeader};

    use super::{Block, BlockAccessListError, Error};

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

    #[test]
    fn read_rejects_block_access_list_hash() {
        let block_access_list = bytes!("0xc0");
        let execution_block =
            execution_block_with_block_access_list_hash(keccak256(block_access_list.as_ref()));
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut encoded);
        block_access_list.write(&mut encoded);

        let err = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap_err();
        assert!(matches!(
            err,
            commonware_codec::Error::Invalid(
                "block access list",
                "unsupported with account extensions"
            )
        ));
    }

    #[test]
    fn constructor_rejects_any_block_access_list_input() {
        let sidecar = bytes!("0xc0");
        for (hash, sidecar) in [
            (None, Some(sidecar.clone())),
            (Some(B256::ZERO), None),
            (Some(B256::ZERO), Some(sidecar.clone())),
            (Some(keccak256(sidecar.as_ref())), Some(sidecar)),
        ] {
            let execution_block = if let Some(hash) = hash {
                execution_block_with_block_access_list_hash(hash)
            } else {
                SealedBlock::seal_slow(TempoBlock::default())
            };
            let err = Block::try_from_execution_block(execution_block, sidecar).unwrap_err();
            assert!(matches!(
                err,
                Error::BlockAccessList(BlockAccessListError::Unsupported)
            ));
        }
    }
}
