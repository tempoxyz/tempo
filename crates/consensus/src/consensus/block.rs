//! The foundational data structure the Tempo network comes to consensus over.
//!
//! The Tempo [`Block`] wraps the execution-layer block transmitted over commonware p2p.

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
    Committable, Digested, Digestible, Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use reth_consensus::ConsensusError;
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
use std::fmt::Display;
use tempo_payload_types::EncodedBlock;
use tempo_primitives::TempoConsensusContext;
use tracing::warn;

use crate::consensus::Digest;
use tempo_evm::consensus::{
    MAX_BLOCK_TRANSACTIONS, TempoConsensusError, validate_body_against_header,
};

/// Consensus block shared through commonware.
///
/// This wraps the execution-layer block Tempo commits to.
/// Locally built blocks keep recovered senders so follow-up validation
/// paths can avoid recovery work; blocks received from the network or storage may only be sealed.
///
/// The shared encoded-byte cache lets payload building, proposal broadcast, and commonware
/// `EncodeSize` reuse the same execution-block RLP bytes once any path has encoded them.
#[derive(Clone, Debug, derive_more::PartialEq, derive_more::Eq)]
pub(crate) struct Block {
    /// The execution-layer block, either sealed-only or fully recovered when built locally.
    execution_block: SealedOrRecoveredBlock<tempo_primitives::Block>,
    /// Cached execution-layer RLP bytes when already encoded by the caller or a payload clone.
    #[eq(skip)]
    execution_block_encoded: EncodedBlock,
}

impl Block {
    /// Creates a block after validating its body, rejecting BAL header commitments, and rejecting
    /// blocks with more than [`MAX_BLOCK_TRANSACTIONS`] transactions or whose RLP encoding exceeds
    /// [`MAX_RLP_BLOCK_SIZE`].
    pub(crate) fn try_from_execution_block<T>(execution_block: T) -> Result<Self, Error>
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        Self::try_from_execution_block_with_encoded_cache(execution_block, EncodedBlock::default())
    }

    /// Creates a validated block with a shared execution-layer RLP byte cache, encoding the block
    /// into the cache if it is empty.
    pub(crate) fn try_from_execution_block_with_encoded_cache<T>(
        execution_block: T,
        execution_block_encoded: EncodedBlock,
    ) -> Result<Self, Error>
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        let execution_block = execution_block.into();
        validate_body_against_header(execution_block.body(), execution_block.header())?;
        let transaction_count = execution_block.body().transactions.len();
        if transaction_count > MAX_BLOCK_TRANSACTIONS {
            return Err(
                ConsensusError::from(TempoConsensusError::TooManyTransactions {
                    count: transaction_count,
                    max: MAX_BLOCK_TRANSACTIONS,
                })
                .into(),
            );
        }
        if execution_block.block_access_list_hash().is_some() {
            return Err(ConsensusError::BlockAccessListHashUnexpected.into());
        }

        let block = Self::from_execution_block_unchecked_with_encoded_cache(
            execution_block,
            execution_block_encoded,
        );
        let rlp_length = block.encoded_execution_block().len();
        if rlp_length > MAX_RLP_BLOCK_SIZE {
            return Err(ConsensusError::BlockTooLarge {
                rlp_length,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }
            .into());
        }
        Ok(block)
    }

    /// Creates a block without validating its body, rejecting BAL header commitments, or enforcing
    /// [`MAX_RLP_BLOCK_SIZE`], which [`commonware_consensus::BoundedBlock`] promises.
    ///
    /// This is for reconstructing trusted blocks from persisted execution-layer data.
    /// Callers must not encode or broadcast a block whose header commits to a BAL.
    pub(crate) fn from_execution_block_unchecked<T>(execution_block: T) -> Self
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        Self::from_execution_block_unchecked_with_encoded_cache(
            execution_block,
            EncodedBlock::default(),
        )
    }

    /// Wraps a trusted execution block and its encoded bytes without validating body or header
    /// commitments. Network and archive reads must use the validating constructor instead.
    pub(crate) fn from_execution_block_unchecked_with_encoded_cache<T>(
        execution_block: T,
        execution_block_encoded: EncodedBlock,
    ) -> Self
    where
        T: Into<SealedOrRecoveredBlock<tempo_primitives::Block>>,
    {
        Self {
            execution_block: execution_block.into(),
            execution_block_encoded,
        }
    }

    /// Returns a shared handle to the wrapped execution block.
    pub(crate) fn execution_block(&self) -> SealedOrRecoveredBlock<tempo_primitives::Block> {
        self.execution_block.clone()
    }

    /// Consumes the block and returns the wrapped execution block handle.
    #[cfg(test)]
    pub(crate) fn into_execution_block(self) -> SealedOrRecoveredBlock<tempo_primitives::Block> {
        self.execution_block
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

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
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

        // Count transactions before decoding them, since decoding expands small transactions about
        // a hundredfold. The walk follows `Decodable2718::network_decode`, which reads a legacy
        // transaction as an RLP list and a typed one as a type byte and an RLP list, either bare or
        // wrapped in an RLP string.
        let rlp_error = |rlp_err: alloy_rlp::Error| {
            commonware_codec::Error::Wrapped("reading RLP transaction list", rlp_err.into())
        };
        let mut block = bytes.as_ref();
        let mut fields = alloy_rlp::Header::decode_bytes(&mut block, true).map_err(rlp_error)?;
        alloy_rlp::Header::decode_bytes(&mut fields, true).map_err(rlp_error)?;
        let mut transactions =
            alloy_rlp::Header::decode_bytes(&mut fields, true).map_err(rlp_error)?;
        let mut transaction_count = 0;
        while !transactions.is_empty() {
            transaction_count += 1;
            if transaction_count > MAX_BLOCK_TRANSACTIONS {
                return Err(commonware_codec::Error::Invalid(
                    "Block",
                    "more transactions than MAX_BLOCK_TRANSACTIONS",
                ));
            }
            let mut item = transactions;
            let header = alloy_rlp::Header::decode(&mut item).map_err(rlp_error)?;
            if header.list {
                transactions = &item[header.payload_length..];
            } else if item.len() == transactions.len() {
                // A bare type byte, which `Header::decode` reads as a one-byte string without
                // advancing, followed by the transaction's RLP list.
                transactions = &item[1..];
                alloy_rlp::Header::decode_bytes(&mut transactions, true).map_err(rlp_error)?;
            } else {
                // `Header::decode` checked that the payload fits in `item`.
                let (envelope, rest) = item.split_at(header.payload_length);
                // `network_decode` would decode envelopes trailing the first one in the string as
                // further transactions, so the string must hold exactly one.
                let mut body = envelope
                    .get(1..)
                    .ok_or_else(|| rlp_error(alloy_rlp::Error::InputTooShort))?;
                alloy_rlp::Header::decode_bytes(&mut body, true).map_err(rlp_error)?;
                if !body.is_empty() {
                    return Err(rlp_error(alloy_rlp::Error::UnexpectedLength));
                }
                transactions = rest;
            }
        }

        let inner = <tempo_primitives::Block as reth_primitives_traits::Block>::decode_sealed(
            &mut bytes.as_ref(),
        )
        .map_err(|rlp_err| {
            commonware_codec::Error::Wrapped("reading RLP encoded block", rlp_err.into())
        })?;

        let execution_block_encoded = EncodedBlock::new(bytes.into());
        Self::try_from_execution_block_with_encoded_cache(inner, execution_block_encoded).map_err(
            |error| commonware_codec::Error::Wrapped("validating execution block", error.into()),
        )
    }
}

impl commonware_consensus::BoundedBlock for Block {
    fn max_encode_size(_cfg: &Self::Cfg) -> usize {
        MAX_RLP_BLOCK_SIZE
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

/// The block's digest is its sealed hash, so wrapping it computes nothing.
impl From<Block> for Digested<Block> {
    fn from(block: Block) -> Self {
        let digest = block.digest();
        Self::precomputed(block, digest)
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

/// Error returned when validating an execution-layer consensus block.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct Error(#[from] ConsensusError);

#[cfg(test)]
mod tests {
    use alloy_consensus::{
        BlockBody, EMPTY_ROOT_HASH, SignableTransaction as _, TxEip1559, TxLegacy,
        proofs::calculate_transaction_root,
    };
    use alloy_primitives::{B256, Signature, bytes, keccak256};
    use commonware_codec::Encode;
    use reth_node_core::primitives::SealedBlock;
    use tempo_primitives::{Block as TempoBlock, TempoHeader, TempoTxEnvelope};

    use super::*;

    /// Encodes a block with valid roots carrying `transactions`.
    fn encoded_block_with_transactions(transactions: Vec<TempoTxEnvelope>) -> Vec<u8> {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    transactions_root: calculate_transaction_root(&transactions),
                    base_fee_per_gas: Some(0),
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
                transactions,
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        });
        alloy_rlp::encode(&execution_block)
    }

    /// Encodes a block with valid roots carrying `count` copies of a small legacy transaction.
    fn encoded_block_with_legacy_transactions(count: usize) -> Vec<u8> {
        let transaction =
            TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::test_signature()));
        encoded_block_with_transactions(vec![transaction; count])
    }

    fn eip1559_transaction() -> TempoTxEnvelope {
        TempoTxEnvelope::Eip1559(TxEip1559::default().into_signed(Signature::test_signature()))
    }

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
        let expected = Block::try_from_execution_block(execution_block.clone())
            .expect("test block should be valid");
        let block_bytes = alloy_rlp::encode(&execution_block);

        let decoded =
            Block::read_cfg(&mut commonware_codec::Copying(block_bytes.as_ref()), &()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode_size(), block_bytes.len());

        let encoded = decoded.encode();

        assert_eq!(encoded.as_ref(), block_bytes.as_slice());
    }

    #[test]
    fn reads_block_with_max_block_transactions() {
        let encoded = encoded_block_with_legacy_transactions(MAX_BLOCK_TRANSACTIONS);

        let decoded =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap();

        assert_eq!(decoded.body().transactions.len(), MAX_BLOCK_TRANSACTIONS);
    }

    #[test]
    fn read_rejects_block_with_more_than_max_block_transactions() {
        let encoded = encoded_block_with_legacy_transactions(MAX_BLOCK_TRANSACTIONS + 1);

        let err =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap_err();

        assert!(
            matches!(
                err,
                commonware_codec::Error::Invalid(
                    "Block",
                    "more transactions than MAX_BLOCK_TRANSACTIONS"
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn read_rejects_malformed_transaction_list() {
        let mut encoded = encoded_block_with_legacy_transactions(0);
        // The block ends with its empty transaction, ommer and withdrawal lists. Turning the
        // transaction list into an empty string keeps every length valid.
        let transactions_at = encoded.len() - 3;
        assert_eq!(encoded[transactions_at..], [alloy_rlp::EMPTY_LIST_CODE; 3]);
        encoded[transactions_at] = alloy_rlp::EMPTY_STRING_CODE;

        let err =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap_err();

        assert!(
            matches!(
                err,
                commonware_codec::Error::Wrapped("reading RLP transaction list", _)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn constructor_rejects_block_with_more_than_max_block_transactions() {
        let transaction =
            TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::test_signature()));
        let transactions = vec![transaction; MAX_BLOCK_TRANSACTIONS + 1];
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    transactions_root: calculate_transaction_root(&transactions),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                transactions,
                ..Default::default()
            },
        });

        let err = Block::try_from_execution_block(execution_block).unwrap_err();

        assert!(
            matches!(
                err.0.downcast_other_ref::<TempoConsensusError>(),
                Some(TempoConsensusError::TooManyTransactions {
                    count,
                    max: MAX_BLOCK_TRANSACTIONS,
                }) if *count == MAX_BLOCK_TRANSACTIONS + 1
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn reads_block_with_typed_transactions() {
        let transactions = vec![eip1559_transaction(), eip1559_transaction()];
        let encoded = encoded_block_with_transactions(transactions.clone());

        let decoded =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap();

        assert_eq!(decoded.body().transactions, transactions);
    }

    /// Encodes a block whose transaction list holds `transactions` as raw bytes, with its
    /// transactions root over `transaction_root_of`.
    fn encoded_block_with_raw_transaction_list(
        transactions: &[u8],
        transaction_root_of: &[TempoTxEnvelope],
    ) -> Vec<u8> {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    transactions_root: calculate_transaction_root(transaction_root_of),
                    base_fee_per_gas: Some(0),
                    withdrawals_root: Some(EMPTY_ROOT_HASH),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody::default(),
        });
        let mut fields = alloy_rlp::encode(execution_block.header());
        alloy_rlp::Header {
            list: true,
            payload_length: transactions.len(),
        }
        .encode(&mut fields);
        fields.extend_from_slice(transactions);
        fields.extend_from_slice(&[alloy_rlp::EMPTY_LIST_CODE; 2]);
        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: fields.len(),
        }
        .encode(&mut encoded);
        encoded.extend_from_slice(&fields);
        encoded
    }

    /// Returns the EIP-2718 envelope of a small EIP-1559 transaction: its type byte and RLP list.
    fn eip1559_envelope() -> Vec<u8> {
        let network_encoded = alloy_rlp::encode(eip1559_transaction());
        alloy_rlp::Header::decode_bytes(&mut network_encoded.as_slice(), false)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn reads_block_with_bare_typed_envelope() {
        let encoded =
            encoded_block_with_raw_transaction_list(&eip1559_envelope(), &[eip1559_transaction()]);

        let decoded =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap();

        assert_eq!(decoded.body().transactions, vec![eip1559_transaction()]);
    }

    #[test]
    fn read_rejects_typed_envelopes_packed_into_one_string() {
        let envelope = eip1559_envelope();
        let mut packed = Vec::new();
        alloy_rlp::Header {
            list: false,
            payload_length: 2 * envelope.len(),
        }
        .encode(&mut packed);
        packed.extend_from_slice(&envelope);
        packed.extend_from_slice(&envelope);
        let encoded = encoded_block_with_raw_transaction_list(
            &packed,
            &[eip1559_transaction(), eip1559_transaction()],
        );

        let err =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap_err();

        let commonware_codec::Error::Wrapped("reading RLP transaction list", error) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(matches!(
            error.downcast_ref::<alloy_rlp::Error>(),
            Some(alloy_rlp::Error::UnexpectedLength)
        ));
    }

    #[test]
    fn constructor_rejects_block_larger_than_max_rlp_block_size() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    base_fee_per_gas: Some(0),
                    withdrawals_root: Some(EMPTY_ROOT_HASH),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    extra_data: vec![0; MAX_RLP_BLOCK_SIZE].into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                withdrawals: Some(Default::default()),
                ..Default::default()
            },
        });

        let err = Block::try_from_execution_block(execution_block).unwrap_err();

        assert!(
            matches!(
                err.0,
                ConsensusError::BlockTooLarge {
                    max_rlp_length: MAX_RLP_BLOCK_SIZE,
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
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
        let encoded = alloy_rlp::encode(&execution_block);

        let err =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_slice()), &()).unwrap_err();

        assert!(
            matches!(
                err,
                commonware_codec::Error::Wrapped("validating execution block", _)
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

        let err = Block::try_from_execution_block(execution_block).unwrap_err();

        assert!(matches!(
            err,
            Error(ConsensusError::BodyWithdrawalsRootDiff(_))
        ));
    }

    #[test]
    fn read_rejects_block_access_list_hash() {
        let block_access_list = bytes!("0xc0");
        let execution_block =
            execution_block_with_block_access_list_hash(keccak256(block_access_list.as_ref()));
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&execution_block, &mut encoded);
        block_access_list.write(&mut encoded);

        let err =
            Block::read_cfg(&mut commonware_codec::Copying(encoded.as_ref()), &()).unwrap_err();

        let commonware_codec::Error::Wrapped("validating execution block", error) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error(ConsensusError::BlockAccessListHashUnexpected))
        ));
    }

    #[test]
    fn constructor_rejects_block_access_list_hash() {
        let execution_block = execution_block_with_block_access_list_hash(B256::ZERO);
        let err = Block::try_from_execution_block(execution_block).unwrap_err();

        assert!(matches!(
            err,
            Error(ConsensusError::BlockAccessListHashUnexpected)
        ));
    }

    #[test]
    fn equality_ignores_encoded_cache() {
        let execution_block = SealedBlock::seal_slow(TempoBlock::default());
        let uncached = Block::from_execution_block_unchecked(execution_block.clone());
        let cached = Block::from_execution_block_unchecked(execution_block);

        assert_eq!(uncached, cached);
        cached.encode();
        assert!(uncached.execution_block_encoded.get().is_none());
        assert!(cached.execution_block_encoded.get().is_some());
        assert_eq!(uncached, cached);
        assert!(!uncached.ne(&cached));

        let different = Block::from_execution_block_unchecked(SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    number: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }));
        assert_ne!(uncached, different);
    }
}
