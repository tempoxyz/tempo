//! The foundational data structure the Tempo network comes to consensus over.
//!
//! The Tempo [`ConsensusPayload`] contains the execution-layer block plus
//! consensus-layer validation data that is transmitted over commonware p2p.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable, Encodable as _, Header};
use bytes::{Buf, BufMut, Bytes as WireBytes};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::{
    Heightable,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Committable, Digestible, Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::Block as ExecutionBlock;

use crate::consensus::Digest;

/// A Tempo consensus payload.
///
/// This wraps the execution-layer block with consensus-layer validation data
/// that is not persisted as part of the block in reth's database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConsensusPayload {
    execution_block: SealedBlock<ExecutionBlock>,
    block_access_list: Option<WireBytes>,
}

pub(crate) type Block = ConsensusPayload;

impl ConsensusPayload {
    /// Creates a consensus payload from an execution-layer block and optional BAL.
    pub(crate) fn from_execution_payload(
        block: SealedBlock<ExecutionBlock>,
        block_access_list: Option<Bytes>,
    ) -> Self {
        Self {
            execution_block: block,
            block_access_list: block_access_list.map(Into::into),
        }
    }

    /// Consumes the payload and returns only the execution-layer block.
    pub(crate) fn into_inner(self) -> SealedBlock<ExecutionBlock> {
        self.execution_block
    }

    /// Consumes the payload and returns the execution-layer block plus optional BAL.
    pub(crate) fn into_parts(self) -> (SealedBlock<ExecutionBlock>, Option<Bytes>) {
        (self.execution_block, self.block_access_list.map(Into::into))
    }

    /// Returns the (eth) hash of the wrapped block.
    pub(crate) fn block_hash(&self) -> B256 {
        self.execution_block.hash()
    }

    /// Returns the hash of the wrapped block as a commonware [`Digest`].
    pub(crate) fn digest(&self) -> Digest {
        Digest(self.hash())
    }

    /// Returns the parent hash of the wrapped block as a commonware [`Digest`].
    pub(crate) fn parent_digest(&self) -> Digest {
        Digest(self.execution_block.parent_hash())
    }

    /// Returns the timestamp of the wrapped block.
    pub(crate) fn timestamp(&self) -> u64 {
        self.execution_block.timestamp()
    }
}

impl std::ops::Deref for ConsensusPayload {
    type Target = SealedBlock<ExecutionBlock>;

    fn deref(&self) -> &Self::Target {
        &self.execution_block
    }
}

impl Write for ConsensusPayload {
    fn write(&self, buf: &mut impl BufMut) {
        self.execution_block.encode(buf);
        self.block_access_list.write(buf);
    }
}

impl Read for ConsensusPayload {
    // TODO: Figure out what this is for/when to use it. This is () for both alto and summit.
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        // XXX: this does not advance `buf`. Also, it assumes that the rlp
        // header is fully contained in the first chunk of `buf`. As per
        // `Buf::chunk`'s documentation, the first slice should never be
        // empty is there are remaining bytes. We hence don't worry about edge
        // cases where the very tiny rlp header is spread over more than one
        // chunk.
        let header = Header::decode(&mut buf.chunk())
            .map_err(|rlp_err| Error::Wrapped("reading RLP header", rlp_err.into()))?;

        if header.length_with_payload() > buf.remaining() {
            // TODO: it would be nice to report more information here, but commonware_codex::Error does not
            // have the fidelity for it (outside abusing Error::Wrapped).
            return Err(Error::EndOfBuffer);
        }
        let bytes = buf.copy_to_bytes(header.length_with_payload());

        // TODO: decode straight to a reth SealedBlock once released:
        // https://github.com/paradigmxyz/reth/pull/18003
        // For now relies on `Decodable for alloy_consensus::Block`.
        let inner = Decodable::decode(&mut bytes.as_ref())
            .map_err(|rlp_err| Error::Wrapped("reading RLP encoded block", rlp_err.into()))?;

        let block_access_list = if buf.remaining() == 0 {
            None
        } else {
            Option::<WireBytes>::read_cfg(buf, &(..).into())?
        };

        Ok(Self {
            execution_block: inner,
            block_access_list,
        })
    }
}

impl EncodeSize for ConsensusPayload {
    fn encode_size(&self) -> usize {
        self.execution_block.length() + self.block_access_list.encode_size()
    }
}

impl Committable for ConsensusPayload {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        self.digest()
    }
}

impl Digestible for ConsensusPayload {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        self.digest()
    }
}

impl Heightable for ConsensusPayload {
    fn height(&self) -> Height {
        Height::new(self.execution_block.number())
    }
}

impl commonware_consensus::Block for ConsensusPayload {
    fn parent(&self) -> Digest {
        self.parent_digest()
    }
}

impl commonware_consensus::CertifiableBlock for ConsensusPayload {
    type Context = Context<Digest, PublicKey>;

    fn context(&self) -> Self::Context {
        match self.consensus_context {
            Some(ctx) => Context {
                leader: ctx.proposer.get().into(),
                round: Round::new(Epoch::new(ctx.epoch), View::new(ctx.view)),
                parent: (View::new(ctx.parent_view), self.parent_digest()),
            },
            None => {
                // Returns a deterministic sentinel `Context`.
                //
                // Pre-T4: Unused; consensus does not consult this context.
                // Post-T4: All blocks must carry a `consensus_context`, so reaching
                // this branch indicates a malformed block. The sentinel intentionally
                // does not match any real consensus values, so it will fail
                // verification rather than panic.
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

// =======================================================================
// TODO: Below here are commented out definitions that will be useful when
// writing an indexer.
// =======================================================================

// /// A notarized [`Block`].
// // XXX: Not used right now but will be used once an indexer is implemented.
// #[derive(Clone, Debug, PartialEq, Eq)]
// pub(crate) struct Notarized {
//     proof: Notarization,
//     block: Block,
// }

// #[derive(Debug, thiserror::Error)]
// #[error(
//     "invalid notarized block: proof proposal `{proposal}` does not match block digest `{digest}`"
// )]
// pub(crate) struct NotarizationProofNotForBlock {
//     proposal: Digest,
//     digest: Digest,
// }

// impl Notarized {
//     /// Constructs a new [`Notarized`] block.
//     pub(crate) fn try_new(
//         proof: Notarization,
//         block: Block,
//     ) -> Result<Self, NotarizationProofNotForBlock> {
//         if proof.proposal.payload != block.digest() {
//             return Err(NotarizationProofNotForBlock {
//                 proposal: proof.proposal.payload,
//                 digest: block.digest(),
//             });
//         }
//         Ok(Self { proof, block })
//     }

//     pub(crate) fn block(&self) -> &Block {
//         &self.block
//     }

//     /// Breaks up [`Notarized`] into its constituent parts.
//     pub(crate) fn into_parts(self) -> (Notarization, Block) {
//         (self.proof, self.block)
//     }

//     /// Verifies the notarized block against `namespace` and `identity`.
//     ///
//     // XXX: But why does this ignore the block entirely??
//     pub(crate) fn verify(&self, namespace: &[u8], identity: &BlsPublicKey) -> bool {
//         self.proof.verify(namespace, identity)
//     }
// }

// impl Write for Notarized {
//     fn write(&self, buf: &mut impl BufMut) {
//         self.proof.write(buf);
//         self.block.write(buf);
//     }
// }

// impl Read for Notarized {
//     // XXX: Same Cfg as for Block.
//     type Cfg = ();

//     fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
//         // FIXME: wrapping this to give it some context on what exactly failed, but it doesn't feel great.
//         // Problem is the catch-all `commonware_codex:Error`.
//         let proof = Notarization::read(buf)
//             .map_err(|err| commonware_codec::Error::Wrapped("failed to read proof", err.into()))?;
//         let block = Block::read(buf)
//             .map_err(|err| commonware_codec::Error::Wrapped("failed to read block", err.into()))?;
//         Self::try_new(proof, block).map_err(|err| {
//             commonware_codec::Error::Wrapped("failed constructing notarized block", err.into())
//         })
//     }
// }

// impl EncodeSize for Notarized {
//     fn encode_size(&self) -> usize {
//         self.proof.encode_size() + self.block.encode_size()
//     }
// }

// /// Used for an indexer.
// //
// // XXX: Not used right now but will be used once an indexer is implemented.
// #[derive(Clone, Debug, PartialEq, Eq)]
// pub(crate) struct Finalized {
//     proof: Finalization,
//     block: Block,
// }

// #[derive(Debug, thiserror::Error)]
// #[error(
//     "invalid finalized block: proof proposal `{proposal}` does not match block digest `{digest}`"
// )]
// pub(crate) struct FinalizationProofNotForBlock {
//     proposal: Digest,
//     digest: Digest,
// }

// impl Finalized {
//     /// Constructs a new [`Finalized`] block.
//     pub(crate) fn try_new(
//         proof: Finalization,
//         block: Block,
//     ) -> Result<Self, FinalizationProofNotForBlock> {
//         if proof.proposal.payload != block.digest() {
//             return Err(FinalizationProofNotForBlock {
//                 proposal: proof.proposal.payload,
//                 digest: block.digest(),
//             });
//         }
//         Ok(Self { proof, block })
//     }

//     pub(crate) fn block(&self) -> &Block {
//         &self.block
//     }

//     /// Breaks up [`Finalized`] into its constituent parts.
//     pub(crate) fn into_parts(self) -> (Finalization, Block) {
//         (self.proof, self.block)
//     }

//     /// Verifies the notarized block against `namespace` and `identity`.
//     ///
//     // XXX: But why does this ignore the block entirely??
//     pub(crate) fn verify(&self, namespace: &[u8], identity: &BlsPublicKey) -> bool {
//         self.proof.verify(namespace, identity)
//     }
// }

// impl Write for Finalized {
//     fn write(&self, buf: &mut impl BufMut) {
//         self.proof.write(buf);
//         self.block.write(buf);
//     }
// }

// impl Read for Finalized {
//     // XXX: Same Cfg as for Block.
//     type Cfg = ();

//     fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
//         // FIXME: wrapping this to give it some context on what exactly failed, but it doesn't feel great.
//         // Problem is the catch-all `commonware_codex:Error`.
//         let proof = Finalization::read(buf)
//             .map_err(|err| commonware_codec::Error::Wrapped("failed to read proof", err.into()))?;
//         let block = Block::read(buf)
//             .map_err(|err| commonware_codec::Error::Wrapped("failed to read block", err.into()))?;
//         Self::try_new(proof, block).map_err(|err| {
//             commonware_codec::Error::Wrapped("failed constructing finalized block", err.into())
//         })
//     }
// }

// impl EncodeSize for Finalized {
//     fn encode_size(&self) -> usize {
//         self.proof.encode_size() + self.block.encode_size()
//     }
// }

#[cfg(test)]
mod tests {
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

    // TODO: Bring back this unit test; preferably with some flavour of tempo reth block.
    //
    // use commonware_codec::{Read as _, Write as _};
    // use reth_chainspec::ChainSpec;

    // use crate::consensus::block::Block;

    // #[test]
    // fn commonware_write_read_roundtrip() {
    //     // TODO: should use a non-default chainspec to make the test more interesting.
    //     let chainspec = ChainSpec::default();
    //     let expected = Block::genesis_from_chainspec(&chainspec);
    //     let mut buf = Vec::new();
    //     expected.write(&mut buf);
    //     let actual = Block::read_cfg(&mut buf.as_slice(), &()).unwrap();
    //     assert_eq!(expected, actual);
    // }
}
