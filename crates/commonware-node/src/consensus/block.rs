//! The foundational data structure the Tempo network comes to consensus over.
//!
//! The Tempo [`Block`] contains the execution-layer block plus
//! consensus-layer validation data that is transmitted over commonware p2p.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::Encodable as _;
use bytes::{Buf, BufMut, Bytes as WireBytes};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
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
use tracing::warn;

use crate::consensus::Digest;

/// A Tempo consensus payload.
///
/// This wraps the execution-layer block with consensus-layer validation data
/// that is not persisted as part of the block in reth's database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    execution_block: SealedBlock<tempo_primitives::Block>,
    block_access_list: Option<WireBytes>,
}

impl Block {
    /// Creates a consensus payload from an execution-layer block and optional BAL.
    pub(crate) fn from_execution_payload(
        block: SealedBlock<tempo_primitives::Block>,
        block_access_list: Option<Bytes>,
    ) -> Self {
        Self {
            execution_block: block,
            block_access_list: block_access_list.map(Into::into),
        }
    }

    /// Consumes the payload and returns only the execution-layer block.
    pub(crate) fn into_inner(self) -> SealedBlock<tempo_primitives::Block> {
        self.execution_block
    }

    /// Consumes the payload and returns the execution-layer block plus optional BAL.
    pub(crate) fn into_parts(self) -> (SealedBlock<tempo_primitives::Block>, Option<Bytes>) {
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

    /// Returns the wrapped block.
    pub(crate) fn block(&self) -> &SealedBlock<tempo_primitives::Block> {
        &self.execution_block
    }

    /// Returns the block access list of the wrapped block.
    pub(crate) fn block_access_list(&self) -> Option<&WireBytes> {
        self.block_access_list.as_ref()
    }
}

impl std::ops::Deref for Block {
    type Target = SealedBlock<tempo_primitives::Block>;

    fn deref(&self) -> &Self::Target {
        &self.execution_block
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.execution_block.encode(buf);
        if self.execution_block.block_access_list_hash().is_some()
            || self.block_access_list.is_some()
        {
            let block_access_list = self
                .block_access_list
                .as_ref()
                .expect("BAL bytes must be present when encoding a BAL sidecar");
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
        let bytes = buf.copy_to_bytes(header.length_with_payload());

        // TODO: decode straight to a reth SealedBlock once released:
        // https://github.com/paradigmxyz/reth/pull/18003
        // For now relies on `Decodable for alloy_consensus::Block`.
        let inner: SealedBlock<tempo_primitives::Block> =
            alloy_rlp::Decodable::decode(&mut bytes.as_ref()).map_err(|rlp_err| {
                commonware_codec::Error::Wrapped("reading RLP encoded block", rlp_err.into())
            })?;

        let block_access_list = if inner.block_access_list_hash().is_some() || buf.has_remaining() {
            Some(WireBytes::read_cfg(buf, &RangeCfg::from(..))?)
        } else {
            None
        };

        Ok(Self {
            execution_block: inner,
            block_access_list,
        })
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.execution_block.length()
            + if self.execution_block.block_access_list_hash().is_some()
                || self.block_access_list.is_some()
            {
                self.block_access_list
                    .as_ref()
                    .expect("BAL bytes must be present when encoding a BAL sidecar")
                    .encode_size()
            } else {
                0
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
                leader: ctx.proposer.get().into(),
                round: Round::new(Epoch::new(ctx.epoch), View::new(ctx.view)),
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
    use alloy_consensus::BlockHeader as _;
    use alloy_primitives::bytes;
    use commonware_codec::{Encode, EncodeSize as _, Read as _};
    use reth_node_core::primitives::SealedBlock;
    use tempo_primitives::{Block as TempoBlock, TempoHeader};

    use super::Block;

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
        // cast rpc debug_getRawBlock $(cast to-hex 19666674) -r https://rpc.testnet.tempo.xyz
        let block_bytes = bytes!(
            "0xf91684f9029c8401c9c3808002f90267a0e0c0b8e4635cd4cb86ae95cfd9771469f254f5c56f9a7504abb4192d2cb0869ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947e8f45d07f1a182fa59aa5b62012459c15309791a0be9342dc837d6cc9b02eb5f86945db3bde2d5af273d4a8fd7e6ff1b0c22e6d7da031cd205ba607346f21c073d770039225f2532b7f5c15d623e51af2f58174e19ba0d00b6660db560dce9196510f45ab9f834ef061398a80d512ee021d1914106bedb90100000000000000200400000008004000000800000002004000000000000000000000000020002000002040023001000000000040000000400008000000002000000802040000240000001008080022002800080200010040020000000084000004000001020200500000000000080808000000090180004000004010100000004000000001002201000200000000220040100000009001080100402000204000200201a1400040040000000108200400000800244400022000100300000010000040500202000004000900202400100004000000000084000c000020010040220000100000000000000001000000000000202100000000400000080000000000008084012c16f2841dcd6500837fb629846a181d0f80a000000000000000000000000000000000000000000000000000000000000000008800000000000000008504a817c800a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ea82038e8229b38229b2a0594011d455fcaef1b39ed39fc9912e3aa996f42c1f52dea4987af0752663808cf913e0f8ee81cf85051f4d5c008303d09094dec000000000000000000000000000000000000080b8844f8f021800000000000000000000000000000000000000000000000000000000000000c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020c000000000000000000000000000000000000000000000000000000000000020c000000000000000000000000000000000000283014ba2a067fe70c84ccdb31bc0094225b357930161465925f8160bc4524706172e4f2f59a0053962a5d787f453c20ba662ace204baa57d9e0601ff26c70a3c1dcd5e06730df8ee81db85051f4d5c008303d09094dec000000000000000000000000000000000000080b8844f8f0218000000000000000000000000000000000000000000000000000000000000005f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020c000000000000000000000000000000000000200000000000000000000000020c000000000000000000000000000000000000083014ba1a0c2814fb9fdaa3b85b8e91d369fb04b33933e1d9162f2ffa28344cc208a910d78a017e5153e3e857f07bc360c0cf905c574366020040ac6a8ace96779cab408d6fcb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000080b84440c10f19000000000000000000000000929aebcb7c620816c547fcc8fe657d4c4dd99820000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b841741bc8453864fef4c124d832e2320f27d1f5adc7952b840983d8849060b3fcd37b683534c8511ed733e954c19b3c0ecff55f54edf3d85a252832581b008d9eb71cb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000180b84440c10f19000000000000000000000000929aebcb7c620816c547fcc8fe657d4c4dd99820000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b841e56a5208372bca99cafd0f150e3a766fd5a59208812dec197c512f319e9ec16e227ff21ba8b7f4c03da9b7df1b938f6e6cd68a47c5518e8eb328e87259b39c621cb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000280b84440c10f19000000000000000000000000929aebcb7c620816c547fcc8fe657d4c4dd99820000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b8413fdad401f3468723731f5a2e8f62959875916d87359308208cd66af62c75d9657f829bb715782332447513ffeb7e177972296989506f624290062e7e6fe5186b1bb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000380b84440c10f19000000000000000000000000929aebcb7c620816c547fcc8fe657d4c4dd99820000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b8414b8c58795ad65931e00f467f149dd52e98df193b81232744adb49bebca440ea25fd93bbf5d07c33589838290138350d0bfde23df0cbbb860e6081edb33e3edfb1bb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000080b84440c10f19000000000000000000000000801f3ca24d6dd63c6146ffbb2cbc1946ceb29d64000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b841f0f1ddb1ea4dcfec9ce5f3f29d0c7deefbe76c7e9c4a76033df193b9833f8fd23dea3e68e82f0a95874568618fab5036258fd0939fb20c9c18a7dcfbce86c50e1cb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000180b84440c10f19000000000000000000000000801f3ca24d6dd63c6146ffbb2cbc1946ceb29d64000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b841f8f4c2063baa1c968e4745daa66dd23305730746ecb0f6302f901b0464278ba528a64aae92663a2e86cf7cdbedc960902597dfe3a09b346e9e5600f13311881b1cb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000280b84440c10f19000000000000000000000000801f3ca24d6dd63c6146ffbb2cbc1946ceb29d64000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b84116afd5f4e64d5efdf698a88abd712b6fc3be0eef8c52ca069343e12ab53d1ac066a3734647b0eb4fca4926e770af45a332321156683b9102f3b34ed7f1a67fc01bb8e076f8dd82a5bf018509502f90018308a9f0f85ef85c9420c000000000000000000000000000000000000380b84440c10f19000000000000000000000000801f3ca24d6dd63c6146ffbb2cbc1946ceb29d64000000000000000000000000000000000000000000000000000000e8d4a51000c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a181d27808080c0b841587907beafc86b1103c31c0be6858937abdf81ac6145b64d2bf1528e429b4106403776d47309a2eac8c15e7e3f137ff84c808de14d10aa4618083cf6cf7be5031cf8ae81cf8504a817c800830a31a49420c000000000000000000000000000000000000180b844a9059cbb0000000000000000000000005576cc9548c41031fc31143a9c6e38caa3354c920000000000000000000000000000000000000000000000000000000015016f8383014ba1a00eb24a275e5a90ea4b7a510b67598f4f07aaafc20b674c88eb42eb789a775392a03512673f83718d7e46a97d72406ad94c4000c1eef811601ff9a59e8ea4b82612f8af8201358504a817c800830a22fe9420c000000000000000000000000000000000000180b844a9059cbb00000000000000000000000066de4f26bf4e07ce69b9dcdf41ac9499e456cdfd00000000000000000000000000000000000000000000000000000000073f2d8f83014ba1a0118279408b029a25238ab9dabfbf9daa7bdb2e06623c962797260ec69e105448a0199f6bb3a2f2760947c0fdcb2b20095fa6cb617a162a04fbbc3e4a53dcf1cd0fb8d176f8ce82a5bf8085059682f00082d071f85ef85c9420c000000000000000000000000000000000000180b844a9059cbb0000000000000000000000006e4d807fc3c54aac156ca6c4d5d83c9ab8bc29440000000000000000000000000000000000000000000000000000000000989680c080821d7380809420c000000000000000000000000000000000000280c0b8413f1404985f8347f533171840994458f9e2ee2f551ba8474fb390ede316df6bd132917120eb333cc75964d5673051d936d00ca2e9120d524e35899c009e51d8a81cb8d176f8ce82a5bf8085059682f00082d071f85ef85c9420c000000000000000000000000000000000000080b844a9059cbb000000000000000000000000d24ff8d2610ad8f659a0cb86cc7dda5af15a049e0000000000000000000000000000000000000000000000000000000000989680c080821db880809420c000000000000000000000000000000000000280c0b84149145f8995642c208ee70dfb1e6bceeb6c9b6d340e45e47b611678d4fed832154d6accc2b43e509e37f21713d1c22dd47dd6d60f5ede34fce16976b5133bf88c1bb8d176f8ce82a5bf8085059682f00082e40df85ef85c9420c000000000000000000000000000000000000180b844a9059cbb00000000000000000000000028c3cabc35eb34cec98b4ee69f65f607131220c70000000000000000000000000000000000000000000000000000000000989680c080821e0280809420c000000000000000000000000000000000000380c0b8415a1b2e485c30b2cfee1fe557332f5d4dc756ffd308d61e67617bf311894d609a47933064f5c11fc48f584fef882204dfb9a720f1b8c4ccc79937506d0a0141061bb8d176f8ce82a5bf8085059682f00082dc9af85ef85c9420c000000000000000000000000000000000000180b844a9059cbb0000000000000000000000000315a592a19b629d4f0bf32685f15ef54430e9720000000000000000000000000000000000000000000000000000000000989680c080821d3380809420c000000000000000000000000000000000000280c0b84154f32a01119ad279a68e197d21162b3ea69cce001e657fa27d9275be052e1ace34ecdd62b39ba1519f873550a2401e59fc2a2ad65112081f5110323f1d0ae4dd1cb8d176f8ce82a5bf8085059682f00082d4c2f85ef85c9420c000000000000000000000000000000000000380b844a9059cbb000000000000000000000000ab224b2fdf6949ad5ebdde0158493cd287cd426b0000000000000000000000000000000000000000000000000000000000989680c08082310680809420c000000000000000000000000000000000000380c0b841e0a24d97eb1a96899b76d36dac52dbf748a59d630430a543e119bff268649bc83ed0c5eacc72524fe7617f595a57216d6459fccfd019071a993aa902a88ba38c1cb9011376f9010f82a5bf8085059682f000830c9314f89ef89c94feec00000000000000000000000000000000000080b884f1aa8cb800000000000000000000000020c0000000000000000000002b6ab9c20a7c3edb00000000000000000000000020c00000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000005f5e1000000000000000000000000003a48d3fb0c0fdcc003e5c64c4d2469c3989a8f47c080821e1d80809420c000000000000000000000000000000000000080c0b8413d5075f4328314185f9c4fa12ee2f28c098eee28a9b946dc455586f5c334cb4f15b5761417ce87fb6c1cd0f6923f61f7bb6b6d3a118dd3ee5d9aff79f20dddc31cf86b7b8504a817c8008263f794ab224b2fdf6949ad5ebdde0158493cd287cd426b8084498c249a83014ba1a0ea1b6c46cabe92afec1f46c6211c5d05f66e622414988ce780d4f1d6dcaf0497a031de7526500306aaaddc2db86312e8dc6e2379c01d8ab1583e4f09529df19088f8ae81868504a817c800830a22fe9420c000000000000000000000000000000000000180b844a9059cbb00000000000000000000000060cda71fb3d97d7f0c19130a108a3286689a33c400000000000000000000000000000000000000000000000000000000a468693c83014ba2a07d23d4082eed9bbb9fd0114dd5abc9b267dee0a341cbfefc6542a6af6d87e3fba016b6e3545ce4c055c95a03b450521461e4102ac1b1423747c3a0c3b5b18f7e05f8af8201258504a817c80083051b619420c000000000000000000000000000000000000080b844095ea7b3000000000000000000000000dec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f5e10083014ba2a0562bb2e16e204d034810a6277570aaad767f7dd2a0c2c9a565f79436d40453afa01a93abbd6f0626aa1a760e7002e6b79276fe7d045ccd8b29948c465ed968fed3b8b402f8b182a5bf820da08085059682f000830441889420c000000000000000000000000000000000000380b844095ea7b3000000000000000000000000dec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008f0d180c001a0636e2f66f5faa365001e63e68bc28844944a64aa0d49a891b7176f3f486feb5ca05cc7e092e007e45c665b580535ba586b8dd707d99a1ecebaeae4fea5880ca6adf8ae818f8504a817c800830a22fe9420c000000000000000000000000000000000000180b844a9059cbb00000000000000000000000016c8798def05b396856736b68755ef6e861a8a1a000000000000000000000000000000000000000000000000000000008f72946683014ba1a07c4f5c23ec44dc95ef4359fcb64dcb951934f99178e914104cc65bb8afe39a67a027232b9ba33f1d4b67e87e71d951db758963781c50bb3357c2c8b628daa8154af86e82011a8504a817c8008307a12094a89e3e260c85d19c0b940245fddb1e845c93ded88084775c300c83014ba1a058343d8e211c1d5955a5865108400b2aff21129efdc8746cbf3c2a026e097be8a04e324b5cfda283593daca329877cdd4f99c0860622b6950b8e459f9b7f77cd10b8b402f8b182a5bf820389808509502f90008301ad419420c000000000000000000000000000000000000080b844a9059cbb0000000000000000000000008675d6aa8b2e644c74d304477a887ba6dd1e161000000000000000000000000000000000000000000000000000000147c521f44fc001a05ec545f1e03d402f82dd2c1cf8ea44b9a00d50d4eebf0505ecfafe548c8de528a030a5fe53dd3b450f7a6047085155ed85be597b237122bf4da00f42b9e3eae228c0c0"
        );

        let decoded = Block::read_cfg(&mut block_bytes.as_ref(), &()).unwrap();
        assert!(decoded.block_access_list().is_none());

        let encoded = decoded.encode();

        assert_eq!(encoded.as_ref(), block_bytes.as_ref());
    }

    #[test]
    fn roundtrips_block_access_list_without_header_hash() {
        let execution_block = SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader::default(),
            body: Default::default(),
        });
        assert!(execution_block.block_access_list_hash().is_none());

        let block_access_list = bytes!("0xc0");
        let block = Block::from_execution_payload(execution_block, Some(block_access_list.clone()));

        let encoded = block.encode();
        assert_eq!(encoded.len(), block.encode_size());

        let decoded = Block::read_cfg(&mut encoded.as_ref(), &()).unwrap();

        assert_eq!(decoded, block);
        assert_eq!(
            decoded.block_access_list().map(|bytes| bytes.as_ref()),
            Some(block_access_list.as_ref())
        );
        assert!(decoded.block().block_access_list_hash().is_none());
    }
}
