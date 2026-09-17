//! Test doubles and deterministic block construction for the follower resolver.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use alloy_consensus::Header;
use bytes::Bytes;
use commonware_codec::{Encode as _, FixedSize, types::lazy::Lazy};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::{
            Certificate as VrfCertificate, Scheme, Signature as VrfSignature,
        },
        types::{Finalization, Proposal},
    },
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use parking_lot::Mutex;
use reth_node_core::primitives::SealedBlock;
use tempo_node::rpc::consensus::CertifiedBlock;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::super::{BlockNetwork, BlockProvider, Upstream};
use crate::consensus::{Block, Digest};

pub(super) fn make_block(height: u64) -> Block {
    let header = TempoHeader {
        inner: Header {
            number: height,
            ..Default::default()
        },
        ..Default::default()
    };
    let inner = TempoBlock {
        header,
        body: BlockBody::default(),
    };
    Block::try_from_execution_block(SealedBlock::seal_slow(inner), None)
        .expect("test block should not contain BAL side data")
}

pub(super) fn make_certified_block(height: Height) -> (CertifiedBlock, Bytes) {
    let block = make_block(height.get());
    let digest = block.digest();
    let signature_bytes = [0u8; <VrfSignature<MinSig> as FixedSize>::SIZE];
    let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest> {
        proposal: Proposal::new(
            Round::new(Epoch::zero(), View::new(height.get())),
            View::zero(),
            digest,
        ),
        certificate: VrfCertificate {
            signature: Lazy::deferred(&mut &signature_bytes[..], ()),
        },
    };
    let value = (finalization.clone(), block.clone()).encode();
    let certified = CertifiedBlock {
        epoch: 0,
        view: height.get(),
        digest: digest.0,
        certificate: alloy_primitives::hex::encode(finalization.encode()),
        block: block.into_execution_block(),
    };
    (certified, value)
}

#[derive(Clone, Default)]
pub(super) struct StubBlockProvider {
    inner: Arc<StubBlockProviderInner>,
}

#[derive(Default)]
struct StubBlockProviderInner {
    blocks: Mutex<HashMap<Digest, Block>>,
    reads: AtomicUsize,
    fail_reads: AtomicBool,
}

impl StubBlockProvider {
    pub(super) fn add_block(&self, block: &Block) {
        self.inner
            .blocks
            .lock()
            .insert(block.digest(), block.clone());
    }

    pub(super) fn fail_reads(&self) {
        self.inner.fail_reads.store(true, Ordering::SeqCst);
    }

    pub(super) fn reads(&self) -> usize {
        self.inner.reads.load(Ordering::SeqCst)
    }
}

impl BlockProvider for StubBlockProvider {
    fn block_by_hash(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        self.inner.reads.fetch_add(1, Ordering::SeqCst);
        if self.inner.fail_reads.load(Ordering::SeqCst) {
            eyre::bail!("local block read failed");
        }

        Ok(self.inner.blocks.lock().get(&digest).cloned())
    }
}

#[derive(Clone, Default)]
pub(super) struct StubUpstream {
    inner: Arc<StubUpstreamInner>,
}

#[derive(Default)]
struct StubUpstreamInner {
    blocks: Mutex<HashMap<Digest, Block>>,
    finalizations: Mutex<HashMap<u64, CertifiedBlock>>,
    block_reads: AtomicUsize,
    finalization_reads: AtomicUsize,
    hang_block_reads: AtomicBool,
}

impl StubUpstream {
    pub(super) fn add_block(&self, block: Block) {
        self.inner.blocks.lock().insert(block.digest(), block);
    }

    pub(super) fn add_finalization(&self, height: Height, block: CertifiedBlock) {
        self.inner.finalizations.lock().insert(height.get(), block);
    }

    pub(super) fn block_reads(&self) -> usize {
        self.inner.block_reads.load(Ordering::SeqCst)
    }

    pub(super) fn finalization_reads(&self) -> usize {
        self.inner.finalization_reads.load(Ordering::SeqCst)
    }

    pub(super) fn hang_block_reads(&self) {
        self.inner.hang_block_reads.store(true, Ordering::SeqCst);
    }
}

impl Upstream for StubUpstream {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send + 'static {
        self.inner.block_reads.fetch_add(1, Ordering::SeqCst);
        let block = self.inner.blocks.lock().get(&digest).cloned();
        let hang = self.inner.hang_block_reads.load(Ordering::SeqCst);
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            block
        }
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedBlock>> + Send + 'static {
        self.inner.finalization_reads.fetch_add(1, Ordering::SeqCst);
        let finalization = self.inner.finalizations.lock().get(&height.get()).cloned();
        async move { finalization }
    }
}

#[derive(Clone, Default)]
pub(super) struct StubBlockNetwork {
    blocks: Arc<Mutex<HashMap<Digest, Block>>>,
    reads: Arc<AtomicUsize>,
}

impl StubBlockNetwork {
    pub(super) fn add_block(&self, block: Block) {
        self.blocks.lock().insert(block.digest(), block);
    }

    pub(super) fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl BlockNetwork for StubBlockNetwork {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send + 'static {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let block = self.blocks.lock().get(&digest).cloned();
        async move { block }
    }
}
