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
use commonware_utils::channel::oneshot;
use parking_lot::Mutex;
use reth_node_core::primitives::SealedBlock;
use tempo_node::rpc::consensus::CertifiedBlock;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::super::{BlockProvider, Upstream};
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
    Block::from_execution_block(SealedBlock::seal_slow(inner), None)
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
    block_gate: Mutex<Option<oneshot::Receiver<()>>>,
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

    pub(super) fn pause_next_block_read(&self) -> oneshot::Sender<()> {
        let (release, gate) = oneshot::channel();
        *self.inner.block_gate.lock() = Some(gate);
        release
    }
}

impl Upstream for StubUpstream {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send {
        self.inner.block_reads.fetch_add(1, Ordering::SeqCst);
        let block = self.inner.blocks.lock().get(&digest).cloned();
        let gate = self.inner.block_gate.lock().take();
        async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            block
        }
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedBlock>> + Send {
        self.inner.finalization_reads.fetch_add(1, Ordering::SeqCst);
        let finalization = self.inner.finalizations.lock().get(&height.get()).cloned();
        async move { finalization }
    }
}
