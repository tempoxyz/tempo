//! Test doubles and deterministic block construction for the follower driver.

use std::{
    collections::HashMap,
    future::Future,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use alloy_consensus::{BlockHeader as _, Header};
use alloy_primitives::Bytes;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Height, Round},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use parking_lot::Mutex;
use reth_node_core::primitives::SealedBlock;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::CertifiedBlock;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::driver::{ExecutionProvider, Executor, Marshal};
use crate::{
    consensus::{Block, Digest},
    test_utils::make_certificate,
};

pub(crate) use crate::test_utils::{DkgFixture, dkg_fixture};

/// Records finalizations sent to execution.
#[derive(Clone, Default)]
pub(crate) struct StubExecutor {
    finalizations: Arc<Mutex<Vec<(Round, Digest)>>>,
}

impl StubExecutor {
    pub(crate) fn finalizations(&self) -> Vec<(Round, Digest)> {
        self.finalizations.lock().clone()
    }
}

impl Executor for StubExecutor {
    fn finalization(&self, round: Round, digest: Digest) {
        self.finalizations.lock().push((round, digest));
    }
}

type ConsensusActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

pub(crate) const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).expect("epoch length is nonzero");

pub(crate) fn make_block(height: u64, outcome: Option<&OnchainDkgOutcome>) -> Block {
    make_block_with_parent(height, Default::default(), outcome)
}

pub(crate) fn make_child_block(
    parent: &Block,
    height: u64,
    outcome: Option<&OnchainDkgOutcome>,
) -> Block {
    make_block_with_parent(height, parent.block_hash(), outcome)
}

fn make_block_with_parent(
    height: u64,
    parent_hash: alloy_primitives::B256,
    outcome: Option<&OnchainDkgOutcome>,
) -> Block {
    let header = TempoHeader {
        inner: Header {
            number: height,
            parent_hash,
            extra_data: outcome.map_or_else(Bytes::new, |outcome| outcome.encode().into()),
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

pub(crate) fn make_finalization(
    block: &Block,
    epoch: Epoch,
    schemes: &[Scheme<PublicKey, MinSig>],
) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
    make_certificate(block.digest(), epoch, block.number(), schemes)
}

pub(crate) fn make_certified_block(
    block: Block,
    finalization: &Finalization<Scheme<PublicKey, MinSig>, Digest>,
) -> CertifiedBlock {
    CertifiedBlock {
        epoch: finalization.proposal.round.epoch().get(),
        view: finalization.proposal.round.view().get(),
        digest: block.digest().0,
        certificate: alloy_primitives::hex::encode(finalization.encode()),
        block: block.into_execution_block(),
    }
}

#[derive(Clone, Default)]
pub(super) struct StubExecutionProvider {
    inner: Arc<StubExecutionProviderInner>,
}

#[derive(Default)]
struct StubExecutionProviderInner {
    finalized: AtomicU64,
    headers: Mutex<HashMap<u64, TempoHeader>>,
    header_reads: Mutex<Vec<u64>>,
    fail_finalized_read: AtomicBool,
}

impl StubExecutionProvider {
    pub(super) fn set_finalized(&self, height: u64) {
        self.inner.finalized.store(height, Ordering::SeqCst);
    }

    pub(super) fn add_header(&self, block: &Block) {
        self.inner
            .headers
            .lock()
            .insert(block.number(), block.header().clone());
    }

    pub(super) fn fail_finalized_read(&self) {
        self.inner.fail_finalized_read.store(true, Ordering::SeqCst);
    }

    pub(super) fn header_reads(&self) -> Vec<u64> {
        self.inner.header_reads.lock().clone()
    }
}

impl ExecutionProvider for StubExecutionProvider {
    fn finalized_block_number(&self) -> eyre::Result<u64> {
        if self.inner.fail_finalized_read.load(Ordering::SeqCst) {
            eyre::bail!("finalized block read failed");
        }
        Ok(self.inner.finalized.load(Ordering::SeqCst))
    }

    fn finalized_header_by_number(&self, number: u64) -> eyre::Result<Option<TempoHeader>> {
        self.inner.header_reads.lock().push(number);
        Ok(self.inner.headers.lock().get(&number).cloned())
    }
}

#[derive(Clone, Default)]
pub(super) struct StubMarshal {
    inner: Arc<StubMarshalInner>,
}

#[derive(Default)]
struct StubMarshalInner {
    blocks: Mutex<HashMap<u64, Block>>,
    block_reads: Mutex<Vec<Height>>,
    hints: Mutex<Vec<Height>>,
    certified: Mutex<Vec<(Round, Block)>>,
    reports: Mutex<Vec<ConsensusActivity>>,
}

impl StubMarshal {
    pub(super) fn add_block(&self, block: Block) {
        self.inner.blocks.lock().insert(block.number(), block);
    }

    pub(super) fn block_reads(&self) -> Vec<Height> {
        self.inner.block_reads.lock().clone()
    }

    pub(super) fn hints(&self) -> Vec<Height> {
        self.inner.hints.lock().clone()
    }

    pub(super) fn certified(&self) -> Vec<(Round, Block)> {
        self.inner.certified.lock().clone()
    }

    pub(super) fn report_count(&self) -> usize {
        self.inner.reports.lock().len()
    }
}

impl Marshal for StubMarshal {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        self.inner.block_reads.lock().push(height);
        let block = self.inner.blocks.lock().get(&height.get()).cloned();
        async move { block }
    }

    fn hint_finalized(&self, height: Height) -> impl Future<Output = ()> + Send {
        self.inner.hints.lock().push(height);
        async {}
    }

    fn certified(&self, round: Round, block: Block) -> impl Future<Output = bool> + Send {
        self.inner.certified.lock().push((round, block));
        async { true }
    }

    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send {
        self.inner.reports.lock().push(activity);
        async {}
    }
}
