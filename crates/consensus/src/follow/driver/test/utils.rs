//! Test doubles and deterministic block construction for the follower driver.

use std::{
    collections::HashMap,
    future::Future,
    iter::repeat_with,
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
        types::{Finalization, Finalize, Proposal},
    },
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use parking_lot::Mutex;
use rand_08::{CryptoRng, Rng};
use reth_node_core::primitives::SealedBlock;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::CertifiedBlock;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::super::{ConsensusActivity, ExecutionProvider, Feed, Marshal};
use crate::consensus::{Block, Digest};

pub(super) const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).expect("epoch length is nonzero");

pub(super) struct DkgFixture {
    pub(super) outcome: OnchainDkgOutcome,
    pub(super) schemes: Vec<Scheme<PublicKey, MinSig>>,
}

pub(super) fn dkg_fixture(rng: &mut (impl Rng + CryptoRng), epoch: Epoch) -> DkgFixture {
    let player_keys = repeat_with(|| PrivateKey::random(&mut *rng))
        .take(4)
        .collect::<Vec<_>>();
    let players = ordered::Set::try_from_iter(
        player_keys
            .iter()
            .map(|private_key| private_key.public_key()),
    )
    .expect("test players should be unique");

    let (output, shares) =
        dkg::deal::<_, _, N3f1>(&mut *rng, Default::default(), players).expect("test DKG");

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            Scheme::signer(
                crate::config::NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                share,
            )
            .expect("test share should match the public polynomial")
        })
        .collect();

    let outcome = OnchainDkgOutcome {
        epoch,
        next_players: output.players().clone(),
        output,
        is_next_full_dkg: false,
    };

    DkgFixture { outcome, schemes }
}

pub(super) fn make_block(height: u64, outcome: Option<&OnchainDkgOutcome>) -> Block {
    let header = TempoHeader {
        inner: Header {
            number: height,
            extra_data: outcome.map_or_else(Bytes::new, |outcome| outcome.encode().into()),
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

pub(super) fn make_finalization(
    block: &Block,
    epoch: Epoch,
    schemes: &[Scheme<PublicKey, MinSig>],
) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
    let proposal = Proposal::new(
        Round::new(epoch, View::new(block.number())),
        View::zero(),
        block.digest(),
    );
    let votes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("signer should sign"))
        .collect::<Vec<_>>();

    Finalization::from_finalizes(&schemes[0], &votes, &Sequential)
        .expect("all test signers form a quorum")
}

pub(super) fn make_certified_block(
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

#[derive(Clone, Default)]
pub(super) struct StubFeed {
    reports: Arc<Mutex<Vec<ConsensusActivity>>>,
}

impl StubFeed {
    pub(super) fn report_count(&self) -> usize {
        self.reports.lock().len()
    }
}

impl Feed for StubFeed {
    fn report(&self, activity: ConsensusActivity) -> impl Future<Output = ()> + Send {
        self.reports.lock().push(activity);
        async {}
    }
}
