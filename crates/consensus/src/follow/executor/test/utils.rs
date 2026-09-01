//! Test doubles and deterministic block construction for the follower executor.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadStatus, PayloadStatusEnum,
};
use commonware_consensus::{
    Heightable as _,
    types::{Height, Round},
};
use futures::{channel::oneshot, future::Either};
use parking_lot::Mutex;
use reth_ethereum::rpc::eth::primitives::BlockNumHash;
use reth_node_core::primitives::{SealedBlock, SealedHeader};
use tempo_node::TempoExecutionData;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{
    Block as TempoBlock, BlockBody, TempoConsensusContext, TempoHeader, ed25519::PublicKey,
};

use super::super::{ExecutionEngine, FinalizedBlockProvider, Marshal};
use crate::consensus::block::Block;

pub(super) fn make_block(height: u64, parent_hash: B256) -> Block {
    make_block_at_round(height, parent_hash, Round::zero())
}

pub(super) fn make_roundless_block(height: u64, parent_hash: B256) -> Block {
    make_block_with_round(height, parent_hash, None)
}

pub(super) fn make_block_at_round(height: u64, parent_hash: B256, round: Round) -> Block {
    make_block_with_round(height, parent_hash, Some(round))
}

fn make_block_with_round(height: u64, parent_hash: B256, round: Option<Round>) -> Block {
    let header = TempoHeader {
        inner: Header {
            parent_hash,
            number: height,
            ..Default::default()
        },
        consensus_context: round.map(|round| TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: 0,
            proposer: PublicKey::from_seed(0),
        }),
        ..Default::default()
    };
    let inner = TempoBlock {
        header,
        body: BlockBody::default(),
    };
    Block::try_from_execution_block(SealedBlock::seal_slow(inner), None)
        .expect("test block should not contain BAL side data")
}

#[derive(Clone, Default)]
pub(super) struct StubExecutionProvider {
    inner: Arc<StubExecutionProviderInner>,
}

#[derive(Default)]
struct StubExecutionProviderInner {
    finalized: Mutex<BlockNumHash>,
    finalized_round: Mutex<Option<Round>>,
    durable: Mutex<HashMap<u64, B256>>,
    fail_durable_reads: AtomicBool,
    payloads: AtomicUsize,
    syncing_payloads: AtomicUsize,
    syncing_forkchoices: AtomicUsize,
    syncing_readiness_probes: AtomicUsize,
    readiness_complete: AtomicBool,
    readiness_probes: AtomicUsize,
    forkchoices: Mutex<Vec<ForkchoiceState>>,
    reject_payloads: AtomicBool,
    reject_forkchoices: AtomicBool,
    forkchoice_gate: Mutex<Option<oneshot::Receiver<()>>>,
}

impl StubExecutionProvider {
    pub(super) fn set_finalized(&self, number: u64, hash: B256, round: Round) {
        *self.inner.finalized.lock() = BlockNumHash::new(number, hash);
        *self.inner.finalized_round.lock() = Some(round);
    }

    /// Models a finalized execution header from before TIP-1031, when headers
    /// had no consensus context and therefore no round.
    pub(super) fn set_prefork_finalized(&self, number: u64, hash: B256) {
        *self.inner.finalized.lock() = BlockNumHash::new(number, hash);
        *self.inner.finalized_round.lock() = None;
    }

    pub(super) fn set_durable(&self, height: u64, hash: B256) {
        self.inner.durable.lock().insert(height, hash);
    }

    pub(super) fn fail_durable_reads(&self) {
        self.inner.fail_durable_reads.store(true, Ordering::SeqCst);
    }

    pub(super) fn reject_payloads(&self) {
        self.inner.reject_payloads.store(true, Ordering::SeqCst);
    }

    pub(super) fn sync_payloads(&self, count: usize) {
        self.inner.syncing_payloads.store(count, Ordering::SeqCst);
    }

    pub(super) fn sync_forkchoices(&self, count: usize) {
        self.inner
            .syncing_forkchoices
            .store(count, Ordering::SeqCst);
    }

    pub(super) fn sync_readiness_probes(&self, count: usize) {
        self.inner
            .syncing_readiness_probes
            .store(count, Ordering::SeqCst);
    }

    pub(super) fn readiness_probes(&self) -> usize {
        self.inner.readiness_probes.load(Ordering::SeqCst)
    }

    pub(super) fn reject_forkchoices(&self) {
        self.inner.reject_forkchoices.store(true, Ordering::SeqCst);
    }

    pub(super) fn pause_next_forkchoice(&self) -> oneshot::Sender<()> {
        let (release, gate) = oneshot::channel();
        *self.inner.forkchoice_gate.lock() = Some(gate);
        release
    }

    pub(super) fn payload_count(&self) -> usize {
        self.inner.payloads.load(Ordering::SeqCst)
    }

    pub(super) fn forkchoices(&self) -> Vec<ForkchoiceState> {
        self.inner.forkchoices.lock().clone()
    }
}

impl FinalizedBlockProvider for StubExecutionProvider {
    fn finalized_num_hash(&self) -> eyre::Result<BlockNumHash> {
        Ok(*self.inner.finalized.lock())
    }

    fn finalized_header(&self) -> eyre::Result<SealedHeader<TempoHeader>> {
        let tip = *self.inner.finalized.lock();
        let consensus_context =
            self.inner
                .finalized_round
                .lock()
                .map(|round| TempoConsensusContext {
                    epoch: round.epoch().get(),
                    view: round.view().get(),
                    parent_view: 0,
                    proposer: PublicKey::from_seed(0),
                });
        Ok(SealedHeader::new(
            TempoHeader {
                inner: Header {
                    number: tip.number,
                    ..Default::default()
                },
                consensus_context,
                ..Default::default()
            },
            tip.hash,
        ))
    }

    fn durable_block_hash(&self, height: u64) -> eyre::Result<Option<B256>> {
        if self.inner.fail_durable_reads.load(Ordering::SeqCst) {
            eyre::bail!("durable block read failed");
        }
        Ok(self.inner.durable.lock().get(&height).copied())
    }
}

impl ExecutionEngine for StubExecutionProvider {
    fn new_payload(
        &self,
        _payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static {
        self.inner.payloads.fetch_add(1, Ordering::SeqCst);
        let rejected = self.inner.reject_payloads.load(Ordering::SeqCst);
        let syncing = self
            .inner
            .syncing_payloads
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        async move {
            let status = if rejected {
                PayloadStatusEnum::Invalid {
                    validation_error: "rejected by test provider".into(),
                }
            } else if syncing {
                PayloadStatusEnum::Syncing
            } else {
                PayloadStatusEnum::Valid
            };
            Ok(PayloadStatus::from_status(status))
        }
    }

    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        _attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static {
        if !self.inner.readiness_complete.load(Ordering::SeqCst) {
            self.inner.readiness_probes.fetch_add(1, Ordering::SeqCst);
            let syncing = self
                .inner
                .syncing_readiness_probes
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            if !syncing {
                self.inner.readiness_complete.store(true, Ordering::SeqCst);
            }
            return Either::Left(async move {
                Ok(ForkchoiceUpdated::from_status(if syncing {
                    PayloadStatusEnum::Syncing
                } else {
                    PayloadStatusEnum::Valid
                }))
            });
        }

        self.inner.forkchoices.lock().push(state);
        let gate = self.inner.forkchoice_gate.lock().take();
        let rejected = self.inner.reject_forkchoices.load(Ordering::SeqCst);
        let syncing = self
            .inner
            .syncing_forkchoices
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        Either::Right(async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            let status = if rejected {
                PayloadStatusEnum::Invalid {
                    validation_error: "rejected by test engine".into(),
                }
            } else if syncing {
                PayloadStatusEnum::Syncing
            } else {
                PayloadStatusEnum::Valid
            };
            Ok(ForkchoiceUpdated::from_status(status))
        })
    }
}

#[derive(Clone, Default)]
pub(super) struct StubMarshal {
    floor: Arc<AtomicU64>,
    blocks: Arc<Mutex<HashMap<u64, Block>>>,
}

impl StubMarshal {
    pub(super) fn floor(&self) -> Height {
        Height::new(self.floor.load(Ordering::SeqCst))
    }

    pub(super) fn set_block(&self, block: Block) {
        self.blocks.lock().insert(block.height().get(), block);
    }
}

impl Marshal for StubMarshal {
    type Finalization = Height;

    async fn get_block(&self, height: Height) -> Option<Block> {
        self.blocks.lock().get(&height.get()).cloned()
    }

    async fn get_finalization(&self, height: Height) -> Option<Self::Finalization> {
        Some(height)
    }

    fn set_floor(&self, height: Self::Finalization) {
        let floor = self.floor.clone();
        floor.fetch_max(height.get(), Ordering::SeqCst);
    }
}
