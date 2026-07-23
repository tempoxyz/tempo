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
use commonware_consensus::types::Height;
use futures::channel::oneshot;
use parking_lot::Mutex;
use reth_ethereum::rpc::eth::primitives::BlockNumHash;
use reth_node_core::primitives::SealedBlock;
use tempo_node::TempoExecutionData;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::super::{ExecutionEngine, FinalizedBlockProvider, Marshal};
use crate::consensus::block::Block;

pub(super) fn make_block(height: u64, parent_hash: B256) -> Block {
    let header = TempoHeader {
        inner: Header {
            parent_hash,
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

#[derive(Clone, Default)]
pub(super) struct StubExecutionProvider {
    inner: Arc<StubExecutionProviderInner>,
}

#[derive(Default)]
struct StubExecutionProviderInner {
    finalized: Mutex<BlockNumHash>,
    durable: Mutex<HashMap<u64, B256>>,
    fail_durable_reads: AtomicBool,
    payloads: AtomicUsize,
    forkchoices: Mutex<Vec<ForkchoiceState>>,
    reject_payloads: AtomicBool,
    reject_forkchoices: AtomicBool,
    forkchoice_gate: Mutex<Option<oneshot::Receiver<()>>>,
}

impl StubExecutionProvider {
    pub(super) fn set_finalized(&self, number: u64, hash: B256) {
        *self.inner.finalized.lock() = BlockNumHash::new(number, hash);
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
    fn finalized_block_num_hash(&self) -> eyre::Result<BlockNumHash> {
        Ok(*self.inner.finalized.lock())
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
        async move {
            let status = if rejected {
                PayloadStatusEnum::Invalid {
                    validation_error: "rejected by test provider".into(),
                }
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
        self.inner.forkchoices.lock().push(state);
        let gate = self.inner.forkchoice_gate.lock().take();
        let rejected = self.inner.reject_forkchoices.load(Ordering::SeqCst);
        async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            let status = if rejected {
                PayloadStatusEnum::Invalid {
                    validation_error: "rejected by test engine".into(),
                }
            } else {
                PayloadStatusEnum::Valid
            };
            Ok(ForkchoiceUpdated::from_status(status))
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct StubMarshal {
    floor: Arc<AtomicU64>,
}

impl StubMarshal {
    pub(super) fn floor(&self) -> Height {
        Height::new(self.floor.load(Ordering::SeqCst))
    }
}

impl Marshal for StubMarshal {
    fn set_floor(&self, height: Height) -> impl Future<Output = ()> + Send {
        let floor = self.floor.clone();
        async move {
            floor.fetch_max(height.get(), Ordering::SeqCst);
        }
    }
}
