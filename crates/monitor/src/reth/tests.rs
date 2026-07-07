use alloy_primitives::{Address, B256};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use tempo_hardfork::TempoHardfork;

use crate::{
    facts::{BlockFacts, BlockNumHash, BlockWithParent, HeaderFacts},
    processor::FinalizedBlockInput,
    reth::*,
    store::{BootstrapPolicy, InMemoryMonitorStore, MonitorStore},
};

fn b(n: u8) -> B256 {
    B256::repeat_byte(n)
}

fn block(number: u64) -> BlockNumHash {
    BlockNumHash {
        number,
        hash: b(number as u8),
    }
}

fn input(number: u64) -> FinalizedBlockInput {
    let head = block(number);
    let parent = if number == 0 {
        B256::ZERO
    } else {
        b(number as u8 - 1)
    };
    let reference = BlockWithParent::new(parent, head);
    FinalizedBlockInput {
        reference,
        block_facts: BlockFacts {
            reference,
            hardfork: TempoHardfork::Genesis,
            header: HeaderFacts {
                timestamp: number,
                timestamp_millis: number * 1000,
                gas_used: 0,
                gas_limit: 1,
                general_gas_limit: 1,
                shared_gas_limit: 0,
                base_fee_per_gas: None,
                beneficiary: Address::ZERO,
                consensus_context: None,
            },
        },
        tx_facts: vec![],
        receipt_facts: vec![],
        ordered_logs: vec![],
    }
}

#[derive(Clone)]
struct FakeSource {
    watermark: Option<BlockNumHash>,
    inputs: BTreeMap<u64, FinalizedBlockInput>,
    canonical: Rc<RefCell<bool>>,
}

impl FakeSource {
    fn through(n: u64) -> Self {
        Self {
            watermark: Some(block(n)),
            inputs: (0..=n).map(|i| (i, input(i))).collect(),
            canonical: Rc::new(RefCell::new(true)),
        }
    }
}

impl FinalizedBlockSource for FakeSource {
    fn finalized_watermark(&self) -> AdapterResult<Option<BlockNumHash>> {
        Ok(self.watermark)
    }

    fn finalized_block_by_number(&self, number: u64) -> AdapterResult<BlockNumHash> {
        self.inputs
            .get(&number)
            .map(FinalizedBlockInput::block)
            .ok_or_else(|| AdapterError::Retry(format!("missing block {number}")))
    }

    fn block_input(&self, block: BlockNumHash) -> AdapterResult<FinalizedBlockInput> {
        self.inputs
            .get(&block.number)
            .filter(|input| input.block() == block)
            .cloned()
            .ok_or_else(|| AdapterError::Retry(format!("missing block input {block:?}")))
    }

    fn is_known_canonical(&self, _block: BlockNumHash) -> AdapterResult<bool> {
        Ok(*self.canonical.borrow())
    }
}

#[derive(Clone, Default)]
struct FakeSink(Rc<RefCell<Vec<BlockNumHash>>>);

impl FinishedHeightSink for FakeSink {
    fn send_finished_height(&self, block: BlockNumHash) -> AdapterResult<()> {
        self.0.borrow_mut().push(block);
        Ok(())
    }
}

#[test]
fn commits_finalized_range_and_finishes_after_commit() -> eyre::Result<()> {
    let store = InMemoryMonitorStore::new();
    let sink = FakeSink::default();
    let sent = sink.0.clone();
    let mut loop_ = FinalizedLoop::new(store, FakeSource::through(2), sink);

    assert_eq!(loop_.tick()?, 3);
    assert_eq!(loop_.store().monitor_head()?, Some(block(2)));
    assert_eq!(*sent.borrow(), vec![block(0), block(1), block(2)]);
    Ok(())
}

#[test]
fn startup_acknowledges_existing_head_without_recommit() -> eyre::Result<()> {
    let store = InMemoryMonitorStore::new();
    store.commit_block(crate::processor::FinalizedBlockProcessor.build_commit(input(0), None)?)?;
    let sink = FakeSink::default();
    let sent = sink.0.clone();
    let mut loop_ = FinalizedLoop::new(store, FakeSource::through(0), sink);

    assert_eq!(loop_.tick()?, 0);
    assert_eq!(*sent.borrow(), vec![block(0)]);
    Ok(())
}

#[test]
fn missing_input_retries_without_head_advancement_or_finish() -> eyre::Result<()> {
    let store = InMemoryMonitorStore::new();
    let sink = FakeSink::default();
    let sent = sink.0.clone();
    let mut source = FakeSource::through(1);
    source.inputs.remove(&0);
    let mut loop_ = FinalizedLoop::new(store, source, sink);

    let err = loop_.tick().expect_err("tick should retry");
    assert!(err.is_retry());
    assert_eq!(loop_.store().monitor_head()?, None);
    assert!(sent.borrow().is_empty());
    Ok(())
}

#[test]
fn bootstrap_policy_blocks_arbitrary_empty_start() -> eyre::Result<()> {
    let store = InMemoryMonitorStore::with_bootstrap_policy(BootstrapPolicy::StartAt(block(1)));
    let sink = FakeSink::default();
    let mut loop_ = FinalizedLoop::new(store, FakeSource::through(1), sink);

    let err = loop_.tick().expect_err("tick should halt");
    assert!(err.is_halt());
    assert_eq!(loop_.store().monitor_head()?, None);
    Ok(())
}

#[test]
fn non_canonical_existing_head_halts_before_finish() -> eyre::Result<()> {
    let store = InMemoryMonitorStore::new();
    store.commit_block(crate::processor::FinalizedBlockProcessor.build_commit(input(0), None)?)?;
    let source = FakeSource::through(0);
    *source.canonical.borrow_mut() = false;
    let sink = FakeSink::default();
    let sent = sink.0.clone();
    let mut loop_ = FinalizedLoop::new(store, source, sink);

    let err = loop_.tick().expect_err("tick should halt");
    assert!(err.is_halt());
    assert!(sent.borrow().is_empty());
    Ok(())
}

#[test]
fn watermark_hash_change_halts() -> eyre::Result<()> {
    let mut watermark = FinalizedWatermark::new();
    watermark.observe(Some(block(1)))?;
    let err = watermark
        .observe(Some(BlockNumHash {
            number: 1,
            hash: b(9),
        }))
        .expect_err("hash change should halt");
    assert!(err.is_halt());
    Ok(())
}
