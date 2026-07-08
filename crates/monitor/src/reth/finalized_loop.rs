use crate::{
    input::facts::BlockNumHash,
    processor::{FinalizedBlockInput, FinalizedBlockProcessor},
    store::{MonitorStore, SchemaStatus},
};
use tracing::{debug, info};

use super::{AdapterError, AdapterResult, FinalizedWatermark};

pub trait FinalizedBlockSource {
    fn finalized_watermark(&self) -> AdapterResult<Option<BlockNumHash>>;
    fn finalized_block_by_number(&self, number: u64) -> AdapterResult<BlockNumHash>;
    fn block_input(&self, block: BlockNumHash) -> AdapterResult<FinalizedBlockInput>;
    fn is_known_canonical(&self, block: BlockNumHash) -> AdapterResult<bool>;
}

pub trait FinishedHeightSink {
    fn send_finished_height(&self, block: BlockNumHash) -> AdapterResult<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedLoopConfig {
    pub acknowledge_existing_head_on_startup: bool,
    pub max_blocks_per_tick: usize,
}

impl Default for FinalizedLoopConfig {
    fn default() -> Self {
        Self {
            acknowledge_existing_head_on_startup: true,
            max_blocks_per_tick: usize::MAX,
        }
    }
}

pub struct FinalizedLoop<S, P, F> {
    store: S,
    source: P,
    finished: F,
    processor: FinalizedBlockProcessor,
    config: FinalizedLoopConfig,
    watermark: FinalizedWatermark,
    started: bool,
}

impl<S, P, F> FinalizedLoop<S, P, F>
where
    S: MonitorStore,
    P: FinalizedBlockSource,
    F: FinishedHeightSink,
{
    pub fn new(store: S, source: P, finished: F) -> Self {
        Self::with_config(store, source, finished, FinalizedLoopConfig::default())
    }

    pub fn with_config(store: S, source: P, finished: F, config: FinalizedLoopConfig) -> Self {
        Self {
            store,
            source,
            finished,
            processor: FinalizedBlockProcessor,
            config,
            watermark: FinalizedWatermark::new(),
            started: false,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn tick(&mut self) -> AdapterResult<usize> {
        self.startup_once()?;
        let previous_watermark = self.watermark.last();
        let observed_watermark = self.source.finalized_watermark()?;
        if let Some(watermark) = observed_watermark {
            if previous_watermark != Some(watermark) {
                info!(
                    finalized_number = watermark.number,
                    finalized_hash = ?watermark.hash,
                    "monitor finalized watermark observed"
                );
            } else {
                debug!(
                    finalized_number = watermark.number,
                    finalized_hash = ?watermark.hash,
                    "monitor finalized watermark unchanged"
                );
            }
        } else {
            debug!("monitor finalized watermark unavailable");
        }
        let target = self.watermark.observe(observed_watermark)?;
        let Some(target) = target else {
            return Ok(0);
        };

        let mut processed = 0usize;
        loop {
            if processed >= self.config.max_blocks_per_tick {
                break;
            }
            let head = self.store.monitor_head()?;
            if let Some(head) = head {
                if head.number >= target.number {
                    break;
                }
                if !self.source.is_known_canonical(head)? {
                    return Err(AdapterError::Halt(format!(
                        "durable monitor head is not known canonical: {head:?}"
                    )));
                }
            }
            let next_number = head.map_or(0, |h| h.number + 1);
            if next_number > target.number {
                break;
            }
            let next = self.source.finalized_block_by_number(next_number)?;
            if next_number == target.number && next != target {
                return Err(AdapterError::Halt(format!(
                    "finalized target mismatch: source returned {next:?}, target is {target:?}"
                )));
            }
            let input = self.source.block_input(next)?;
            let committed = self.processor.process_and_commit(&self.store, input)?;
            let durable = self.store.monitor_head()?;
            if durable.is_none_or(|head| head.number < committed.number) {
                return Err(AdapterError::Halt(
                    "commit succeeded but durable monitor head did not advance".into(),
                ));
            }
            self.finished.send_finished_height(committed)?;
            info!(
                block_number = committed.number,
                block_hash = ?committed.hash,
                "monitor FinishedHeight emitted"
            );
            processed += 1;
        }
        Ok(processed)
    }

    fn startup_once(&mut self) -> AdapterResult<()> {
        if self.started {
            return Ok(());
        }
        self.started = true;
        match self.store.schema_status()? {
            SchemaStatus::Ready { .. } => {}
            status => {
                return Err(AdapterError::Halt(format!(
                    "monitor store schema is not ready: {status:?}"
                )));
            }
        }
        if self.config.acknowledge_existing_head_on_startup
            && let Some(head) = self.store.monitor_head()?
        {
            if !self.source.is_known_canonical(head)? {
                return Err(AdapterError::Halt(format!(
                    "durable monitor head is not known canonical: {head:?}"
                )));
            }
            self.finished.send_finished_height(head)?;
            info!(
                block_number = head.number,
                block_hash = ?head.hash,
                "monitor FinishedHeight emitted for existing durable head"
            );
        }
        Ok(())
    }
}
