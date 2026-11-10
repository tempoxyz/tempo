use crate::Node;
use eyre::Result;
use reth_provider::{ProviderFactory, SaveBlocksInput};
use std::{
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

/// The driver may produce blocks while running, but must drain both frontiers when flushing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Threshold saves may lag the head and mask recent state.
    Running,
    /// All input is executed; wait for saves and flush unmasked state to the head.
    Flushing,
}

/// One background database writer with at most one unacknowledged save.
pub(crate) struct Persistence {
    requests: mpsc::SyncSender<SaveBlocksInput>,
    acknowledgements: mpsc::Receiver<Result<()>>,
    writer: JoinHandle<()>,
    state: WriteState,
}

impl Persistence {
    /// Start the same bounded writer used for both threshold saves and the final flush.
    pub(crate) fn new(factory: ProviderFactory<Node>) -> Self {
        let (requests, request_rx) = mpsc::sync_channel::<SaveBlocksInput>(1);
        let (ack_tx, acknowledgements) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            while let Ok(input) = request_rx.recv() {
                let result = (|| -> Result<()> {
                    let provider = factory.provider_rw()?;
                    provider.save_blocks(&input)?;
                    provider.commit()?;
                    Ok(())
                })();
                if ack_tx.send(result).is_err() {
                    break;
                }
            }
        });
        Self { requests, acknowledgements, writer, state: WriteState::Idle }
    }

    /// Whether a new save can be submitted without overlapping an unacknowledged commit.
    pub(crate) const fn is_idle(&self) -> bool {
        matches!(self.state, WriteState::Idle)
    }

    /// Submit a save without advancing the driver's durable frontiers.
    pub(crate) fn save(
        &mut self,
        input: SaveBlocksInput,
        db_tip: u64,
        state_tip: u64,
    ) -> Result<()> {
        self.requests.send(input)?;
        self.state = WriteState::InFlight { db_tip, state_tip };
        Ok(())
    }

    /// Poll a pending commit, or wait up to the timeout during backpressure and final flushing.
    /// Only a successful acknowledgement returns the frontiers safe to verify and prune.
    pub(crate) fn acknowledge(
        &mut self,
        wait: bool,
        timeout: Duration,
    ) -> Result<Option<(u64, u64)>> {
        let WriteState::InFlight { db_tip, state_tip } = self.state else { return Ok(None) };
        let result = if wait {
            Some(self.acknowledgements.recv_timeout(timeout)?)
        } else {
            match self.acknowledgements.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    eyre::bail!("persistence worker disconnected")
                }
            }
        };
        if let Some(result) = result {
            result?;
            self.state = WriteState::Idle;
            return Ok(Some((db_tip, state_tip)));
        }
        Ok(None)
    }

    /// Close the request channel and join the writer after all saves have been acknowledged.
    pub(crate) fn finish(self) -> Result<()> {
        drop(self.requests);
        self.writer.join().map_err(|_| eyre::eyre!("persistence worker panicked"))?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum WriteState {
    Idle,
    InFlight { db_tip: u64, state_tip: u64 },
}
