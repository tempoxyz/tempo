//! Fuzz harness for Tempo Zone block execution.
//!
//! A [`ZoneCase`] describes a zone on one Tempo hardfork, the Tempo L1 state it reads at its
//! anchor (the portal's transfer opt-in, pathUSD's pause flag and registered TIP-1022 masters)
//! and the user transactions of up to [`input::MAX_BLOCKS`] zone blocks. [`run`] builds the
//! complete witness for that batch, executes it with the stateless proof function
//! ([`zone_spf::prove_zone_batch_with_observer`]), the same code that proves zone batches, and
//! checks the receipts and state changes against the T15 invariants in [`invariants`].
//!
//! The proof function only sees state the witness proves, so a missing L1 or zone read surfaces
//! as an error instead of a silent default.

pub mod input;
pub mod invariants;
pub mod witness;

use alloy_primitives::{Address, B256, U256};
use tempo_primitives::TempoReceipt;
use zone_spf::{BatchObserver, BatchOutput, Error as SpfError};

pub use input::ZoneCase;
pub use invariants::Violation;
pub use witness::Fixture;

/// What one executed zone block left behind.
#[derive(Debug, Clone)]
pub struct BlockRecord {
    /// The block's receipts, including its system transactions.
    pub receipts: Vec<TempoReceipt>,
    /// pathUSD balances whose storage the block changed, keyed by account, with their new values.
    pub balances: Vec<(Address, U256)>,
}

/// The result of running one case.
#[derive(Debug)]
pub struct Outcome {
    /// What the proof function returned.
    pub result: Result<BatchOutput, SpfError>,
    /// Each executed block, in order.
    pub blocks: Vec<BlockRecord>,
    /// The calls that were sent, block by block, after dropping those the batch could not include.
    pub sent: Vec<Vec<witness::SentCall>>,
    /// Broken invariants. Empty for a passing case.
    pub violations: Vec<Violation>,
}

impl Outcome {
    /// Whether any invariant broke.
    pub fn failed(&self) -> bool {
        !self.violations.is_empty()
    }
}

/// Most times [`run`] drops a user transaction the batch could not include and retries.
const MAX_RETRIES: usize = 16;

/// Runs `case` as one proven batch and checks its invariants.
///
/// A user transaction the zone would refuse to include (such as one whose fee the sender can no
/// longer pay) makes the whole batch invalid, as it would for a sequencer. The harness drops it
/// and runs the batch again, so one refused transaction does not hide the rest of the case.
pub fn run(case: &ZoneCase) -> Outcome {
    let mut dropped = Vec::new();
    loop {
        let fixture = Fixture::new(case, &dropped);
        let mut observer = Recorder::new(&fixture);
        let result = zone_spf::prove_zone_batch_with_observer(
            fixture.config(),
            fixture.witness(),
            &mut observer,
        );
        if let Err(SpfError::TransactionExecution {
            block_index,
            transaction_index,
        }) = &result
            && dropped.len() < MAX_RETRIES
            && let Some(call) = fixture.call_at(*block_index, *transaction_index)
        {
            dropped.push(call);
            continue;
        }
        let sent = fixture.sent().to_vec();
        let violations = invariants::check(case, &fixture, &result, &observer.blocks);
        return Outcome {
            result,
            blocks: observer.blocks,
            sent,
            violations,
        };
    }
}

/// Records each block's receipts and changed pathUSD balances.
struct Recorder {
    /// Every account whose balance an invariant reads, with its balance slot.
    tracked: Vec<(Address, U256)>,
    blocks: Vec<BlockRecord>,
}

impl Recorder {
    fn new(fixture: &Fixture) -> Self {
        Self {
            tracked: fixture
                .tracked_accounts()
                .into_iter()
                .map(|account| (account, witness::balance_slot(account)))
                .collect(),
            blocks: Vec::new(),
        }
    }
}

impl BatchObserver for Recorder {
    fn on_block(
        &mut self,
        _block_index: usize,
        output: &reth_execution_types::BlockExecutionOutput<TempoReceipt>,
    ) {
        let balances = self
            .tracked
            .iter()
            .filter_map(|(account, slot)| {
                output
                    .storage(&tempo_precompiles::PATH_USD_ADDRESS, *slot)
                    .map(|value| (*account, value))
            })
            .collect();
        self.blocks.push(BlockRecord {
            receipts: output.result.receipts.clone(),
            balances,
        });
    }
}

/// The key `index` signs with.
fn signer_key(index: usize) -> B256 {
    B256::with_last_byte(u8::try_from(index + 1).expect("few signers"))
}
