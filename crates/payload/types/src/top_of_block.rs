//! The privileged top-of-block lane.
//!
//! Consensus opens the lane for a round when this node starts proposing it.
//! Authenticated top-of-block operators submit signed transactions for that
//! round until the lane's window elapses, also before the lane opens: they
//! compute upcoming leaders from consensus certificates. The payload builder takes the
//! lane after its start-of-block system work and executes the taken
//! transactions before any transaction from the pool.
//!
//! A slot is keyed by the maker (the recovered signer) and the transaction's
//! nonce key, so a maker can quote several markets independently by using a
//! nonce key per market. Ethereum transactions use nonce key zero.
//!
//! Each submission carries a replacement sequence. It replaces the slot's
//! transaction only if its sequence is higher, so the latest quote wins
//! regardless of arrival order, and the slot keeps its position in the prefix.
//! Slots are ordered by the time they were first filled in the round.
//!
//! A submission may carry an expiry. The builder drops it unless the block's
//! timestamp is before the expiry.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, B256, U256};
use reth_primitives_traits::Recovered;
use tempo_primitives::TempoTxEnvelope;

/// Limits an operator is held to within one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopOfBlockLimits {
    /// Maximum number of slots the operator may hold.
    pub max_txs: usize,
    /// Maximum sum of gas limits over the operator's slots.
    pub max_gas: u64,
}

/// A transaction submitted to the lane.
#[derive(Debug, Clone)]
pub struct TopOfBlockSubmission {
    pub tx: Recovered<TempoTxEnvelope>,
    /// Replacement sequence within the transaction's slot; higher wins.
    pub seq: u64,
    /// Unix time in milliseconds at which the submission expires; zero never
    /// expires.
    pub expires_at_ms: u64,
}

/// The lane slot of a transaction: its maker and nonce key.
pub fn top_of_block_slot(tx: &Recovered<TempoTxEnvelope>) -> (Address, U256) {
    (tx.signer(), tx.nonce_key().unwrap_or_default())
}

/// Result of a submission to an open round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TopOfBlockSubmitOutcome {
    /// Transactions that filled a new slot.
    pub accepted: u32,
    /// Transactions that replaced their slot's transaction.
    pub replaced: u32,
    /// Transactions dropped because of the operator's limits, because another
    /// operator holds the slot, or because the slot already holds an equal or
    /// higher sequence.
    pub rejected: u32,
    /// Time since the round was opened.
    pub since_open: Duration,
}

/// Why a submission was refused as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TopOfBlockSubmitError {
    /// This node is not building the round.
    #[error("the lane is not open for this round")]
    NotOpen,
    /// The builder already took the lane for this round.
    #[error("the lane was already taken by the builder")]
    Closed,
}

/// Maximum number of rounds that hold submissions before this node opens them.
const MAX_PENDING_ROUNDS: usize = 4;

/// Handle to the lane, shared by consensus and the payload builder.
///
/// A default lane is never opened, so the builder takes nothing from it.
#[derive(Debug, Clone, Default)]
pub struct TopOfBlockLane {
    inner: Arc<Mutex<LaneState>>,
}

#[derive(Debug, Default)]
struct LaneState {
    /// Rounds by `(epoch, view)`: the round this node opened last, and rounds
    /// that operators submitted to before this node opened them.
    rounds: BTreeMap<(u64, u64), LaneRound>,
    /// The latest round this node opened. Earlier rounds are discarded.
    latest_opened: Option<(u64, u64)>,
}

#[derive(Debug, Default)]
struct LaneRound {
    /// When this node opened the round and when the builder takes it; `None`
    /// while operators submit ahead of the round.
    opened: Option<(Instant, Instant)>,
    /// Whether the builder took the round.
    taken: bool,
    slots: Vec<Slot>,
    slot_index: HashMap<(Address, U256), usize>,
    usage_by_operator: HashMap<B256, (usize, u64)>,
}

#[derive(Debug)]
struct Slot {
    operator: B256,
    submission: TopOfBlockSubmission,
}

impl TopOfBlockLane {
    /// Opens the lane for `(epoch, view)`, keeping what operators already
    /// submitted to this round and discarding earlier rounds.
    ///
    /// Submissions are accepted until the builder takes the lane. The builder
    /// waits for `window` after opening before it takes the lane.
    pub fn open(&self, epoch: u64, view: u64, window: Duration) {
        let now = Instant::now();
        let mut state = self.lock();
        let key = (epoch, view);
        state.latest_opened = state.latest_opened.max(Some(key));
        state.rounds = state.rounds.split_off(&key);
        let round = state.rounds.entry(key).or_default();
        if round.taken {
            // A rebuild of a round starts from an empty lane.
            *round = LaneRound::default();
        }
        round.opened = Some((now, now + window));
    }

    /// Adds `submissions` from `operator` to round `(epoch, view)`.
    ///
    /// Operators compute upcoming leaders from consensus certificates, so a
    /// submission may arrive before this node opens the round. Such rounds are
    /// kept until opened, up to a small number of rounds ahead.
    pub fn submit(
        &self,
        epoch: u64,
        view: u64,
        operator: B256,
        limits: TopOfBlockLimits,
        submissions: impl IntoIterator<Item = TopOfBlockSubmission>,
    ) -> Result<TopOfBlockSubmitOutcome, TopOfBlockSubmitError> {
        let mut state = self.lock();
        let key = (epoch, view);
        if state.latest_opened.is_some_and(|latest| key < latest) {
            return Err(TopOfBlockSubmitError::NotOpen);
        }
        if !state.rounds.contains_key(&key) && state.rounds.len() >= MAX_PENDING_ROUNDS {
            return Err(TopOfBlockSubmitError::NotOpen);
        }
        let round = state.rounds.entry(key).or_default();
        if round.taken {
            return Err(TopOfBlockSubmitError::Closed);
        }

        let mut outcome = TopOfBlockSubmitOutcome {
            since_open: round
                .opened
                .map(|(opened_at, _)| opened_at.elapsed())
                .unwrap_or_default(),
            ..Default::default()
        };
        for submission in submissions {
            let key = top_of_block_slot(&submission.tx);
            let gas = submission.tx.gas_limit();
            let (slots, used_gas) = round
                .usage_by_operator
                .get(&operator)
                .copied()
                .unwrap_or_default();
            match round.slot_index.get(&key).copied() {
                Some(index) => {
                    let slot = &mut round.slots[index];
                    let old_gas = slot.submission.tx.gas_limit();
                    if slot.operator != operator
                        || submission.seq <= slot.submission.seq
                        || used_gas - old_gas + gas > limits.max_gas
                    {
                        outcome.rejected += 1;
                        continue;
                    }
                    slot.submission = submission;
                    round
                        .usage_by_operator
                        .insert(operator, (slots, used_gas - old_gas + gas));
                    outcome.replaced += 1;
                }
                None => {
                    if slots >= limits.max_txs || used_gas + gas > limits.max_gas {
                        outcome.rejected += 1;
                        continue;
                    }
                    round.slot_index.insert(key, round.slots.len());
                    round.slots.push(Slot {
                        operator,
                        submission,
                    });
                    round
                        .usage_by_operator
                        .insert(operator, (slots + 1, used_gas + gas));
                    outcome.accepted += 1;
                }
            }
        }
        Ok(outcome)
    }

    /// Waits until the window of round `(epoch, view)` elapses, then closes the
    /// round and returns its transactions in prefix order, without those
    /// expired at `block_timestamp_ms`.
    ///
    /// Returns nothing if this node did not open the round.
    pub fn take(
        &self,
        epoch: u64,
        view: u64,
        block_timestamp_ms: u64,
    ) -> Vec<Recovered<TempoTxEnvelope>> {
        let key = (epoch, view);
        let deadline = match self.lock().rounds.get(&key) {
            Some(LaneRound {
                opened: Some((_, deadline)),
                taken: false,
                ..
            }) => *deadline,
            _ => return Vec::new(),
        };
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));

        let mut state = self.lock();
        let Some(round) = state
            .rounds
            .get_mut(&key)
            .filter(|round| round.opened.is_some() && !round.taken)
        else {
            return Vec::new();
        };
        let txs: Vec<_> = round
            .slots
            .drain(..)
            .map(|slot| slot.submission)
            .filter(|submission| {
                submission.expires_at_ms == 0 || block_timestamp_ms < submission.expires_at_ms
            })
            .map(|submission| submission.tx)
            .collect();
        round.taken = true;
        txs
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LaneState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::Signature;

    const LIMITS: TopOfBlockLimits = TopOfBlockLimits {
        max_txs: 2,
        max_gas: 100_000,
    };

    fn quote(maker: u8, gas: u64, seq: u64) -> TopOfBlockSubmission {
        let tx = TxLegacy {
            gas_limit: gas,
            value: U256::from(seq),
            ..Default::default()
        };
        TopOfBlockSubmission {
            tx: Recovered::new_unchecked(
                TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature())),
                Address::repeat_byte(maker),
            ),
            seq,
            expires_at_ms: 0,
        }
    }

    #[test]
    fn highest_sequence_wins_and_keeps_the_slots_first_position() {
        let lane = TopOfBlockLane::default();
        let operator = B256::repeat_byte(1);
        lane.open(0, 7, Duration::ZERO);

        lane.submit(
            0,
            7,
            operator,
            LIMITS,
            [quote(1, 21_000, 5), quote(2, 21_000, 1)],
        )
        .unwrap();
        // A newer quote replaces maker 1's; an older one arriving later does
        // not; maker 3 exceeds the slot limit.
        let outcome = lane
            .submit(
                0,
                7,
                operator,
                LIMITS,
                [
                    quote(1, 21_000, 7),
                    quote(1, 21_000, 6),
                    quote(3, 21_000, 1),
                ],
            )
            .unwrap();
        assert_eq!(
            (outcome.accepted, outcome.replaced, outcome.rejected),
            (0, 1, 2)
        );

        let taken = lane.take(0, 7, 0);
        let got: Vec<_> = taken.iter().map(|tx| (tx.signer(), tx.value())).collect();
        assert_eq!(
            got,
            [
                (Address::repeat_byte(1), U256::from(7)),
                (Address::repeat_byte(2), U256::from(1))
            ]
        );
    }

    #[test]
    fn submissions_expire_at_the_block_timestamp() {
        let lane = TopOfBlockLane::default();
        let operator = B256::repeat_byte(1);
        lane.open(0, 7, Duration::ZERO);
        let (mut expiring, mut live) = (quote(1, 21_000, 1), quote(2, 21_000, 1));
        expiring.expires_at_ms = 1_000;
        live.expires_at_ms = 1_001;
        lane.submit(0, 7, operator, LIMITS, [expiring, live])
            .unwrap();

        let taken = lane.take(0, 7, 1_000);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].signer(), Address::repeat_byte(2));
    }

    #[test]
    fn submissions_ahead_of_a_round_are_kept_until_it_opens() {
        let lane = TopOfBlockLane::default();
        let operator = B256::repeat_byte(1);
        lane.submit(0, 7, operator, LIMITS, [quote(1, 21_000, 1)])
            .unwrap();
        assert!(lane.take(0, 7, 0).is_empty(), "not opened by this node");
        // Rounds further ahead are bounded.
        for view in 8..=10 {
            lane.submit(0, view, operator, LIMITS, [quote(1, 21_000, 1)])
                .unwrap();
        }
        assert_eq!(
            lane.submit(0, 11, operator, LIMITS, [quote(1, 21_000, 1)]),
            Err(TopOfBlockSubmitError::NotOpen)
        );

        lane.open(0, 7, Duration::ZERO);
        lane.submit(0, 7, operator, LIMITS, [quote(2, 21_000, 1)])
            .unwrap();
        let taken = lane.take(0, 7, 0);
        let makers: Vec<_> = taken.iter().map(|tx| tx.signer()).collect();
        assert_eq!(makers, [Address::repeat_byte(1), Address::repeat_byte(2)]);

        // Opening a later round discards earlier ones.
        lane.open(0, 9, Duration::ZERO);
        assert_eq!(
            lane.submit(0, 8, operator, LIMITS, [quote(1, 21_000, 2)]),
            Err(TopOfBlockSubmitError::NotOpen)
        );
        assert_eq!(lane.take(0, 9, 0).len(), 1);
    }

    #[test]
    fn lane_accepts_its_round_until_taken() {
        let lane = TopOfBlockLane::default();
        let (operator, other) = (B256::repeat_byte(1), B256::repeat_byte(2));
        lane.open(0, 7, Duration::ZERO);
        assert_eq!(
            lane.submit(0, 6, operator, LIMITS, [quote(1, 21_000, 1)]),
            Err(TopOfBlockSubmitError::NotOpen)
        );
        // Gas is limited per operator, and a slot belongs to the operator that
        // filled it.
        let outcome = lane
            .submit(
                0,
                7,
                operator,
                LIMITS,
                [quote(1, 90_000, 1), quote(2, 21_000, 1)],
            )
            .unwrap();
        assert_eq!((outcome.accepted, outcome.rejected), (1, 1));
        let outcome = lane
            .submit(0, 7, other, LIMITS, [quote(1, 21_000, 2)])
            .unwrap();
        assert_eq!((outcome.replaced, outcome.rejected), (0, 1));

        assert_eq!(lane.take(0, 7, 0).len(), 1);
        assert_eq!(
            lane.submit(0, 7, operator, LIMITS, [quote(3, 21_000, 1)]),
            Err(TopOfBlockSubmitError::Closed)
        );
        assert!(lane.take(0, 7, 0).is_empty(), "a round is taken once");
    }
}
