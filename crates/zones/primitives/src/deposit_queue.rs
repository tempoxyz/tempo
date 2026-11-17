//! Deposit-queue range selection for full Zone blocks (TIP-1171).

use crate::constants::{DEPOSITS_PER_BUCKET, MAX_DEPOSIT_WEIGHT_PER_BLOCK};
use tempo_contracts::zones::DepositType;

/// Where the deposit-queue range a full Zone block processes ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositRangeEnd {
    /// The Portal's queue head.
    Head,
    /// The Portal's stored checkpoint at `index`, which covers entry number `target`.
    Checkpoint { index: u64, target: u64 },
}

impl DepositRangeEnd {
    /// Selects where the range after entry `processed` ends.
    ///
    /// `head` is the Portal's deposit count and `checkpoint_base` its checkpoint base, or `None`
    /// before checkpoints bootstrap. The range ends at the head when the head is within
    /// [`DEPOSITS_PER_BUCKET`] entries or no checkpoint exists, and otherwise at the first
    /// checkpoint after `processed`. Returns `None` if `processed` exceeds `head`.
    pub fn new(processed: u64, head: u64, checkpoint_base: Option<u64>) -> Option<Self> {
        let spacing = DEPOSITS_PER_BUCKET as u64;
        let pending = head.checked_sub(processed)?;
        let Some(base) = checkpoint_base.filter(|_| pending > spacing) else {
            return Some(Self::Head);
        };
        let index = match processed.checked_sub(base) {
            None => 0,
            Some(offset) => offset / spacing + 1,
        };
        let target = base + index * spacing;
        Some(Self::Checkpoint { index, target })
    }
}

/// Returns how many leading entries of a range a full Zone block executes.
///
/// `deposit_types` yields the type of each entry of the range, in queue order. The block executes
/// the longest prefix whose weight fits [`MAX_DEPOSIT_WEIGHT_PER_BLOCK`] and only hashes the rest.
/// Every entry type weighs one unit. No entry outweighs the budget, so a nonempty range executes
/// at least one entry.
pub fn executed_count(deposit_types: impl IntoIterator<Item = DepositType>) -> usize {
    let mut weight = 0;
    deposit_types
        .into_iter()
        .take_while(|deposit_type| {
            weight += match deposit_type {
                DepositType::Deposit | DepositType::WithdrawalBounceBack => 1,
                DepositType::__Invalid => 0, // unreachable in practice
            };
            weight <= MAX_DEPOSIT_WEIGHT_PER_BLOCK
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(0, 5, None => Some(DepositRangeEnd::Head))]
    #[test_case(0, 231, None => Some(DepositRangeEnd::Head))]
    #[test_case(0, 230, Some(0) => Some(DepositRangeEnd::Head))]
    #[test_case(0, 231, Some(0) => Some(DepositRangeEnd::Checkpoint { index: 1, target: 230 }))]
    #[test_case(229, 460, Some(0) => Some(DepositRangeEnd::Checkpoint { index: 1, target: 230 }))]
    #[test_case(230, 461, Some(0) => Some(DepositRangeEnd::Checkpoint { index: 2, target: 460 }))]
    #[test_case(0, 331, Some(100) => Some(DepositRangeEnd::Checkpoint { index: 0, target: 100 }))]
    #[test_case(100, 331, Some(100) => Some(DepositRangeEnd::Checkpoint { index: 1, target: 330 }))]
    #[test_case(101, 331, Some(100) => Some(DepositRangeEnd::Head))]
    #[test_case(101, 100, Some(0) => None)]
    #[test_case(0, u64::MAX, Some(u64::MAX - 1) => Some(DepositRangeEnd::Checkpoint { index: 0, target: u64::MAX - 1 }))]
    fn selects_range_end(processed: u64, head: u64, base: Option<u64>) -> Option<DepositRangeEnd> {
        DepositRangeEnd::new(processed, head, base)
    }

    #[test_case(0, 0 => 0; "empty range")]
    #[test_case(230, 0 => 230; "deposits fill the budget")]
    #[test_case(115, 115 => 230; "mixed entries fill the budget")]
    #[test_case(200, 31 => 230; "entry past the budget waits")]
    fn executes_weighted_prefix(deposits: usize, bounce_backs: usize) -> usize {
        executed_count(core::iter::repeat_n(DepositType::Deposit, deposits).chain(
            core::iter::repeat_n(DepositType::WithdrawalBounceBack, bounce_backs),
        ))
    }
}
