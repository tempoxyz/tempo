//! Deposit-queue range selection for full Zone blocks (TIP-1171).

use crate::constants::DEPOSITS_PER_BUCKET;

/// Where the deposit-queue range a full Zone block processes ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositRangeEnd {
    /// Number of the range's last entry.
    pub target: u64,
    /// Index of the Portal checkpoint that covers `target`. `None` if the range ends at the head.
    pub checkpoint_index: Option<u64>,
}

impl DepositRangeEnd {
    /// Selects where the range after entry `processed` ends. `None` if `processed` exceeds `head`.
    pub fn new(processed: u64, head: u64, checkpoint_base: Option<u64>) -> Option<Self> {
        let spacing = DEPOSITS_PER_BUCKET as u64;
        let pending = head.checked_sub(processed)?;
        let checkpoint = checkpoint_base.filter(|_| pending > spacing).map(|base| {
            let index = processed
                .checked_sub(base)
                .map_or(0, |offset| offset / spacing + 1);
            (base + index * spacing, index)
        });
        Some(Self {
            target: checkpoint.map_or(head, |(target, _)| target),
            checkpoint_index: checkpoint.map(|(_, index)| index),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(0, 5, None => Some(DepositRangeEnd { target: 5, checkpoint_index: None }))]
    #[test_case(0, 231, None => Some(DepositRangeEnd { target: 231, checkpoint_index: None }))]
    #[test_case(0, 230, Some(0) => Some(DepositRangeEnd { target: 230, checkpoint_index: None }))]
    #[test_case(0, 231, Some(0) => Some(DepositRangeEnd { target: 230, checkpoint_index: Some(1) }))]
    #[test_case(229, 460, Some(0) => Some(DepositRangeEnd { target: 230, checkpoint_index: Some(1) }))]
    #[test_case(230, 461, Some(0) => Some(DepositRangeEnd { target: 460, checkpoint_index: Some(2) }))]
    #[test_case(0, 331, Some(100) => Some(DepositRangeEnd { target: 100, checkpoint_index: Some(0) }))]
    #[test_case(100, 331, Some(100) => Some(DepositRangeEnd { target: 330, checkpoint_index: Some(1) }))]
    #[test_case(101, 331, Some(100) => Some(DepositRangeEnd { target: 331, checkpoint_index: None }))]
    #[test_case(101, 100, Some(0) => None)]
    #[test_case(0, u64::MAX, Some(u64::MAX - 1) => Some(DepositRangeEnd { target: u64::MAX - 1, checkpoint_index: Some(0) }))]
    fn selects_range_end(processed: u64, head: u64, base: Option<u64>) -> Option<DepositRangeEnd> {
        DepositRangeEnd::new(processed, head, base)
    }
}
