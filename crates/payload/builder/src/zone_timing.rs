//! Diagnostic classification for the synthetic zone benchmark workload.
//!
//! This matches the benchmark's calldata, not a consensus transaction category or a verified
//! destination contract. A deposit transaction includes both the deposit and settlement calls.

use alloy_primitives::keccak256;
use std::sync::LazyLock;

static SELECTORS: LazyLock<([u8; 4], [u8; 4])> = LazyLock::new(|| {
    (
        keccak256(
            b"deposit(address,uint128,uint256,(bytes32,uint8,bytes,bytes12,bytes16),address)",
        )[..4]
            .try_into()
            .unwrap(),
        keccak256(b"settle(address,address,address,bool)")[..4]
            .try_into()
            .unwrap(),
    )
});

/// Identifies the benchmark's deposit or withdrawal transaction from its calls.
pub(crate) fn zone_timing_kind<'a>(
    calls: impl IntoIterator<Item = &'a [u8]>,
) -> Option<&'static str> {
    let (deposit, settle) = &*SELECTORS;
    let mut withdrawal = false;
    for input in calls {
        if input.starts_with(deposit) {
            return Some("deposit");
        }
        if input.starts_with(settle)
            && input.len() == 132
            && input[100..131].iter().all(|byte| *byte == 0)
            && input[131] == 1
        {
            withdrawal = true;
        }
    }
    withdrawal.then_some("withdraw")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_benchmark_calls_without_counting_deposit_settlement_as_withdrawal() {
        let (deposit, settle) = &*SELECTORS;
        let mut settlement = vec![0; 132];
        settlement[..4].copy_from_slice(settle);
        assert_eq!(zone_timing_kind([settlement.as_slice()]), None);
        assert_eq!(
            zone_timing_kind([deposit.as_slice(), settlement.as_slice()]),
            Some("deposit")
        );
        settlement[131] = 1;
        assert_eq!(zone_timing_kind([settlement.as_slice()]), Some("withdraw"));
        assert_eq!(
            zone_timing_kind([settlement.as_slice(), deposit.as_slice()]),
            Some("deposit")
        );
        assert_eq!(zone_timing_kind([&settlement[..131]]), None);
        assert_eq!(zone_timing_kind([b"unrelated".as_slice(), &[]]), None);
        settlement[100] = 1;
        assert_eq!(zone_timing_kind([settlement.as_slice()]), None);
    }
}
