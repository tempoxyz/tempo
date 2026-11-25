//! A block's receipts, checked once its transactions have run.

use invariants_core::{check, ensure};

use crate::{Check, Checked, TempoHardfork};

pub const GAS_MONOTONIC: &str = "TEMPO-BLOCK-GAS-MONOTONIC";

/// The receipts of a block's transactions, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipts {
    /// Each receipt's cumulative gas used, in block order.
    pub cumulative_gas_used: Vec<u64>,
}

pub const CHECKS: &[Check<Receipts>] = &[check! {
    id: GAS_MONOTONIC,
    doc: "A block's receipts never lower its cumulative gas used.",
    over: |r: &Receipts| 1..r.cumulative_gas_used.len(),
    judge: |r, index| {
        let (before, after) = (r.cumulative_gas_used[index - 1], r.cumulative_gas_used[*index]);
        ensure!(after >= before, "receipt {index}: cumulative gas {before} -> {after}")
    },
}];

impl Checked<TempoHardfork> for Receipts {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_gas_never_falls() {
        let fired = |gas: Vec<u64>| {
            Receipts {
                cumulative_gas_used: gas,
            }
            .check()
            .len()
        };
        assert_eq!(fired(vec![21_000, 21_000, 50_000]), 0);
        assert_eq!(fired(vec![21_000, 20_999]), 1);
    }
}
