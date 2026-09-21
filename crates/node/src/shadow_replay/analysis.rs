//! Classify typed differences before formatting bounded samples. Expectedness and continuation
//! are independent: even an accepted fee balance change may invalidate the remaining comparisons.

use super::{
    Boundary, Evidence, ObservedTx, ReplayOutcome,
    expectations::{Context, Continuation, Expectation},
};
use alloy_primitives::{Address, B256, U256};
use reth_revm::db::{TransitionAccount, TransitionState};
use std::collections::{BTreeMap, HashSet};

#[cfg(test)]
mod tests;

const MAX_SAMPLES: usize = 8;

#[derive(Debug, Default)]
pub(super) struct Report {
    pub unexplained: usize,
    pub expected: BTreeMap<&'static str, usize>,
    pub boundaries_evaluated: usize,
    pub boundaries_not_evaluated: usize,
    pub cutoff: Option<Boundary>,
    /// ID of the first accepting rule, or `None` for an unexplained difference.
    pub samples: Vec<(Boundary, Difference, Option<&'static str>)>,
}

impl Report {
    pub(super) fn outcome(&self, shadow: &Evidence) -> ReplayOutcome {
        let unexplained_failure = shadow
            .failure
            .as_ref()
            .is_some_and(|failure| self.cutoff.is_none_or(|cutoff| failure.boundary <= cutoff));
        if self.unexplained > 0 || unexplained_failure {
            ReplayOutcome::Findings
        } else if self.boundaries_not_evaluated > 0 {
            ReplayOutcome::Inconclusive
        } else if !self.expected.is_empty() {
            ReplayOutcome::Expected
        } else {
            ReplayOutcome::Match
        }
    }

    pub(super) fn analyze(real: &Evidence, shadow: &Evidence, rules: &[&Expectation]) -> Self {
        let mut report = Self::default();
        let context = |boundary| Context {
            boundary,
            real,
            shadow,
        };
        if let Some((real, shadow)) = real.pre_block.as_ref().zip(shadow.pre_block.as_ref()) {
            report.record_state_diffs(&context(Boundary::PreBlock), real, shadow, None, rules);
            report.boundaries_evaluated += 1;
        }
        for index in 0..real.txs.len().min(shadow.txs.len()) {
            if report.cutoff.is_some() {
                break;
            }
            let ctx = context(Boundary::Transaction(index));
            let (real, shadow) = (&ctx.real.txs[index], &ctx.shadow.txs[index]);
            for difference in [
                Difference::Success(real.receipt.success, shadow.receipt.success),
                Difference::Output(real.output_hash, shadow.output_hash),
                Difference::Logs(real.logs_hash, shadow.logs_hash),
                Difference::FeeLogs(real.fee_logs_hash, shadow.fee_logs_hash),
                Difference::ReceiptLogs(real.receipt.logs_hash, shadow.receipt.logs_hash),
                Difference::Gas(real.receipt.gas_used, shadow.receipt.gas_used),
                Difference::BlockGas(real.block_gas_used, shadow.block_gas_used),
            ] {
                report.record(&ctx, difference, rules);
            }
            // Finish ALL comparisons at this boundary, even if one already caused a cutoff.
            report.record_state_diffs(
                &ctx,
                &real.state,
                &shadow.state,
                Some((real, shadow)),
                rules,
            );
            report.boundaries_evaluated += 1;
        }
        if report.cutoff.is_none()
            && let Some((real, shadow)) = real.post_block.as_ref().zip(shadow.post_block.as_ref())
        {
            report.record_state_diffs(&context(Boundary::PostBlock), real, shadow, None, rules);
            report.boundaries_evaluated += 1;
        }
        // Include a rejected transaction and its unexecuted suffix in missing coverage.
        let total = usize::from(real.pre_block.is_some())
            + real.txs.len()
            + usize::from(real.post_block.is_some());
        report.boundaries_not_evaluated = total - report.boundaries_evaluated;
        report
    }

    fn record(&mut self, ctx: &Context<'_>, difference: Difference, rules: &[&Expectation]) {
        if difference.is_equal() {
            return;
        }
        let accepted = rules
            .iter()
            .find_map(|rule| (rule.check)(ctx, &difference).map(|result| (rule.id, result)));
        let (rule_id, cutoff) = match accepted {
            Some((id, continuation)) => {
                *self.expected.entry(id).or_default() += 1;
                (Some(id), continuation == Continuation::InconclusiveSuffix)
            }
            None => {
                self.unexplained += 1;
                (None, difference.affects_continuation())
            }
        };
        if cutoff {
            self.cutoff.get_or_insert(ctx.boundary);
        }
        self.samples.push((ctx.boundary, difference, rule_id));
        // Prioritize unexplained samples; stable ordering is independent of HashSet iteration.
        self.samples
            .sort_by(|a, b| (a.2.is_some(), a.0, &a.1).cmp(&(b.2.is_some(), b.0, &b.1)));
        self.samples.truncate(MAX_SAMPLES);
    }

    fn record_state_diffs(
        &mut self,
        ctx: &Context<'_>,
        real: &TransitionState,
        shadow: &TransitionState,
        tx: Option<(&ObservedTx, &ObservedTx)>,
        rules: &[&Expectation],
    ) {
        let addresses: HashSet<_> = real
            .transitions
            .keys()
            .chain(shadow.transitions.keys())
            .copied()
            .collect();
        for address in addresses {
            let real = AccountDelta(real.transitions.get(&address));
            let shadow = AccountDelta(shadow.transitions.get(&address));
            for difference in [
                Difference::Existence {
                    address,
                    real: real.existence(),
                    shadow: shadow.existence(),
                },
                Difference::Balance {
                    address,
                    real: real.info(|a| a.balance),
                    shadow: shadow.info(|a| a.balance),
                },
                Difference::Nonce {
                    address,
                    real: real.info(|a| a.nonce),
                    shadow: shadow.info(|a| a.nonce),
                },
                Difference::Code {
                    address,
                    real: real.info(|a| a.code_hash),
                    shadow: shadow.info(|a| a.code_hash),
                },
                Difference::StorageReset {
                    address,
                    real: real.0.is_some_and(|a| a.storage_was_destroyed),
                    shadow: shadow.0.is_some_and(|a| a.storage_was_destroyed),
                },
            ] {
                self.record(ctx, difference, rules);
            }
            let slots: HashSet<_> = real.slots().chain(shadow.slots()).copied().collect();
            for slot in slots {
                let fee_associated = tx.is_some_and(|(real, shadow)| {
                    real.fee_slots.contains(&(address, slot))
                        || shadow.fee_slots.contains(&(address, slot))
                });
                self.record(
                    ctx,
                    Difference::Storage {
                        address,
                        slot,
                        fee_associated,
                        real: real.storage(slot),
                        shadow: shadow.storage(slot),
                    },
                    rules,
                );
            }
        }
    }
}

/// Values remain typed for semantic checks. Account/storage values describe net transitions;
/// `None` means no net effect at this boundary, not a missing execution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Difference {
    StorageReset {
        address: Address,
        real: bool,
        shadow: bool,
    },
    Existence {
        address: Address,
        real: Option<(bool, bool)>,
        shadow: Option<(bool, bool)>,
    },
    Balance {
        address: Address,
        real: Option<(U256, U256)>,
        shadow: Option<(U256, U256)>,
    },
    Nonce {
        address: Address,
        real: Option<(u64, u64)>,
        shadow: Option<(u64, u64)>,
    },
    Code {
        address: Address,
        real: Option<(B256, B256)>,
        shadow: Option<(B256, B256)>,
    },
    Storage {
        address: Address,
        slot: U256,
        fee_associated: bool,
        real: Option<(U256, U256)>,
        shadow: Option<(U256, U256)>,
    },
    Success(bool, bool),
    Output(B256, B256),
    Logs(B256, B256),
    FeeLogs(B256, B256),
    /// Full ordered receipt logs also preserve ordering between fee and application logs.
    ReceiptLogs(B256, B256),
    Gas(u64, u64),
    BlockGas(u64, u64),
}

impl Difference {
    fn is_equal(&self) -> bool {
        match self {
            Self::StorageReset { real, shadow, .. } | Self::Success(real, shadow) => real == shadow,
            Self::Existence { real, shadow, .. } => real == shadow,
            Self::Balance { real, shadow, .. } | Self::Storage { real, shadow, .. } => {
                real == shadow
            }
            Self::Nonce { real, shadow, .. } => real == shadow,
            Self::Code { real, shadow, .. } => real == shadow,
            Self::Output(real, shadow)
            | Self::Logs(real, shadow)
            | Self::FeeLogs(real, shadow)
            | Self::ReceiptLogs(real, shadow) => real == shadow,
            Self::Gas(real, shadow) | Self::BlockGas(real, shadow) => real == shadow,
        }
    }

    fn affects_continuation(&self) -> bool {
        !matches!(
            self,
            Self::Success(..)
                | Self::Output(..)
                | Self::Logs(..)
                | Self::FeeLogs(..)
                | Self::ReceiptLogs(..)
        )
    }
}

#[derive(Clone, Copy)]
struct AccountDelta<'a>(Option<&'a TransitionAccount>);

impl<'a> AccountDelta<'a> {
    fn info<T: Eq>(self, get: impl Fn(&reth_revm::state::AccountInfo) -> T) -> Option<(T, T)> {
        let account = self.0?;
        // Also compare initial values on creation and final values on destruction.
        let default = reth_revm::state::AccountInfo::default();
        Self::changed(
            get(account.previous_info.as_ref().unwrap_or(&default)),
            get(account.info.as_ref().unwrap_or(&default)),
        )
    }

    fn existence(self) -> Option<(bool, bool)> {
        let account = self.0?;
        Self::changed(account.previous_info.is_some(), account.info.is_some())
    }

    fn storage(self, slot: U256) -> Option<(U256, U256)> {
        let value = self.0?.storage.get(&slot)?;
        Self::changed(value.original_value(), value.present_value())
    }

    fn slots(self) -> impl Iterator<Item = &'a U256> {
        self.0
            .into_iter()
            .flat_map(|account| account.storage.keys())
    }

    fn changed<T: Eq>(before: T, after: T) -> Option<(T, T)> {
        (before != after).then_some((before, after))
    }
}
