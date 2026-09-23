//! Classify independent boundary differences before formatting bounded samples.

use self::expectations::{Context, Expectation};
use super::{Boundary, Evidence, ReplayOutcome};
use alloy::consensus::BlockHeader as _;
use alloy_primitives::{Address, U256};
use reth_primitives_traits::RecoveredBlock;
use reth_revm::db::{TransitionAccount, TransitionState};
use std::{collections::BTreeMap, fmt::Debug};
use tempo_primitives::Block;

mod expectations;
pub(super) use expectations::between;

#[cfg(test)]
mod tests;

const MAX_SAMPLES: usize = 8;

/// Difference counts, comparison coverage, and bounded diagnostic samples.
///
/// Each sample carries the first accepting rule's ID, or `None` for an unexplained difference.
#[derive(Debug, Default)]
pub(super) struct Report {
    pub unexplained: usize,
    pub expected: BTreeMap<&'static str, usize>,
    pub boundaries_evaluated: usize,
    pub boundaries_not_evaluated: usize,
    pub samples: Vec<(Boundary, Difference, Option<&'static str>)>,
}

impl Report {
    pub(super) fn outcome(&self, shadow: &Evidence) -> ReplayOutcome {
        if self.unexplained > 0 || shadow.failure.is_some() {
            ReplayOutcome::Findings
        } else if self.boundaries_not_evaluated > 0 {
            ReplayOutcome::Inconclusive
        } else if !self.expected.is_empty() {
            ReplayOutcome::Expected
        } else {
            ReplayOutcome::Match
        }
    }

    pub(super) fn analyze(
        real: &Evidence,
        shadow: &Evidence,
        rules: &[&Expectation],
        block: &RecoveredBlock<Block>,
    ) -> Self {
        let mut report = Self::default();
        let base_fee = block.header().base_fee_per_gas();
        let context = |boundary| Context {
            boundary,
            real,
            shadow,
            base_fee,
            tx: match boundary {
                Boundary::Transaction(index) => block.body().transactions.get(index),
                _ => None,
            },
        };
        if let Some((real, shadow)) = real.pre_block.as_ref().zip(shadow.pre_block.as_ref()) {
            report.record_state_diffs(&context(Boundary::PreBlock), real, shadow, rules);
            report.boundaries_evaluated += 1;
        }
        for index in 0..real.txs.len().min(shadow.txs.len()) {
            let ctx = context(Boundary::Transaction(index));
            let (Ok(real), shadow) = (&ctx.real.txs[index], &ctx.shadow.txs[index]) else {
                // A control failure terminates execution and is handled by `Evidence::failure`.
                break;
            };
            match shadow {
                Ok(shadow) => {
                    let mut diff = Comparison::new(&mut report, &ctx, rules, None, real, shadow);
                    diff.record("success", |tx| tx.outcome == super::TxOutcome::Success);
                    diff.record("output", |tx| tx.output_hash);
                    // Keep all logs, in order; mask only a verified gas-derived fee amount.
                    let (real_logs, shadow_logs) = ctx
                        .verified_fee_log_hashes()
                        .unwrap_or((real.receipt_logs_hash, shadow.receipt_logs_hash));
                    diff.record_values("receipt_logs", real_logs, shadow_logs);
                    diff.record("gas", |tx| tx.gas_used);
                    diff.record("block_gas", |tx| tx.block_gas_used);
                    report.record_state_diffs(&ctx, &real.state, &shadow.state, rules);
                }
                Err(error) => report.record(
                    &ctx,
                    Field {
                        name: "execution",
                        address: None,
                        slot: None,
                        fee_associated: false,
                    },
                    Ok::<(), &str>(()),
                    Err(error.as_str()),
                    &[],
                ),
            }
            report.boundaries_evaluated += 1;
        }
        if let Some((real, shadow)) = real.post_block.as_ref().zip(shadow.post_block.as_ref()) {
            report.record_state_diffs(&context(Boundary::PostBlock), real, shadow, rules);
            report.boundaries_evaluated += 1;
        }
        // Include a rejected transaction and its unexecuted suffix in missing coverage.
        let total = usize::from(real.pre_block.is_some())
            + real.txs.len()
            + usize::from(real.post_block.is_some());
        report.boundaries_not_evaluated = total - report.boundaries_evaluated;
        report
    }

    fn record<V: Debug + Eq>(
        &mut self,
        ctx: &Context<'_>,
        mut field: Field,
        real: V,
        shadow: V,
        rules: &[&Expectation],
    ) {
        if real == shadow {
            return;
        }
        if let (Boundary::Transaction(index), Some(address), Some(slot)) =
            (ctx.boundary, field.address, field.slot)
        {
            field.fee_associated = ctx.real.txs[index]
                .as_ref()
                .is_ok_and(|tx| tx.fee.slots.contains(&(address, slot)))
                || ctx.shadow.txs[index]
                    .as_ref()
                    .is_ok_and(|tx| tx.fee.slots.contains(&(address, slot)));
        }
        let accepted = rules
            .iter()
            .find_map(|rule| (rule.check)(ctx, &field).map(|()| rule.id));
        let rule_id = match accepted {
            Some(id) => {
                *self.expected.entry(id).or_default() += 1;
                Some(id)
            }
            None => {
                self.unexplained += 1;
                None
            }
        };
        // Rank by metadata before formatting: only retained samples allocate strings.
        let key = (rule_id.is_some(), ctx.boundary, field);
        let index = self.samples.partition_point(|(boundary, diff, rule)| {
            (rule.is_some(), *boundary, diff.field) < key
        });
        if index < MAX_SAMPLES {
            let difference = Difference {
                field,
                real: format!("{real:?}"),
                shadow: format!("{shadow:?}"),
            };
            self.samples
                .insert(index, (ctx.boundary, difference, rule_id));
            self.samples.truncate(MAX_SAMPLES);
        }
    }

    fn record_state_diffs(
        &mut self,
        ctx: &Context<'_>,
        real: &TransitionState,
        shadow: &TransitionState,
        rules: &[&Expectation],
    ) {
        for &address in real.transitions.keys().chain(
            shadow
                .transitions
                .keys()
                .filter(|address| !real.transitions.contains_key(*address)),
        ) {
            let real = AccountDelta(real.transitions.get(&address));
            let shadow = AccountDelta(shadow.transitions.get(&address));
            let mut diff = Comparison::new(self, ctx, rules, Some(address), &real, &shadow);
            diff.record("existence", |a| a.existence());
            diff.record("balance", |a| a.info(|info| info.balance));
            diff.record("nonce", |a| a.info(|info| info.nonce));
            diff.record("code", |a| a.info(|info| info.code_hash));
            diff.record("storage_reset", |a| {
                a.0.is_some_and(|a| a.storage_was_destroyed)
            });
            for &slot in real.slots().chain(shadow.slots().filter(|slot| {
                real.0
                    .is_none_or(|account| !account.storage.contains_key(*slot))
            })) {
                diff.slot = Some(slot);
                diff.record("storage", |a| a.storage(slot));
            }
        }
    }
}

/// Identifies a changed field; rules read its typed values from `Context`.
///
/// Fee association records provenance only and is never sufficient to accept a difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Field {
    pub name: &'static str,
    pub address: Option<Address>,
    pub slot: Option<U256>,
    pub fee_associated: bool,
}

/// Diagnostic values, formatted only after classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Difference {
    pub field: Field,
    pub real: String,
    pub shadow: String,
}

struct Comparison<'a, T> {
    report: &'a mut Report,
    ctx: &'a Context<'a>,
    rules: &'a [&'a Expectation],
    address: Option<Address>,
    slot: Option<U256>,
    real: &'a T,
    shadow: &'a T,
}

impl<'a, T> Comparison<'a, T> {
    fn new(
        report: &'a mut Report,
        ctx: &'a Context<'a>,
        rules: &'a [&'a Expectation],
        address: Option<Address>,
        real: &'a T,
        shadow: &'a T,
    ) -> Self {
        Self {
            report,
            ctx,
            rules,
            address,
            slot: None,
            real,
            shadow,
        }
    }

    fn record<V: Debug + Eq>(&mut self, name: &'static str, get: impl Fn(&T) -> V) {
        self.record_values(name, get(self.real), get(self.shadow));
    }

    fn record_values<V: Debug + Eq>(&mut self, name: &'static str, real: V, shadow: V) {
        self.report.record(
            self.ctx,
            Field {
                name,
                address: self.address,
                slot: self.slot,
                fee_associated: false,
            },
            real,
            shadow,
            self.rules,
        );
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
