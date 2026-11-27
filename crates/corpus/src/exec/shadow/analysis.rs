//! Classify independent boundary differences before formatting bounded samples.

use super::{
    Arms, Boundary, Evidence, ReplayOutcome, TxEvidence,
    expectations::{Context, Expectation},
    fees::fee_wrote,
    uncaptured,
};
use crate::{
    exec::db::View,
    types::{Change, Delta},
};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, U256};
use evm2::evm::AccountInfo;
use reth_primitives_traits::RecoveredBlock;
use std::{collections::BTreeMap, fmt::Debug};
use tempo_primitives::Block;

pub(super) const MAX_SAMPLES: usize = 8;

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
    pub(super) fn outcome(&self, evidence: &Evidence) -> ReplayOutcome {
        // A shadow arm that read uncaptured state was not compared, which is not a finding.
        if self.unexplained > 0
            || evidence
                .failure
                .as_ref()
                .is_some_and(|failure| !uncaptured(&failure.error))
        {
            ReplayOutcome::Findings
        } else if self.boundaries_not_evaluated > 0 {
            ReplayOutcome::Inconclusive
        } else if !self.expected.is_empty() {
            ReplayOutcome::Expected
        } else {
            ReplayOutcome::Match
        }
    }

    /// Compares `evidence` boundary by boundary. Every boundary of `block` that was not compared
    /// counts as not evaluated.
    pub(super) fn analyze(
        evidence: &Evidence,
        rules: &[&Expectation],
        block: &RecoveredBlock<Block>,
    ) -> Self {
        let mut report = Self::default();
        let base_fee = block.header().base_fee_per_gas();
        let context = |boundary| Context {
            boundary,
            evidence,
            base_fee,
            tx: match boundary {
                Boundary::Transaction(index) => block.body().transactions.get(index),
                _ => None,
            },
        };
        if let Some(Arms { real, shadow }) = &evidence.pre_block {
            report.record_state_diffs(&context(Boundary::PreBlock), real, shadow, rules);
            report.boundaries_evaluated += 1;
        }
        for (index, tx) in evidence.txs.iter().enumerate() {
            let ctx = context(Boundary::Transaction(index));
            match tx {
                TxEvidence::Same => {}
                TxEvidence::Differs(arms) => {
                    let Arms { real, shadow } = &**arms;
                    let mut diff = Comparison::new(&mut report, &ctx, rules, None, real, shadow);
                    diff.record("outcome", |tx| tx.outcome.clone());
                    diff.record("output", |tx| tx.output_hash);
                    // Keep all logs, in order; mask only a verified gas-derived fee amount.
                    let (real_logs, shadow_logs) = ctx
                        .verified_fee_log_hashes()
                        .unwrap_or((real.receipt_logs_hash, shadow.receipt_logs_hash));
                    diff.record_values("receipt_logs", real_logs, shadow_logs);
                    report.record_state_diffs(&ctx, &real.changes, &shadow.changes, rules);
                }
                TxEvidence::Failed(error) if uncaptured(error) => continue,
                TxEvidence::Failed(error) => report.record(
                    &ctx,
                    Field {
                        name: "execution",
                        address: None,
                        slot: None,
                        fee_associated: false,
                    },
                    Ok(()),
                    Err(error.to_string()),
                    &[],
                ),
            }
            report.boundaries_evaluated += 1;
        }
        if let Some(Arms { real, shadow }) = &evidence.post_block {
            report.record_state_diffs(&context(Boundary::PostBlock), real, shadow, rules);
            report.boundaries_evaluated += 1;
        }
        // Every transaction plus the pre- and post-block boundaries.
        let total = block.body().transactions.len() + 2;
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
            && let Some(TxEvidence::Differs(arms)) = ctx.evidence.txs.get(index)
        {
            field.fee_associated = fee_wrote(&arms.real.actions, address, slot)
                || fee_wrote(&arms.shadow.actions, address, slot);
        }
        let accepted = rules
            .iter()
            .find_map(|rule| rule.accepts(ctx, &field).then_some(rule.id));
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
        real: &StepChanges,
        shadow: &StepChanges,
        rules: &[&Expectation],
    ) {
        for &address in real.0.keys().chain(
            shadow
                .0
                .keys()
                .filter(|address| !real.0.contains_key(*address)),
        ) {
            let real = real.account(address);
            let shadow = shadow.account(address);
            let mut diff = Comparison::new(self, ctx, rules, Some(address), &real, &shadow);
            diff.record("existence", |a| a.existence());
            diff.record("balance", |a| a.info(|info| info.balance));
            diff.record("nonce", |a| a.info(|info| info.nonce));
            diff.record("code", |a| a.info(|info| info.code_hash));
            diff.record("storage_reset", |a| a.0.is_some_and(|a| a.storage_reset));
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

/// What one arm changed at a boundary, by account.
#[derive(Debug, Default)]
pub(super) struct StepChanges(pub(super) BTreeMap<Address, AccountChange>);

/// One account's state before and after a boundary.
#[derive(Debug, Default)]
pub(super) struct AccountChange {
    /// The account before the boundary, `None` if it did not exist.
    pub before: Option<AccountInfo>,
    /// The account after the boundary, `None` if it did not exist.
    pub after: Option<AccountInfo>,
    /// Whether the boundary cleared the account's storage by creating or destroying it.
    pub storage_reset: bool,
    /// Each slot the boundary wrote, before and after it. A slot of an account whose storage
    /// was reset counts as zero before.
    pub storage: BTreeMap<U256, (U256, U256)>,
}

impl StepChanges {
    /// What `delta` changes when applied to `before`.
    pub(super) fn new(before: &View<'_>, delta: &Delta) -> eyre::Result<Self> {
        // Only code hashes are compared, so keep candidate bytecode out of the process-wide cache.
        let hashes_only = delta.0.iter().map(|commit| {
            commit
                .iter()
                .map(|(address, change)| {
                    let change = Change {
                        code: None,
                        ..change.clone()
                    };
                    (*address, change)
                })
                .collect()
        });
        let mut after = before.child();
        after.apply(&Delta(hashes_only.collect()))?;
        let mut changes = BTreeMap::<Address, AccountChange>::new();
        for (address, change) in delta.0.iter().flatten() {
            let account = changes.entry(Address::from(*address)).or_default();
            account.storage_reset |= change.created || change.info.is_none();
            for key in change.storage.keys() {
                account
                    .storage
                    .insert(U256::from_be_bytes(*key), Default::default());
            }
        }
        // The executor loaded every account and slot it changed, so `before` holds them all.
        for (address, account) in &mut changes {
            account.before = before.account(address)?;
            account.after = after.account(address)?;
            for (slot, values) in &mut account.storage {
                let previous = if account.storage_reset {
                    U256::ZERO
                } else {
                    before.storage(address, slot)?
                };
                *values = (previous, after.storage(address, slot)?);
            }
        }
        Ok(Self(changes))
    }

    pub(super) fn account(&self, address: Address) -> AccountDelta<'_> {
        AccountDelta(self.0.get(&address))
    }
}

#[derive(Clone, Copy)]
pub(super) struct AccountDelta<'a>(pub(super) Option<&'a AccountChange>);

impl<'a> AccountDelta<'a> {
    pub(super) fn info<T: Eq>(self, get: impl Fn(&AccountInfo) -> T) -> Option<(T, T)> {
        let account = self.0?;
        // Also compare initial values on creation and final values on destruction.
        let default = AccountInfo::default();
        Self::changed(
            get(account.before.as_ref().unwrap_or(&default)),
            get(account.after.as_ref().unwrap_or(&default)),
        )
    }

    fn existence(self) -> Option<(bool, bool)> {
        let account = self.0?;
        Self::changed(account.before.is_some(), account.after.is_some())
    }

    pub(super) fn storage(self, slot: U256) -> Option<(U256, U256)> {
        let (before, after) = *self.0?.storage.get(&slot)?;
        Self::changed(before, after)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        code,
        exec::db::tests::{change, commit, info, input},
        types::{CodeChange, InfoChange},
    };
    use alloy_primitives::{KECCAK256_EMPTY, keccak256};
    use reth_primitives_traits::Account;

    #[test]
    fn step_changes_pair_each_written_value_with_its_previous_one() {
        let [changed, created, destroyed] = [1, 2, 3].map(Address::repeat_byte);
        let account = Account {
            nonce: 1,
            balance: U256::from(10),
            ..Default::default()
        };
        let slot = U256::from(4);
        let before = View::new(input(
            &[
                (changed, Some(account.clone())),
                (created, None),
                (destroyed, Some(account)),
            ],
            &[(changed, slot, U256::from(5))],
        ));
        let balance = change(info(None, Some(7)), &[(slot, U256::from(9))]);
        let mut delta = commit(changed, balance);
        let runtime = b"step changes leave this runtime uncached";
        let code_hash = keccak256(runtime);
        let created_info = InfoChange {
            code: CodeChange::Hash(Some(code_hash.0)),
            ..info(Some(1), None)
        };
        let creation = Change {
            created: true,
            code: Some(runtime.to_vec()),
            ..change(created_info, &[(slot, U256::from(3))])
        };
        let destruction = Change {
            info: None,
            ..change(info(None, None), &[])
        };
        delta.0[0].insert(created.into_array(), creation);
        delta.0.push([(destroyed.into_array(), destruction)].into());

        let changes = StepChanges::new(&before, &delta).unwrap();

        let account = changes.account(changed);
        assert_eq!(
            account.info(|info| info.balance),
            Some((U256::from(10), U256::from(7)))
        );
        assert_eq!(account.info(|info| info.nonce), None);
        assert_eq!(account.storage(slot), Some((U256::from(5), U256::from(9))));
        assert!(!changes.0[&changed].storage_reset);
        // A created account's slots start from zero, whatever the corpus captured.
        let account = changes.account(created);
        assert_eq!(account.existence(), Some((false, true)));
        assert_eq!(account.storage(slot), Some((U256::ZERO, U256::from(3))));
        assert!(changes.0[&created].storage_reset);
        assert_eq!(
            account.info(|info| info.code_hash),
            Some((KECCAK256_EMPTY, code_hash))
        );
        assert!(!code::has_code(&code_hash.0));
        assert_eq!(changes.account(destroyed).existence(), Some((true, false)));
        assert!(changes.0[&destroyed].storage_reset);
        assert!(changes.account(Address::ZERO).0.is_none());
    }
}
