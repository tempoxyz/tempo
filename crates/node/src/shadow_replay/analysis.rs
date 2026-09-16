//! Direct comparison and classification of net effects at completed replay boundaries.
//!
//! Only unexpected findings are formatted into the diagnostic representation retained by a report.
//! A missing state change means “no net effect at this boundary”.

use super::{Boundary, Evidence, ObservedTx};
use alloy_primitives::{Address, U256};
use reth_revm::db::{TransitionAccount, TransitionState};
use std::{cmp::Ordering, collections::HashSet, fmt::Debug};

/// Maximum retained diagnostic samples; finding counters remain exact.
const MAX_SAMPLES: usize = 8;

/// Exact finding counters plus a bounded, deterministic sample set.
#[derive(Debug, Default)]
pub(super) struct Report {
    pub fee_associated: usize,
    pub observation: usize,
    pub gas_divergent_txs: usize,
    pub stopping: usize,
    pub boundaries_not_evaluated: usize,
    pub cutoff: Option<Boundary>,
    pub samples: Vec<(Boundary, Difference)>,
}

impl Report {
    pub(super) fn findings(&self) -> usize {
        self.fee_associated + self.observation + self.gas_divergent_txs + self.stopping
    }

    /// Compares common completed boundaries in order and stops after finishing the first boundary
    /// containing a stopping difference.
    pub(super) fn analyze(real: &Evidence, shadow: &Evidence) -> Self {
        let mut report = Self::default();
        let common_txs = real.txs.len().min(shadow.txs.len());

        if let Some((real, shadow)) = real.pre_block.as_ref().zip(shadow.pre_block.as_ref()) {
            report.record_state_diffs(Boundary::PreBlock, real, shadow, None);
        }
        for index in 0..common_txs {
            if report.cutoff.is_some() {
                report.boundaries_not_evaluated += common_txs - index;
                break;
            }
            report.record_tx_diffs(&real.txs[index], &shadow.txs[index], index);
        }
        if let Some((real, shadow)) = real.post_block.as_ref().zip(shadow.post_block.as_ref()) {
            if report.cutoff.is_some() {
                report.boundaries_not_evaluated += 1;
            } else {
                report.record_state_diffs(Boundary::PostBlock, real, shadow, None);
            }
        }
        report
    }

    fn record(&mut self, boundary: Boundary, difference: Difference) {
        *match difference.kind {
            Kind::Stop => &mut self.stopping,
            Kind::Observation => &mut self.observation,
            Kind::Gas => &mut self.gas_divergent_txs,
            Kind::Fee => &mut self.fee_associated,
        } += 1;

        if difference.kind == Kind::Gas && self.gas_divergent_txs > 1 {
            return;
        }

        self.samples.push((boundary, difference));
        self.samples.sort_by(sample_cmp);
        self.samples.truncate(MAX_SAMPLES);
    }

    fn record_state_diffs(
        &mut self,
        boundary: Boundary,
        real: &TransitionState,
        shadow: &TransitionState,
        tx: Option<(&ObservedTx, &ObservedTx)>,
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
            let mut diff =
                Comparison::new(self, boundary, Location::Account(address), &real, &shadow);
            diff.record("existence", |account| account.existence(), Kind::Stop);
            diff.record("balance", |acc| acc.info(|info| info.balance), Kind::Stop);
            diff.record("nonce", |acc| acc.info(|info| info.nonce), Kind::Stop);

            let slots: HashSet<_> = real.slots().chain(shadow.slots()).copied().collect();
            for slot in slots {
                let kind = if tx.is_some_and(|(real, shadow)| {
                    real.fee_slots.contains(&(address, slot))
                        || shadow.fee_slots.contains(&(address, slot))
                }) {
                    Kind::Fee
                } else {
                    Kind::Stop
                };
                Comparison::new(
                    self,
                    boundary,
                    Location::Storage(address, slot),
                    &real,
                    &shadow,
                )
                .record("storage", |account| account.storage(slot), kind);
            }
        }

        if self.stopping > 0 && self.cutoff.is_none() {
            self.cutoff = Some(boundary);
        }
    }

    fn record_tx_diffs(&mut self, real: &ObservedTx, shadow: &ObservedTx, index: usize) {
        let boundary = Boundary::Transaction(index);
        let mut diff = Comparison::new(self, boundary, Location::Observation, real, shadow);
        diff.record("success", |tx| tx.receipt.success, Kind::Observation);
        diff.record("output", |tx| tx.output_hash, Kind::Observation);
        if real.logs_hash != shadow.logs_hash {
            diff.record("logs", |tx| tx.logs_hash, Kind::Observation);
        } else {
            diff.record("fee_logs", |tx| tx.receipt.logs_hash, Kind::Fee);
        }
        diff.record("gas", |tx| tx.receipt.gas_used, Kind::Gas);
        self.record_state_diffs(boundary, &real.state, &shadow.state, Some((real, shadow)));
    }
}

/// Diagnostic data for one unexpected field difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Difference {
    kind: Kind,
    field: &'static str,
    address: Option<Address>,
    slot: Option<U256>,
    real: String,
    shadow: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Stop,
    Observation,
    Gas,
    Fee,
}

#[derive(Clone, Copy)]
enum Location {
    Observation,
    Account(Address),
    Storage(Address, U256),
}

impl Location {
    fn parts(self) -> (Option<Address>, Option<U256>) {
        match self {
            Self::Observation => (None, None),
            Self::Account(address) => (Some(address), None),
            Self::Storage(address, slot) => (Some(address), Some(slot)),
        }
    }
}

struct Comparison<'a, T> {
    report: &'a mut Report,
    boundary: Boundary,
    loc: Location,
    real: &'a T,
    shadow: &'a T,
}

impl<'a, T> Comparison<'a, T> {
    fn new(
        report: &'a mut Report,
        boundary: Boundary,
        location: Location,
        real: &'a T,
        shadow: &'a T,
    ) -> Self {
        Self {
            report,
            boundary,
            loc: location,
            real,
            shadow,
        }
    }

    fn record<V: Debug + Eq>(&mut self, field: &'static str, get: impl Fn(&T) -> V, kind: Kind) {
        let (real, shadow) = (get(self.real), get(self.shadow));
        if real == shadow {
            return;
        }

        let (address, slot) = self.loc.parts();
        self.report.record(
            self.boundary,
            Difference {
                kind,
                field,
                address,
                slot,
                real: format!("{real:?}"),
                shadow: format!("{shadow:?}"),
            },
        );
    }
}

#[derive(Clone, Copy)]
struct AccountDelta<'a>(Option<&'a TransitionAccount>);

impl<'a> AccountDelta<'a> {
    fn info<T: Eq>(self, get: impl Fn(&reth_revm::state::AccountInfo) -> T) -> Option<(T, T)> {
        let account = self.0?;
        Self::changed(
            get(account.previous_info.as_ref()?),
            get(account.info.as_ref()?),
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

fn sample_cmp(a: &(Boundary, Difference), b: &(Boundary, Difference)) -> Ordering {
    a.1.kind
        .cmp(&b.1.kind)
        .then_with(|| a.0.cmp(&b.0))
        .then_with(|| a.1.address.cmp(&b.1.address))
        .then_with(|| a.1.slot.cmp(&b.1.slot))
        .then_with(|| a.1.field.cmp(b.1.field))
}
