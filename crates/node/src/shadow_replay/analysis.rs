//! Direct comparison and classification of net effects at completed replay boundaries.
//!
//! Only unexpected findings are formatted into the diagnostic representation retained by a report.
//! A missing state change means “no net effect at this boundary”.

use super::{Boundary, Evidence, ObservedTx};
use alloy_primitives::{Address, U256};
use reth_revm::db::{TransitionAccount, TransitionState};
use std::{cmp::Ordering, collections::HashSet, fmt::Debug};

/// Diagnostic data for one unexpected field difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Difference {
    kind: Kind,
    field: &'static str,
    address: Option<Address>,
    slot: Option<U256>,
    control: String,
    candidate: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Stopping,
    Observation,
    Gas,
    Fee,
}

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

impl Report {
    pub(super) fn findings(&self) -> usize {
        self.fee_associated + self.observation + self.gas_divergent_txs + self.stopping
    }

    /// Compares common completed boundaries in order and stops after finishing the first boundary
    /// containing a stopping difference.
    pub(super) fn analyze(control: &Evidence, candidate: &Evidence) -> Self {
        let mut report = Self::default();
        let common_txs = control.txs.len().min(candidate.txs.len());

        if let Some((control, candidate)) =
            control.pre_block.as_ref().zip(candidate.pre_block.as_ref())
        {
            report.record_state_diffs(Boundary::PreBlock, control, candidate, None);
        }
        for index in 0..common_txs {
            if report.cutoff.is_some() {
                report.boundaries_not_evaluated += common_txs - index;
                break;
            }
            report.record_tx_diffs(control, candidate, index);
        }
        if let Some((control, candidate)) = control
            .post_block
            .as_ref()
            .zip(candidate.post_block.as_ref())
        {
            if report.cutoff.is_some() {
                report.boundaries_not_evaluated += 1;
            } else {
                report.record_state_diffs(Boundary::PostBlock, control, candidate, None);
            }
        }
        report
    }

    fn record_diff<T: Debug + Eq>(
        &mut self,
        boundary: Boundary,
        location: Location,
        field: &'static str,
        control: T,
        candidate: T,
        kind: Kind,
    ) {
        if control == candidate {
            return;
        }

        let (address, slot) = location.parts();
        self.record(
            boundary,
            Difference {
                kind,
                field,
                address,
                slot,
                control: format!("{control:?}"),
                candidate: format!("{candidate:?}"),
            },
        );
    }

    fn record(&mut self, boundary: Boundary, difference: Difference) {
        *match difference.kind {
            Kind::Stopping => &mut self.stopping,
            Kind::Observation => &mut self.observation,
            Kind::Gas => &mut self.gas_divergent_txs,
            Kind::Fee => &mut self.fee_associated,
        } += 1;

        if difference.kind == Kind::Gas && self.gas_divergent_txs > 1 {
            return;
        }

        self.samples.push((boundary, difference));
        self.samples.sort_by(sample_cmp);
        self.samples.truncate(8);
    }

    fn record_state_diffs(
        &mut self,
        boundary: Boundary,
        control: &TransitionState,
        candidate: &TransitionState,
        tx: Option<(&ObservedTx, &ObservedTx)>,
    ) {
        let addresses: HashSet<_> = control
            .transitions
            .keys()
            .chain(candidate.transitions.keys())
            .copied()
            .collect();

        for address in addresses {
            let control = AccountDelta(control.transitions.get(&address));
            let candidate = AccountDelta(candidate.transitions.get(&address));
            let location = Location::Account(address);

            self.record_diff(
                boundary,
                location,
                "existence",
                control.existence(),
                candidate.existence(),
                Kind::Stopping,
            );
            self.record_diff(
                boundary,
                location,
                "balance",
                control.info(|info| info.balance),
                candidate.info(|info| info.balance),
                Kind::Stopping,
            );
            self.record_diff(
                boundary,
                location,
                "nonce",
                control.info(|info| info.nonce),
                candidate.info(|info| info.nonce),
                Kind::Stopping,
            );

            let slots: HashSet<_> = control.slots().chain(candidate.slots()).copied().collect();
            for slot in slots {
                let kind = if tx.is_some_and(|(control, candidate)| {
                    control.fee_slots.contains(&(address, slot))
                        || candidate.fee_slots.contains(&(address, slot))
                }) {
                    Kind::Fee
                } else {
                    Kind::Stopping
                };
                self.record_diff(
                    boundary,
                    Location::Storage(address, slot),
                    "storage",
                    control.storage(slot),
                    candidate.storage(slot),
                    kind,
                );
            }
        }

        if self.stopping > 0 && self.cutoff.is_none() {
            self.cutoff = Some(boundary);
        }
    }

    fn record_tx_diffs(&mut self, control: &Evidence, candidate: &Evidence, index: usize) {
        let boundary = Boundary::Transaction(index);
        let (control_tx, candidate_tx) = (&control.txs[index], &candidate.txs[index]);
        self.record_diff(
            boundary,
            Location::Observation,
            "success",
            control_tx.receipt.success,
            candidate_tx.receipt.success,
            Kind::Observation,
        );
        self.record_diff(
            boundary,
            Location::Observation,
            "output",
            control_tx.output_hash,
            candidate_tx.output_hash,
            Kind::Observation,
        );
        if control_tx.logs_hash != candidate_tx.logs_hash {
            self.record_diff(
                boundary,
                Location::Observation,
                "logs",
                control_tx.logs_hash,
                candidate_tx.logs_hash,
                Kind::Observation,
            );
        } else {
            self.record_diff(
                boundary,
                Location::Observation,
                "fee_logs",
                control_tx.receipt.logs_hash,
                candidate_tx.receipt.logs_hash,
                Kind::Fee,
            );
        }
        self.record_diff(
            boundary,
            Location::Observation,
            "gas",
            control_tx.receipt.gas_used,
            candidate_tx.receipt.gas_used,
            Kind::Gas,
        );
        self.record_state_diffs(
            boundary,
            &control_tx.state,
            &candidate_tx.state,
            Some((control_tx, candidate_tx)),
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
