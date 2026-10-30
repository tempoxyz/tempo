//! Reading models through views and checking them.

use std::fmt::Display;

use alloy_primitives::{Address, KECCAK256_EMPTY};
use invariants_core::{Observe, ObserveError, Report, Violation};
use tempo_evm::{TempoEvmConfig, TempoEvmEnv};
use tempo_invariants::all;

use super::{
    StepEffects,
    views::{EvmViews, PreView, ViewFailed},
};
use crate::state::Db;

/// Reads models from the state after a step and, with its `effects`, from the state before it.
pub(super) struct Reader<'a> {
    pub(super) db: &'a Db,
    pub(super) evm_config: &'a TempoEvmConfig,
    pub(super) env: &'a TempoEvmEnv,
    pub(super) effects: Option<&'a StepEffects<'a>>,
}

impl Reader<'_> {
    /// Reads the model `at` names at `contract` after the step and checks it into `report`; with
    /// the step's effects, also reads it before the step and checks the step. A read that fails
    /// is counted under `view` as [`observed`] does.
    pub(super) fn check<M: Observe + 'static>(
        &self,
        report: &mut Report,
        at: M::At<'_>,
        contract: Address,
        view: &'static str,
    ) {
        let pre_state = &self.db.pre;
        let after = EvmViews::new(self.db.view(), self.evm_config, self.env.clone(), pre_state);
        let Some(post) = observed(report, view, contract, M::observe(&mut { after }, at)) else {
            return;
        };
        report.run_any(all(), &post);
        let Some(effects) = self.effects else {
            return;
        };
        // A contract the step deployed has no state before it to read.
        let deployed = |address: &Address| {
            effects.net.get(address).is_some_and(|account| {
                account
                    .original()
                    .is_none_or(|info| info.code_hash == KECCAK256_EMPTY)
            })
        };
        if deployed(&contract) {
            return;
        }
        let before = PreView {
            reader: self.db.view(),
            net: effects.net,
        };
        let before = EvmViews::new(before, self.evm_config, self.env.clone(), pre_state);
        let subject = format!("{contract} before the step");
        let read = M::observe(&mut { before }, at);
        // Nor does one it reads, such as a token the step created.
        if let Err(ObserveError::Views(failed)) = &read
            && deployed(&failed.target())
        {
            return;
        }
        let Some(pre) = observed(report, view, subject, read) else {
            return;
        };
        report.run_any(all(), &effects.step(contract, pre, post));
    }
}

/// `read`'s value, counting it under `view`: a read nothing answered is not armed, one that
/// failed otherwise breaks `view`.
fn observed<T>(
    report: &mut Report,
    view: &'static str,
    subject: impl Display,
    read: Result<T, ObserveError<ViewFailed>>,
) -> Option<T> {
    let counts = report.counts.entry(view).or_default();
    counts.evaluated += 1;
    match read {
        Ok(value) => {
            counts.armed += 1;
            Some(value)
        }
        Err(err) if err.is_not_answered() => None,
        Err(err) => {
            counts.armed += 1;
            counts.fired += 1;
            report.violations.push(Violation {
                id: view,
                subject: subject.to_string(),
                detail: err.to_string(),
            });
            None
        }
    }
}
