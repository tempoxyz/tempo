//! Reading models through views and checking them.

use std::fmt::{self, Display};

use alloy_primitives::{Address, KECCAK256_EMPTY};
use invariants_core::{
    Check, Checked, Observe, ObserveError, Probe, Report, StepChecked, Violation,
};
use tempo_evm::{TempoEvmConfig, TempoEvmEnv};
use tempo_invariants::{Ran, TempoHardfork, model};

use super::{
    StepEffects,
    views::{EvmViews, PreView, ViewCache, ViewFailed},
};
use crate::state::Db;

/// Reads models from the state after a step and, with its `effects`, from the state before it, and
/// checks them into a report at the step's hardfork.
pub(super) struct EvmReader<'a> {
    /// Views of the state after the step.
    after: EvmViews<'a>,
    /// The step's effects and views of the state before it, which undo them.
    before: Option<(&'a StepEffects<'a>, EvmViews<'a>)>,
    report: &'a mut Report,
    spec: TempoHardfork,
}

impl<'a> EvmReader<'a> {
    /// Reads `db` in `env`, answering views from `view_cache`, and checks into `report`.
    pub(super) fn new(
        db: &'a Db,
        evm_config: &TempoEvmConfig,
        env: &TempoEvmEnv,
        effects: Option<&'a StepEffects<'a>>,
        view_cache: &'a ViewCache,
        report: &'a mut Report,
    ) -> Self {
        Self {
            after: EvmViews::new(
                db.view(),
                evm_config,
                env.clone(),
                &db.pre,
                view_cache,
                false,
            ),
            before: effects.map(|effects| {
                let db_before = PreView {
                    reader: db.view(),
                    net: effects.net,
                };
                (
                    effects,
                    EvmViews::new(
                        db_before,
                        evm_config,
                        env.clone(),
                        &db.pre,
                        view_cache,
                        true,
                    ),
                )
            }),
            report,
            spec: env.spec,
        }
    }

    /// Runs `checks` on `ctx` at the step's hardfork.
    pub(super) fn run<C>(&mut self, checks: &[Check<C, TempoHardfork>], ctx: &C) {
        self.report.run(checks, ctx, Some(&self.spec));
    }
}

impl<'a> model::Reader for EvmReader<'a> {
    type Views = EvmViews<'a>;

    fn after(&mut self) -> &mut EvmViews<'a> {
        &mut self.after
    }

    fn check<M>(&mut self, at: M::At<'_>, contract: Address, view: &'static str)
    where
        M: Observe + Checked<TempoHardfork> + StepChecked<Ran, TempoHardfork>,
    {
        let read = M::observe(&mut self.after, at);
        let Some(post) = observed(self.report, view, contract, read) else {
            return;
        };
        self.report.run(M::CHECKS, &post, Some(&self.spec));
        let Some((effects, before)) = &mut self.before else {
            return;
        };
        // The executor drops a system call's logs, so a system step's step checks would judge its
        // changes against none.
        if effects.ran.tx().is_none() {
            return;
        }
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
        let read = M::observe(before, at);
        // Nor does one it reads, such as a token the step created, whose views revert.
        if let Err(ObserveError::Unexpected { to, .. }) = &read
            && deployed(to)
        {
            return;
        }
        let subject = fmt::from_fn(|f| write!(f, "{contract} before the step"));
        let Some(pre) = observed(self.report, view, subject, read) else {
            return;
        };
        self.report
            .run(M::STEP_CHECKS, &effects.step(pre, post), Some(&self.spec));
    }

    fn probe<M>(&mut self, at: M::At<'_>, contract: Address, view: &'static str)
    where
        M: Probe + Checked<TempoHardfork>,
    {
        let read = M::probe(&mut self.after, at);
        if let Some(model) = observed(self.report, view, contract, read) {
            self.report.run(M::CHECKS, &model, Some(&self.spec));
        }
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
                id: view.into(),
                subject: subject.to_string(),
                detail: err.to_string(),
            });
            None
        }
    }
}
