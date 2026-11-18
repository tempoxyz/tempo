//! What an engine's own invariants read after an execution step.

use alloy_primitives::{Address, Log};
use evm2::evm::AccountInfo;
use invariants_core::{Observe, Report};
use reth_evm::Database;
use tempo_evm::TempoEvmEnv;
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{Tx, configurable_account::Leaf};

use crate::{
    engine::{Engine, EvmConfig},
    invariants::{self, ViewCache},
    state::{Db, Net},
};

/// The state after an execution step, with what the step did, as [`Engine::check_step`] reads it.
pub struct StepState<'a, C> {
    pub(crate) db: &'a Db,
    pub(crate) evm_config: &'a C,
    pub(crate) env: &'a TempoEvmEnv,
    pub(crate) net: &'a Net,
    pub(crate) tx: Option<&'a Tx>,
    pub(crate) logs: &'a [Log],
    pub(crate) scope: &'a InvariantScope,
}

impl<C: EvmConfig> StepState<'_, C> {
    /// Where in the input the step is.
    pub const fn scope(&self) -> &InvariantScope {
        self.scope
    }

    /// The EVM configuration the step executed with.
    pub const fn evm_config(&self) -> &C {
        self.evm_config
    }

    /// The environment the step executed in.
    pub const fn env(&self) -> &TempoEvmEnv {
        self.env
    }

    /// The transaction the step executed, or `None` for a block's pre-execution changes.
    pub const fn tx(&self) -> Option<&Tx> {
        self.tx
    }

    /// The logs of the step's transaction.
    pub const fn logs(&self) -> &[Log] {
        self.logs
    }

    /// The accounts the step changed.
    pub fn changed(&self) -> impl Iterator<Item = Address> + '_ {
        self.net.addresses().copied()
    }

    /// The account at `address` after the step: `Some(None)` if it does not exist, `None` if the
    /// pre-state cannot say.
    pub fn account(&self, address: Address) -> Option<Option<AccountInfo>> {
        invariants::account_at(self.db, None, address)
    }

    /// The TIP-1108 commitment and code hash of the account at `address` after the step, `None` if
    /// the pre-state cannot say or the account's configuration does not encode.
    pub fn leaf(&self, address: Address) -> Option<Leaf> {
        invariants::leaf(self.account(address)?, self.env.spec)
    }

    /// The state after the step, as a database to execute over.
    pub fn database(&self) -> impl Database + '_ {
        self.db.view()
    }

    /// Reads the model `at` names from the state after the step with view calls, counting the read
    /// under `view`: a read nothing answered is not armed, one that failed otherwise breaks
    /// `view`.
    pub fn observe<M: Observe>(
        &self,
        report: &mut Report,
        view: &'static str,
        subject: impl std::fmt::Display,
        at: M::At<'_>,
    ) -> Option<M> {
        let view_cache = ViewCache::default();
        let mut views = invariants::EvmViews::new(
            self.db.view(),
            self.evm_config,
            self.env.clone(),
            &self.db.pre,
            &view_cache,
            false,
        );
        invariants::observed(report, view, subject, M::observe(&mut views, at))
    }
}

/// Runs `engine`'s own invariants on `state`, adding what they find to `failures` and `report`.
pub(crate) fn check(
    engine: &impl Engine,
    state: &StepState<'_, impl EvmConfig>,
    failures: &mut Vec<InvariantFailure>,
    report: &mut Report,
) {
    if !*invariants::ENABLED {
        return;
    }
    // The engine's reads are not part of execution.
    let missed = state.db.pre.missed();
    let mut own = Report::default();
    engine.check_step(state, &mut own);
    failures.extend(own.violations.drain(..).map(|violation| InvariantFailure {
        id: violation.id.to_string(),
        message: format!("{} {}", violation.subject, violation.detail),
        scope: state.scope.clone(),
    }));
    report.merge(own);
    state.db.pre.restore_missed(missed);
}
