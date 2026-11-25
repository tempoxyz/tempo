//! What an engine's own invariants read after an execution step.

use std::sync::Arc;

use alloy_primitives::{Address, Log};
use evm2::evm::AccountInfo;
use invariants_core::{Effects, Report};
use reth_evm::Database;
use tempo_evm::TempoEvmEnv;
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{Ran, configurable_account::Leaf};

use crate::{
    engine::Engine,
    invariants,
    state::{Db, Net},
};

/// The state after an execution step, with what the step did, as [`Engine::check_step`] reads it.
pub struct StepState<'a, C> {
    pub(crate) db: &'a Db,
    pub(crate) evm_config: &'a C,
    pub(crate) env: &'a TempoEvmEnv,
    pub(crate) net: &'a Net,
    pub(crate) effects: Arc<Effects<Ran>>,
}

impl<C> StepState<'_, C> {
    /// The EVM configuration the step executed with.
    pub const fn evm_config(&self) -> &C {
        self.evm_config
    }

    /// The environment the step executed in.
    pub const fn env(&self) -> &TempoEvmEnv {
        self.env
    }

    /// What the step ran: a block's pre- or post-execution changes, or a transaction.
    pub fn ran(&self) -> &Ran {
        &self.effects.ran
    }

    /// The logs the step emitted.
    pub fn logs(&self) -> &[Log] {
        &self.effects.logs
    }

    /// What the step did, as a model's step over it shares it.
    pub fn effects(&self) -> Arc<Effects<Ran>> {
        Arc::clone(&self.effects)
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
}

/// Runs `engine`'s own invariants on `state`, adding what they find at `scope` to `failures` and
/// `report`.
pub(crate) fn check<E: Engine>(
    engine: &E,
    state: &StepState<'_, E::EvmConfig>,
    scope: &InvariantScope,
    failures: &mut Vec<InvariantFailure>,
    report: &mut Report,
) {
    if !*invariants::ENABLED {
        return;
    }
    // The engine's reads are not part of execution.
    let missed = state.db.pre.missed();
    let start = report.violations.len();
    engine.check_step(state, report);
    failures.extend(
        report
            .violations
            .drain(start..)
            .map(|violation| InvariantFailure {
                violation,
                scope: scope.clone(),
            }),
    );
    state.db.pre.restore_missed(missed);
}
