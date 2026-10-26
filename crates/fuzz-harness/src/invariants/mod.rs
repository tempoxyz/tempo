//! Protocol invariants checked on state after a block's pre-execution changes and each transaction.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

mod tip20;

use alloy_evm::{Evm as _, EvmEnv};
use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use revm::database_interface::WrapDatabaseRef;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_primitives::TempoBlockEnv;

use crate::state::{Db, PreStateDb};

/// Appends to `failures` each invariant `db` breaks, at `scope`. `env` is the block's environment.
/// Only contracts for which `selected` holds are checked, e.g. those whose state changed, as no
/// other contract's invariants can have broken.
pub(crate) fn check(
    db: &Db,
    env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    failures: &mut Vec<InvariantFailure>,
) {
    let pre_state = &db.database.0;
    let missed = pre_state.missed();
    let mut accounts: Vec<Address> = db
        .cache
        .accounts
        .iter()
        .filter(|(_, account)| account.account.is_some())
        .map(|(address, _)| *address)
        .collect();
    accounts.sort_unstable();

    let mut views = Views(TempoEvm::new(WrapDatabaseRef(db), env.clone()));
    for (id, message) in tip20::check(&mut views, &accounts, selected) {
        failures.push(InvariantFailure {
            id: id.to_string(),
            message,
            scope: scope.clone(),
        });
    }
    pre_state.restore_missed(missed);
}

/// Read-only calls against the state being checked.
struct Views<'a>(TempoEvm<WrapDatabaseRef<&'a Db>>);

impl Views<'_> {
    fn pre_state(&self) -> &PreStateDb {
        &self.0.components().0.0.database.0
    }

    /// `call`'s return value from `target`. `Ok(None)` when nothing answers: `target` has no code,
    /// or the view read a key the pre-state lacks. `Err` when the view reverts, halts or returns
    /// something undecodable.
    fn call<C: SolCall>(&mut self, target: Address, call: C) -> Result<Option<C::Return>, String> {
        self.pre_state().restore_missed(false);
        let result = self
            .0
            .transact_system_call(Address::ZERO, target, call.abi_encode().into());
        if self.pre_state().missed() {
            return Ok(None);
        }
        let result = result
            .map_err(|err| format!("{} on {target}: {err}", C::SIGNATURE))?
            .result;
        if !result.is_success() {
            return Err(format!("{} on {target}: {result:?}", C::SIGNATURE));
        }
        match result.output() {
            Some(output) if !output.is_empty() => C::abi_decode_returns(output)
                .map(Some)
                .map_err(|err| format!("{} on {target} returned {output}: {err}", C::SIGNATURE)),
            _ => Ok(None),
        }
    }
}
