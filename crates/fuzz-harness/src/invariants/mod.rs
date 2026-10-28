//! Protocol invariants checked on state after a block's pre-execution changes and each transaction.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

mod tip20;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use evm2::evm::SystemTx;
use reth_evm::ConfigureEvm as _;
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv};
use tempo_fuzz_types::{InvariantFailure, InvariantScope};

use crate::state::{Db, PreStateDb};

/// Appends to `failures` each invariant `db` breaks, at `scope`, over the accounts `db` holds;
/// `holders` are summed as balance holders too, but never checked as contracts. `env` is the
/// block's environment, which the views run in. Only contracts for which `selected` holds are
/// checked, e.g. those whose state changed, as no other contract's invariants can have broken.
pub(crate) fn check(
    db: &Db,
    evm_config: &TempoEvmConfig,
    env: TempoEvmEnv,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    holders: &[Address],
    failures: &mut Vec<InvariantFailure>,
) {
    let missed = db.pre.missed();
    let mut accounts: Vec<Address> = db
        .cache
        .borrow()
        .accounts
        .iter()
        .filter(|(_, account)| account.is_some())
        .map(|(address, _)| *address)
        .collect();
    accounts.sort_unstable();
    let mut all_holders: Vec<Address> = accounts.iter().chain(holders).copied().collect();
    all_holders.sort_unstable();
    all_holders.dedup();

    let mut views = Views {
        evm: evm_config.evm_with_env(db.view(), env),
        pre_state: &db.pre,
    };
    for (id, message) in tip20::check(&mut views, &accounts, &all_holders, selected) {
        failures.push(InvariantFailure {
            id: id.to_string(),
            message,
            scope: scope.clone(),
        });
    }
    db.pre.restore_missed(missed);
}

/// Read-only calls against the state being checked.
struct Views<'a> {
    evm: TempoEvm<'a>,
    pre_state: &'a PreStateDb,
}

impl Views<'_> {
    /// `call`'s return value from `target`. `Ok(None)` when nothing answers: `target` has no code,
    /// or the view read a key the pre-state lacks. `Err` when the view reverts, halts or returns
    /// something undecodable.
    fn call<C: SolCall>(&mut self, target: Address, call: C) -> Result<Option<C::Return>, String> {
        self.pre_state.restore_missed(false);
        let data: Bytes = call.abi_encode().into();
        let result = self
            .evm
            .system_call(SystemTx::new(target, data).with_caller(Address::ZERO));
        if self.pre_state.missed() {
            return Ok(None);
        }
        let executed = result.map_err(|err| format!("{} on {target}: {err}", C::SIGNATURE))?;
        let result = executed.result();
        if !result.is_success() {
            return Err(format!("{} on {target}: {result:?}", C::SIGNATURE));
        }
        let output = &result.output;
        if output.is_empty() {
            return Ok(None);
        }
        C::abi_decode_returns(output)
            .map(Some)
            .map_err(|err| format!("{} on {target} returned {output}: {err}", C::SIGNATURE))
    }
}
