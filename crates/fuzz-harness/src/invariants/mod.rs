//! Protocol invariants checked on state after a block's pre-execution changes and each transaction.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

use std::fmt::Display;

use alloy_evm::{Evm as _, EvmEnv};
use alloy_primitives::{Address, Bytes};
use invariants_core::{ObserveError, Report, Violation};
use revm::database_interface::WrapDatabaseRef;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{dex, fee_amm, tip20};
use tempo_primitives::{TempoBlockEnv, is_tip20_prefix};

use crate::state::{Db, PreStateDb};

/// A TIP-20's views answer.
const TIP20_VIEW: &str = "TEMPO-TIP20-VIEW";
/// The fee manager's views answer.
const FEE_VIEW: &str = "TEMPO-FEE-VIEW";
/// The DEX's views answer.
const DEX_VIEW: &str = "TEMPO-DEX-VIEW";

/// Appends to `failures` each invariant `db` breaks, at `scope`, over the accounts `db` holds,
/// and adds how many subjects each judged, was armed for and found broken to `report`; `holders`
/// are read as balance holders too, but never checked as contracts. `env` is the block's
/// environment. Only contracts for which `selected` holds are checked, e.g. those whose state
/// changed, as no other contract's invariants can have broken.
pub(crate) fn check(
    db: &Db,
    env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    holders: &[Address],
    failures: &mut Vec<InvariantFailure>,
    report: &mut Report,
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
    let mut all_holders: Vec<Address> = accounts.iter().chain(holders).copied().collect();
    all_holders.sort_unstable();
    all_holders.dedup();
    let tokens: Vec<Address> = accounts
        .iter()
        .copied()
        .filter(|account| is_tip20_prefix(*account))
        .collect();

    let mut views = Views(TempoEvm::new(WrapDatabaseRef(db), env.clone()));
    let mut step = Report::default();
    step.register(tip20::CHECKS);
    step.register(fee_amm::CHECKS);
    step.register(dex::CHECKS);
    for id in [TIP20_VIEW, FEE_VIEW, DEX_VIEW] {
        step.counts.entry(id).or_default();
    }

    for &token in tokens.iter().filter(|token| selected(token)) {
        let ledger = tip20::observe_partial(&mut views, token, &all_holders);
        if let Some(ledger) = observed(&mut step, TIP20_VIEW, format!("token={token}"), ledger) {
            step.run(tip20::CHECKS, &ledger);
        }
    }
    if selected(&TIP_FEE_MANAGER_ADDRESS) {
        let pairs: Vec<(Address, Address)> = tokens
            .iter()
            .flat_map(|&user| tokens.iter().map(move |&validator| (user, validator)))
            .filter(|(user, validator)| user != validator)
            .collect();
        let books = fee_amm::observe(
            &mut views,
            TIP_FEE_MANAGER_ADDRESS,
            &tokens,
            &pairs,
            &[env.block_env.inner.beneficiary],
            &all_holders,
        );
        if let Some(books) = observed(&mut step, FEE_VIEW, TIP_FEE_MANAGER_ADDRESS, books) {
            step.run(fee_amm::CHECKS, &books);
        }
    }
    if selected(&STABLECOIN_DEX_ADDRESS) {
        let books = dex::observe(
            &mut views,
            STABLECOIN_DEX_ADDRESS,
            &tokens,
            &all_holders,
            &[],
        );
        if let Some(books) = observed(&mut step, DEX_VIEW, STABLECOIN_DEX_ADDRESS, books) {
            step.run(dex::CHECKS, &books);
        }
    }

    failures.extend(step.violations.drain(..).map(|violation| InvariantFailure {
        id: violation.id.to_string(),
        message: format!("{} {}", violation.subject, violation.detail),
        scope: scope.clone(),
    }));
    report.merge(step);
    pre_state.restore_missed(missed);
}

/// `read`'s value, counting it under `view`: a read nothing answered is not armed, one that
/// failed otherwise breaks `view`.
fn observed<T>(
    report: &mut Report,
    view: &'static str,
    subject: impl Display,
    read: Result<T, ObserveError<String>>,
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

/// Read-only calls against the state being checked.
struct Views<'a>(TempoEvm<WrapDatabaseRef<&'a Db>>);

impl Views<'_> {
    fn pre_state(&self) -> &PreStateDb {
        &self.0.components().0.0.database.0
    }

    /// `input`'s output from `target`. `Ok(None)` when nothing answers: `target` has no code, or
    /// the call read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, target: Address, input: &Bytes) -> Result<Option<Bytes>, String> {
        let selector = input
            .get(..4)
            .map(Bytes::copy_from_slice)
            .unwrap_or_default();
        self.pre_state().restore_missed(false);
        let result = self
            .0
            .transact_system_call(Address::ZERO, target, input.clone());
        if self.pre_state().missed() {
            return Ok(None);
        }
        let result = result
            .map_err(|err| format!("{selector} on {target}: {err}"))?
            .result;
        if !result.is_success() {
            return Err(format!("{selector} on {target}: {result:?}"));
        }
        Ok(result.output().filter(|output| !output.is_empty()).cloned())
    }
}

impl invariants_core::Views for Views<'_> {
    type Error = String;

    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, String> {
        calls
            .iter()
            .map(|(target, input)| self.call_one(*target, input))
            .collect()
    }
}
