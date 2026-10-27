//! Protocol invariants checked on state after a block's pre-execution changes and each transaction,
//! and on what each transaction changed.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

use std::fmt::{Debug, Display};

use alloy_evm::{Evm as _, EvmEnv};
use alloy_primitives::{Address, B256, Bytes, Log, U256};
use invariants_core::{Observe, ObserveError, Report, SlotChange, Step, Views, Violation};
use revm::{
    DatabaseRef, bytecode::Bytecode, database::TransitionState,
    database_interface::WrapDatabaseRef, state::AccountInfo,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{all, dex, fee_amm, tip20};
use tempo_primitives::{TempoBlockEnv, is_tip20_prefix};

use crate::state::{Db, PreStateDb};

/// A TIP-20's views answer.
const TIP20_VIEW: &str = "TEMPO-TIP20-VIEW";
/// The fee manager's views answer.
const FEE_VIEW: &str = "TEMPO-FEE-VIEW";
/// The DEX's views answer.
const DEX_VIEW: &str = "TEMPO-DEX-VIEW";

/// What a transaction step did: its state transitions, not yet applied to the bundle, and its logs.
pub(crate) struct StepEffects<'a> {
    pub(crate) transitions: &'a TransitionState,
    pub(crate) logs: &'a [Log],
}

impl StepEffects<'_> {
    /// The step from `pre` to `post`, models of `contract`.
    fn step<M>(&self, contract: Address, pre: M, post: M) -> Step<M> {
        let changes = self
            .transitions
            .transitions
            .get(&contract)
            .into_iter()
            .flat_map(|account| &account.storage)
            .filter(|(_, slot)| slot.is_changed())
            .map(|(slot, value)| SlotChange {
                address: contract,
                slot: *slot,
                before: value.original_value(),
                after: value.present_value(),
            })
            .collect();
        Step {
            pre,
            post,
            changes,
            logs: self.logs.to_vec(),
            tx: (),
        }
    }
}

/// Reads models from the state after a step and, with its `effects`, from the state before it.
struct Reader<'a> {
    db: &'a Db,
    env: &'a EvmEnv<TempoHardfork, TempoBlockEnv>,
    pre_state: &'a PreStateDb,
    effects: Option<&'a StepEffects<'a>>,
}

impl Reader<'_> {
    /// Reads the model `at` names at `contract` after the step and checks it into `report`; with
    /// the step's effects, also reads it before the step and checks the step. A read that fails
    /// is counted under `view` as [`observed`] does.
    fn check<M: Observe + 'static>(
        &self,
        report: &mut Report,
        at: M::At<'_>,
        contract: Address,
        view: &'static str,
    ) {
        let after = EvmViews::new(self.db, self.env, self.pre_state);
        let Some(post) = observed(report, view, contract, M::observe(&mut { after }, at)) else {
            return;
        };
        report.run_any(all(), &post);
        let Some(effects) = self.effects else {
            return;
        };
        let before = PreView {
            db: self.db,
            transitions: effects.transitions,
        };
        let before = EvmViews::new(before, self.env, self.pre_state);
        let subject = format!("{contract} before the step");
        let Some(pre) = observed(report, view, subject, M::observe(&mut { before }, at)) else {
            return;
        };
        report.run_any(all(), &effects.step(contract, pre, post));
    }
}

/// The state before a step: `db` with the step's `transitions` undone.
#[derive(Debug)]
struct PreView<'a> {
    db: &'a Db,
    transitions: &'a TransitionState,
}

impl DatabaseRef for PreView<'_> {
    type Error = <Db as DatabaseRef>::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.transitions.transitions.get(&address) {
            Some(account) => Ok(account.previous_info.clone()),
            None => self.db.basic_ref(address),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.db.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        if let Some(account) = self.transitions.transitions.get(&address) {
            if let Some(value) = account.storage.get(&slot) {
                return Ok(value.original_value());
            }
            if account.previous_info.is_none() {
                return Ok(U256::ZERO);
            }
        }
        self.db.storage_ref(address, slot)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash_ref(number)
    }
}

/// Read-only calls against the state `D` holds, noting reads the seeded pre-state misses.
struct EvmViews<'a, D: DatabaseRef + Debug> {
    evm: TempoEvm<WrapDatabaseRef<D>>,
    pre_state: &'a PreStateDb,
}

impl<'a, D: DatabaseRef + Debug> EvmViews<'a, D> {
    fn new(db: D, env: &EvmEnv<TempoHardfork, TempoBlockEnv>, pre_state: &'a PreStateDb) -> Self {
        Self {
            evm: TempoEvm::new(WrapDatabaseRef(db), env.clone()),
            pre_state,
        }
    }

    fn pre_state(&self) -> &PreStateDb {
        self.pre_state
    }

    /// `input`'s output from `target`. `Ok(None)` when nothing answers: `target` has no code, or
    /// the call read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, target: Address, input: &Bytes) -> Result<Option<Bytes>, ViewFailed> {
        let selector = input
            .get(..4)
            .map(Bytes::copy_from_slice)
            .unwrap_or_default();
        self.pre_state().restore_missed(false);
        let result = self
            .evm
            .transact_system_call(Address::ZERO, target, input.clone());
        if self.pre_state().missed() {
            return Ok(None);
        }
        let failed = |reason| ViewFailed {
            selector: selector.clone(),
            target,
            reason,
        };
        let result = result.map_err(|err| failed(err.to_string()))?.result;
        if !result.is_success() {
            return Err(failed(format!("{result:?}")));
        }
        Ok(result.output().filter(|output| !output.is_empty()).cloned())
    }
}

impl<D: DatabaseRef + Debug> Views for EvmViews<'_, D> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls
            .iter()
            .map(|(target, input)| self.call_one(*target, input))
            .collect()
    }

    /// The seeded pre-state may hold only the accounts and slots execution touched.
    fn partial(&self) -> bool {
        true
    }
}

/// A view call that reverted, halted or could not run.
#[derive(Debug)]
struct ViewFailed {
    selector: Bytes,
    target: Address,
    reason: String,
}

impl Display for ViewFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} on {}: {}", self.selector, self.target, self.reason)
    }
}

/// Appends to `failures` each invariant `db` breaks, at `scope`, over the accounts `db` holds,
/// and adds how many subjects each judged, was armed for and found broken to `report`; `holders`
/// are read as balance holders too, but never checked as contracts. `env` is the block's
/// environment. Only contracts for which `selected` holds are checked, e.g. those whose state
/// changed, as no other contract's invariants can have broken. With `effects`, a token's step
/// checks also run on its ledger before the step against its ledger after it.
#[expect(clippy::too_many_arguments)]
pub(crate) fn check(
    db: &Db,
    env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    holders: &[Address],
    effects: Option<StepEffects<'_>>,
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
    // A step's own logs name holders its transitions touched only through a token's storage,
    // such as a transfer's recipient.
    let logged = effects
        .iter()
        .flat_map(|effects| effects.logs)
        .flat_map(|log| log.topics())
        .filter(|topic| topic[..12] == [0; 12])
        .map(|topic| Address::from_word(*topic));
    let mut all_holders: Vec<Address> = accounts
        .iter()
        .chain(holders)
        .copied()
        .chain(logged)
        .collect();
    all_holders.sort_unstable();
    all_holders.dedup();
    let tokens: Vec<Address> = accounts
        .iter()
        .copied()
        .filter(|account| is_tip20_prefix(*account))
        .collect();

    let reader = Reader {
        db,
        env,
        pre_state,
        effects: effects.as_ref(),
    };
    let mut step = Report::default();
    step.register_any(all());
    for id in [TIP20_VIEW, FEE_VIEW, DEX_VIEW] {
        step.counts.entry(id).or_default();
    }

    for &token in tokens.iter().filter(|token| selected(token)) {
        let at = tip20::At {
            token,
            holders: &all_holders,
        };
        reader.check::<tip20::Ledger>(&mut step, at, token, TIP20_VIEW);
    }
    if selected(&TIP_FEE_MANAGER_ADDRESS) {
        let pairs: Vec<(Address, Address)> = tokens
            .iter()
            .flat_map(|&user| tokens.iter().map(move |&validator| (user, validator)))
            .filter(|(user, validator)| user != validator)
            .collect();
        let at = fee_amm::At {
            fee_manager: TIP_FEE_MANAGER_ADDRESS,
            tokens: &tokens,
            pairs: &pairs,
            validators: &[env.block_env.inner.beneficiary],
            holders: &all_holders,
        };
        reader.check::<fee_amm::Books>(&mut step, at, TIP_FEE_MANAGER_ADDRESS, FEE_VIEW);
    }
    if selected(&STABLECOIN_DEX_ADDRESS) {
        let at = dex::At {
            dex: STABLECOIN_DEX_ADDRESS,
            tokens: &tokens,
            users: &all_holders,
            orders: &[],
        };
        reader.check::<dex::Books>(&mut step, at, STABLECOIN_DEX_ADDRESS, DEX_VIEW);
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
