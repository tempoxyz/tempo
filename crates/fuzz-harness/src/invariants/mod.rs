//! Protocol invariants checked on state after a block's pre-execution changes and each transaction,
//! and on what each transaction changed.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

use alloy_evm::EvmEnv;
use alloy_primitives::{Address, Log};
use invariants_core::{Report, SlotChange, Step};
use revm::database::TransitionState;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
};
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{Tx, account, all, dex, fee_amm, tip20};
use tempo_primitives::{TempoBlockEnv, is_tip20_prefix};

use crate::state::Db;

use reader::Reader;

mod reader;
mod views;

/// What a transaction step did: its state transitions, not yet applied to the bundle, and its logs.
pub(crate) struct StepEffects<'a> {
    pub(crate) transitions: &'a TransitionState,
    pub(crate) logs: &'a [Log],
    pub(crate) tx: Tx,
}

impl StepEffects<'_> {
    /// The step from `pre` to `post`, models of `contract`.
    fn step<M>(&self, contract: Address, pre: M, post: M) -> Step<M, Option<Tx>> {
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
            tx: Some(self.tx),
        }
    }
}

/// The addresses in the topics of `logs`, such as the holders a `Transfer` names.
pub(crate) fn logged_addresses<'a>(
    logs: impl IntoIterator<Item = &'a Log>,
) -> impl Iterator<Item = Address> {
    logs.into_iter()
        .flat_map(|log| log.topics())
        .filter(|topic| topic[..12] == [0; 12])
        .map(|topic| Address::from_word(*topic))
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
    let logged = logged_addresses(effects.iter().flat_map(|effects| effects.logs));
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
    for id in [tip20::VIEW, fee_amm::VIEW, dex::VIEW, account::VIEW] {
        step.counts.entry(id).or_default();
    }

    for &token in tokens.iter().filter(|token| selected(token)) {
        let at = tip20::At {
            token,
            holders: &all_holders,
        };
        reader.check::<tip20::Ledger>(&mut step, at, token, tip20::VIEW);
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
        reader.check::<fee_amm::Books>(&mut step, at, TIP_FEE_MANAGER_ADDRESS, fee_amm::VIEW);
    }
    if selected(&STABLECOIN_DEX_ADDRESS) {
        let at = dex::At {
            dex: STABLECOIN_DEX_ADDRESS,
            tokens: &tokens,
            users: &all_holders,
            orders: &[],
        };
        reader.check::<dex::Books>(&mut step, at, STABLECOIN_DEX_ADDRESS, dex::VIEW);
    }
    if let Some(effects) = &effects {
        // A transaction changes a commitment only by changing its account, so the accounts it
        // changed and its sender are all it can have moved.
        let mut changed: Vec<Address> = effects
            .transitions
            .transitions
            .keys()
            .copied()
            .chain([effects.tx.sender])
            .collect();
        changed.sort_unstable();
        changed.dedup();
        let at = account::At {
            precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
            accounts: &changed,
        };
        let precompile = CONFIGURABLE_ACCOUNT_ADDRESS;
        reader.check::<account::Commitments>(&mut step, at, precompile, account::VIEW);
    }

    failures.extend(step.violations.drain(..).map(|violation| InvariantFailure {
        id: violation.id.to_string(),
        message: format!("{} {}", violation.subject, violation.detail),
        scope: scope.clone(),
    }));
    report.merge(step);
    pre_state.restore_missed(missed);
}
