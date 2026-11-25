//! Protocol invariants checked on state after a block's pre-execution changes and each transaction,
//! and on what each transaction changed.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

use alloy_primitives::{Address, Log};
use invariants_core::{Effects, Report, SlotChange, Step};
use std::{
    ops::Deref,
    sync::{Arc, LazyLock},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmConfig, TempoEvmEnv};
use tempo_fuzz_types::{InvariantFailure, InvariantInfo, InvariantScope};
use tempo_invariants::{
    Check, Ran, VIEWS, configurable_account as account, dex, fee_amm, model, tip20,
};
use tempo_primitives::is_tip20_prefix;

use crate::state::{Db, Net};

/// Whether invariants are checked: unless the process sets `TEMPO_FUZZ_INVARIANTS=0`, as callers that only
/// need coverage, such as a corpus minimizer, do.
pub(crate) static ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("TEMPO_FUZZ_INVARIANTS").is_none_or(|value| value != "0"));

use reader::EvmReader;
pub(crate) use views::ViewCache;

mod configurable_account;
mod reader;
mod views;

pub(crate) use configurable_account::authority;

/// What a step did: its net state changes, already written to the database, and what
/// every model's step shares, which it derefs to.
pub(crate) struct StepEffects<'a> {
    pub(crate) net: &'a Net,
    pub(crate) spec: TempoHardfork,
    shared: Arc<Effects<Ran>>,
}

impl<'a> StepEffects<'a> {
    /// The effects of `ran`, which made `net`'s changes and emitted `logs`.
    pub(crate) fn new(net: &'a Net, logs: &[Log], ran: Ran, spec: TempoHardfork) -> Self {
        let changes = net
            .accounts()
            .flat_map(|(&address, account)| {
                account
                    .changed_slots()
                    .map(move |(slot, value)| SlotChange {
                        address,
                        slot: *slot,
                        before: value.original_value(),
                        after: value.present_value(),
                    })
            })
            .collect();
        let shared = Effects {
            changes,
            logs: logs.to_vec(),
            calls: None,
            ran,
        };
        Self {
            net,
            spec,
            shared: Arc::new(shared),
        }
    }

    /// The step from `pre` to `post`.
    fn step<M>(&self, pre: M, post: M) -> Step<M, Ran> {
        Step::new(pre, post, Arc::clone(&self.shared))
    }
}

impl Deref for StepEffects<'_> {
    type Target = Effects<Ran>;

    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

/// Every invariant the harness checks, and each model's counter of reads that failed.
pub(crate) fn catalog() -> Vec<InvariantInfo> {
    fn infos<C>(checks: &[Check<C>]) -> impl Iterator<Item = InvariantInfo> + '_ {
        checks.iter().map(|check| InvariantInfo {
            id: check.id.to_string(),
            doc: check.meta.doc.to_string(),
            tip: check.meta.tip.map(String::from),
            covers: check.meta.covers.iter().map(|&id| id.to_string()).collect(),
            since: check.meta.since,
            until: check.meta.until,
        })
    }
    let views = VIEWS.map(|(id, doc)| InvariantInfo {
        id: id.to_string(),
        doc: doc.to_string(),
        tip: None,
        covers: Vec::new(),
        since: None,
        until: None,
    });
    infos(tip20::CHECKS)
        .chain(infos(tip20::STEP_CHECKS))
        .chain(infos(fee_amm::CHECKS))
        .chain(infos(fee_amm::STEP_CHECKS))
        .chain(infos(dex::CHECKS))
        .chain(infos(dex::STEP_CHECKS))
        .chain(infos(account::STEP_CHECKS))
        .chain(infos(account::LEAF_CHECKS))
        .chain(views)
        .collect()
}

/// Appends to `failures` each invariant `db` breaks, at `scope`, over the accounts `db` holds,
/// and adds how many subjects each judged, was armed for and found broken to `report`; `holders`
/// are read as balance holders too, but never checked as contracts. `env` is the block's
/// environment, which the views run in. Only contracts for which `selected` holds are checked, and
/// of those only the ones the step changed, as no other contract's invariants can have broken,
/// except at the block's first step. With a transaction's `effects`, a model's step checks also run
/// on it before the step against it after. Views are answered from `view_cache`, the calls the block's
/// earlier steps made that this step left as they were.
#[expect(clippy::too_many_arguments)]
pub(crate) fn check(
    db: &Db,
    evm_config: &TempoEvmConfig,
    env: TempoEvmEnv,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    holders: &[Address],
    effects: Option<StepEffects<'_>>,
    view_cache: &ViewCache,
    failures: &mut Vec<InvariantFailure>,
    report: &mut Report,
) {
    if !*ENABLED {
        return;
    }
    // The block's first step also checks the state it starts from.
    let changed = effects
        .as_ref()
        .filter(|effects| effects.ran != Ran::PreBlock)
        .map(|effects| effects.net);
    let selected =
        |contract: &Address| selected(contract) && changed.is_none_or(|net| net.contains(contract));
    let missed = db.pre.missed();
    if let Some(effects) = &effects {
        view_cache.advance(effects.net);
    }
    let accounts: Vec<Address> = db
        .cache
        .borrow()
        .accounts
        .iter()
        .filter(|(_, account)| account.is_some())
        .map(|(address, _)| *address)
        .collect();
    // A step's own logs name holders its transitions touched only through a token's storage,
    // such as a transfer's recipient.
    let logged = model::logged_addresses(effects.iter().flat_map(|effects| &effects.logs));
    let mut all_holders: Vec<Address> = accounts
        .iter()
        .chain(holders)
        .copied()
        .chain(logged)
        .collect();
    all_holders.sort_unstable();
    all_holders.dedup();
    let mut tokens: Vec<Address> = accounts
        .iter()
        .copied()
        .filter(|account| is_tip20_prefix(*account))
        .collect();
    tokens.sort_unstable();

    let start = report.violations.len();
    {
        let mut reader = EvmReader::new(db, evm_config, &env, effects.as_ref(), view_cache, report);
        model::check(
            &mut reader,
            &model::Scope {
                tokens: &tokens,
                holders: &all_holders,
                beneficiary: env.block.beneficiary,
                effects: effects.as_deref(),
                selected: &selected,
            },
        );
        if let Some(effects) = &effects
            && let Some(tx) = effects.ran.tx()
        {
            configurable_account::check(&mut reader, db, effects, tx);
        }
    }

    failures.extend(
        report
            .violations
            .drain(start..)
            .map(|violation| InvariantFailure {
                violation,
                scope: scope.clone(),
            }),
    );
    db.pre.restore_missed(missed);
}
