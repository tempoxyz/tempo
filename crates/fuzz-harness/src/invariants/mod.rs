//! Protocol invariants checked on state after a block's pre-execution changes and each transaction,
//! and on what each transaction changed.
//!
//! A check reads state only through view calls, over the accounts the state holds. On an exact
//! pre-state those are the accounts execution touched, so a check asserts only what holds for any
//! subset of accounts, and a view that reads a key the pre-state lacks answers nothing rather than
//! failing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy_primitives::{Address, Log, U256};
use invariants_core::{ObserveError, Report, SlotChange, Step};
use tempo_contracts::precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS, IStablecoinDEX, STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
};
use tempo_evm::{TempoEvmConfig, TempoEvmEnv};
use tempo_fuzz_types::{InvariantFailure, InvariantScope};
use tempo_invariants::{Tx, account, all, dex, fee_amm, tip20};
use tempo_precompiles::{storage::StorageKey, tip_fee_manager::amm::PoolKey};
use tempo_primitives::is_tip20_prefix;

use crate::state::{Db, Net};

use reader::Reader;

mod reader;
mod views;

/// How many of the newest DEX orders the books are read over.
const MAX_ORDERS: u128 = 256;

/// What a transaction step did: its net state changes, already written to the database, and its
/// logs.
pub(crate) struct StepEffects<'a> {
    pub(crate) net: &'a Net,
    pub(crate) logs: &'a [Log],
    pub(crate) tx: Tx,
}

impl StepEffects<'_> {
    /// The step from `pre` to `post`, models of `contract`.
    fn step<M>(&self, contract: Address, pre: M, post: M) -> Step<M, Option<Tx>> {
        let changes = self
            .net
            .get(&contract)
            .into_iter()
            .flat_map(|account| account.changed_slots())
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

/// What a block's last checked step read of each token's ledger and of the fee manager's books,
/// which is the state before its next step. A transaction's step rereads only the balances, pools,
/// LP balances and collected fees whose storage it wrote, and those new to the check, and takes the
/// rest from here, so its checks judge the same models a full read would.
#[derive(Default)]
pub(crate) struct Seen {
    /// Each token's ledger, with the holders read of it.
    ledgers: BTreeMap<Address, (Vec<Address>, tip20::Ledger)>,
    books: Option<SeenBooks>,
}

/// The fee manager's books, `None` if nothing answered them, what they were read over, the first
/// slot they missed, and what each slot read stores.
struct SeenBooks {
    tokens: Vec<Address>,
    validators: Vec<Address>,
    holders: Vec<Address>,
    books: Option<fee_amm::Books>,
    missing: Option<(Address, U256, Option<Stored>)>,
    slots: HashMap<U256, Stored>,
}

/// What a fee manager slot stores: a pool's reserves or LP supply, a holder's LP balance in it (by
/// the pool's index in the pairs read), or a validator's collected fees.
#[derive(Clone, Copy)]
enum Stored {
    Pool(usize),
    Lp(usize, Address),
    Fees(Address),
}

/// The slots of `address` the step wrote.
fn written(effects: Option<&StepEffects<'_>>, address: Address) -> BTreeSet<U256> {
    effects
        .and_then(|effects| effects.net.get(&address))
        .into_iter()
        .flat_map(|account| account.changed_slots())
        .map(|(slot, _)| *slot)
        .collect()
}

/// The slots the fee manager's books are read from, in the order they are read: the fee manager's
/// balance of each token, then each pool's reserves, LP supply and holders' LP balances, then the
/// validators' collected fees. Each with what it stores, `None` for a token balance.
fn fee_slots<'a>(
    tokens: &'a [Address],
    pairs: impl Iterator<Item = (usize, (Address, Address))> + 'a,
    holders: &'a [Address],
    validators: &'a [Address],
) -> impl Iterator<Item = (Address, U256, Option<Stored>)> + 'a {
    use tempo_precompiles::tip_fee_manager::slots;
    let manager = TIP_FEE_MANAGER_ADDRESS;
    let held = manager.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
    let pools = pairs.flat_map(move |(i, (user, validator))| {
        let id = PoolKey::new(user, validator).get_id();
        let lp = id.mapping_slot(slots::LIQUIDITY_BALANCES);
        [slots::POOLS, slots::TOTAL_SUPPLY]
            .map(|base| (manager, id.mapping_slot(base), Some(Stored::Pool(i))))
            .into_iter()
            .chain(
                holders
                    .iter()
                    .map(move |&h| (manager, h.mapping_slot(lp), Some(Stored::Lp(i, h)))),
            )
    });
    let fees = validators.iter().flat_map(move |&v| {
        let fees = v.mapping_slot(slots::COLLECTED_FEES);
        tokens
            .iter()
            .map(move |&t| (manager, t.mapping_slot(fees), Some(Stored::Fees(v))))
    });
    tokens
        .iter()
        .map(move |&token| (token, held, None))
        .chain(pools)
        .chain(fees)
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
/// environment, which the views run in. Only contracts for which `selected` holds are checked, e.g. those whose state
/// changed, as no other contract's invariants can have broken. With `effects`, a token's step
/// checks also run on its ledger before the step against its ledger after it, and `seen` holds
/// what the block's last step read, updated to what this one read.
#[expect(clippy::too_many_arguments)]
pub(crate) fn check(
    db: &Db,
    evm_config: &TempoEvmConfig,
    env: TempoEvmEnv,
    scope: &InvariantScope,
    selected: impl Fn(&Address) -> bool,
    holders: &[Address],
    effects: Option<StepEffects<'_>>,
    seen: &mut Seen,
    failures: &mut Vec<InvariantFailure>,
    report: &mut Report,
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
        evm_config,
        env: &env,
        effects: effects.as_ref(),
    };
    let mut step = Report::default();
    step.register_any(all());
    for id in [tip20::VIEW, fee_amm::VIEW, dex::VIEW, account::VIEW] {
        step.counts.entry(id).or_default();
    }

    for &token in tokens.iter().filter(|token| selected(token)) {
        let prior = seen.ledgers.remove(&token).filter(|_| effects.is_some());
        let written = written(effects.as_ref(), token);
        let balance =
            |holder: &Address| holder.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
        let fresh: Vec<Address> = all_holders
            .iter()
            .copied()
            .filter(|holder| {
                prior.as_ref().is_none_or(|(read, _)| {
                    read.binary_search(holder).is_err() || written.contains(&balance(holder))
                })
            })
            .collect();
        let complete = |read: reader::Read<tip20::Ledger>| {
            read.map(|mut ledger| {
                if let Some((_, prior)) = &prior {
                    let kept = all_holders
                        .iter()
                        .filter(|h| fresh.binary_search(h).is_err());
                    ledger
                        .balances
                        .extend(kept.filter_map(|h| Some((*h, *prior.balances.get(h)?))));
                }
                ledger
            })
        };
        let at = tip20::At {
            token,
            holders: &fresh,
        };
        if let Some(Some(ledger)) = reader.check(&mut step, at, token, tip20::VIEW, complete) {
            seen.ledgers.insert(token, (all_holders.clone(), ledger));
        }
    }
    if selected(&TIP_FEE_MANAGER_ADDRESS) {
        let pairs: Vec<(Address, Address)> = tokens
            .iter()
            .flat_map(|&user| tokens.iter().map(move |&validator| (user, validator)))
            .filter(|(user, validator)| user != validator)
            .collect();
        // Fees are collected for the block's beneficiary; a step that distributes another
        // validator's fees names it in its logs.
        let mut validators: Vec<Address> = logged_addresses(effects.iter().flat_map(|e| e.logs))
            .chain([env.block.beneficiary])
            .collect();
        validators.sort_unstable();
        validators.dedup();
        let manager = TIP_FEE_MANAGER_ADDRESS;
        let read = |list: &[Address], a: &Address| list.binary_search(a).is_ok();
        // Books nothing answered stay so while the first slot they missed is missing and read.
        let prior = seen.books.take().filter(|prior| {
            effects.is_some()
                && prior.tokens == tokens
                && (prior.books.is_some()
                    || prior.missing.is_some_and(|(address, slot, stored)| {
                        db.misses(&address, &slot)
                            && match stored {
                                Some(Stored::Lp(_, holder)) => read(&all_holders, &holder),
                                Some(Stored::Fees(validator)) => read(&validators, &validator),
                                _ => true,
                            }
                    }))
        });
        let (fresh_pairs, fresh_validators, fresh_holders) = match &prior {
            None => (
                (0..pairs.len()).collect(),
                validators.clone(),
                all_holders.clone(),
            ),
            Some(prior) => {
                let (mut pools, mut lp, mut fees) =
                    (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
                let written = written(effects.as_ref(), manager);
                for stored in written.iter().filter_map(|slot| prior.slots.get(slot)) {
                    match *stored {
                        Stored::Pool(pool) => pools.insert(pool),
                        Stored::Lp(pool, holder) => pools.insert(pool) | lp.insert(holder),
                        Stored::Fees(validator) => fees.insert(validator),
                    };
                }
                let holders: Vec<Address> = all_holders
                    .iter()
                    .copied()
                    .filter(|h| !read(&prior.holders, h) || lp.contains(h))
                    .collect();
                // A new holder's LP is read in every pool.
                let pairs: Vec<usize> = if all_holders.iter().any(|h| !read(&prior.holders, h)) {
                    (0..pairs.len()).collect()
                } else {
                    pools.into_iter().collect()
                };
                let validators = validators
                    .iter()
                    .copied()
                    .filter(|v| !read(&prior.validators, v) || fees.contains(v))
                    .collect();
                (pairs, validators, holders)
            }
        };
        let read_pairs: Vec<(Address, Address)> = fresh_pairs.iter().map(|&i| pairs[i]).collect();
        let complete = |read: reader::Read<fee_amm::Books>| {
            let Some(prior) = &prior else {
                return read;
            };
            let Some(before) = &prior.books else {
                return match read {
                    Err(err) if !err.is_not_answered() => Err(err),
                    _ => Err(ObserveError::NotAnswered {
                        call: "the fee manager's books",
                        to: manager,
                    }),
                };
            };
            read.map(|fresh| {
                let mut read = fresh.pools.into_iter();
                let pools = before
                    .pools
                    .iter()
                    .enumerate()
                    .map(|(i, before)| {
                        let mut pool = match fresh_pairs.binary_search(&i) {
                            Ok(_) => read.next().expect("a pool is read for each fresh pair"),
                            Err(_) => before.clone(),
                        };
                        pool.lp = all_holders
                            .iter()
                            .filter_map(|h| Some((*h, *pool.lp.get(h).or(before.lp.get(h))?)))
                            .collect();
                        pool
                    })
                    .collect();
                let collected = validators
                    .iter()
                    .flat_map(|&v| tokens.iter().map(move |&t| (v, t)))
                    .filter_map(|key| {
                        let fees = fresh.collected.get(&key).or(before.collected.get(&key))?;
                        Some((key, *fees))
                    })
                    .collect();
                fee_amm::Books {
                    pools,
                    collected,
                    ..fresh
                }
            })
        };
        let at = fee_amm::At {
            fee_manager: manager,
            tokens: &tokens,
            pairs: &read_pairs,
            validators: &fresh_validators,
            holders: &fresh_holders,
        };
        if let Some(books) = reader.check(&mut step, at, manager, fee_amm::VIEW, complete) {
            let fresh = fresh_pairs.iter().copied().zip(read_pairs.iter().copied());
            let missing = match (&books, &prior) {
                (Some(_), _) => None,
                (
                    None,
                    Some(SeenBooks {
                        books: None,
                        missing,
                        ..
                    }),
                ) => *missing,
                (None, _) => {
                    let pairs = pairs.iter().copied().enumerate();
                    fee_slots(&tokens, pairs, &all_holders, &validators)
                        .find(|(address, slot, _)| db.misses(address, slot))
                }
            };
            let mut slots = prior.map(|prior| prior.slots).unwrap_or_default();
            slots.extend(
                fee_slots(&tokens, fresh, &fresh_holders, &fresh_validators)
                    .filter_map(|(_, slot, stored)| Some((slot, stored?))),
            );
            if books.is_some() || missing.is_some() {
                seen.books = Some(SeenBooks {
                    tokens: tokens.clone(),
                    validators,
                    holders: all_holders.clone(),
                    books,
                    missing,
                    slots,
                });
            }
        }
    }
    if selected(&STABLECOIN_DEX_ADDRESS) {
        // The newest orders the DEX numbered (ids start at 1), so DEX10 counts their escrow.
        let mut views = views::EvmViews::new(db.view(), evm_config, env.clone(), &db.pre);
        let next = invariants_core::view(
            &mut views,
            STABLECOIN_DEX_ADDRESS,
            IStablecoinDEX::nextOrderIdCall {},
        )
        .unwrap_or(0);
        let orders: Vec<u128> = (next.saturating_sub(MAX_ORDERS).max(1)..next).collect();
        let at = dex::At {
            dex: STABLECOIN_DEX_ADDRESS,
            tokens: &tokens,
            users: &all_holders,
            orders: &orders,
        };
        reader.check::<dex::Books>(&mut step, at, STABLECOIN_DEX_ADDRESS, dex::VIEW, |read| {
            read
        });
    }
    if let Some(effects) = &effects {
        // A transaction changes a commitment only by changing its account, so the accounts it
        // changed and its sender are all it can have moved.
        let mut changed: Vec<Address> = effects
            .net
            .addresses()
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
        reader.check::<account::Commitments>(&mut step, at, precompile, account::VIEW, |read| read);
    }

    failures.extend(step.violations.drain(..).map(|violation| InvariantFailure {
        id: violation.id.to_string(),
        message: format!("{} {}", violation.subject, violation.detail),
        scope: scope.clone(),
    }));
    report.merge(step);
    db.pre.restore_missed(missed);
}
