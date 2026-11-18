//! A plain model of the reservation core that random sequences compare the precompile with.

use super::*;
use std::collections::BTreeSet;

const OWNERS: usize = 2;
const TOKENS: usize = 2;
const IDS: usize = 3;
/// Accounts: two owners, two holders, two payees, a stranger and a lien authority.
const ACCOUNTS: usize = 8;
const H0: usize = 2;
const H1: usize = 3;
const P0: usize = 4;
const P1: usize = 5;
const STRANGER: usize = 6;
const AUTHORITY: usize = 7;
/// Accounts that may place records: the owners, the holders and the authority.
const PLACERS: [usize; 5] = [0, 1, H0, H1, AUTHORITY];
/// Payees a hold or charge may name; the owner itself is refused.
const PAYEES: [usize; 3] = [P0, P1, 0];
const MINT: u128 = 1_000;
/// Stands for the op's owner as its caller.
const SELF: usize = usize::MAX;

/// What a targeted op does to an existing record.
#[derive(Debug, Clone, Copy)]
pub(super) enum Action {
    Adjust,
    Capture,
    Release,
}

#[derive(Debug, Clone)]
pub(super) enum Op {
    Hold {
        caller: usize,
        owner: usize,
        token: usize,
        id: usize,
        amount: u128,
        ttl: u64,
        stand_in: bool,
        payee: usize,
    },
    Pledge {
        owner: usize,
        token: usize,
        id: usize,
        amount: u128,
        ttl: u64,
        authority: usize,
    },
    PledgeFrom {
        caller: usize,
        owner: usize,
        token: usize,
        id: usize,
        amount: u128,
        ttl: u64,
    },
    Lien {
        caller: usize,
        owner: usize,
        token: usize,
        id: usize,
        amount: u128,
        ttl: u64,
    },
    Adjust {
        caller: usize,
        owner: usize,
        placer: usize,
        id: usize,
        amount: u128,
    },
    Capture {
        caller: usize,
        owner: usize,
        placer: usize,
        id: usize,
        amount: u128,
        is_final: bool,
    },
    Release {
        caller: usize,
        owner: usize,
        placer: usize,
        id: usize,
    },
    ReleaseExpired {
        owner: usize,
        placer: usize,
        id: usize,
    },
    Charge {
        caller: usize,
        owner: usize,
        token: usize,
        amount: u128,
        stand_in: bool,
        payee: usize,
    },
    Refund {
        caller: usize,
        owner: usize,
        token: usize,
        amount: u128,
    },
    Transfer {
        from: usize,
        to: usize,
        token: usize,
        amount: u128,
    },
    Approve {
        owner: usize,
        holder: usize,
        token: usize,
        limit: u128,
        period: u32,
    },
    Block {
        account: usize,
        token: usize,
        blocked: bool,
    },
    ClearLapsed {
        owner: usize,
        token: usize,
    },
    Warp {
        seconds: u64,
    },
    /// Acts on the live record `pick` selects, as its placer, payee, owner or a stranger (`who`).
    Targeted {
        action: Action,
        pick: usize,
        who: usize,
        amount: u128,
        is_final: bool,
    },
}

pub(super) fn op_strategy() -> impl Strategy<Value = Op> {
    let account = 0..ACCOUNTS;
    let owner = 0..OWNERS;
    let token = 0..TOKENS;
    let id = 0..IDS;
    let placer = 0..PLACERS.len();
    let amount = 0..400u128;
    prop_oneof![
        5 => (prop::sample::select(vec![SELF, SELF, H0, H1, STRANGER, P0]), owner.clone(), token.clone(), id.clone(), amount.clone(), 0..900u64, any::<bool>(), 0..PAYEES.len())
            .prop_map(|(caller, owner, token, id, amount, ttl, stand_in, payee)| Op::Hold { caller, owner, token, id, amount, ttl, stand_in, payee }),
        1 => (owner.clone(), token.clone(), id.clone(), amount.clone(), 1..900u64, prop::sample::select(vec![P0, H0, AUTHORITY, 0]))
            .prop_map(|(owner, token, id, amount, ttl, authority)| Op::Pledge { owner, token, id, amount, ttl, authority }),
        2 => (prop::sample::select(vec![SELF, H0, H1, STRANGER]), owner.clone(), token.clone(), id.clone(), amount.clone(), 1..900u64)
            .prop_map(|(caller, owner, token, id, amount, ttl)| Op::PledgeFrom { caller, owner, token, id, amount, ttl }),
        1 => (prop::sample::select(vec![AUTHORITY, STRANGER]), owner.clone(), token.clone(), id.clone(), amount.clone(), 0..900u64)
            .prop_map(|(caller, owner, token, id, amount, ttl)| Op::Lien { caller, owner, token, id, amount, ttl }),
        2 => (account.clone(), owner.clone(), placer.clone(), id.clone(), amount)
            .prop_map(|(caller, owner, placer, id, amount)| Op::Adjust { caller, owner, placer: PLACERS[placer], id, amount }),
        5 => (account.clone(), owner.clone(), placer.clone(), id.clone(), 0..500u128, any::<bool>())
            .prop_map(|(caller, owner, placer, id, amount, is_final)| Op::Capture { caller, owner, placer: PLACERS[placer], id, amount, is_final }),
        2 => (account.clone(), owner.clone(), placer.clone(), id.clone())
            .prop_map(|(caller, owner, placer, id)| Op::Release { caller, owner, placer: PLACERS[placer], id }),
        1 => (owner.clone(), placer, id)
            .prop_map(|(owner, placer, id)| Op::ReleaseExpired { owner, placer: PLACERS[placer], id }),
        3 => (prop::sample::select(vec![SELF, SELF, H0, H1, STRANGER]), owner.clone(), token.clone(), 0..700u128, any::<bool>(), 0..PAYEES.len())
            .prop_map(|(caller, owner, token, amount, stand_in, payee)| Op::Charge { caller, owner, token, amount, stand_in, payee }),
        2 => (account.clone(), owner.clone(), token.clone(), 0..300u128)
            .prop_map(|(caller, owner, token, amount)| Op::Refund { caller, owner, token, amount }),
        2 => (account.clone(), account.clone(), token.clone(), 1..400u128)
            .prop_map(|(from, to, token, amount)| Op::Transfer { from, to, token, amount }),
        1 => (owner.clone(), prop::sample::select(vec![H0, H1, STRANGER]), token.clone(), 0..700u128, prop::sample::select(vec![0u32, 3_600]))
            .prop_map(|(owner, holder, token, limit, period)| Op::Approve { owner, holder, token, limit, period }),
        1 => (account, token.clone(), any::<bool>())
            .prop_map(|(account, token, blocked)| Op::Block { account, token, blocked }),
        1 => (owner, token).prop_map(|(owner, token)| Op::ClearLapsed { owner, token }),
        2 => prop_oneof![0..600u64, Just(DAY)].prop_map(|seconds| Op::Warp { seconds }),
        10 => (prop_oneof![Just(Action::Adjust), Just(Action::Capture), Just(Action::Capture), Just(Action::Release)], any::<usize>(), prop::sample::select(vec![0usize, 0, 1, 1, 2, 3]), 0..500u128, any::<bool>())
            .prop_map(|(action, pick, who, amount, is_final)| Op::Targeted { action, pick, who, amount, is_final }),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MHold {
    token: usize,
    payee: usize,
    held: u128,
    capture_limit: u128,
    expires_at: u64,
    kind: u8,
    stand_in: bool,
    tolerance_bps: u16,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MBudget {
    limit: u128,
    spent: u128,
    outstanding: u128,
    period: u32,
    period_start: u64,
}

impl MBudget {
    fn roll(&mut self, now: u64) {
        if self.period == 0 {
            return;
        }
        let period = u64::from(self.period);
        if now >= self.period_start + period {
            self.period_start += (now - self.period_start) / period * period;
            self.spent = 0;
        }
    }

    fn nonzero(&self) -> bool {
        *self != Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MDebt {
    creditor: usize,
    amount: u128,
    lapses_at: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct MTerms {
    debt_cap: u128,
    offline_cap: u128,
    tolerance_bps: u16,
    debt_term: u32,
}

type HoldKey = (usize, usize, usize);
type Outcome = std::result::Result<(), TempoPrecompileError>;

/// The model's state: plain maps over account and token indices.
#[derive(Debug, Clone, Default)]
struct Model {
    now: u64,
    balances: BTreeMap<(usize, usize), u128>,
    holds: BTreeMap<HoldKey, MHold>,
    budgets: BTreeMap<(usize, usize, usize), MBudget>,
    terms: BTreeMap<(usize, usize, usize), MTerms>,
    debts: BTreeMap<(usize, usize), Vec<MDebt>>,
    blocked: BTreeSet<(usize, usize)>,
}

fn refuse(cap: u128) -> TempoPrecompileError {
    if cap == 0 {
        e(ReservationsError::insufficient_available())
    } else {
        e(ReservationsError::debt_cap_exceeded())
    }
}

impl Model {
    fn bal(&self, token: usize, account: usize) -> u128 {
        self.balances.get(&(token, account)).copied().unwrap_or(0)
    }

    fn add(&mut self, token: usize, account: usize, amount: u128) {
        *self.balances.entry((token, account)).or_default() += amount;
    }

    fn sub(&mut self, token: usize, account: usize, amount: u128) {
        *self
            .balances
            .get_mut(&(token, account))
            .expect("debited balance") -= amount;
    }

    fn allowed(&self, token: usize, from: usize, to: usize, sender_exempt: bool) -> bool {
        to != from
            && (sender_exempt || !self.blocked.contains(&(token, from)))
            && !self.blocked.contains(&(token, to))
    }

    fn ensure_allowed(&self, token: usize, from: usize, to: usize, sender_exempt: bool) -> Outcome {
        if self.allowed(token, from, to, sender_exempt) {
            Ok(())
        } else {
            Err(e(ReservationsError::policy_forbids()))
        }
    }

    fn live_debts(&self, owner: usize, token: usize) -> Vec<MDebt> {
        self.debts
            .get(&(owner, token))
            .map(|entries| {
                entries
                    .iter()
                    .filter(|d| self.now < d.lapses_at)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_debts(&mut self, owner: usize, token: usize, entries: Vec<MDebt>) {
        if entries.is_empty() {
            self.debts.remove(&(owner, token));
        } else {
            self.debts.insert((owner, token), entries);
        }
    }

    /// Moves a payment and repays the recipient's debts in the token from it, as a TIP-20 credit
    /// does.
    fn move_funds(&mut self, token: usize, from: usize, to: usize, amount: u128) {
        if amount == 0 {
            return;
        }
        self.sub(token, from, amount);
        self.credit(token, to, amount);
    }

    fn credit(&mut self, token: usize, account: usize, amount: u128) {
        self.add(token, account, amount);
        if !self.debts.contains_key(&(account, token)) {
            return;
        }
        let mut entries = self.live_debts(account, token);
        let mut left = amount;
        for entry in &mut entries {
            if left == 0 {
                break;
            }
            if !self.allowed(token, account, entry.creditor, false) {
                continue;
            }
            let repaid = left.min(entry.amount);
            left -= repaid;
            entry.amount -= repaid;
            self.sub(token, account, repaid);
            self.add(token, entry.creditor, repaid);
        }
        entries.retain(|entry| entry.amount != 0);
        self.set_debts(account, token, entries);
    }

    fn add_debt(
        &mut self,
        owner: usize,
        token: usize,
        creditor: usize,
        amount: u128,
        offline: bool,
    ) -> Outcome {
        let terms = self
            .terms
            .get(&(owner, creditor, token))
            .copied()
            .unwrap_or_default();
        let cap = if offline {
            terms.debt_cap.max(terms.offline_cap)
        } else {
            terms.debt_cap
        };
        let mut entries = self.live_debts(owner, token);
        if let Some(entry) = entries.iter_mut().find(|entry| entry.creditor == creditor) {
            if entry.amount + amount > cap {
                return Err(refuse(cap));
            }
            entry.amount += amount;
        } else {
            if amount > cap {
                return Err(refuse(cap));
            }
            if entries.len() >= usize::from(MAX_CREDITORS) {
                return Err(e(ReservationsError::too_many_creditors()));
            }
            let term = match u64::from(terms.debt_term) {
                0 => MAX_DEBT_TERM,
                term => term.min(MAX_DEBT_TERM),
            };
            entries.push(MDebt {
                creditor,
                amount,
                lapses_at: self.now + term,
            });
        }
        self.set_debts(owner, token, entries);
        Ok(())
    }

    /// Pays from the owner's available balance, recording what it lacks as debt; returns the debt.
    fn pay(
        &mut self,
        token: usize,
        owner: usize,
        payee: usize,
        amount: u128,
        offline: bool,
    ) -> std::result::Result<u128, TempoPrecompileError> {
        let paid = amount.min(self.bal(token, owner));
        let debt = amount - paid;
        if debt != 0 {
            self.add_debt(owner, token, payee, debt, offline)?;
        }
        self.move_funds(token, owner, payee, paid);
        Ok(debt)
    }

    fn budget_mut(&mut self, owner: usize, holder: usize, token: usize) -> &mut MBudget {
        let now = self.now;
        let budget = self.budgets.entry((owner, holder, token)).or_default();
        budget.roll(now);
        budget
    }

    fn draw(
        &mut self,
        owner: usize,
        holder: usize,
        token: usize,
        check: u128,
        outstanding: u128,
        spent: u128,
    ) -> Outcome {
        let budget = self.budget_mut(owner, holder, token);
        if budget.limit == 0 {
            return Err(e(ReservationsError::unauthorized()));
        }
        if budget.spent + budget.outstanding + check > budget.limit {
            return Err(e(ReservationsError::budget_exceeded()));
        }
        budget.outstanding += outstanding;
        budget.spent += spent;
        Ok(())
    }

    fn settle(
        &mut self,
        owner: usize,
        holder: usize,
        token: usize,
        paid: u128,
        released: u128,
        excess: u128,
    ) -> Outcome {
        if paid == 0 && released == 0 && excess == 0 {
            return Ok(());
        }
        let budget = self.budget_mut(owner, holder, token);
        budget.outstanding -= paid + released;
        budget.spent += paid;
        if excess != 0 {
            if budget.spent + budget.outstanding + excess > budget.limit {
                return Err(e(ReservationsError::budget_exceeded()));
            }
            budget.spent += excess;
        }
        Ok(())
    }

    fn live(&self, key: HoldKey) -> std::result::Result<MHold, TempoPrecompileError> {
        let hold = self
            .holds
            .get(&key)
            .copied()
            .ok_or_else(|| e(ReservationsError::hold_not_found()))?;
        if expired(&hold, self.now) {
            return Err(e(ReservationsError::hold_expired()));
        }
        Ok(hold)
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of one hold")]
    fn hold(
        &mut self,
        placer: usize,
        owner: usize,
        token: usize,
        id: usize,
        amount: u128,
        expires_at: u64,
        stand_in: bool,
        payee: usize,
    ) -> Outcome {
        if amount == 0 {
            return Err(e(ReservationsError::invalid_amount()));
        }
        if expires_at <= self.now || expires_at > self.now + MAX_HOLD_DURATION {
            return Err(e(ReservationsError::invalid_expiry()));
        }
        if self.holds.contains_key(&(owner, placer, id)) {
            return Err(e(ReservationsError::hold_exists()));
        }
        self.ensure_allowed(token, owner, payee, false)?;
        let free = self.bal(token, owner);
        let held = if stand_in {
            free.min(amount)
        } else if amount > free {
            return Err(e(ReservationsError::insufficient_available()));
        } else {
            amount
        };
        let tolerance_bps = self
            .terms
            .get(&(owner, payee, token))
            .map(|t| t.tolerance_bps)
            .unwrap_or(0);
        let capture_limit = amount * (10_000 + u128::from(tolerance_bps)) / 10_000;
        if placer != owner {
            self.draw(owner, placer, token, amount, held, 0)?;
        }
        self.sub(token, owner, held);
        self.holds.insert(
            (owner, placer, id),
            MHold {
                token,
                payee,
                held,
                capture_limit,
                expires_at,
                kind: kind::HOLD,
                stand_in,
                tolerance_bps,
            },
        );
        Ok(())
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of one pledge")]
    fn pledge(
        &mut self,
        placer: usize,
        owner: usize,
        authority: usize,
        token: usize,
        id: usize,
        amount: u128,
        expires_at: u64,
    ) -> Outcome {
        if amount == 0 {
            return Err(e(ReservationsError::invalid_amount()));
        }
        if expires_at <= self.now || expires_at > self.now + MAX_PLEDGE_DURATION {
            return Err(e(ReservationsError::invalid_expiry()));
        }
        if self.holds.contains_key(&(owner, placer, id)) {
            return Err(e(ReservationsError::hold_exists()));
        }
        self.ensure_allowed(token, owner, authority, false)?;
        if amount > self.bal(token, owner) {
            return Err(e(ReservationsError::insufficient_available()));
        }
        if placer != owner {
            self.draw(owner, placer, token, amount, amount, 0)?;
        }
        self.sub(token, owner, amount);
        self.holds.insert(
            (owner, placer, id),
            MHold {
                token,
                payee: authority,
                held: amount,
                capture_limit: amount,
                expires_at,
                kind: kind::PLEDGE,
                stand_in: false,
                tolerance_bps: 0,
            },
        );
        Ok(())
    }

    fn apply(&mut self, op: &Op) -> Outcome {
        match *op {
            Op::Hold {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
                stand_in,
                payee,
            } => self.hold(
                caller,
                owner,
                token,
                id,
                amount,
                self.now + ttl,
                stand_in,
                PAYEES[payee],
            ),
            Op::Pledge {
                owner,
                token,
                id,
                amount,
                ttl,
                authority,
            } => {
                if authority == owner {
                    return Err(e(ReservationsError::unauthorized()));
                }
                self.pledge(owner, owner, authority, token, id, amount, self.now + ttl)
            }
            Op::PledgeFrom {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
            } => {
                if caller == owner {
                    return Err(e(ReservationsError::unauthorized()));
                }
                self.pledge(caller, owner, caller, token, id, amount, self.now + ttl)
            }
            Op::Lien {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
            } => {
                if caller != AUTHORITY {
                    return Err(e(ReservationsError::unauthorized()));
                }
                let expires_at = if ttl == 0 { 0 } else { self.now + ttl };
                if amount == 0 {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                if self.holds.contains_key(&(owner, caller, id)) {
                    return Err(e(ReservationsError::hold_exists()));
                }
                if amount > self.bal(token, owner) {
                    return Err(e(ReservationsError::insufficient_available()));
                }
                self.sub(token, owner, amount);
                self.holds.insert(
                    (owner, caller, id),
                    MHold {
                        token,
                        payee: caller,
                        held: amount,
                        capture_limit: amount,
                        expires_at,
                        kind: kind::LIEN,
                        stand_in: false,
                        tolerance_bps: 0,
                    },
                );
                Ok(())
            }
            Op::Adjust {
                caller,
                owner,
                placer,
                id,
                amount,
            } => {
                let key = (owner, placer, id);
                let mut hold = self.live(key)?;
                if amount == 0 {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                if hold.kind == kind::HOLD {
                    if caller != placer {
                        return Err(e(ReservationsError::unauthorized()));
                    }
                } else if caller != hold.payee {
                    return Err(e(ReservationsError::unauthorized()));
                } else if amount > hold.held {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                let budgeted = placer != owner && hold.kind != kind::LIEN;
                let token = hold.token;
                if amount > hold.held {
                    let increase = amount - hold.held;
                    let wanted = amount * (10_000 + u128::from(hold.tolerance_bps)) / 10_000;
                    let raise = wanted.saturating_sub(hold.capture_limit);
                    if raise != 0 && hold.stand_in {
                        return Err(e(ReservationsError::invalid_amount()));
                    }
                    self.ensure_allowed(token, owner, hold.payee, false)?;
                    if increase > self.bal(token, owner) {
                        return Err(e(ReservationsError::insufficient_available()));
                    }
                    if budgeted {
                        self.draw(owner, placer, token, increase, increase, 0)?;
                    }
                    self.sub(token, owner, increase);
                    if raise != 0 {
                        hold.capture_limit = wanted;
                    }
                } else if amount < hold.held {
                    let decrease = hold.held - amount;
                    self.add(token, owner, decrease);
                    if budgeted {
                        self.settle(owner, placer, token, 0, decrease, 0)?;
                    }
                    if hold.kind != kind::HOLD {
                        hold.capture_limit = amount;
                    }
                }
                hold.held = amount;
                self.holds.insert(key, hold);
                Ok(())
            }
            Op::Capture {
                caller,
                owner,
                placer,
                id,
                amount,
                is_final,
            } => {
                let key = (owner, placer, id);
                let mut hold = self.live(key)?;
                let authorized = match hold.kind {
                    kind::HOLD => caller == placer || caller == hold.payee,
                    _ => caller == hold.payee,
                };
                if !authorized {
                    return Err(e(ReservationsError::unauthorized()));
                }
                if amount == 0 && !is_final {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                if amount > hold.capture_limit {
                    return Err(e(ReservationsError::capture_limit_exceeded()));
                }
                let token = hold.token;
                let from_hold = amount.min(hold.held);
                let excess = amount - from_hold;
                let rest = if is_final { hold.held - from_hold } else { 0 };
                let sender_exempt =
                    (hold.kind == kind::HOLD && excess == 0) || hold.kind == kind::LIEN;
                self.ensure_allowed(token, owner, hold.payee, sender_exempt)?;
                if placer != owner && hold.kind != kind::LIEN {
                    self.settle(owner, placer, token, from_hold, rest, excess)?;
                }
                if hold.kind == kind::HOLD {
                    self.add(token, owner, from_hold + rest);
                    self.pay(token, owner, hold.payee, amount, hold.stand_in)?;
                } else {
                    self.add(token, owner, from_hold);
                    self.move_funds(token, owner, hold.payee, from_hold);
                    self.add(token, owner, rest);
                }
                hold.held -= from_hold + rest;
                hold.capture_limit = if hold.kind == kind::HOLD {
                    hold.capture_limit - amount
                } else {
                    hold.held
                };
                if is_final || (hold.kind != kind::HOLD && hold.held == 0) {
                    self.holds.remove(&key);
                } else {
                    self.holds.insert(key, hold);
                }
                Ok(())
            }
            Op::Release {
                caller,
                owner,
                placer,
                id,
            } => {
                let key = (owner, placer, id);
                let hold = self
                    .holds
                    .get(&key)
                    .copied()
                    .ok_or_else(|| e(ReservationsError::hold_not_found()))?;
                if caller != hold.payee && !(hold.kind == kind::HOLD && caller == placer) {
                    return Err(e(ReservationsError::unauthorized()));
                }
                self.end(key, hold)
            }
            Op::ReleaseExpired { owner, placer, id } => {
                let key = (owner, placer, id);
                let hold = self
                    .holds
                    .get(&key)
                    .copied()
                    .ok_or_else(|| e(ReservationsError::hold_not_found()))?;
                if !expired(&hold, self.now) {
                    return Err(e(ReservationsError::hold_not_expired()));
                }
                self.end(key, hold)
            }
            Op::Charge {
                caller,
                owner,
                token,
                amount,
                stand_in,
                payee,
            } => {
                let payee = PAYEES[payee];
                if amount == 0 {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                self.ensure_allowed(token, owner, payee, false)?;
                if caller != owner {
                    self.draw(owner, caller, token, amount, 0, amount)?;
                }
                self.pay(token, owner, payee, amount, stand_in)?;
                Ok(())
            }
            Op::Refund {
                caller,
                owner,
                token,
                amount,
            } => {
                if amount == 0 {
                    return Err(e(ReservationsError::invalid_amount()));
                }
                self.ensure_allowed(token, caller, owner, false)?;
                let mut entries = self.live_debts(owner, token);
                let mut forgiven = 0;
                if let Some(entry) = entries.iter_mut().find(|entry| entry.creditor == caller) {
                    forgiven = entry.amount.min(amount);
                    entry.amount -= forgiven;
                }
                entries.retain(|entry| entry.amount != 0);
                if self.debts.contains_key(&(owner, token)) {
                    self.set_debts(owner, token, entries);
                }
                let paid = amount - forgiven;
                if paid > self.bal(token, caller) {
                    return Err(e(ReservationsError::insufficient_available()));
                }
                self.move_funds(token, caller, owner, paid);
                Ok(())
            }
            Op::Transfer {
                from,
                to,
                token,
                amount,
            } => {
                if self.blocked.contains(&(token, from))
                    || self.blocked.contains(&(token, to))
                    || amount > self.bal(token, from)
                {
                    return Err(e(ReservationsError::policy_forbids()));
                }
                self.move_funds(token, from, to, amount);
                Ok(())
            }
            Op::Approve {
                owner,
                holder,
                token,
                limit,
                period,
            } => {
                let now = self.now;
                let budget = self.budget_mut(owner, holder, token);
                budget.limit = limit;
                if budget.period != period {
                    budget.period = period;
                    budget.period_start = now;
                }
                Ok(())
            }
            Op::Block {
                account,
                token,
                blocked,
            } => {
                if blocked {
                    self.blocked.insert((token, account));
                } else {
                    self.blocked.remove(&(token, account));
                }
                Ok(())
            }
            Op::ClearLapsed { owner, token } => {
                if self.debts.contains_key(&(owner, token)) {
                    let entries = self.live_debts(owner, token);
                    self.set_debts(owner, token, entries);
                }
                Ok(())
            }
            Op::Warp { seconds } => {
                self.now += seconds;
                Ok(())
            }
            Op::Targeted { .. } => unreachable!("targeted ops are resolved first"),
        }
    }

    fn end(&mut self, key: HoldKey, hold: MHold) -> Outcome {
        let (owner, placer, _) = key;
        self.add(hold.token, owner, hold.held);
        if placer != owner && hold.kind != kind::LIEN {
            self.settle(owner, placer, hold.token, 0, hold.held, 0)?;
        }
        self.holds.remove(&key);
        Ok(())
    }
}

fn expired(hold: &MHold, now: u64) -> bool {
    hold.expires_at != 0 && now >= hold.expires_at
}

/// The precompile, its tokens and accounts, and the model it must match.
pub(super) struct World {
    admin: Address,
    tokens: Vec<TIP20Token>,
    policies: Vec<u64>,
    accounts: Vec<Address>,
    ids: Vec<B256>,
    reservations: Reservations,
    model: Model,
}

impl World {
    pub(super) fn new() -> eyre::Result<Self> {
        let admin = Address::random();
        let accounts: Vec<Address> = (0..ACCOUNTS).map(|_| Address::random()).collect();
        let mut model = Model {
            now: NOW,
            ..Default::default()
        };
        let mut tokens = Vec::new();
        let mut policies = Vec::new();
        let mut registry = TIP403Registry::new();
        registry.initialize()?;
        for index in 0..TOKENS {
            let mut setup = TIP20Setup::create("Core USD", "CUSD", admin).with_issuer(admin);
            for account in [0, 1, H0, P0, STRANGER] {
                setup = setup.with_mint(accounts[account], U256::from(MINT));
                model.add(index, account, MINT);
            }
            let mut token = setup.apply()?;
            token.grant_role_internal(accounts[AUTHORITY], LIEN_ROLE)?;
            let policy = registry.create_policy_with_accounts(
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    accounts: vec![],
                },
            )?;
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
            )?;
            tokens.push(token);
            policies.push(policy);
        }
        let mut reservations = Reservations::new();
        reservations.initialize()?;
        for owner in 0..OWNERS {
            for (token, contract) in tokens.iter().enumerate() {
                let token_address = contract.address();
                for (holder, limit, period) in [(H0, 500u128, 0u32), (H1, 300, 3_600)] {
                    reservations.approve_holder(
                        accounts[owner],
                        IReservationCore::approveHolderCall {
                            holder: accounts[holder],
                            token: token_address,
                            limit,
                            period,
                        },
                    )?;
                    model.budgets.insert(
                        (owner, holder, token),
                        MBudget {
                            limit,
                            period,
                            period_start: if period == 0 { 0 } else { NOW },
                            ..Default::default()
                        },
                    );
                }
                let terms = [
                    (
                        P0,
                        MTerms {
                            debt_cap: 100,
                            offline_cap: 250,
                            tolerance_bps: 2_000,
                            debt_term: 0,
                        },
                    ),
                    (
                        P1,
                        MTerms {
                            debt_cap: 0,
                            offline_cap: 50,
                            tolerance_bps: 0,
                            debt_term: DAY as u32,
                        },
                    ),
                ];
                for (payee, t) in terms {
                    reservations.set_payee_terms(
                        accounts[owner],
                        IReservationCore::setPayeeTermsCall {
                            payee: accounts[payee],
                            token: token_address,
                            terms: IReservationCore::PayeeTerms {
                                debtCap: t.debt_cap,
                                offlineCap: t.offline_cap,
                                toleranceBps: t.tolerance_bps,
                                debtTerm: t.debt_term,
                            },
                        },
                    )?;
                    model.terms.insert((owner, payee, token), t);
                }
            }
        }
        Ok(Self {
            admin,
            tokens,
            policies,
            accounts,
            ids: (0..IDS).map(|_| B256::random()).collect(),
            reservations,
            model,
        })
    }

    fn call(&mut self, op: &Op) -> Outcome {
        let a = |index: usize| self.accounts[index];
        let token_address = |index: usize| self.tokens[index].address();
        let now = self.model.now;
        match *op {
            Op::Hold {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
                stand_in,
                payee,
            } => {
                let request = IReservationCore::HoldRequest {
                    token: token_address(token),
                    id: self.ids[id],
                    amount,
                    expiresAt: now + ttl,
                    payee: a(PAYEES[payee]),
                    standIn: stand_in,
                };
                self.reservations.place(a(caller), a(owner), request)
            }
            Op::Pledge {
                owner,
                token,
                id,
                amount,
                ttl,
                authority,
            } => self.reservations.pledge(
                a(owner),
                IReservationCore::pledgeCall {
                    authority: a(authority),
                    token: token_address(token),
                    id: self.ids[id],
                    amount,
                    expiresAt: now + ttl,
                },
            ),
            Op::PledgeFrom {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
            } => self.reservations.pledge_from(
                a(caller),
                IReservationCore::pledgeFromCall {
                    owner: a(owner),
                    token: token_address(token),
                    id: self.ids[id],
                    amount,
                    expiresAt: now + ttl,
                },
            ),
            Op::Lien {
                caller,
                owner,
                token,
                id,
                amount,
                ttl,
            } => self.reservations.lien(
                a(caller),
                IReservationCore::lienCall {
                    owner: a(owner),
                    token: token_address(token),
                    id: self.ids[id],
                    amount,
                    expiresAt: if ttl == 0 { 0 } else { now + ttl },
                },
            ),
            Op::Adjust {
                caller,
                owner,
                placer,
                id,
                amount,
            } => self.reservations.adjust(
                a(caller),
                IReservationCore::adjustCall {
                    owner: a(owner),
                    placer: a(placer),
                    id: self.ids[id],
                    amount,
                },
            ),
            Op::Capture {
                caller,
                owner,
                placer,
                id,
                amount,
                is_final,
            } => self.reservations.capture(
                a(caller),
                IReservationCore::captureCall {
                    owner: a(owner),
                    placer: a(placer),
                    id: self.ids[id],
                    amount,
                    isFinal: is_final,
                },
            ),
            Op::Release {
                caller,
                owner,
                placer,
                id,
            } => self.reservations.release(
                a(caller),
                IReservationCore::releaseCall {
                    owner: a(owner),
                    placer: a(placer),
                    id: self.ids[id],
                },
            ),
            Op::ReleaseExpired { owner, placer, id } => {
                self.reservations
                    .release_expired(IReservationCore::releaseExpiredCall {
                        owner: a(owner),
                        placer: a(placer),
                        id: self.ids[id],
                    })
            }
            Op::Charge {
                caller,
                owner,
                token,
                amount,
                stand_in,
                payee,
            } => self.reservations.charge(
                a(caller),
                IReservationCore::chargeCall {
                    owner: a(owner),
                    token: token_address(token),
                    id: B256::ZERO,
                    amount,
                    payee: a(PAYEES[payee]),
                    standIn: stand_in,
                },
            ),
            Op::Refund {
                caller,
                owner,
                token,
                amount,
            } => self.reservations.refund(
                a(caller),
                IReservationCore::refundCall {
                    owner: a(owner),
                    token: token_address(token),
                    placer: a(0),
                    id: B256::ZERO,
                    amount,
                },
            ),
            Op::Transfer {
                from,
                to,
                token,
                amount,
            } => {
                let to = a(to);
                self.tokens[token]
                    .transfer(
                        a(from),
                        ITIP20::transferCall {
                            to,
                            amount: U256::from(amount),
                        },
                    )
                    .map(|_| ())
                    .map_err(|_| e(ReservationsError::policy_forbids()))
            }
            Op::Approve {
                owner,
                holder,
                token,
                limit,
                period,
            } => self.reservations.approve_holder(
                a(owner),
                IReservationCore::approveHolderCall {
                    holder: a(holder),
                    token: token_address(token),
                    limit,
                    period,
                },
            ),
            Op::Block {
                account,
                token,
                blocked,
            } => {
                let account = a(account);
                TIP403Registry::new().modify_policy_blacklist(
                    self.admin,
                    ITIP403Registry::modifyPolicyBlacklistCall {
                        policyId: self.policies[token],
                        account,
                        restricted: blocked,
                    },
                )
            }
            Op::ClearLapsed { owner, token } => self
                .reservations
                .clear_lapsed_debt(a(owner), token_address(token)),
            Op::Warp { seconds } => {
                warp(seconds);
                Ok(())
            }
            Op::Targeted { .. } => unreachable!("targeted ops are resolved first"),
        }
    }

    /// Turns a targeted op into the plain op it stands for, and the owner placeholder into the
    /// op's owner.
    fn resolve(&self, op: &Op) -> Op {
        let mut op = op.clone();
        match &mut op {
            Op::Hold { caller, owner, .. }
            | Op::PledgeFrom { caller, owner, .. }
            | Op::Charge { caller, owner, .. }
                if *caller == SELF =>
            {
                *caller = *owner;
            }
            _ => {}
        }
        let Op::Targeted {
            action,
            pick,
            who,
            amount,
            is_final,
        } = op
        else {
            return op;
        };
        let holds = &self.model.holds;
        if holds.is_empty() {
            return Op::Warp { seconds: 0 };
        }
        let (&(owner, placer, id), hold) = holds.iter().nth(pick % holds.len()).expect("picked");
        let caller = [placer, hold.payee, owner, STRANGER][who];
        match action {
            Action::Adjust => Op::Adjust {
                caller,
                owner,
                placer,
                id,
                amount,
            },
            Action::Capture => Op::Capture {
                caller,
                owner,
                placer,
                id,
                amount,
                is_final,
            },
            Action::Release => Op::Release {
                caller,
                owner,
                placer,
                id,
            },
        }
    }

    /// Runs the op on the precompile and the model and checks both agree on its outcome.
    pub(super) fn step(&mut self, op: &Op) -> eyre::Result<()> {
        let op = &self.resolve(op);
        let mut expected = self.model.clone();
        let want = expected.apply(op);
        let checkpoint = StorageCtx.checkpoint();
        let got = self.call(op);
        if got.is_ok() {
            checkpoint.commit();
        } else {
            drop(checkpoint);
        }
        if want != got {
            eyre::bail!("{op:?}: precompile returned {got:?}, model expected {want:?}");
        }
        if want.is_ok() {
            self.model = expected;
        }
        Ok(())
    }

    /// Asserts the precompile's state matches the model and the invariants hold. The slot count is
    /// the reservation core's non-zero storage slots.
    pub(super) fn check(&self, slots: usize) -> eyre::Result<()> {
        let m = &self.model;
        for token in 0..TOKENS {
            let tip20 = &self.tokens[token];
            let address = tip20.address();
            let mut supply = 0u128;
            for account in 0..ACCOUNTS {
                let who = self.accounts[account];
                let slot: u128 = tip20.balances[who].read()?.saturating_to();
                eyre::ensure!(
                    slot == m.bal(token, account),
                    "available of {account} in {token}: {slot} != {}",
                    m.bal(token, account)
                );
                let held: u128 = m
                    .holds
                    .iter()
                    .filter(|((o, _, _), h)| *o == account && h.token == token)
                    .map(|(_, h)| h.held)
                    .sum();
                let reserved = self.reservations.reserved_of(who, address)?;
                eyre::ensure!(
                    reserved == held,
                    "reserved of {account} in {token}: {reserved} != {held}"
                );
                let balance: u128 = tip20
                    .balance_of(ITIP20::balanceOfCall { account: who })?
                    .saturating_to();
                eyre::ensure!(balance == slot + reserved, "balanceOf of {account}");
                supply += balance;
            }
            eyre::ensure!(supply == 5 * MINT, "supply of {token}: {supply}");
        }
        for owner in 0..OWNERS {
            for &placer in &PLACERS {
                for id in 0..IDS {
                    let got = self.reservations.get_hold(
                        self.accounts[owner],
                        self.accounts[placer],
                        self.ids[id],
                    )?;
                    let want = m
                        .holds
                        .get(&(owner, placer, id))
                        .map_or_else(empty_hold, |h| IReservationCore::HoldRecord {
                            token: self.tokens[h.token].address(),
                            payee: self.accounts[h.payee],
                            held: h.held,
                            captureLimit: h.capture_limit,
                            expiresAt: h.expires_at,
                            kind: h.kind,
                            standIn: h.stand_in,
                        });
                    eyre::ensure!(
                        got == want,
                        "hold ({owner}, {placer}, {id}): {got:?} != {want:?}"
                    );
                }
            }
            let mut owes = false;
            for token in 0..TOKENS {
                let address = self.tokens[token].address();
                for holder in [H0, H1, STRANGER] {
                    let got = self.reservations.budget(
                        self.accounts[owner],
                        self.accounts[holder],
                        address,
                    )?;
                    let mut want = m
                        .budgets
                        .get(&(owner, holder, token))
                        .copied()
                        .unwrap_or_default();
                    want.roll(m.now);
                    eyre::ensure!(
                        (
                            got.limit,
                            got.spent,
                            got.outstanding,
                            got.period,
                            got.periodStart
                        ) == (
                            want.limit,
                            want.spent,
                            want.outstanding,
                            want.period,
                            want.period_start
                        ),
                        "budget ({owner}, {holder}, {token}): {got:?} != {want:?}"
                    );
                    let held: u128 = m
                        .holds
                        .iter()
                        .filter(|((o, p, _), h)| {
                            *o == owner && *p == holder && h.token == token && h.kind != kind::LIEN
                        })
                        .map(|(_, h)| h.held)
                        .sum();
                    eyre::ensure!(
                        got.outstanding == held,
                        "outstanding ({owner}, {holder}, {token})"
                    );
                }
                let got: Vec<(Address, u128)> = self
                    .reservations
                    .debt_of(self.accounts[owner], address)?
                    .into_iter()
                    .map(|d| (d.creditor, d.amount))
                    .collect();
                let want: Vec<(Address, u128)> = m
                    .live_debts(owner, token)
                    .into_iter()
                    .map(|d| (self.accounts[d.creditor], d.amount))
                    .collect();
                eyre::ensure!(got == want, "debts ({owner}, {token}): {got:?} != {want:?}");
                eyre::ensure!(
                    want.len() <= usize::from(MAX_CREDITORS),
                    "too many creditors"
                );
                for d in m.debts.get(&(owner, token)).into_iter().flatten() {
                    let t = m
                        .terms
                        .get(&(owner, d.creditor, token))
                        .copied()
                        .unwrap_or_default();
                    eyre::ensure!(
                        d.amount <= t.debt_cap.max(t.offline_cap),
                        "debt past its cap"
                    );
                    eyre::ensure!(
                        d.lapses_at <= m.now + MAX_DEBT_TERM,
                        "debt standing past its term"
                    );
                }
                owes |= m.debts.contains_key(&(owner, token));
            }
            eyre::ensure!(
                self.reservations.owes_debt(self.accounts[owner])? == owes,
                "debtor count of {owner}"
            );
        }
        // Settled records and finished debts leave nothing behind.
        let positions = (0..ACCOUNTS)
            .flat_map(|account| (0..TOKENS).map(move |token| (account, token)))
            .filter(|&(account, token)| {
                m.holds
                    .iter()
                    .any(|((o, _, _), h)| *o == account && h.token == token && h.held != 0)
                    || m.debts.contains_key(&(account, token))
            })
            .count();
        let expected = 2 * m.holds.len()
            + positions
            + m.budgets.values().filter(|b| b.nonzero()).count()
            + m.terms.len()
            + m.debts.values().map(Vec::len).sum::<usize>();
        eyre::ensure!(
            slots == expected,
            "reservation core slots: {slots} != {expected}"
        );
        Ok(())
    }
}
