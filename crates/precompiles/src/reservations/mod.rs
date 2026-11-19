//! Reservation core ([TIP-1153]): holds, captures, charges, refunds, capped debt, pledges and
//! liens on TIP-20 balances.
//!
//! Every reservation is a hold record keyed by `(owner, placer, id)`, so each placer's ids are its
//! own namespace and nobody can take another placer's id. A hold moves part of the owner's balance
//! out of its TIP-20 balance slot and reserves it for a payee until an expiry. Transfers, fees and
//! the pool read only the balance slot, so they never see reservations; `balanceOf` adds them back.
//! A record is two slots and is deleted when it settles.
//!
//! Three kinds share the record:
//!
//! - A hold, placed by the owner or by a holder within the spend budget the owner approved, pays a
//!   merchant payee. The placer adjusts it; the placer or payee captures or releases it. Captures
//!   may exceed it up to the tolerance the owner set for the payee when it was placed; the excess
//!   comes from the available balance, then from debt within the owner's caps.
//! - A pledge reserves funds for an authority (the payee) for up to 400 days, placed by the owner or
//!   by a holder on its own behalf within its budget. Only the authority reduces, seizes (captures)
//!   or releases it.
//! - A lien reserves funds for a holder of the token's `LIEN_ROLE`, with or without expiry. Only that
//!   authority reduces, seizes or releases it, and seizure needs the role at that time.
//!
//! After its expiry a record can only be released, by anyone. Debt is owed per creditor, lapses
//! after the term the owner set for that creditor, and is repaid oldest first from the owner's
//! incoming credits of the token.
//!
//! [TIP-1153]: <https://docs.tempo.xyz/protocol/tips/tip-1153>

pub mod dispatch;
#[cfg(test)]
mod tests;

use crate::{
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, Mapping},
    tip20::{Recipient, TIP20Token},
    tip403_registry::TIP403Registry,
};
use alloy::primitives::{Address, B256, U256};
use keccak_const::Keccak256;
pub use tempo_contracts::precompiles::{
    IReservationCore, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoEvmKind;

/// Longest a hold may last, in seconds: 31 days.
pub const MAX_HOLD_DURATION: u64 = 31 * 24 * 60 * 60;

/// Longest a pledge may last, in seconds: 400 days, enough for a 90 to 120 day reserve with room to
/// spare.
pub const MAX_PLEDGE_DURATION: u64 = 400 * 24 * 60 * 60;

/// Longest a debt may stand before it lapses, in seconds: 365 days. Also the term of a creditor the
/// owner set none for.
pub const MAX_DEBT_TERM: u64 = 365 * 24 * 60 * 60;

/// Most creditors one owner may owe in one token at a time.
pub const MAX_CREDITORS: u8 = 4;

/// TIP-20 role whose holders may lien balances of that token, granted by the token's
/// administrator with `grantRole`. Computed as `keccak256("LIEN_ROLE")`.
pub const LIEN_ROLE: B256 = B256::new(Keccak256::new().update(b"LIEN_ROLE").finalize());

/// Basis points in one whole, for capture tolerances.
const BPS: u128 = 10_000;

/// Record kinds, as `HoldRecord.kind` reports them.
pub mod kind {
    /// An ordinary hold for a merchant payee.
    pub const HOLD: u8 = 1;
    /// A pledge to an authority.
    pub const PLEDGE: u8 = 2;
    /// A lien by a holder of the token's `LIEN_ROLE`.
    pub const LIEN: u8 = 3;
}

/// Which TIP-403 check a reservation payment skips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaymentExemption {
    /// Every check applies.
    None,
    /// The sender's TIP-403 authorization is not checked: funds the owner reserved for this payee
    /// while authorized (a hold's held part), or a lien's seizure by its authority.
    Sender,
}

/// Reserved funds of one owner in one token and how many creditors it owes, in one slot.
///
/// TIP-20 reads it for `balanceOf` and, for owners counted as debtors, after credits.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Funds held outside the owner's balance slot for its live records, less what compliance
    /// burns took (`Reservations::shortfalls`).
    reserved: u128,
    /// Number of debt entries in `Reservations::debts`.
    creditors: u8,
    /// Whether the shortfall may be non-zero, so record changes skip that slot otherwise.
    short: bool,
}

/// A holder's spend budget on one owner's balance of one token, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Budget {
    /// Most `spent + outstanding` may reach; zero revokes.
    limit: u64,
    /// Paid by captures, charges and seizures in the current period; never returned.
    spent: u64,
    /// Still reserved by the holder's live holds and pledges.
    outstanding: u64,
    /// Seconds after which `spent` resets; zero for a lifetime budget.
    period: u32,
    /// Start of the current period.
    period_start: u32,
}

impl Budget {
    /// Starts a new period, resetting `spent`, once the current one has passed.
    fn roll(&mut self, now: u64) {
        if self.period == 0 {
            return;
        }
        let (start, period) = (u64::from(self.period_start), u64::from(self.period));
        if now >= start.saturating_add(period) {
            let elapsed = (now - start) / period * period;
            self.period_start = u32::try_from(start + elapsed).unwrap_or(u32::MAX);
            self.spent = 0;
        }
    }

    /// Refuses drawing `amount` more: revoked, or past the limit.
    fn admit(&self, amount: u64) -> Result<()> {
        if self.limit == 0 {
            return Err(ReservationsError::unauthorized().into());
        }
        self.admit_within_limit(amount)
    }

    /// Refuses drawing `amount` more past the limit, revoked or not.
    fn admit_within_limit(&self, amount: u64) -> Result<()> {
        let used = u128::from(self.spent) + u128::from(self.outstanding) + u128::from(amount);
        if used > u128::from(self.limit) {
            return Err(ReservationsError::budget_exceeded().into());
        }
        Ok(())
    }
}

/// The terms an owner sets for one payee or creditor in one token, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Terms {
    debt_cap: u64,
    offline_cap: u64,
    tolerance_bps: u16,
    /// Zero means [`MAX_DEBT_TERM`].
    debt_term: u32,
}

/// One creditor's debt, in one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct DebtEntry {
    creditor: Address,
    amount: u64,
    lapses_at: u32,
}

/// First slot of a record. The record exists while `token` is non-zero.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct HoldHead {
    token: Address,
    /// Amount still reserved.
    held: u64,
    /// Expiry timestamp; zero for a lien without expiry.
    expires_at: u32,
}

/// Second slot of a record.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct HoldTerms {
    payee: Address,
    /// What captures may still pay; equals `held` for pledges and liens.
    capture_limit: u64,
    /// The payee's capture tolerance when the hold was placed.
    tolerance_bps: u16,
    kind: u8,
    stand_in: bool,
}

/// A loaded record and its key.
#[derive(Debug, Clone, Copy)]
struct Hold {
    owner: Address,
    placer: Address,
    id: B256,
    head: HoldHead,
    terms: HoldTerms,
}

impl Hold {
    /// Whether the record draws on its placer's budget: a hold or pledge a holder placed.
    fn budgeted(&self) -> bool {
        self.placer != self.owner && self.terms.kind != kind::LIEN
    }

    /// Whether the record has passed its expiry.
    fn expired(&self, now: u64) -> bool {
        self.head.expires_at != 0 && now >= u64::from(self.head.expires_at)
    }
}

/// Reservation core precompile.
#[contract(addr = RESERVATIONS_ADDRESS)]
pub struct Reservations {
    /// Keyed by owner then token.
    positions: Mapping<Address, Mapping<Address, Position>>,
    /// Part of the live records compliance burns took, keyed by owner then token. Freed
    /// reservations repay it first.
    shortfalls: Mapping<Address, Mapping<Address, u128>>,
    /// Keyed by owner, holder, then token.
    budgets: Mapping<Address, Mapping<Address, Mapping<Address, Budget>>>,
    /// Keyed by owner, payee, then token.
    terms: Mapping<Address, Mapping<Address, Mapping<Address, Terms>>>,
    /// Debt entries keyed by owner, token, then position, oldest first.
    debts: Mapping<Address, Mapping<Address, Mapping<u8, DebtEntry>>>,
    /// Records keyed by owner, placer, then id, one mapping per slot.
    hold_heads: Mapping<Address, Mapping<Address, Mapping<B256, HoldHead>>>,
    hold_terms: Mapping<Address, Mapping<Address, Mapping<B256, HoldTerms>>>,
    /// On a zone, the number of tokens in which each owner owes debt. Tempo L1 keeps this count in
    /// the owner's TIP-1028 receive policy slot, which a zone mirrors from L1 and cannot write.
    zone_debts: Mapping<Address, u32>,
}

impl Reservations {
    /// Initializes the precompile account.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns whether `owner` owes debt in any token, which every credit of a TIP-20 token checks
    /// before looking for a repayment.
    pub(crate) fn owes_debt(&self, owner: Address) -> Result<bool> {
        if matches!(self.storage.kind(), TempoEvmKind::Zone) {
            return Ok(self.zone_debts[owner].read()? != 0);
        }
        TIP403Registry::new().has_reservation_debt(owner)
    }

    /// Counts a token in which `owner` starts (`owes`) or stops owing debt.
    fn count_debt(&mut self, owner: Address, owes: bool) -> Result<()> {
        if !matches!(self.storage.kind(), TempoEvmKind::Zone) {
            return TIP403Registry::new().count_reservation_debt(owner, owes);
        }
        let count = self.zone_debts[owner].read()?;
        let count = if owes {
            count.checked_add(1)
        } else {
            count.checked_sub(1)
        }
        .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.zone_debts[owner].write(count)
    }

    /// Returns the amount of `token` that `owner` has reserved.
    pub fn reserved_of(&self, owner: Address, token: Address) -> Result<u128> {
        self.positions[owner][token].reserved.read()
    }

    /// Sets `owner`'s reserved amount of `token` without a record, moving the difference out of or
    /// back into its balance slot, so test fixtures outside this crate can reserve funds.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_reserved_unchecked(
        &mut self,
        owner: Address,
        token: Address,
        reserved: u128,
    ) -> Result<()> {
        let previous = self.positions[owner][token].reserved.read()?;
        let mut tip20 = TIP20Token::from_address(token)?;
        if reserved > previous {
            tip20.reserve(owner, U256::from(reserved - previous))?;
        } else {
            tip20.unreserve(owner, U256::from(previous - reserved))?;
        }
        self.positions[owner][token].reserved.write(reserved)
    }

    /// Returns reserved funds to `owner`'s balance for a compliance burn that needs `needed` beyond
    /// it, and returns the amount taken. The records it backed settle against what remains.
    pub(crate) fn take_for_burn(
        &mut self,
        owner: Address,
        token: Address,
        needed: U256,
    ) -> Result<U256> {
        let mut position = self.positions[owner][token].read()?;
        let taken = position.reserved.min(needed.saturating_to());
        if taken == 0 {
            return Ok(U256::ZERO);
        }
        let unbacked = self.shortfalls[owner][token]
            .read()?
            .checked_add(taken)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.shortfalls[owner][token].write(unbacked)?;
        position.reserved -= taken;
        position.short = true;
        self.positions[owner][token].write(position)?;
        Ok(U256::from(taken))
    }

    /// Settles `owner`'s debts in `token` from up to `received`, oldest first, dropping lapsed
    /// ones, and emits `DebtRepaid` for each.
    ///
    /// Called by TIP-20 after crediting an owner counted as a debtor. `admits` tells from a
    /// creditor whether a repayment may move to it now; a refused creditor keeps its debt. Returns
    /// each creditor paid and the amount TIP-20 must move from `owner` to it.
    pub(crate) fn take_repayments(
        &mut self,
        owner: Address,
        token: Address,
        received: U256,
        mut admits: impl FnMut(Address) -> Result<bool>,
    ) -> Result<Vec<(Address, U256)>> {
        let mut position = self.positions[owner][token].read()?;
        if position.creditors == 0 {
            return Ok(Vec::new());
        }
        let loaded = self.load_debts(owner, token, position.creditors)?;
        let mut entries = self.drop_lapsed(owner, token, &loaded)?;
        let mut left: u64 = received.saturating_to();
        let mut paid = Vec::new();
        for entry in &mut entries {
            if left == 0 {
                break;
            }
            if !admits(entry.creditor)? {
                continue;
            }
            let repaid = left.min(entry.amount);
            left -= repaid;
            entry.amount -= repaid;
            self.emit_event(ReservationsEvent::debt_repaid(
                owner,
                entry.creditor,
                token,
                repaid.into(),
            ))?;
            paid.push((entry.creditor, U256::from(repaid)));
        }
        entries.retain(|entry| entry.amount != 0);
        self.store_debts(owner, token, &mut position, &loaded, &entries)?;
        Ok(paid)
    }

    fn approve_holder(
        &mut self,
        owner: Address,
        call: IReservationCore::approveHolderCall,
    ) -> Result<()> {
        root_only(owner)?;
        if call.holder.is_zero() || call.holder == owner {
            return Err(ReservationsError::unauthorized().into());
        }
        TIP20Token::from_address(call.token)?;
        let now = self.now();
        let mut budget = self.budgets[owner][call.holder][call.token].read()?;
        budget.roll(now);
        budget.limit = u64::try_from(call.limit).unwrap_or(u64::MAX);
        if budget.period != call.period {
            budget.period = call.period;
            budget.period_start = timestamp_u32(now);
        }
        self.budgets[owner][call.holder][call.token].write(budget)?;
        self.emit_event(ReservationsEvent::holder_approved(
            owner,
            call.holder,
            call.token,
            budget.limit.into(),
            call.period,
        ))
    }

    fn set_payee_terms(
        &mut self,
        owner: Address,
        call: IReservationCore::setPayeeTermsCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        if u64::from(call.terms.debtTerm) > MAX_DEBT_TERM {
            return Err(ReservationsError::invalid_expiry().into());
        }
        let terms = Terms {
            debt_cap: u64::try_from(call.terms.debtCap).unwrap_or(u64::MAX),
            offline_cap: u64::try_from(call.terms.offlineCap).unwrap_or(u64::MAX),
            tolerance_bps: call.terms.toleranceBps,
            debt_term: call.terms.debtTerm,
        };
        self.terms[owner][payee][call.token].write(terms)?;
        self.emit_event(ReservationsEvent::payee_terms_set(
            owner,
            payee,
            call.token,
            terms_abi(terms),
        ))
    }

    /// Places a hold on `owner`'s balance for `placer`: the owner itself, or a holder within its
    /// budget.
    fn place(
        &mut self,
        placer: Address,
        owner: Address,
        request: IReservationCore::HoldRequest,
    ) -> Result<()> {
        let amount = amount_u64(request.amount)?;
        let now = self.now();
        if request.expiresAt <= now
            || request.expiresAt > now.saturating_add(MAX_HOLD_DURATION)
            || request.expiresAt > u64::from(u32::MAX)
        {
            return Err(ReservationsError::invalid_expiry().into());
        }
        self.ensure_vacant(owner, placer, request.id)?;
        let payee = resolve_payee(request.payee)?;
        let mut token = TIP20Token::from_address(request.token)?;
        // The caller's own authority is checked before the owner's policy and balance, so a caller
        // the owner never approved learns nothing about either.
        let budget = if placer != owner {
            Some(self.admit_budget(owner, placer, request.token, amount)?)
        } else {
            None
        };
        ensure_allowed(&token, owner, payee, PaymentExemption::None)?;
        let free = available(&token, owner)?;
        let held = if request.standIn {
            u64::try_from(free).unwrap_or(u64::MAX).min(amount)
        } else if u128::from(amount) > free {
            return Err(ReservationsError::insufficient_available().into());
        } else {
            amount
        };
        let tolerance_bps = self.terms[owner][payee][request.token]
            .tolerance_bps
            .read()?;
        let capture_limit = with_tolerance(amount, tolerance_bps);
        if let Some(mut budget) = budget {
            budget.outstanding += held;
            self.budgets[owner][placer][request.token].write(budget)?;
        } else {
            // An access key answers for everything the hold lets captures pay, not only what it
            // reserves now.
            AccountKeychain::new().authorize_transfer(
                owner,
                request.token,
                U256::from(capture_limit),
            )?;
        }
        self.reserve(&mut token, owner, held.into())?;
        let terms = HoldTerms {
            payee,
            capture_limit,
            tolerance_bps,
            kind: kind::HOLD,
            stand_in: request.standIn,
        };
        self.write_record(
            owner,
            placer,
            request.id,
            request.token,
            held,
            request.expiresAt,
            terms,
        )?;
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            placer,
            request.token,
            request.id,
            kind::HOLD,
            payee,
            request.amount,
            held.into(),
            capture_limit.into(),
            request.expiresAt,
            request.standIn,
        ))
    }

    /// Pledges `owner`'s available balance to `authority`; `placer` is the owner, or the
    /// authority itself as a holder within its budget.
    #[expect(clippy::too_many_arguments, reason = "the fields of one pledge")]
    fn place_pledge(
        &mut self,
        placer: Address,
        owner: Address,
        authority: Address,
        token: Address,
        id: B256,
        amount: u128,
        expires_at: u64,
    ) -> Result<()> {
        let amount = amount_u64(amount)?;
        let now = self.now();
        if expires_at <= now
            || expires_at > now.saturating_add(MAX_PLEDGE_DURATION)
            || expires_at > u64::from(u32::MAX)
        {
            return Err(ReservationsError::invalid_expiry().into());
        }
        self.ensure_vacant(owner, placer, id)?;
        let mut tip20 = TIP20Token::from_address(token)?;
        // The holder's budget is checked before the owner's policy and balance, so a caller the
        // owner never approved learns nothing about either.
        if placer != owner {
            self.draw_budget(owner, placer, token, amount, amount, 0)?;
        }
        ensure_allowed(&tip20, owner, authority, PaymentExemption::None)?;
        if u128::from(amount) > available(&tip20, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        self.reserve(&mut tip20, owner, amount.into())?;
        let terms = HoldTerms {
            payee: authority,
            capture_limit: amount,
            tolerance_bps: 0,
            kind: kind::PLEDGE,
            stand_in: false,
        };
        self.write_record(owner, placer, id, token, amount, expires_at, terms)?;
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            placer,
            token,
            id,
            kind::PLEDGE,
            authority,
            amount.into(),
            amount.into(),
            amount.into(),
            expires_at,
            false,
        ))
    }

    fn pledge(&mut self, owner: Address, call: IReservationCore::pledgeCall) -> Result<()> {
        let authority = resolve_counterparty_as_root(owner, call.authority, call.token)?;
        self.place_pledge(
            owner,
            owner,
            authority,
            call.token,
            call.id,
            call.amount,
            call.expiresAt,
        )
    }

    /// Places a pledge to `holder` on `owner`'s balance, within the budget `owner` approved for
    /// it. A revoked holder places none, but its existing pledges still release and seize.
    fn pledge_from(
        &mut self,
        holder: Address,
        call: IReservationCore::pledgeFromCall,
    ) -> Result<()> {
        root_only(holder)?;
        if holder == call.owner {
            return Err(ReservationsError::unauthorized().into());
        }
        self.place_pledge(
            holder,
            call.owner,
            holder,
            call.token,
            call.id,
            call.amount,
            call.expiresAt,
        )
    }

    fn lien(&mut self, authority: Address, call: IReservationCore::lienCall) -> Result<()> {
        root_only(authority)?;
        let mut token = TIP20Token::from_address(call.token)?;
        if !token.has_role_internal(authority, LIEN_ROLE)? {
            return Err(ReservationsError::unauthorized().into());
        }
        if call.expiresAt != 0
            && (call.expiresAt <= self.now() || call.expiresAt > u64::from(u32::MAX))
        {
            return Err(ReservationsError::invalid_expiry().into());
        }
        let amount = amount_u64(call.amount)?;
        // A lien on a virtual address applies to its master, whose balance holds the funds.
        let owner = resolve_payee(call.owner)?;
        if owner == authority {
            return Err(ReservationsError::unauthorized().into());
        }
        self.ensure_vacant(owner, authority, call.id)?;
        if u128::from(amount) > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        self.reserve(&mut token, owner, amount.into())?;
        let terms = HoldTerms {
            payee: authority,
            capture_limit: amount,
            tolerance_bps: 0,
            kind: kind::LIEN,
            stand_in: false,
        };
        self.write_record(
            owner,
            authority,
            call.id,
            call.token,
            amount,
            call.expiresAt,
            terms,
        )?;
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            authority,
            call.token,
            call.id,
            kind::LIEN,
            authority,
            amount.into(),
            amount.into(),
            amount.into(),
            call.expiresAt,
            false,
        ))
    }

    fn adjust(&mut self, caller: Address, call: IReservationCore::adjustCall) -> Result<()> {
        let mut hold = self.live_hold(call.owner, call.placer, call.id)?;
        let owner = hold.owner;
        let amount = amount_u64(call.amount)?;
        let held = hold.head.held;
        if hold.terms.kind == kind::HOLD {
            if caller != hold.placer {
                return Err(ReservationsError::unauthorized().into());
            }
        } else if caller != hold.terms.payee {
            return Err(ReservationsError::unauthorized().into());
        } else if amount > held {
            // An authority only reduces a pledge or lien.
            return Err(ReservationsError::invalid_amount().into());
        }
        let token_address = hold.head.token;
        let mut token = TIP20Token::from_address(token_address)?;
        if amount > held {
            let increase = amount - held;
            let wanted = with_tolerance(amount, hold.terms.tolerance_bps);
            let raise = wanted.saturating_sub(hold.terms.capture_limit);
            // A stand-in's approval was fixed offline; raising another hold raises its approval.
            if raise != 0 && hold.terms.stand_in {
                return Err(ReservationsError::invalid_amount().into());
            }
            // Reserving more is a new authorization, so it checks the policy as a new hold does.
            ensure_allowed(&token, owner, hold.terms.payee, PaymentExemption::None)?;
            if u128::from(increase) > available(&token, owner)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            if hold.budgeted() {
                self.draw_budget(owner, hold.placer, token_address, increase, increase, 0)?;
            } else if raise != 0 {
                AccountKeychain::new().authorize_transfer(
                    owner,
                    token_address,
                    U256::from(raise),
                )?;
            }
            self.reserve(&mut token, owner, increase.into())?;
            if raise != 0 {
                hold.terms.capture_limit = wanted;
                self.hold_terms[owner][hold.placer][hold.id].write(hold.terms)?;
            }
        } else if amount < held {
            let decrease = held - amount;
            self.unreserve(&mut token, owner, decrease.into())?;
            if hold.budgeted() {
                self.settle_budget(owner, hold.placer, token_address, 0, decrease, 0)?;
            }
            if hold.terms.kind != kind::HOLD {
                hold.terms.capture_limit = amount;
                self.hold_terms[owner][hold.placer][hold.id].write(hold.terms)?;
            }
        }
        hold.head.held = amount;
        self.hold_heads[owner][hold.placer][hold.id].write(hold.head)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            hold.placer,
            token_address,
            hold.id,
            amount.into(),
            hold.terms.capture_limit.into(),
        ))
    }

    fn capture(&mut self, caller: Address, call: IReservationCore::captureCall) -> Result<()> {
        let mut hold = self.live_hold(call.owner, call.placer, call.id)?;
        let (owner, payee, token_address) = (hold.owner, hold.terms.payee, hold.head.token);
        let mut token = TIP20Token::from_address(token_address)?;
        match hold.terms.kind {
            kind::HOLD if caller == hold.placer || caller == payee => {}
            kind::PLEDGE if caller == payee => {}
            kind::LIEN if caller == payee => {
                root_only(caller)?;
                if !token.has_role_internal(caller, LIEN_ROLE)? {
                    return Err(ReservationsError::unauthorized().into());
                }
            }
            _ => return Err(ReservationsError::unauthorized().into()),
        }
        if call.amount == 0 && !call.isFinal {
            return Err(ReservationsError::invalid_amount().into());
        }
        let amount = u64::try_from(call.amount)
            .ok()
            .filter(|amount| *amount <= hold.terms.capture_limit)
            .ok_or_else(ReservationsError::capture_limit_exceeded)?;
        let held = hold.head.held;
        let from_hold = amount.min(held);
        let excess = amount - from_hold;
        let rest = if call.isFinal { held - from_hold } else { 0 };
        // A hold returns what it still backs to the balance first: a compliance burn may have
        // taken part of the reservation, and only what comes back was reserved for this payee.
        let freed = if hold.terms.kind == kind::HOLD {
            self.unreserve(&mut token, owner, u128::from(from_hold + rest))?
        } else {
            0
        };
        let exemption = match hold.terms.kind {
            // Funds the hold still backs were reserved for this payee while the owner was
            // authorized, so they still pay it after the owner is blocked. A payment that also
            // draws on the free balance (beyond the hold, or in place of burned funds) is new.
            kind::HOLD if excess == 0 && u128::from(amount) <= freed => PaymentExemption::Sender,
            kind::LIEN => PaymentExemption::Sender,
            _ => PaymentExemption::None,
        };
        ensure_allowed(&token, owner, payee, exemption)?;
        if hold.budgeted() {
            self.settle_budget(owner, hold.placer, token_address, from_hold, rest, excess)?;
        }
        let (paid, debt) = if hold.terms.kind == kind::HOLD {
            let debt = self.pay(
                &mut token,
                owner,
                payee,
                amount.into(),
                hold.terms.stand_in,
                exemption,
            )?;
            (u128::from(amount) - debt, debt)
        } else {
            // A seizure pays only what the record still backs, never creating debt.
            let backed = self.unreserve(&mut token, owner, from_hold.into())?;
            token.reservation_transfer(owner, payee, U256::from(backed), exemption)?;
            self.unreserve(&mut token, owner, rest.into())?;
            (backed, 0)
        };
        hold.head.held -= from_hold + rest;
        hold.terms.capture_limit = if hold.terms.kind == kind::HOLD {
            hold.terms.capture_limit - amount
        } else {
            hold.head.held
        };
        let settled = call.isFinal || (hold.terms.kind != kind::HOLD && hold.head.held == 0);
        if settled {
            self.delete_record(&hold)?;
        } else {
            self.hold_heads[owner][hold.placer][hold.id].write(hold.head)?;
            self.hold_terms[owner][hold.placer][hold.id].write(hold.terms)?;
        }
        self.emit_event(ReservationsEvent::hold_captured(
            owner,
            hold.placer,
            token_address,
            hold.id,
            payee,
            paid,
            debt,
            settled,
        ))
    }

    fn release(&mut self, caller: Address, call: IReservationCore::releaseCall) -> Result<()> {
        let hold = self.load_hold(call.owner, call.placer, call.id)?;
        let allowed =
            caller == hold.terms.payee || (hold.terms.kind == kind::HOLD && caller == hold.placer);
        if !allowed {
            return Err(ReservationsError::unauthorized().into());
        }
        self.end_hold(hold, false)
    }

    fn release_expired(&mut self, call: IReservationCore::releaseExpiredCall) -> Result<()> {
        let hold = self.load_hold(call.owner, call.placer, call.id)?;
        if !hold.expired(self.now()) {
            return Err(ReservationsError::hold_not_expired().into());
        }
        self.end_hold(hold, true)
    }

    fn charge(&mut self, caller: Address, call: IReservationCore::chargeCall) -> Result<()> {
        let (owner, token_address) = (call.owner, call.token);
        let payee = resolve_payee(call.payee)?;
        let amount = amount_u64(call.amount)?;
        let mut token = TIP20Token::from_address(token_address)?;
        // A holder's budget is checked before the owner's policy, so a caller the owner never
        // approved learns nothing about it.
        if caller != owner {
            self.draw_budget(owner, caller, token_address, amount, 0, amount)?;
        }
        ensure_allowed(&token, owner, payee, PaymentExemption::None)?;
        if caller == owner {
            AccountKeychain::new().authorize_transfer(owner, token_address, U256::from(amount))?;
        }
        let debt = self.pay(
            &mut token,
            owner,
            payee,
            amount.into(),
            call.standIn,
            PaymentExemption::None,
        )?;
        self.emit_event(ReservationsEvent::charged(
            owner,
            caller,
            token_address,
            call.id,
            payee,
            amount.into(),
            debt,
        ))
    }

    /// Pays `amount` of the caller's balance back to `owner`, first forgiving what `owner` owes
    /// the caller in the token. The placer of the hold bounds what it honors as a refund.
    fn refund(&mut self, caller: Address, call: IReservationCore::refundCall) -> Result<()> {
        if call.amount == 0 {
            return Err(ReservationsError::invalid_amount().into());
        }
        let owner = resolve_payee(call.owner)?;
        let mut token = TIP20Token::from_address(call.token)?;
        ensure_allowed(&token, caller, owner, PaymentExemption::None)?;
        let forgiven = self.forgive(owner, call.token, caller, call.amount)?;
        let paid = call.amount - forgiven;
        if paid != 0 {
            if paid > available(&token, caller)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            AccountKeychain::new().authorize_transfer(caller, call.token, U256::from(paid))?;
            token.reservation_transfer(caller, owner, U256::from(paid), PaymentExemption::None)?;
        }
        self.emit_event(ReservationsEvent::refunded(
            owner,
            caller,
            call.token,
            call.placer,
            call.id,
            call.amount,
            forgiven,
        ))
    }

    fn clear_lapsed_debt(&mut self, owner: Address, token: Address) -> Result<()> {
        let mut position = self.positions[owner][token].read()?;
        if position.creditors == 0 {
            return Ok(());
        }
        let loaded = self.load_debts(owner, token, position.creditors)?;
        let entries = self.drop_lapsed(owner, token, &loaded)?;
        self.store_debts(owner, token, &mut position, &loaded, &entries)
    }

    pub fn get_hold(
        &self,
        owner: Address,
        placer: Address,
        id: B256,
    ) -> Result<IReservationCore::HoldRecord> {
        let head = self.hold_heads[owner][placer][id].read()?;
        if head.token.is_zero() {
            return Ok(empty_hold());
        }
        let terms = self.hold_terms[owner][placer][id].read()?;
        Ok(IReservationCore::HoldRecord {
            token: head.token,
            payee: terms.payee,
            held: head.held.into(),
            captureLimit: terms.capture_limit.into(),
            expiresAt: head.expires_at.into(),
            kind: terms.kind,
            standIn: terms.stand_in,
        })
    }

    fn available_of(&self, owner: Address, token: Address) -> Result<u128> {
        available(&TIP20Token::from_address(token)?, owner)
    }

    pub fn budget(
        &self,
        owner: Address,
        holder: Address,
        token: Address,
    ) -> Result<IReservationCore::Budget> {
        let mut budget = self.budgets[owner][holder][token].read()?;
        budget.roll(self.now());
        Ok(IReservationCore::Budget {
            limit: budget.limit.into(),
            spent: budget.spent.into(),
            outstanding: budget.outstanding.into(),
            period: budget.period,
            periodStart: budget.period_start.into(),
        })
    }

    pub fn payee_terms(
        &self,
        owner: Address,
        payee: Address,
        token: Address,
    ) -> Result<IReservationCore::PayeeTerms> {
        let payee = Recipient::resolve(payee)?.target;
        Ok(terms_abi(self.terms[owner][payee][token].read()?))
    }

    /// Returns the debts `owner` owes in `token` that have not lapsed, oldest first.
    pub fn debt_of(&self, owner: Address, token: Address) -> Result<Vec<IReservationCore::Debt>> {
        let count = self.positions[owner][token].creditors.read()?;
        let now = self.now();
        Ok(self
            .load_debts(owner, token, count)?
            .into_iter()
            .filter(|entry| !lapsed(entry, now))
            .map(|entry| IReservationCore::Debt {
                creditor: entry.creditor,
                amount: entry.amount.into(),
                lapsesAt: entry.lapses_at.into(),
            })
            .collect())
    }

    fn ensure_vacant(&self, owner: Address, placer: Address, id: B256) -> Result<()> {
        if !self.hold_heads[owner][placer][id].token.read()?.is_zero() {
            return Err(ReservationsError::hold_exists().into());
        }
        Ok(())
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of one record")]
    fn write_record(
        &mut self,
        owner: Address,
        placer: Address,
        id: B256,
        token: Address,
        held: u64,
        expires_at: u64,
        terms: HoldTerms,
    ) -> Result<()> {
        self.hold_heads[owner][placer][id].write(HoldHead {
            token,
            held,
            expires_at: timestamp_u32(expires_at),
        })?;
        self.hold_terms[owner][placer][id].write(terms)
    }

    fn delete_record(&mut self, hold: &Hold) -> Result<()> {
        self.hold_heads[hold.owner][hold.placer][hold.id].delete()?;
        self.hold_terms[hold.owner][hold.placer][hold.id].delete()
    }

    fn load_hold(&self, owner: Address, placer: Address, id: B256) -> Result<Hold> {
        let head = self.hold_heads[owner][placer][id].read()?;
        if head.token.is_zero() {
            return Err(ReservationsError::hold_not_found().into());
        }
        Ok(Hold {
            owner,
            placer,
            id,
            head,
            terms: self.hold_terms[owner][placer][id].read()?,
        })
    }

    /// Loads a record that has not expired.
    fn live_hold(&self, owner: Address, placer: Address, id: B256) -> Result<Hold> {
        let hold = self.load_hold(owner, placer, id)?;
        if hold.expired(self.now()) {
            return Err(ReservationsError::hold_expired().into());
        }
        Ok(hold)
    }

    /// Releases what `hold` still reserves and deletes it.
    fn end_hold(&mut self, hold: Hold, expired: bool) -> Result<()> {
        let held = hold.head.held;
        let token_address = hold.head.token;
        if held != 0 {
            let mut token = TIP20Token::from_address(token_address)?;
            self.unreserve(&mut token, hold.owner, held.into())?;
            if hold.budgeted() {
                self.settle_budget(hold.owner, hold.placer, token_address, 0, held, 0)?;
            }
        }
        self.delete_record(&hold)?;
        self.emit_event(ReservationsEvent::hold_released(
            hold.owner,
            hold.placer,
            token_address,
            hold.id,
            held.into(),
            expired,
        ))
    }

    /// Reads a holder's budget, starting a new period if the current one has passed.
    fn load_budget(&self, owner: Address, holder: Address, token: Address) -> Result<Budget> {
        let mut budget = self.budgets[owner][holder][token].read()?;
        budget.roll(self.now());
        Ok(budget)
    }

    /// Reads a holder's budget and checks it for `check` more: refused when revoked or past the
    /// limit.
    fn admit_budget(
        &self,
        owner: Address,
        holder: Address,
        token: Address,
        check: u64,
    ) -> Result<Budget> {
        let budget = self.load_budget(owner, holder, token)?;
        budget.admit(check)?;
        Ok(budget)
    }

    /// Checks a holder's budget for `check` more, then adds `outstanding` and `spent` to it.
    fn draw_budget(
        &mut self,
        owner: Address,
        holder: Address,
        token: Address,
        check: u64,
        outstanding: u64,
        spent: u64,
    ) -> Result<()> {
        let mut budget = self.admit_budget(owner, holder, token, check)?;
        budget.outstanding += outstanding;
        budget.spent += spent;
        self.budgets[owner][holder][token].write(budget)
    }

    /// Settles part of a holder's outstanding draw: `paid` of it moves to what the holder spent
    /// and `released` returns to its budget. `excess`, a capture beyond the hold, is a new spend
    /// that needs room within the limit, even from a revoked holder finishing its hold.
    fn settle_budget(
        &mut self,
        owner: Address,
        holder: Address,
        token: Address,
        paid: u64,
        released: u64,
        excess: u64,
    ) -> Result<()> {
        if paid == 0 && released == 0 && excess == 0 {
            return Ok(());
        }
        let mut budget = self.load_budget(owner, holder, token)?;
        budget.outstanding = budget
            .outstanding
            .checked_sub(paid + released)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        budget.spent = budget.spent.saturating_add(paid);
        if excess != 0 {
            budget.admit_within_limit(excess)?;
            budget.spent += excess;
        }
        self.budgets[owner][holder][token].write(budget)
    }

    /// Moves `amount` of `owner`'s balance into reservation.
    fn reserve(&mut self, token: &mut TIP20Token, owner: Address, amount: u128) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let token_address = token.address();
        let mut position = self.positions[owner][token_address].read()?;
        position.reserved = position
            .reserved
            .checked_add(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.positions[owner][token_address].write(position)?;
        token.reserve(owner, U256::from(amount))
    }

    /// Frees `amount` of `owner`'s reservation, repaying any burned part first, and returns what
    /// it moved back to the balance.
    fn unreserve(&mut self, token: &mut TIP20Token, owner: Address, amount: u128) -> Result<u128> {
        if amount == 0 {
            return Ok(0);
        }
        let token_address = token.address();
        let mut position = self.positions[owner][token_address].read()?;
        let mut backed = amount;
        if position.short {
            let mut unbacked = self.shortfalls[owner][token_address].read()?;
            let covered = unbacked.min(amount);
            unbacked -= covered;
            backed -= covered;
            position.short = unbacked != 0;
            self.shortfalls[owner][token_address].write(unbacked)?;
        }
        position.reserved = position
            .reserved
            .checked_sub(backed)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.positions[owner][token_address].write(position)?;
        token.unreserve(owner, U256::from(backed))?;
        Ok(backed)
    }

    /// Pays `amount` from `owner`'s available balance to `payee`, recording what it lacks as debt,
    /// and returns that debt. `offline` lets the debt reach the owner's offline cap.
    fn pay(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        payee: Address,
        amount: u128,
        offline: bool,
        exemption: PaymentExemption,
    ) -> Result<u128> {
        let paid = amount.min(available(token, owner)?);
        let debt = amount - paid;
        if debt != 0 {
            self.add_debt(owner, token.address(), payee, debt, offline)?;
        }
        token.reservation_transfer(owner, payee, U256::from(paid), exemption)?;
        Ok(debt)
    }

    fn add_debt(
        &mut self,
        owner: Address,
        token: Address,
        creditor: Address,
        amount: u128,
        offline: bool,
    ) -> Result<()> {
        let terms = self.terms[owner][creditor][token].read()?;
        let cap = if offline {
            terms.debt_cap.max(terms.offline_cap)
        } else {
            terms.debt_cap
        };
        let refuse = || -> TempoPrecompileError {
            if cap == 0 {
                ReservationsError::insufficient_available().into()
            } else {
                ReservationsError::debt_cap_exceeded().into()
            }
        };
        let mut position = self.positions[owner][token].read()?;
        let loaded = self.load_debts(owner, token, position.creditors)?;
        let mut entries = self.drop_lapsed(owner, token, &loaded)?;
        if let Some(entry) = entries.iter_mut().find(|entry| entry.creditor == creditor) {
            // More debt to a standing creditor keeps its lapse time, so no debt stands longer than
            // one term.
            let owed = u128::from(entry.amount) + amount;
            if owed > u128::from(cap) {
                return Err(refuse());
            }
            entry.amount = owed as u64;
        } else {
            if amount > u128::from(cap) {
                return Err(refuse());
            }
            if entries.len() >= usize::from(MAX_CREDITORS) {
                return Err(ReservationsError::too_many_creditors().into());
            }
            let term = match u64::from(terms.debt_term) {
                0 => MAX_DEBT_TERM,
                term => term.min(MAX_DEBT_TERM),
            };
            entries.push(DebtEntry {
                creditor,
                amount: amount as u64,
                lapses_at: timestamp_u32(self.now().saturating_add(term)),
            });
        }
        self.store_debts(owner, token, &mut position, &loaded, &entries)
    }

    /// Forgives up to `amount` of what `owner` owes `creditor` in `token`, and returns it.
    fn forgive(
        &mut self,
        owner: Address,
        token: Address,
        creditor: Address,
        amount: u128,
    ) -> Result<u128> {
        let mut position = self.positions[owner][token].read()?;
        if position.creditors == 0 {
            return Ok(0);
        }
        let loaded = self.load_debts(owner, token, position.creditors)?;
        let mut entries = self.drop_lapsed(owner, token, &loaded)?;
        let mut forgiven = 0;
        if let Some(entry) = entries.iter_mut().find(|entry| entry.creditor == creditor) {
            forgiven = entry.amount.min(amount.try_into().unwrap_or(u64::MAX));
            entry.amount -= forgiven;
        }
        entries.retain(|entry| entry.amount != 0);
        self.store_debts(owner, token, &mut position, &loaded, &entries)?;
        Ok(forgiven.into())
    }

    fn load_debts(&self, owner: Address, token: Address, count: u8) -> Result<Vec<DebtEntry>> {
        (0..count)
            .map(|index| self.debts[owner][token][index].read())
            .collect()
    }

    /// Returns `entries` without the lapsed ones, emitting `DebtLapsed` for each dropped.
    fn drop_lapsed(
        &mut self,
        owner: Address,
        token: Address,
        entries: &[DebtEntry],
    ) -> Result<Vec<DebtEntry>> {
        let now = self.now();
        let mut kept = Vec::new();
        for entry in entries {
            if lapsed(entry, now) {
                self.emit_event(ReservationsEvent::debt_lapsed(
                    owner,
                    entry.creditor,
                    token,
                    entry.amount.into(),
                ))?;
            } else {
                kept.push(*entry);
            }
        }
        Ok(kept)
    }

    /// Writes `entries` over `loaded`, touching only slots that change, and counts `owner` as a
    /// debtor in any token while it has entries.
    fn store_debts(
        &mut self,
        owner: Address,
        token: Address,
        position: &mut Position,
        loaded: &[DebtEntry],
        entries: &[DebtEntry],
    ) -> Result<()> {
        for (index, entry) in entries.iter().enumerate() {
            if loaded.get(index) != Some(entry) {
                self.debts[owner][token][index as u8].write(*entry)?;
            }
        }
        for index in entries.len()..loaded.len() {
            self.debts[owner][token][index as u8].delete()?;
        }
        let count = entries.len() as u8;
        if count == position.creditors {
            return Ok(());
        }
        let was = position.creditors != 0;
        position.creditors = count;
        self.positions[owner][token].write(*position)?;
        if was != (count != 0) {
            self.count_debt(owner, count != 0)?;
        }
        Ok(())
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to()
    }
}

/// The record of a hold that does not exist.
pub fn empty_hold() -> IReservationCore::HoldRecord {
    IReservationCore::HoldRecord {
        token: Address::ZERO,
        payee: Address::ZERO,
        held: 0,
        captureLimit: 0,
        expiresAt: 0,
        kind: 0,
        standIn: false,
    }
}

fn terms_abi(terms: Terms) -> IReservationCore::PayeeTerms {
    IReservationCore::PayeeTerms {
        debtCap: terms.debt_cap.into(),
        offlineCap: terms.offline_cap.into(),
        toleranceBps: terms.tolerance_bps,
        debtTerm: terms.debt_term,
    }
}

fn lapsed(entry: &DebtEntry, now: u64) -> bool {
    now >= u64::from(entry.lapses_at)
}

/// Refuses calls `account` authorized with an access key rather than its root key.
fn root_only(account: Address) -> Result<()> {
    if AccountKeychain::new()
        .signing_access_key(account)?
        .is_some()
    {
        return Err(ReservationsError::unauthorized().into());
    }
    Ok(())
}

/// Resolves `account`, a counterparty the owner sets terms for or pledges to, through the address
/// registry as a payee is, for an owner signing with its root key and a TIP-20 `token`.
fn resolve_counterparty_as_root(
    owner: Address,
    account: Address,
    token: Address,
) -> Result<Address> {
    root_only(owner)?;
    // Debt is owed to resolved payees, so terms for a virtual address apply to its master.
    let resolved = Recipient::resolve(account)?.target;
    if resolved.is_zero() || resolved == owner {
        return Err(ReservationsError::unauthorized().into());
    }
    TIP20Token::from_address(token)?;
    Ok(resolved)
}

/// Resolves a virtual payee to its master and rejects zero and TIP-20 addresses.
fn resolve_payee(payee: Address) -> Result<Address> {
    let payee = Recipient::resolve(payee)?;
    payee.validate()?;
    Ok(payee.target)
}

/// Refuses a payment `token` cannot move from `from` to `to` now.
fn ensure_allowed(
    token: &TIP20Token,
    from: Address,
    to: Address,
    exemption: PaymentExemption,
) -> Result<()> {
    if !token.reservation_payment_allowed(from, to, exemption)? {
        return Err(ReservationsError::policy_forbids().into());
    }
    Ok(())
}

/// Returns `owner`'s spendable balance of `token`: its balance slot, which excludes reservations.
fn available(token: &TIP20Token, owner: Address) -> Result<u128> {
    Ok(token.balances[owner].read()?.saturating_to())
}

/// Returns what captures of a hold of `amount` may pay with a tolerance of `bps`.
fn with_tolerance(amount: u64, bps: u16) -> u64 {
    let limit = u128::from(amount) * (BPS + u128::from(bps)) / BPS;
    u64::try_from(limit).unwrap_or(u64::MAX)
}

fn timestamp_u32(timestamp: u64) -> u32 {
    u32::try_from(timestamp).unwrap_or(u32::MAX)
}

/// Checks an amount is non-zero and fits a record.
fn amount_u64(amount: u128) -> Result<u64> {
    match u64::try_from(amount) {
        Ok(amount) if amount != 0 => Ok(amount),
        _ => Err(ReservationsError::invalid_amount().into()),
    }
}
