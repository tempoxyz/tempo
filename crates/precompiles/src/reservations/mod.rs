//! Reservation core ([TIP-1153]): holds, captures, charges, refunds, pledges and liens inside
//! TIP-20 balances, with holders the owner gives a spend budget.
//!
//! It is a payment primitive: funds stay in the owner's balance, set aside for a payee until they
//! are paid, returned or expire. Card authorization is one use (authorize, then capture the final
//! amount within a tolerance); deposits, pre-authorization, capped subscriptions, escrow and
//! collateral kept in place are others. Program logic lives in the contracts that place records.
//!
//! Every reservation is a record keyed by `(owner, placer, id)`, so each placer's ids are its own
//! namespace and nobody can take another placer's id. A hold moves part of the owner's balance out
//! of its TIP-20 balance slot and reserves it for a payee until an expiry. Transfers, fees and the
//! pool read only the balance slot, so they never see reservations; `balanceOf` adds them back. A
//! record is two slots and is deleted when it settles.
//!
//! Three kinds share the record:
//!
//! - A hold, placed by the owner or by a holder within the spend budget the owner approved, pays a
//!   payee. The placer adjusts it; the placer or payee captures or releases it. Captures may exceed
//!   it up to the tolerance the owner set for the payee when it was placed; the excess comes from
//!   the owner's available balance.
//! - A pledge reserves funds for an authority (the payee) for up to 400 days, placed by the owner or
//!   by a holder on its own behalf within its budget. Only the authority reduces, seizes (captures)
//!   or releases it.
//! - A lien reserves funds for a holder of the token's `LIEN_ROLE`, with or without expiry. Only that
//!   authority reduces, seizes or releases it, and seizure needs the role at that time. Pooled
//!   custody that compliance burns never take (TIP-20's protected accounts) is never liened.
//!
//! After its expiry a record can only be released, by anyone. A charge pays from the available
//! balance without a record. Nothing is ever paid beyond what a record backs or the owner holds.
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
};
use alloy::primitives::{Address, B256, U256};
use keccak_const::Keccak256;
pub use tempo_contracts::precompiles::{
    IReservationCore, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// Longest a hold may last, in seconds: 31 days.
pub const MAX_HOLD_DURATION: u64 = 31 * 24 * 60 * 60;

/// Longest a pledge may last, in seconds: 400 days, enough for a 90 to 120 day reserve with room to
/// spare.
pub const MAX_PLEDGE_DURATION: u64 = 400 * 24 * 60 * 60;

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

/// Reserved funds of one owner in one token, in one slot. TIP-20 reads it for `balanceOf`.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Funds held outside the owner's balance slot for its live records, less what compliance
    /// burns took from its holds (`Reservations::shortfalls`).
    reserved: u128,
    /// Whether the shortfall may be non-zero, so record changes skip that slot otherwise.
    short: bool,
    /// Part of `reserved` held by live pledges and liens, which compliance burns never take.
    claimed: u64,
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

    /// Whether the record is a pledge or lien, a claim compliance burns never take.
    fn claim(&self) -> bool {
        self.terms.kind != kind::HOLD
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
    /// Part of the live holds compliance burns took, keyed by owner then token. Freed hold
    /// reservations repay it first; pledges and liens never bear it.
    shortfalls: Mapping<Address, Mapping<Address, u128>>,
    /// Keyed by owner, holder, then token.
    budgets: Mapping<Address, Mapping<Address, Mapping<Address, Budget>>>,
    /// Capture tolerance in basis points, keyed by owner, payee, then token.
    tolerances: Mapping<Address, Mapping<Address, Mapping<Address, u16>>>,
    /// Records keyed by owner, placer, then id, one mapping per slot.
    hold_heads: Mapping<Address, Mapping<Address, Mapping<B256, HoldHead>>>,
    hold_terms: Mapping<Address, Mapping<Address, Mapping<B256, HoldTerms>>>,
}

impl Reservations {
    /// Initializes the precompile account.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
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
    /// it, and returns the amount taken. Only what holds reserve is taken; the holds settle against
    /// what remains, while pledges and liens stay fully backed.
    pub(crate) fn take_for_burn(
        &mut self,
        owner: Address,
        token: Address,
        needed: U256,
    ) -> Result<U256> {
        let mut position = self.positions[owner][token].read()?;
        let held_by_holds = position.reserved.saturating_sub(position.claimed.into());
        let taken = held_by_holds.min(needed.saturating_to());
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

    fn set_capture_tolerance(
        &mut self,
        owner: Address,
        call: IReservationCore::setCaptureToleranceCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        self.tolerances[owner][payee][call.token].write(call.toleranceBps)?;
        self.emit_event(ReservationsEvent::capture_tolerance_set(
            owner,
            payee,
            call.token,
            call.toleranceBps,
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
        if u128::from(amount) > self.available_to_holds(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        let tolerance_bps = self.tolerances[owner][payee][request.token].read()?;
        let capture_limit = with_tolerance(amount, tolerance_bps);
        if let Some(mut budget) = budget {
            budget.outstanding += amount;
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
        self.reserve(&mut token, owner, amount.into(), false)?;
        let terms = HoldTerms {
            payee,
            capture_limit,
            tolerance_bps,
            kind: kind::HOLD,
        };
        self.write_record(
            owner,
            placer,
            request.id,
            request.token,
            amount,
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
            capture_limit.into(),
            request.expiresAt,
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
        self.reserve(&mut tip20, owner, amount.into(), true)?;
        let terms = HoldTerms {
            payee: authority,
            capture_limit: amount,
            tolerance_bps: 0,
            kind: kind::PLEDGE,
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
            expires_at,
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
        // Pooled custody (the DEX, the fee manager, the channel reserve, zone portals) backs other
        // users' claims, so it is never liened, as compliance burns never take it.
        if owner == authority || token.is_protected_custody(owner) {
            return Err(ReservationsError::unauthorized().into());
        }
        self.ensure_vacant(owner, authority, call.id)?;
        if u128::from(amount) > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        self.reserve(&mut token, owner, amount.into(), true)?;
        let terms = HoldTerms {
            payee: authority,
            capture_limit: amount,
            tolerance_bps: 0,
            kind: kind::LIEN,
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
            call.expiresAt,
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
            // Reserving more is a new authorization, so it checks the policy as a new hold does.
            ensure_allowed(&token, owner, hold.terms.payee, PaymentExemption::None)?;
            if u128::from(increase) > self.available_to_holds(&token, owner)? {
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
            self.reserve(&mut token, owner, increase.into(), false)?;
            if raise != 0 {
                hold.terms.capture_limit = wanted;
                self.hold_terms[owner][hold.placer][hold.id].write(hold.terms)?;
            }
        } else if amount < held {
            let decrease = held - amount;
            self.unreserve(&mut token, owner, decrease.into(), hold.claim())?;
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
                // Rechecked at seizure, for an account a later fork protects.
                if !token.has_role_internal(caller, LIEN_ROLE)? || token.is_protected_custody(owner)
                {
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
        // taken part of the owner's hold reservations, and only what comes back was reserved for
        // this payee. Pledges and liens are never burned, so what they hold is always there.
        let freed = if hold.terms.kind == kind::HOLD {
            self.unreserve(&mut token, owner, u128::from(from_hold + rest), false)?
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
        let paid = if hold.terms.kind == kind::HOLD {
            self.pay(&mut token, owner, payee, amount.into(), exemption)?;
            u128::from(amount)
        } else {
            // A seizure pays from the record alone.
            self.unreserve(&mut token, owner, u128::from(from_hold + rest), true)?;
            token.reservation_transfer(owner, payee, U256::from(from_hold), exemption)?;
            from_hold.into()
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
        self.pay(
            &mut token,
            owner,
            payee,
            amount.into(),
            PaymentExemption::None,
        )?;
        self.emit_event(ReservationsEvent::charged(
            owner,
            caller,
            token_address,
            call.id,
            payee,
            amount.into(),
        ))
    }

    /// Pays `amount` of the caller's available balance back to `owner`. The placer of the hold
    /// bounds what it honors as a refund.
    fn refund(&mut self, caller: Address, call: IReservationCore::refundCall) -> Result<()> {
        if call.amount == 0 {
            return Err(ReservationsError::invalid_amount().into());
        }
        let owner = resolve_payee(call.owner)?;
        let mut token = TIP20Token::from_address(call.token)?;
        ensure_allowed(&token, caller, owner, PaymentExemption::None)?;
        if call.amount > available(&token, caller)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        AccountKeychain::new().authorize_transfer(caller, call.token, U256::from(call.amount))?;
        token.reservation_transfer(
            caller,
            owner,
            U256::from(call.amount),
            PaymentExemption::None,
        )?;
        self.emit_event(ReservationsEvent::refunded(
            owner,
            caller,
            call.token,
            call.placer,
            call.id,
            call.amount,
        ))
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

    /// Returns the capture tolerance `owner` set for `payee` in `token`, in basis points.
    pub fn capture_tolerance(&self, owner: Address, payee: Address, token: Address) -> Result<u16> {
        let payee = Recipient::resolve(payee)?.target;
        self.tolerances[owner][payee][token].read()
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
            self.unreserve(&mut token, hold.owner, held.into(), hold.claim())?;
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

    /// What `owner` may reserve for holds in `token`: its available balance, or nothing while a
    /// compliance burn's shortfall stands, so a new hold or raise never backs older burned holds.
    fn available_to_holds(&self, token: &TIP20Token, owner: Address) -> Result<u128> {
        if self.positions[owner][token.address()].short.read()? {
            return Ok(0);
        }
        available(token, owner)
    }

    /// Moves `amount` of `owner`'s balance into reservation, for a pledge or lien when `claim`.
    fn reserve(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        amount: u128,
        claim: bool,
    ) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let token_address = token.address();
        let mut position = self.positions[owner][token_address].read()?;
        position.reserved = position
            .reserved
            .checked_add(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if claim {
            position.claimed = u64::try_from(amount)
                .ok()
                .and_then(|amount| position.claimed.checked_add(amount))
                .ok_or_else(TempoPrecompileError::under_overflow)?;
        }
        self.positions[owner][token_address].write(position)?;
        token.reserve(owner, U256::from(amount))
    }

    /// Frees `amount` of `owner`'s reservation and returns what it moved back to the balance. A
    /// hold's part repays any burned part first; a pledge's or lien's (`claim`) is always backed.
    fn unreserve(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        amount: u128,
        claim: bool,
    ) -> Result<u128> {
        if amount == 0 {
            return Ok(0);
        }
        let token_address = token.address();
        let mut position = self.positions[owner][token_address].read()?;
        let mut backed = amount;
        if claim {
            position.claimed = u64::try_from(amount)
                .ok()
                .and_then(|amount| position.claimed.checked_sub(amount))
                .ok_or_else(TempoPrecompileError::under_overflow)?;
        } else if position.short {
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

    /// Pays `amount` from `owner`'s available balance to `payee`; nothing is paid beyond it.
    fn pay(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        payee: Address,
        amount: u128,
        exemption: PaymentExemption,
    ) -> Result<()> {
        if amount > available(token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        token.reservation_transfer(owner, payee, U256::from(amount), exemption)
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
    }
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

/// Resolves `account`, a counterparty the owner sets a tolerance for or pledges to, through the address
/// registry as a payee is, for an owner signing with its root key and a TIP-20 `token`.
fn resolve_counterparty_as_root(
    owner: Address,
    account: Address,
    token: Address,
) -> Result<Address> {
    root_only(owner)?;
    // Holds pay resolved payees, so a tolerance for a virtual address applies to its master.
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
