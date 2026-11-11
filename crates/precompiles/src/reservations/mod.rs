//! Account reservations precompile: native holds on TIP-20 balances, capped debt and linked
//! refunds.
//!
//! Held funds stay the owner's: a hold moves them from the owner's spendable TIP-20 balance into
//! its reserved amount, and TIP-20 `balanceOf` reports both, so debits need no reservation check.
//! From T15, every TIP-20 credit to an owner with debt in that token pays the creditor first when
//! the token's and the creditor's policies admit that payment. A capture releases the part of the
//! hold it takes (a final capture, the whole hold) back to the spendable balance before paying, so
//! it spends the reservation it consumes. Non-final captures keep the rest of the hold live.
//!
//! Open holds count as spend of the access key that placed them (TIP-1011 limits), and every
//! amount a hold stops committing, or a payee refunds, is given back to that key's limit.

pub mod dispatch;

use crate::{
    account_keychain::{AccountKeychain, LimitSpend},
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, Mapping},
    tip20::{Recipient, TIP20Token},
    tip403_registry::TIP403Registry,
};
use alloy::primitives::{Address, B256, U256, aliases::U96};
pub use tempo_contracts::precompiles::{
    IReservations, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// Longest a hold may last, in seconds: 31 days.
///
/// Card authorizations expire within 30 days under network rules, so a longer hold has no use
/// and would only lock funds; the bound also caps how long a hold outlives a policy change.
pub const MAX_HOLD_DURATION: u64 = 31 * 24 * 60 * 60;

/// Basis points in one whole, for capture tolerances.
const BPS: u64 = 10_000;

/// Reserved and owed amounts of one owner in one token, packed in one slot.
///
/// Reserved funds are moved out of the owner's TIP-20 `balances` slot, so debits never read this.
/// Credits read it only for owners the TIP-403 registry counts as debtors.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Sum of the owner's live holds in the token, less the burned part in `Shortfall`. Held
    /// outside the owner's spendable TIP-20 balance; `balanceOf` adds it back.
    reserved: u128,
    /// Debt owed to the creditor stored in `Reservations::creditors`.
    debt: u128,
}

/// Part of an owner's holds in one token that compliance burns took, in one slot.
///
/// Only hold changes read it, keeping TIP-20 debits and credits at one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Shortfall {
    /// Amount of the holds live at the last burn that `reserved` no longer backs.
    unbacked: u128,
    /// Count of burns that lowered `reserved`; holds placed before the latest share `unbacked`.
    epoch: u32,
}

/// How far an owner lets final captures for one payee in one token exceed the hold, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Tolerance {
    /// Whether the bound applies; captures are unbounded otherwise.
    bounded: bool,
    /// Basis points a final capture's captured total may exceed the hold's authorized total by.
    bps: u32,
}

/// One authorization of an owner, from its hold to its refunds, in five slots.
///
/// The record exists while `token` is non-zero and the hold is live while `expires_at` is
/// non-zero. A live hold's captured total is the sum of its non-final captures; a final capture or
/// a release ends the hold. The captured slot is written on capture and the key slot only for
/// authorizations an access key placed.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Authorization {
    token: Address,
    /// Amount the live hold still reserves, after any non-final captures.
    held: U96,
    /// Resolved payee, the only account allowed to refund or to capture for the owner.
    payee: Address,
    expires_at: u64,
    /// `Shortfall::epoch` when the hold was placed; an earlier epoch means a burn took part of it.
    burn_epoch: u32,
    /// Total captured or charged under this id, including any part that became debt.
    captured: U96,
    /// Total refunded by the payee under this id.
    refunded: U96,
    /// Access key that placed the hold or first charge, whose limit counts it; zero for the root
    /// key. Other access keys of the owner cannot act on this id.
    key_id: Address,
    /// End of `key_id`'s limit period of the latest spend counted; limit is given back only
    /// within that period.
    limit_period_end: u64,
    /// Amount `key_id`'s limit counted in that period and not yet given back. Spend the root key
    /// adds is never counted, so it is never given back.
    counted: U96,
}

impl Authorization {
    fn exists(&self) -> bool {
        !self.token.is_zero()
    }

    fn is_held(&self) -> bool {
        self.expires_at != 0
    }

    /// Amount the authorization still commits: its live hold plus what was captured and not
    /// refunded. `refund` keeps `refunded <= captured`.
    fn committed(&self) -> u128 {
        self.held.to::<u128>() + (self.captured - self.refunded).to::<u128>()
    }
}

/// Account reservations precompile.
#[contract(addr = RESERVATIONS_ADDRESS)]
pub struct Reservations {
    /// Reserved and owed amounts, keyed by owner then token.
    positions: Mapping<Address, Mapping<Address, Position>>,
    /// Creditor of the outstanding debt, keyed by owner then token; zero without debt.
    creditors: Mapping<Address, Mapping<Address, Address>>,
    /// Debt an owner accepts, keyed by owner, creditor, then token.
    debt_caps: Mapping<Address, Mapping<Address, Mapping<Address, u128>>>,
    /// Authorizations keyed by owner then hold id.
    authorizations: Mapping<Address, Mapping<B256, Authorization>>,
    /// Burned part of the live holds, keyed by owner then token.
    shortfalls: Mapping<Address, Mapping<Address, Shortfall>>,
    /// Overcapture bound an owner sets, keyed by owner, payee, then token.
    capture_tolerances: Mapping<Address, Mapping<Address, Mapping<Address, Tolerance>>>,
}

impl Reservations {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the amount of `token` that `owner` has reserved.
    ///
    /// Called by TIP-20 `balanceOf` from T15.
    pub(crate) fn reserved_of(&self, owner: Address, token: Address) -> Result<u128> {
        self.positions[owner][token].reserved.read()
    }

    /// Sets `owner`'s reserved amount of `token` without a hold, moving the difference out of or
    /// back into its spendable balance, so test fixtures outside this crate can reserve funds.
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
            tip20.decrement_balance(owner, U256::from(reserved - previous))?;
        } else {
            tip20.increment_balance(owner, U256::from(previous - reserved))?;
        }
        self.positions[owner][token].reserved.write(reserved)
    }

    /// Lowers `owner`'s reserved amount of `token` by up to `needed`, leaving its holds as they
    /// are, and returns the amount lowered, which TIP-20 adds back to the spendable balance.
    ///
    /// Called by TIP-20 before a compliance burn above the spendable balance from T15, so the burn
    /// may take reserved funds. Afterwards `reserved` may be below the sum of the live holds.
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
        let mut shortfall = self.shortfalls[owner][token].read()?;
        shortfall.unbacked = shortfall.unbacked.saturating_add(taken);
        shortfall.epoch = shortfall.epoch.saturating_add(1);
        self.shortfalls[owner][token].write(shortfall)?;
        position.reserved -= taken;
        self.positions[owner][token].write(position)?;
        Ok(U256::from(taken))
    }

    /// Settles up to `received` of `owner`'s debt in `token` and emits `DebtRepaid`.
    ///
    /// Called by TIP-20 after crediting an `owner` counted as a debtor from T15. `admits` tells from the creditor whether
    /// the repayment may move now. Returns the creditor and the amount TIP-20 must move from
    /// `owner` to it, or `None` when `owner` has no debt or `admits` returns false, which leaves
    /// the debt unchanged.
    pub(crate) fn take_repayment(
        &mut self,
        owner: Address,
        token: Address,
        received: U256,
        admits: impl FnOnce(Address) -> Result<bool>,
    ) -> Result<Option<(Address, U256)>> {
        let position = self.positions[owner][token].read()?;
        if position.debt == 0 {
            return Ok(None);
        }
        let creditor = self.creditors[owner][token].read()?;
        if !admits(creditor)? {
            return Ok(None);
        }
        let repaid = position.debt.min(received.saturating_to::<u128>());
        self.reduce_debt(owner, token, position, creditor, repaid)?;
        Ok(Some((creditor, U256::from(repaid))))
    }

    fn hold(&mut self, owner: Address, call: IReservations::holdCall) -> Result<()> {
        let held = amount_u96(call.amount)?;
        let now = self.now();
        if call.expiresAt <= now || call.expiresAt > now.saturating_add(MAX_HOLD_DURATION) {
            return Err(ReservationsError::invalid_amount().into());
        }
        let mut token = TIP20Token::from_address(call.token)?;
        let payee = resolve_payee(call.payee)?;
        token.ensure_transfer_authorized(owner, payee)?;
        if self.authorizations[owner][call.id].token.read()? != Address::ZERO {
            return Err(ReservationsError::hold_exists().into());
        }

        let mut position = self.positions[owner][call.token].read()?;
        if call.amount > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        position.reserved = position
            .reserved
            .checked_add(call.amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let spend =
            AccountKeychain::new().spend_limit(owner, call.token, U256::from(call.amount))?;
        token.decrement_balance(owner, U256::from(call.amount))?;
        self.positions[owner][call.token].write(position)?;
        let mut auth = Authorization {
            token: call.token,
            held,
            payee,
            expires_at: call.expiresAt,
            burn_epoch: self.shortfalls[owner][call.token].epoch.read()?,
            key_id: spend.map_or(Address::ZERO, |spend| spend.key_id),
            ..Default::default()
        };
        record_spend(&mut auth, spend, call.amount);
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            call.id,
            call.token,
            payee,
            call.amount,
            call.expiresAt,
        ))
    }

    fn adjust(&mut self, owner: Address, call: IReservations::adjustCall) -> Result<()> {
        let mut auth = self.live_hold(owner, call.id)?;
        ensure_key_may_act(owner, &auth)?;
        let held = amount_u96(call.amount)?;
        let previous = auth.held.to::<u128>();
        let mut position = self.positions[owner][auth.token].read()?;
        let decrease = previous.saturating_sub(call.amount);
        if call.amount > previous {
            let increase = call.amount - previous;
            let mut token = TIP20Token::from_address(auth.token)?;
            if increase > available(&token, owner)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            position.reserved = position
                .reserved
                .checked_add(increase)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            let spend =
                AccountKeychain::new().spend_limit(owner, auth.token, U256::from(increase))?;
            record_spend(&mut auth, spend, increase);
            token.decrement_balance(owner, U256::from(increase))?;
        } else {
            let returned = self.unreserve(owner, &auth, &mut position, decrease)?;
            return_to_balance(auth.token, owner, returned)?;
        }
        self.positions[owner][auth.token].write(position)?;
        auth.held = held;
        settle_limit(owner, &mut auth)?;
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            call.id,
            auth.token,
            call.amount,
        ))
    }

    /// Captures `amount` of the owner's live hold `id` for its payee: `capture` when `is_final`,
    /// otherwise `capturePart`, which takes at most the held amount and keeps the rest held.
    fn capture_part(
        &mut self,
        owner: Address,
        id: B256,
        amount: u128,
        is_final: bool,
    ) -> Result<()> {
        let auth = self.live_hold(owner, id)?;
        ensure_key_may_act(owner, &auth)?;
        if is_final {
            self.settle_hold(owner, id, auth, amount)
        } else {
            self.capture_hold_part(owner, id, auth, amount)
        }
    }

    /// Captures `amount`, at most the held amount, of the owner's live hold for its payee (the
    /// caller), so an approved hold still settles after the owner revoked or rotated the key that
    /// placed it. Called for `captureFor` (always final) and `captureForPart`.
    fn capture_for_part(
        &mut self,
        payee: Address,
        owner: Address,
        id: B256,
        amount: u128,
        is_final: bool,
    ) -> Result<()> {
        let auth = self.live_hold(owner, id)?;
        if auth.payee != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        // The owner may be its own payee; another of its access keys still may not settle the hold.
        ensure_key_may_act(owner, &auth)?;
        // The hold is the owner's consent; capturing more would spend beyond it.
        if amount > auth.held.to::<u128>() {
            return Err(ReservationsError::invalid_amount().into());
        }
        if is_final {
            self.settle_hold(owner, id, auth, amount)
        } else {
            self.capture_hold_part(owner, id, auth, amount)
        }
    }

    fn charge(&mut self, owner: Address, call: IReservations::chargeCall) -> Result<()> {
        let amount = amount_u96(call.amount)?;
        let mut token = TIP20Token::from_address(call.token)?;
        let payee = resolve_payee(call.payee)?;
        token.ensure_transfer_authorized(owner, payee)?;
        let mut auth = self.authorizations[owner][call.id].read()?;
        // A live hold is settled with `capture`; later charges must match the earlier payment.
        if auth.is_held() || (auth.exists() && (auth.token != call.token || auth.payee != payee)) {
            return Err(ReservationsError::hold_exists().into());
        }
        // A new charge records the key that signs it; other access keys cannot charge it again.
        if auth.exists() {
            ensure_key_may_act(owner, &auth)?;
        }

        let position = self.positions[owner][call.token].read()?;
        let (debt, spend) = self.pay(
            &mut token,
            owner,
            payee,
            Payment {
                amount: call.amount,
                released: 0,
                spend: call.amount,
            },
            position,
        )?;

        if !auth.exists()
            && let Some(spend) = spend
        {
            auth.key_id = spend.key_id;
        }
        record_spend(&mut auth, spend, call.amount);
        auth.token = call.token;
        auth.payee = payee;
        auth.captured = auth
            .captured
            .checked_add(amount)
            .ok_or_else(ReservationsError::invalid_amount)?;
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::charged(
            owner,
            call.id,
            call.token,
            payee,
            call.amount,
            debt,
        ))
    }

    fn release(&mut self, owner: Address, id: B256) -> Result<()> {
        let auth = self.live_hold(owner, id)?;
        ensure_key_may_act(owner, &auth)?;
        self.end_hold(owner, id, auth)
    }

    fn release_expired(&mut self, owner: Address, id: B256) -> Result<()> {
        let auth = self.live_hold(owner, id)?;
        if self.now() < auth.expires_at {
            return Err(ReservationsError::hold_not_expired().into());
        }
        self.end_hold(owner, id, auth)
    }

    fn refund(&mut self, payee: Address, call: IReservations::refundCall) -> Result<()> {
        let mut auth = self.authorizations[call.owner][call.id].read()?;
        if !auth.exists() {
            return Err(ReservationsError::hold_not_found().into());
        }
        if auth.payee != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        let refunded = auth
            .refunded
            .checked_add(amount_u96(call.amount)?)
            .filter(|refunded| *refunded <= auth.captured)
            .ok_or_else(ReservationsError::refund_exceeds_capture)?;

        let mut token = TIP20Token::from_address(auth.token)?;
        token.ensure_transfer_authorized(payee, call.owner)?;
        // A refund to an owner in debt to the refunding payee first cancels that debt, so a
        // payee can refund a debt-financed payment without holding the unpaid part.
        let position = self.positions[call.owner][auth.token].read()?;
        let offset =
            if position.debt != 0 && self.creditors[call.owner][auth.token].read()? == payee {
                position.debt.min(call.amount)
            } else {
                0
            };
        let moved = call.amount - offset;
        if moved != 0 {
            AccountKeychain::new().authorize_transfer(payee, auth.token, U256::from(moved))?;
        }
        if offset != 0 {
            self.reduce_debt(call.owner, auth.token, position, payee, offset)?;
        }
        token.reservation_transfer(payee, call.owner, U256::from(moved))?;
        // Refunds of non-final captures leave a live hold's amount committed.
        auth.refunded = refunded;
        settle_limit(call.owner, &mut auth)?;
        self.authorizations[call.owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::refunded(
            call.owner,
            call.id,
            call.amount,
        ))
    }

    fn set_debt_cap(&mut self, owner: Address, call: IReservations::setDebtCapCall) -> Result<()> {
        let creditor = resolve_counterparty_as_root(owner, call.creditor, call.token)?;
        self.debt_caps[owner][creditor][call.token].write(call.cap)
    }

    fn set_capture_tolerance(
        &mut self,
        owner: Address,
        call: IReservations::setCaptureToleranceCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        if !call.bounded && call.toleranceBps != 0 {
            return Err(ReservationsError::invalid_amount().into());
        }
        self.capture_tolerances[owner][payee][call.token].write(Tolerance {
            bounded: call.bounded,
            bps: call.toleranceBps,
        })
    }

    fn get_hold(&self, owner: Address, id: B256) -> Result<IReservations::Hold> {
        let auth = self.authorizations[owner][id].read()?;
        Ok(IReservations::Hold {
            token: auth.token,
            payee: auth.payee,
            amount: auth.held.to(),
            expiresAt: auth.expires_at,
        })
    }

    fn available_of(&self, owner: Address, token: Address) -> Result<u128> {
        available(&TIP20Token::from_address(token)?, owner)
    }

    fn debt_cap(&self, owner: Address, creditor: Address, token: Address) -> Result<u128> {
        self.debt_caps[owner][Recipient::resolve(creditor)?.target][token].read()
    }

    fn capture_tolerance(
        &self,
        owner: Address,
        payee: Address,
        token: Address,
    ) -> Result<IReservations::captureToleranceReturn> {
        let tolerance =
            self.capture_tolerances[owner][Recipient::resolve(payee)?.target][token].read()?;
        Ok(IReservations::captureToleranceReturn {
            bounded: tolerance.bounded,
            toleranceBps: tolerance.bps,
        })
    }

    fn debt_of(&self, owner: Address, token: Address) -> Result<IReservations::debtOfReturn> {
        let debt = self.positions[owner][token].debt.read()?;
        Ok(IReservations::debtOfReturn {
            creditor: if debt == 0 {
                Address::ZERO
            } else {
                self.creditors[owner][token].read()?
            },
            amount: debt,
        })
    }

    fn captured(&self, owner: Address, id: B256) -> Result<IReservations::capturedReturn> {
        let auth = self.authorizations[owner][id].read()?;
        Ok(IReservations::capturedReturn {
            captured: auth.captured.to(),
            refunded: auth.refunded.to(),
        })
    }

    /// Pays `amount` of `owner`'s live hold `auth` to its payee, ends the hold and adds `amount` to
    /// the captured total of its non-final captures. Only the excess over what is still held
    /// counts against the signing access key's limit.
    fn settle_hold(
        &mut self,
        owner: Address,
        id: B256,
        mut auth: Authorization,
        amount: u128,
    ) -> Result<()> {
        let captured = auth
            .captured
            .checked_add(amount_u96(amount)?)
            .ok_or_else(ReservationsError::invalid_amount)?;
        let held = auth.held.to::<u128>();
        // Only a capture above what is still held can pass the owner's tolerance for this payee.
        if amount > held {
            let tolerance = self.capture_tolerances[owner][auth.payee][auth.token].read()?;
            let authorized = U256::from(auth.captured.to::<u128>()) + U256::from(held);
            if tolerance.bounded
                && U256::from(captured.to::<u128>()) * U256::from(BPS)
                    > authorized * (U256::from(BPS) + U256::from(tolerance.bps))
            {
                return Err(ReservationsError::tolerance_exceeded().into());
            }
        }
        let mut token = TIP20Token::from_address(auth.token)?;
        // The payee may have become forbidden since the hold was placed.
        token.ensure_transfer_authorized(owner, auth.payee)?;
        let mut position = self.positions[owner][auth.token].read()?;
        // Releasing the hold first returns the reservation it consumes to the spendable balance.
        let released = self.unreserve(owner, &auth, &mut position, held)?;
        // The hold already counted against the key's limit; only an excess is new spend.
        let excess = amount.saturating_sub(held);
        let (debt, spend) = self.pay(
            &mut token,
            owner,
            auth.payee,
            Payment {
                amount,
                released,
                spend: excess,
            },
            position,
        )?;
        record_spend(&mut auth, spend, excess);
        auth.held = U96::ZERO;
        auth.expires_at = 0;
        auth.captured = captured;
        settle_limit(owner, &mut auth)?;
        self.authorizations[owner][id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_captured(
            owner, id, auth.token, amount, debt,
        ))
    }

    /// Pays `amount`, at most what `owner`'s live hold `auth` still holds, to its payee, lowers the
    /// hold by `amount` and adds it to the captured total, keeping the hold live with its expiry.
    /// The hold already counted `amount` against the key's limit, so nothing is spent or given back.
    fn capture_hold_part(
        &mut self,
        owner: Address,
        id: B256,
        mut auth: Authorization,
        amount: u128,
    ) -> Result<()> {
        let part = amount_u96(amount)?;
        // A non-final capture never pays beyond the hold; only a final one may take more.
        let held = auth
            .held
            .checked_sub(part)
            .ok_or_else(ReservationsError::invalid_amount)?;
        let captured = auth
            .captured
            .checked_add(part)
            .ok_or_else(ReservationsError::invalid_amount)?;
        let mut token = TIP20Token::from_address(auth.token)?;
        // The payee may have become forbidden since the hold was placed.
        token.ensure_transfer_authorized(owner, auth.payee)?;
        let mut position = self.positions[owner][auth.token].read()?;
        let released = self.unreserve(owner, &auth, &mut position, amount)?;
        // A compliance burn can leave less than `amount` reserved; the rest is paid as in a capture.
        let (debt, _) = self.pay(
            &mut token,
            owner,
            auth.payee,
            Payment {
                amount,
                released,
                spend: 0,
            },
            position,
        )?;

        auth.held = held;
        auth.captured = captured;
        self.authorizations[owner][id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_part_captured(
            owner, id, auth.token, amount, debt,
        ))
    }

    /// Pays `payment.amount` from `owner`'s available balance plus the `released` reservation to
    /// `payee` and records the shortfall as debt towards `payee`, within the owner's cap. Writes
    /// `position` and returns the released reservation to the balance once every check passed.
    ///
    /// Counts `spend`, debt included, against the access key signing for `owner`. Returns the
    /// new debt and the limit charge, if any.
    fn pay(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        payee: Address,
        payment: Payment,
        mut position: Position,
    ) -> Result<(u128, Option<LimitSpend>)> {
        let Payment {
            amount,
            released,
            spend,
        } = payment;
        let token_address = token.address();
        let paid = amount.min(available(token, owner)?.saturating_add(released));
        let debt = amount - paid;
        let new_creditor = position.debt == 0;
        if debt != 0 {
            if !new_creditor && self.creditors[owner][token_address].read()? != payee {
                return Err(ReservationsError::debt_cap_exceeded().into());
            }
            position.debt = position
                .debt
                .checked_add(debt)
                .ok_or_else(ReservationsError::debt_cap_exceeded)?;
            if position.debt > self.debt_caps[owner][payee][token_address].read()? {
                return Err(ReservationsError::debt_cap_exceeded().into());
            }
        }
        let spend = if spend == 0 {
            None
        } else {
            AccountKeychain::new().spend_limit(owner, token_address, U256::from(spend))?
        };
        if debt != 0 && new_creditor {
            self.creditors[owner][token_address].write(payee)?;
            TIP403Registry::new().count_reservation_debt(owner, true)?;
        }
        self.positions[owner][token_address].write(position)?;
        return_to_balance(token_address, owner, released)?;
        token.reservation_transfer(owner, payee, U256::from(paid))?;
        Ok((debt, spend))
    }

    /// Lowers `owner`'s debt in `token` by `amount` and emits `DebtRepaid`.
    fn reduce_debt(
        &mut self,
        owner: Address,
        token: Address,
        mut position: Position,
        creditor: Address,
        amount: u128,
    ) -> Result<()> {
        position.debt = position
            .debt
            .checked_sub(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.positions[owner][token].write(position)?;
        if position.debt == 0 {
            self.creditors[owner][token].delete()?;
            TIP403Registry::new().count_reservation_debt(owner, false)?;
        }
        self.emit_event(ReservationsEvent::debt_repaid(
            owner, token, creditor, amount,
        ))
    }

    /// Releases what `auth` still holds. An authorization with non-final captures stays as a
    /// settled record of them, for refunds; one without is deleted, so its id can be held again.
    fn end_hold(&mut self, owner: Address, id: B256, mut auth: Authorization) -> Result<()> {
        let mut position = self.positions[owner][auth.token].read()?;
        let returned = self.unreserve(owner, &auth, &mut position, auth.held.to())?;
        return_to_balance(auth.token, owner, returned)?;
        self.positions[owner][auth.token].write(position)?;
        auth.held = U96::ZERO;
        auth.expires_at = 0;
        settle_limit(owner, &mut auth)?;
        if auth.captured.is_zero() {
            self.authorizations[owner][id].delete()?;
        } else {
            self.authorizations[owner][id].write(auth)?;
        }
        self.emit_event(ReservationsEvent::hold_released(owner, id, auth.token))
    }

    /// Removes `amount` of `auth`'s hold from `position` and returns the reserved amount it frees,
    /// which the caller adds back to the spendable balance. A hold live at the latest burn first
    /// consumes the burned part, which no longer exists, so the reservation behind the other
    /// holds stays in place.
    fn unreserve(
        &mut self,
        owner: Address,
        auth: &Authorization,
        position: &mut Position,
        amount: u128,
    ) -> Result<u128> {
        let mut from_unbacked = 0;
        if amount != 0 {
            let mut shortfall = self.shortfalls[owner][auth.token].read()?;
            if shortfall.unbacked != 0 && auth.burn_epoch < shortfall.epoch {
                from_unbacked = shortfall.unbacked.min(amount);
                shortfall.unbacked -= from_unbacked;
                self.shortfalls[owner][auth.token].write(shortfall)?;
            }
        }
        let returned = position.reserved.min(amount - from_unbacked);
        position.reserved -= returned;
        Ok(returned)
    }

    fn live_hold(&self, owner: Address, id: B256) -> Result<Authorization> {
        let auth = self.authorizations[owner][id].read()?;
        if !auth.is_held() {
            return Err(ReservationsError::hold_not_found().into());
        }
        Ok(auth)
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to()
    }
}

/// Rejects an access key of `owner` other than the one that placed `auth`. Only the root key
/// acts on authorizations the root key placed, so an access key never spends them outside its limit.
fn ensure_key_may_act(owner: Address, auth: &Authorization) -> Result<()> {
    match AccountKeychain::new().signing_access_key(owner)? {
        Some(key_id) if key_id != auth.key_id => Err(ReservationsError::unauthorized().into()),
        _ => Ok(()),
    }
}

/// Records `amount` that `auth.key_id`'s limit counted in `spend`. A spend in a new period drops
/// what earlier periods counted, since the keychain gives back only within the current period.
fn record_spend(auth: &mut Authorization, spend: Option<LimitSpend>, amount: u128) {
    let Some(spend) = spend else { return };
    if amount == 0 || spend.key_id != auth.key_id {
        return;
    }
    if spend.period_end != auth.limit_period_end {
        auth.limit_period_end = spend.period_end;
        auth.counted = U96::ZERO;
    }
    let counted = auth.counted.to::<u128>().saturating_add(amount);
    auth.counted = U96::try_from(counted).unwrap_or(U96::MAX);
}

/// Lowers `auth.counted` to at most what the authorization still commits (`Authorization::committed`),
/// after the caller updated it, and gives the difference back to the placing key within the period
/// it was counted in. Amounts the root key added are released first, so they never turn into key
/// limit.
fn settle_limit(owner: Address, auth: &mut Authorization) -> Result<()> {
    let counted = auth.counted.to::<u128>();
    let amount = counted.saturating_sub(auth.committed());
    if amount == 0 {
        return Ok(());
    }
    auth.counted = U96::from(counted - amount);
    AccountKeychain::new().restore_limit(
        owner,
        auth.key_id,
        auth.token,
        U256::from(amount),
        auth.limit_period_end,
    )
}

/// Converts a non-zero ABI amount to its stored width.
/// Resolves `account`, a creditor or payee the owner sets terms for, through the address registry
/// as a payee is, for an owner signing with its root key and a TIP-20 `token`. Card access keys
/// must never loosen the terms on their own spending.
fn resolve_counterparty_as_root(
    owner: Address,
    account: Address,
    token: Address,
) -> Result<Address> {
    if AccountKeychain::new().signing_access_key(owner)?.is_some() {
        return Err(ReservationsError::unauthorized().into());
    }
    // Debt is owed to resolved payees, so terms for a virtual address apply to its master.
    let resolved = Recipient::resolve(account)?.target;
    if resolved.is_zero() || resolved == owner {
        return Err(ReservationsError::unauthorized().into());
    }
    TIP20Token::from_address(token)?;
    Ok(resolved)
}

fn amount_u96(amount: u128) -> Result<U96> {
    if amount == 0 {
        return Err(ReservationsError::invalid_amount().into());
    }
    U96::try_from(amount).map_err(|_| ReservationsError::invalid_amount().into())
}

/// Resolves a virtual payee to its master and rejects zero and TIP-20 addresses.
fn resolve_payee(payee: Address) -> Result<Address> {
    let payee = Recipient::resolve(payee)?;
    payee.validate()?;
    Ok(payee.target)
}

/// Returns `owner`'s spendable balance of `token`, which excludes its reserved amount.
fn available(token: &TIP20Token, owner: Address) -> Result<u128> {
    Ok(token.balances[owner].read()?.saturating_to())
}

/// Adds `amount` of freed reservation back to `owner`'s spendable balance of `token`.
fn return_to_balance(token: Address, owner: Address, amount: u128) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    TIP20Token::from_address(token)?.increment_balance(owner, U256::from(amount))
}

/// Amounts of one capture or charge.
struct Payment {
    /// Amount owed to the payee, debt included.
    amount: u128,
    /// Reservation the captured part of the hold frees, spendable by this payment.
    released: u128,
    /// Amount to count against the signing access key's limit.
    spend: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_keychain::AccountKeychain,
        address_registry::{AddressRegistry, MasterId, TempoAddressExt, UserTag},
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
        tip20::{BURN_AT_ROLE, BURN_BLOCKED_ROLE, ITIP20, PAUSE_ROLE, TIP20Error, TIP20Event},
        tip403_registry::{
            ALLOW_ALL_POLICY_ID, ITIP403Registry, REJECT_ALL_POLICY_ID, TIP403Registry,
        },
    };
    use alloy::{
        primitives::{IntoLogData, TxKind, U256},
        sol_types::{SolCall, SolInterface},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        AccountKeychainError, IAccountKeychain, IReservations::IReservationsCalls,
    };

    const NOW: u64 = 1_000;
    const EXPIRY: u64 = NOW + 600;
    /// Renewal period of the card key limits in these tests.
    const CARD_LIMIT_PERIOD: u64 = 86_400;

    struct Fixture {
        admin: Address,
        owner: Address,
        payee: Address,
        token: TIP20Token,
        reservations: Reservations,
    }

    impl Fixture {
        /// Mints `balance` to a fresh owner of a fresh token.
        fn new(balance: u64) -> Result<Self> {
            let admin = Address::random();
            let owner = Address::random();
            let token = TIP20Setup::create("Card USD", "CUSD", admin)
                .with_issuer(admin)
                .with_mint(owner, U256::from(balance))
                .apply()?;
            let mut reservations = Reservations::new();
            reservations.initialize()?;
            Ok(Self {
                admin,
                owner,
                payee: Address::random(),
                token,
                reservations,
            })
        }

        fn hold(&mut self, id: B256, amount: u128) -> Result<()> {
            self.hold_until(id, amount, EXPIRY)
        }

        fn hold_until(&mut self, id: B256, amount: u128, expires_at: u64) -> Result<()> {
            self.reservations.hold(
                self.owner,
                IReservations::holdCall {
                    token: self.token.address(),
                    id,
                    amount,
                    expiresAt: expires_at,
                    payee: self.payee,
                },
            )
        }

        fn adjust(&mut self, id: B256, amount: u128) -> Result<()> {
            self.reservations
                .adjust(self.owner, IReservations::adjustCall { id, amount })
        }

        fn capture(&mut self, id: B256, amount: u128) -> Result<()> {
            self.capture_part(id, amount, true)
        }

        fn capture_part(&mut self, id: B256, amount: u128, is_final: bool) -> Result<()> {
            self.reservations
                .capture_part(self.owner, id, amount, is_final)
        }

        fn capture_for(&mut self, caller: Address, id: B256, amount: u128) -> Result<()> {
            self.capture_for_part(caller, id, amount, true)
        }

        fn capture_for_part(
            &mut self,
            caller: Address,
            id: B256,
            amount: u128,
            is_final: bool,
        ) -> Result<()> {
            self.reservations
                .capture_for_part(caller, self.owner, id, amount, is_final)
        }

        fn captured(&self, id: B256) -> Result<(u128, u128)> {
            let totals = self.reservations.captured(self.owner, id)?;
            Ok((totals.captured, totals.refunded))
        }

        fn charge(&mut self, id: B256, amount: u128, payee: Address) -> Result<()> {
            self.reservations.charge(
                self.owner,
                IReservations::chargeCall {
                    token: self.token.address(),
                    id,
                    amount,
                    payee,
                },
            )
        }

        fn refund(&mut self, caller: Address, id: B256, amount: u128) -> Result<()> {
            self.reservations.refund(
                caller,
                IReservations::refundCall {
                    owner: self.owner,
                    id,
                    amount,
                },
            )
        }

        fn set_debt_cap(&mut self, creditor: Address, cap: u128) -> Result<()> {
            self.reservations.set_debt_cap(
                self.owner,
                IReservations::setDebtCapCall {
                    creditor,
                    token: self.token.address(),
                    cap,
                },
            )
        }

        fn set_capture_tolerance(&mut self, payee: Address, bounded: bool, bps: u32) -> Result<()> {
            self.reservations.set_capture_tolerance(
                self.owner,
                IReservations::setCaptureToleranceCall {
                    payee,
                    token: self.token.address(),
                    bounded,
                    toleranceBps: bps,
                },
            )
        }

        fn transfer(&mut self, from: Address, to: Address, amount: u64) -> Result<bool> {
            self.token.transfer(
                from,
                ITIP20::transferCall {
                    to,
                    amount: U256::from(amount),
                },
            )
        }

        fn balance(&self, account: Address) -> Result<U256> {
            self.token.balance_of(ITIP20::balanceOfCall { account })
        }

        fn reserved(&self) -> Result<u128> {
            self.reservations
                .reserved_of(self.owner, self.token.address())
        }

        fn available(&self) -> Result<u128> {
            self.reservations
                .available_of(self.owner, self.token.address())
        }

        fn debt(&self) -> Result<IReservations::debtOfReturn> {
            self.reservations.debt_of(self.owner, self.token.address())
        }

        /// Makes the token's transfer policy a blacklist of `accounts`.
        fn blacklist(&mut self, accounts: Vec<Address>) -> Result<()> {
            let mut registry = TIP403Registry::new();
            registry.initialize()?;
            let policy = registry.create_policy_with_accounts(
                self.admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin: self.admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    accounts,
                },
            )?;
            self.token.change_transfer_policy_id(
                self.admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
            )
        }
    }

    /// Runs `f` at T15 with the block timestamp at [`NOW`].
    fn at_t15(f: impl FnOnce() -> eyre::Result<()>) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, f)
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        at_t15(|| {
            let mut reservations = Reservations::new();
            let unsupported = check_selector_coverage(
                &mut reservations,
                IReservationsCalls::SELECTORS,
                "IReservations",
                IReservationsCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_hold_reserves_in_place() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 600)?;

            assert_eq!(f.balance(f.owner)?, U256::from(1_000));
            assert_eq!(f.reserved()?, 600);
            assert_eq!(f.available()?, 400);
            assert_eq!(
                f.reservations.get_hold(f.owner, id)?,
                IReservations::Hold {
                    token: f.token.address(),
                    payee: f.payee,
                    amount: 600,
                    expiresAt: EXPIRY,
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_placed(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    600,
                    EXPIRY,
                )]);

            let other = Address::random();
            assert_eq!(
                f.transfer(f.owner, other, 401).unwrap_err(),
                TIP20Error::insufficient_balance(
                    U256::from(400),
                    U256::from(401),
                    f.token.address()
                )
                .into()
            );
            assert!(f.transfer(f.owner, other, 400)?);
            assert_eq!(f.available()?, 0);
            assert_eq!(
                f.token.transfer_fee_pre_tx(f.owner, U256::ONE).unwrap_err(),
                TIP20Error::insufficient_balance(U256::ZERO, U256::ONE, f.token.address()).into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_hold_rejects_invalid_requests() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            for (amount, expires_at) in [
                (0, EXPIRY),
                (1u128 << 96, EXPIRY),
                (1, NOW),
                (1, NOW - 1),
                (1, NOW + MAX_HOLD_DURATION + 1),
            ] {
                assert_eq!(
                    f.hold_until(id, amount, expires_at).unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
            }
            assert_eq!(
                f.hold(id, 1_001).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );

            f.payee = Address::ZERO;
            assert_eq!(
                f.hold(id, 1).unwrap_err(),
                TIP20Error::invalid_recipient().into()
            );
            f.payee = Address::random();
            assert_eq!(
                f.reservations
                    .hold(
                        f.owner,
                        IReservations::holdCall {
                            token: Address::random(),
                            id,
                            amount: 1,
                            expiresAt: EXPIRY,
                            payee: f.payee,
                        },
                    )
                    .unwrap_err(),
                TIP20Error::invalid_token().into()
            );

            f.hold(id, 500)?;
            assert_eq!(
                f.hold(id, 1).unwrap_err(),
                ReservationsError::hold_exists().into()
            );
            // A second hold only sees the balance left available by the first.
            assert_eq!(
                f.hold(B256::random(), 501).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_capture_above_hold_takes_excess_from_available() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 500)?;
            f.reservations.clear_emitted_events();
            f.capture(id, 550)?;

            assert_eq!(f.balance(f.payee)?, U256::from(550));
            assert_eq!(f.balance(f.owner)?, U256::from(450));
            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.debt()?.amount, 0);
            assert_eq!(
                f.reservations.captured(f.owner, id)?,
                IReservations::capturedReturn {
                    captured: 550,
                    refunded: 0
                }
            );
            let hold = f.reservations.get_hold(f.owner, id)?;
            assert_eq!((hold.amount, hold.expiresAt), (0, 0));
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    550,
                    0,
                )]);

            // The hold is settled: it can be neither captured again nor re-held.
            assert_eq!(
                f.capture(id, 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            assert_eq!(
                f.hold(id, 1).unwrap_err(),
                ReservationsError::hold_exists().into()
            );
            assert_eq!(
                f.capture(B256::random(), 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_final_capture_stays_within_the_tolerance() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            f.set_capture_tolerance(f.payee, true, 2_000)?;
            let id = B256::random();
            f.hold(id, 500)?;
            assert_eq!(
                f.capture(id, 601).unwrap_err(),
                ReservationsError::tolerance_exceeded().into()
            );
            assert_eq!(f.reserved()?, 500);
            f.capture(id, 600)?;
            assert_eq!(f.balance(f.payee)?, U256::from(600));

            // The bound covers the whole authorization: non-final parts plus the final capture.
            let split = B256::random();
            f.hold(split, 250)?;
            f.capture_part(split, 100, false)?;
            assert_eq!(
                f.capture_part(split, 201, true).unwrap_err(),
                ReservationsError::tolerance_exceeded().into()
            );
            f.capture_part(split, 200, true)?;
            assert_eq!(f.captured(split)?, (300, 0));

            // The bound is per payee, and an unbounded one lets captures exceed the hold again.
            let other = B256::random();
            f.reservations.hold(
                f.owner,
                IReservations::holdCall {
                    token: f.token.address(),
                    id: other,
                    amount: 10,
                    expiresAt: EXPIRY,
                    payee: Address::random(),
                },
            )?;
            f.capture(other, 50)?;
            f.set_capture_tolerance(f.payee, false, 0)?;
            let unbounded = B256::random();
            f.hold(unbounded, 10)?;
            f.capture(unbounded, 50)?;
            assert_eq!(f.balance(f.owner)?, U256::from(0));
            Ok(())
        })
    }

    #[test]
    fn test_set_capture_tolerance_requires_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            assert_eq!(
                f.set_capture_tolerance(Address::ZERO, true, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.set_capture_tolerance(f.owner, true, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.set_capture_tolerance(f.payee, false, 1).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.set_capture_tolerance(f.payee, true, 2_000)?;
            assert_eq!(
                f.reservations
                    .capture_tolerance(f.owner, f.payee, f.token.address())?,
                IReservations::captureToleranceReturn {
                    bounded: true,
                    toleranceBps: 2_000
                }
            );

            let key = Address::random();
            let _keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            assert_eq!(
                f.set_capture_tolerance(f.payee, false, 0).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_capture_below_hold_releases_the_rest() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            let other = B256::random();
            f.hold(id, 500)?;
            f.hold(other, 200)?;
            assert_eq!(
                f.capture(id, 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.capture(id, 300)?;

            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.balance(f.owner)?, U256::from(700));
            assert_eq!(f.reserved()?, 200);
            assert_eq!(f.available()?, 500);
            Ok(())
        })
    }

    #[test]
    fn test_capture_shortfall_becomes_debt() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(500)?;
            let id = B256::random();
            f.hold(id, 500)?;
            assert_eq!(
                f.capture(id, 600).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_debt_cap(f.payee, 100)?;
            f.reservations.clear_emitted_events();
            f.capture(id, 600)?;

            assert_eq!(f.balance(f.payee)?, U256::from(500));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(
                f.debt()?,
                IReservations::debtOfReturn {
                    creditor: f.payee,
                    amount: 100
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    600,
                    100,
                )]);
            Ok(())
        })
    }

    #[test]
    fn test_payee_captures_after_the_key_is_revoked() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let id = B256::random();
            f.hold(id, 300)?;

            // The owner revokes the key that placed the hold; the hold stays live, even past its
            // expiry, until it is released.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.revoke_key(f.owner, IAccountKeychain::revokeKeyCall { keyId: key })?;
            StorageCtx.set_timestamp(U256::from(EXPIRY));
            keychain.set_tx_origin(f.payee)?;
            f.reservations.clear_emitted_events();
            f.capture_for(f.payee, id, 250)?;

            assert_eq!(f.balance(f.payee)?, U256::from(250));
            assert_eq!(f.balance(f.owner)?, U256::from(750));
            assert_eq!((f.reserved()?, f.available()?), (0, 750));
            assert_eq!(
                f.reservations.captured(f.owner, id)?,
                IReservations::capturedReturn {
                    captured: 250,
                    refunded: 0
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    250,
                    0,
                )]);

            // The settled record takes refunds like an owner capture.
            f.refund(f.payee, id, 50)?;
            assert_eq!(f.balance(f.owner)?, U256::from(800));
            assert_eq!(
                f.capture_for(f.payee, id, 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_capture_for_requires_the_payee_and_the_held_amount() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            // Debt room does not let the payee capture above the hold.
            f.set_debt_cap(f.payee, 1_000)?;
            let id = B256::random();
            f.hold(id, 300)?;

            for caller in [f.owner, Address::random()] {
                assert_eq!(
                    f.capture_for(caller, id, 100).unwrap_err(),
                    ReservationsError::unauthorized().into()
                );
            }
            for amount in [0, 301] {
                assert_eq!(
                    f.capture_for(f.payee, id, amount).unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
            }
            assert_eq!(
                f.capture_for(f.payee, B256::random(), 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            // Releasing stays with the owner: the payee's release looks up its own holds.
            assert_eq!(
                f.reservations.release(f.payee, id).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            assert_eq!(f.reserved()?, 300);

            f.capture_for(f.payee, id, 300)?;
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.debt()?.amount, 0);
            Ok(())
        })
    }

    #[test]
    fn test_part_captures_keep_the_hold_until_the_final_one() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 600)?;
            f.reservations.clear_emitted_events();
            f.capture_part(id, 200, false)?;

            assert_eq!(f.balance(f.payee)?, U256::from(200));
            assert_eq!(f.balance(f.owner)?, U256::from(800));
            assert_eq!((f.reserved()?, f.available()?), (400, 400));
            let hold = f.reservations.get_hold(f.owner, id)?;
            assert_eq!((hold.amount, hold.expiresAt), (400, EXPIRY));
            assert_eq!(f.captured(id)?, (200, 0));
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_part_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    200,
                    0,
                )]);

            // The payee takes the next part itself.
            f.capture_for_part(f.payee, id, 150, false)?;
            assert_eq!((f.reserved()?, f.available()?), (250, 400));
            assert_eq!(f.captured(id)?, (350, 0));

            // The final part may exceed what is left of the hold, like a capture.
            f.reservations.clear_emitted_events();
            f.capture_part(id, 300, true)?;
            assert_eq!(f.balance(f.payee)?, U256::from(650));
            assert_eq!(f.balance(f.owner)?, U256::from(350));
            assert_eq!((f.reserved()?, f.available()?), (0, 350));
            assert_eq!(f.captured(id)?, (650, 0));
            let hold = f.reservations.get_hold(f.owner, id)?;
            assert_eq!((hold.amount, hold.expiresAt), (0, 0));
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    300,
                    0,
                )]);
            for result in [
                f.capture_part(id, 1, false),
                f.capture_for_part(f.payee, id, 1, false),
            ] {
                assert_eq!(
                    result.unwrap_err(),
                    ReservationsError::hold_not_found().into()
                );
            }
            Ok(())
        })
    }

    #[test]
    fn test_part_capture_stays_within_the_hold() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            // Debt room does not let a non-final capture exceed the hold.
            f.set_debt_cap(f.payee, 1_000)?;
            let id = B256::random();
            f.hold(id, 300)?;
            for amount in [0, 301] {
                assert_eq!(
                    f.capture_part(id, amount, false).unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
                assert_eq!(
                    f.capture_for_part(f.payee, id, amount, false).unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
            }
            for caller in [f.owner, Address::random()] {
                assert_eq!(
                    f.capture_for_part(caller, id, 100, false).unwrap_err(),
                    ReservationsError::unauthorized().into()
                );
            }

            // A part may take the whole hold, leaving it live with nothing reserved.
            f.capture_part(id, 300, false)?;
            let hold = f.reservations.get_hold(f.owner, id)?;
            assert_eq!((hold.amount, hold.expiresAt), (0, EXPIRY));
            assert_eq!(
                f.capture_part(id, 1, false).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.capture(id, 20)?;
            assert_eq!(f.balance(f.payee)?, U256::from(320));
            assert_eq!(f.captured(id)?, (320, 0));
            assert_eq!(f.debt()?.amount, 0);
            Ok(())
        })
    }

    #[test]
    fn test_part_capture_rechecks_the_policy() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 300)?;
            f.capture_part(id, 100, false)?;
            f.blacklist(vec![f.payee])?;
            assert_eq!(
                f.capture_part(id, 100, false).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            assert_eq!(
                f.capture_for_part(f.payee, id, 100, false).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_release_after_part_captures_keeps_the_record() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());
            let id = B256::random();
            f.hold(id, 500)?;
            f.capture_part(id, 200, false)?;
            // A non-final capture spends what the hold already counted.
            assert_eq!(remaining()?, U256::from(500));

            f.reservations.clear_emitted_events();
            f.reservations.release(f.owner, id)?;
            assert_eq!(remaining()?, U256::from(800));
            assert_eq!((f.reserved()?, f.available()?), (0, 800));
            assert_eq!(f.captured(id)?, (200, 0));
            assert_eq!(
                f.reservations.get_hold(f.owner, id)?,
                IReservations::Hold {
                    token: f.token.address(),
                    payee: f.payee,
                    amount: 0,
                    expiresAt: 0,
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_released(
                    f.owner,
                    id,
                    f.token.address(),
                )]);

            // The settled id cannot be held again, and takes refunds of its parts.
            assert_eq!(
                f.hold(id, 1).unwrap_err(),
                ReservationsError::hold_exists().into()
            );
            assert_eq!(
                f.reservations.release(f.owner, id).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            f.refund(f.payee, id, 200)?;
            assert_eq!(remaining()?, U256::from(1_000));
            assert_eq!(f.balance(f.owner)?, U256::from(1_000));
            Ok(())
        })
    }

    #[test]
    fn test_release_expired_after_part_captures() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 500)?;
            f.capture_part(id, 200, false)?;

            StorageCtx.set_timestamp(U256::from(EXPIRY));
            // An expired hold still takes parts until it is released.
            f.capture_for_part(f.payee, id, 100, false)?;
            f.reservations.release_expired(f.owner, id)?;
            assert_eq!((f.reserved()?, f.available()?), (0, 700));
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.captured(id)?, (300, 0));
            assert_eq!(
                f.reservations.release_expired(f.owner, id).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_refunds_are_capped_at_the_parts_captured() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());
            let id = B256::random();
            f.hold(id, 500)?;
            f.capture_part(id, 100, false)?;
            f.capture_part(id, 150, false)?;
            assert_eq!(
                f.refund(f.payee, id, 251).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );

            // A refund while the hold is live gives back only the refund; the hold stays counted.
            f.refund(f.payee, id, 100)?;
            assert_eq!(remaining()?, U256::from(600));
            assert_eq!((f.reserved()?, f.available()?), (250, 600));
            assert_eq!(f.captured(id)?, (250, 100));

            f.capture_part(id, 250, true)?;
            assert_eq!(remaining()?, U256::from(600));
            assert_eq!(
                f.refund(f.payee, id, 401).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            f.refund(f.payee, id, 400)?;
            assert_eq!(f.captured(id)?, (500, 500));
            assert_eq!(remaining()?, U256::from(1_000));
            assert_eq!(f.balance(f.owner)?, U256::from(1_000));
            Ok(())
        })
    }

    #[test]
    fn test_adjust_after_part_captures_sets_what_is_left() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());
            let id = B256::random();
            f.hold(id, 500)?;
            f.capture_part(id, 200, false)?;

            // The captured part stays committed; only the hold's remainder changes.
            f.adjust(id, 100)?;
            assert_eq!(remaining()?, U256::from(700));
            assert_eq!((f.reserved()?, f.available()?), (100, 700));
            f.adjust(id, 400)?;
            assert_eq!(remaining()?, U256::from(400));
            assert_eq!(f.reservations.get_hold(f.owner, id)?.amount, 400);

            f.capture_part(id, 300, true)?;
            assert_eq!(remaining()?, U256::from(500));
            assert_eq!(f.captured(id)?, (500, 0));
            assert_eq!(f.balance(f.payee)?, U256::from(500));
            Ok(())
        })
    }

    #[test]
    fn test_payee_captures_parts_after_the_key_is_revoked() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let id = B256::random();
            f.hold(id, 300)?;

            keychain.set_transaction_key(Address::ZERO)?;
            keychain.revoke_key(f.owner, IAccountKeychain::revokeKeyCall { keyId: key })?;
            keychain.set_tx_origin(f.payee)?;
            f.capture_for_part(f.payee, id, 100, false)?;
            f.capture_for_part(f.payee, id, 150, true)?;

            assert_eq!(f.balance(f.payee)?, U256::from(250));
            assert_eq!(f.balance(f.owner)?, U256::from(750));
            assert_eq!((f.reserved()?, f.available()?), (0, 750));
            assert_eq!(f.captured(id)?, (250, 0));
            Ok(())
        })
    }

    #[test]
    fn test_part_capture_of_a_burned_hold_becomes_debt() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(500)?;
            let id = B256::random();
            f.hold(id, 500)?;
            f.token.grant_role_internal(f.admin, BURN_AT_ROLE)?;
            f.token.burn_at(
                f.admin,
                ITIP20::burnAtCall {
                    from: f.owner,
                    amount: U256::from(300),
                },
            )?;
            f.set_debt_cap(f.payee, 300)?;
            // The burned part is consumed first, as when a capture ends a burned hold.
            f.reservations.clear_emitted_events();
            f.capture_part(id, 250, false)?;
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_part_captured(
                    f.owner,
                    id,
                    f.token.address(),
                    250,
                    250,
                )]);
            assert_eq!(f.reserved()?, 200);
            f.capture_part(id, 250, true)?;
            assert_eq!(f.balance(f.payee)?, U256::from(200));
            assert_eq!(f.debt()?.amount, 300);
            Ok(())
        })
    }

    #[test]
    fn test_adjust() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 500)?;

            f.reservations.clear_emitted_events();
            f.adjust(id, 800)?;
            assert_eq!(f.reserved()?, 800);
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_adjusted(
                    f.owner,
                    id,
                    f.token.address(),
                    800,
                )]);
            assert_eq!(
                f.adjust(id, 1_001).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            f.adjust(id, 200)?;
            assert_eq!(f.reserved()?, 200);
            assert_eq!(f.reservations.get_hold(f.owner, id)?.amount, 200);
            assert_eq!(
                f.adjust(id, 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            assert_eq!(
                f.adjust(B256::random(), 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_release() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 500)?;
            f.reservations.clear_emitted_events();
            f.reservations.release(f.owner, id)?;

            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.available()?, 1_000);
            assert_eq!(
                f.reservations.get_hold(f.owner, id)?,
                IReservations::Hold {
                    token: Address::ZERO,
                    payee: Address::ZERO,
                    amount: 0,
                    expiresAt: 0,
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::hold_released(
                    f.owner,
                    id,
                    f.token.address(),
                )]);
            assert_eq!(
                f.reservations.release(f.owner, id).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            // A released id carries no record, so it can be held again.
            f.hold(id, 100)?;
            Ok(())
        })
    }

    #[test]
    fn test_release_expired() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            let captured = B256::random();
            f.hold(id, 500)?;
            f.hold(captured, 100)?;

            StorageCtx.set_timestamp(U256::from(EXPIRY - 1));
            assert_eq!(
                f.reservations.release_expired(f.owner, id).unwrap_err(),
                ReservationsError::hold_not_expired().into()
            );

            StorageCtx.set_timestamp(U256::from(EXPIRY));
            // Expired holds keep reserving until released, and can still be adjusted and captured.
            assert_eq!(f.reserved()?, 600);
            f.adjust(id, 400)?;
            f.capture(captured, 100)?;
            f.reservations.release_expired(f.owner, id)?;
            assert_eq!(f.reserved()?, 0);
            assert_eq!(
                f.reservations.release_expired(f.owner, id).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_charge_shortfall_is_capped_debt() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            assert_eq!(
                f.charge(id, 1_001, f.payee).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_debt_cap(f.payee, 300)?;
            assert_eq!(
                f.reservations
                    .debt_cap(f.owner, f.payee, f.token.address())?,
                300
            );
            f.charge(id, 1_200, f.payee)?;

            assert_eq!(f.balance(f.payee)?, U256::from(1_000));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(
                f.debt()?,
                IReservations::debtOfReturn {
                    creditor: f.payee,
                    amount: 200
                }
            );
            assert_eq!(
                f.charge(id, 101, f.payee).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            // Later charges under the same id accumulate the captured total.
            f.charge(id, 100, f.payee)?;
            assert_eq!(f.debt()?.amount, 300);
            assert_eq!(f.reservations.captured(f.owner, id)?.captured, 1_300);
            assert_eq!(
                f.reservations.emitted_events().last(),
                Some(
                    &ReservationsEvent::charged(f.owner, id, f.token.address(), f.payee, 100, 100)
                        .into_log_data()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn test_charge_rejects_conflicting_ids() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let held = B256::random();
            f.hold(held, 100)?;
            assert_eq!(
                f.charge(held, 1, f.payee).unwrap_err(),
                ReservationsError::hold_exists().into()
            );

            let charged = B256::random();
            f.charge(charged, 1, f.payee)?;
            assert_eq!(
                f.charge(charged, 1, Address::random()).unwrap_err(),
                ReservationsError::hold_exists().into()
            );
            assert_eq!(
                f.charge(charged, 0, f.payee).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_debt_is_repaid_first_on_receive() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            f.set_debt_cap(f.payee, 500)?;
            f.charge(B256::random(), 300, f.payee)?;
            assert_eq!(f.debt()?.amount, 200);
            f.reservations.clear_emitted_events();
            f.token.clear_emitted_events();

            let sender = Address::random();
            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: U256::from(1_000),
                },
            )?;
            f.token.clear_emitted_events();
            f.transfer(sender, f.owner, 150)?;
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(f.balance(f.payee)?, U256::from(250));
            assert_eq!(f.debt()?.amount, 50);
            f.token.assert_emitted_events(vec![
                TIP20Event::transfer(sender, f.owner, U256::from(150)),
                TIP20Event::transfer(f.owner, f.payee, U256::from(150)),
            ]);

            // Mints also repay first; only the excess stays with the owner.
            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: f.owner,
                    amount: U256::from(80),
                },
            )?;
            assert_eq!(f.balance(f.owner)?, U256::from(30));
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(
                f.debt()?,
                IReservations::debtOfReturn {
                    creditor: Address::ZERO,
                    amount: 0
                }
            );
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::debt_repaid(f.owner, f.token.address(), f.payee, 150),
                ReservationsEvent::debt_repaid(f.owner, f.token.address(), f.payee, 50),
            ]);

            // Without debt, credits stay with the owner.
            f.transfer(sender, f.owner, 10)?;
            assert_eq!(f.balance(f.owner)?, U256::from(40));
            Ok(())
        })
    }

    #[test]
    fn test_debtor_count_gates_repayment() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let registry = TIP403Registry::new();
            assert!(!registry.has_reservation_debt(f.owner)?);
            f.set_debt_cap(f.payee, 500)?;
            f.charge(B256::random(), 300, f.payee)?;
            assert!(registry.has_reservation_debt(f.owner)?);

            // Setting a receive policy keeps the count, so later credits still repay.
            set_receive_policy(f.owner, ALLOW_ALL_POLICY_ID)?;
            assert!(registry.has_reservation_debt(f.owner)?);
            let sender = Address::random();
            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: U256::from(1_000),
                },
            )?;
            assert!(f.transfer(sender, f.owner, 150)?);
            assert_eq!(f.debt()?.amount, 50);
            assert!(registry.has_reservation_debt(f.owner)?);

            // Full repayment clears the count; the next credit stays with the owner.
            assert!(f.transfer(sender, f.owner, 70)?);
            assert_eq!(f.debt()?.amount, 0);
            assert!(!registry.has_reservation_debt(f.owner)?);
            assert!(f.transfer(sender, f.owner, 30)?);
            assert_eq!(f.balance(f.owner)?, U256::from(50));
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            Ok(())
        })
    }

    #[test]
    fn test_second_creditor_rejected_while_debt_exists() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let second = Address::random();
            f.set_debt_cap(f.payee, 500)?;
            f.set_debt_cap(second, 500)?;
            f.charge(B256::random(), 150, f.payee)?;
            assert_eq!(
                f.charge(B256::random(), 10, second).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            // The first creditor can still extend its own debt.
            f.charge(B256::random(), 10, f.payee)?;
            assert_eq!(f.debt()?.amount, 60);
            Ok(())
        })
    }

    #[test]
    fn test_refund_is_linked_and_capped() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let id = B256::random();
            f.hold(id, 300)?;
            // Nothing is captured while the hold is live.
            assert_eq!(
                f.refund(f.payee, id, 1).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            f.capture(id, 300)?;

            assert_eq!(
                f.refund(Address::random(), id, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.refund(f.payee, B256::random(), 1).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            assert_eq!(
                f.refund(f.payee, id, 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.reservations.clear_emitted_events();
            f.refund(f.payee, id, 100)?;
            assert_eq!(f.balance(f.owner)?, U256::from(800));
            assert_eq!(f.balance(f.payee)?, U256::from(200));
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::refunded(f.owner, id, 100)]);
            assert_eq!(
                f.refund(f.payee, id, 201).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            f.refund(f.payee, id, 200)?;
            assert_eq!(
                f.reservations.captured(f.owner, id)?,
                IReservations::capturedReturn {
                    captured: 300,
                    refunded: 300
                }
            );
            Ok(())
        })
    }

    #[test]
    fn test_refund_settles_debt_to_the_refunding_creditor() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            f.set_debt_cap(f.payee, 500)?;
            f.charge(id, 300, f.payee)?;
            f.reservations.clear_emitted_events();
            f.refund(f.payee, id, 250)?;

            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::debt_repaid(f.owner, f.token.address(), f.payee, 200),
                ReservationsEvent::refunded(f.owner, id, 250),
            ]);
            assert_eq!(f.debt()?.amount, 0);
            assert_eq!(f.balance(f.owner)?, U256::from(50));
            assert_eq!(f.balance(f.payee)?, U256::from(50));
            Ok(())
        })
    }

    #[test]
    fn test_policy_forbids_hold_and_charge() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let held = B256::random();
            f.hold(held, 100)?;
            f.blacklist(vec![f.payee])?;

            assert_eq!(
                f.hold(B256::random(), 1).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            // A hold placed before the payee was forbidden cannot settle; it can only be released.
            assert_eq!(
                f.capture(held, 100).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            f.reservations.release(f.owner, held)?;
            assert_eq!(
                f.charge(B256::random(), 1, f.payee).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
            // Both interfaces share the `PolicyForbids()` selector.
            assert_eq!(
                TIP20Error::policy_forbids().selector(),
                ReservationsError::policy_forbids().selector()
            );
            Ok(())
        })
    }

    #[test]
    fn test_repayment_waits_until_the_creditor_may_receive() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            f.set_debt_cap(f.payee, 500)?;
            f.charge(B256::random(), 300, f.payee)?;
            let sender = Address::random();
            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: U256::from(1_000),
                },
            )?;
            // Credits stay with the owner and the debt stays in place while repayment is blocked.
            let assert_unrepaid = |f: &Fixture, owner_balance: u64, debt: u128| -> Result<()> {
                assert_eq!(f.balance(f.owner)?, U256::from(owner_balance));
                assert_eq!(f.balance(f.payee)?, U256::from(300 - debt as u64));
                assert_eq!(f.debt()?.amount, debt);
                Ok(())
            };

            // The creditor's receive policy rejects the owner.
            set_receive_policy(f.payee, REJECT_ALL_POLICY_ID)?;
            assert!(f.transfer(sender, f.owner, 10)?);
            assert_unrepaid(&f, 10, 200)?;
            set_receive_policy(f.payee, ALLOW_ALL_POLICY_ID)?;
            assert!(f.transfer(sender, f.owner, 10)?);
            assert_unrepaid(&f, 10, 190)?;

            // The token's transfer policy forbids the creditor as recipient.
            f.blacklist(vec![f.payee])?;
            assert!(f.transfer(sender, f.owner, 10)?);
            assert_unrepaid(&f, 20, 190)?;
            // ... or the owner as sender; fee refunds never repay.
            f.blacklist(vec![f.owner])?;
            f.token.transfer_fee_pre_tx(sender, U256::from(100))?;
            f.token
                .transfer_fee_post_tx(f.owner, U256::from(10), U256::from(90))?;
            assert_unrepaid(&f, 30, 190)?;
            f.blacklist(vec![])?;
            assert!(f.transfer(sender, f.owner, 10)?);
            assert_unrepaid(&f, 30, 180)?;

            // A fee refund credits without repaying, paused or not.
            f.token.transfer_fee_pre_tx(sender, U256::from(100))?;
            f.token.grant_role_internal(f.admin, PAUSE_ROLE)?;
            f.token.pause(f.admin, ITIP20::pauseCall {})?;
            f.token
                .transfer_fee_post_tx(f.owner, U256::from(60), U256::from(40))?;
            assert_unrepaid(&f, 90, 180)?;
            Ok(())
        })
    }

    #[test]
    fn test_burned_holds_keep_later_holds_backed() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let old = B256::random();
            f.hold(old, 100)?;
            f.token.grant_role_internal(f.admin, BURN_AT_ROLE)?;
            f.token.burn_at(
                f.admin,
                ITIP20::burnAtCall {
                    from: f.owner,
                    amount: U256::from(100),
                },
            )?;
            assert_eq!(f.reserved()?, 0);

            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: f.owner,
                    amount: U256::from(80),
                },
            )?;
            let new = B256::random();
            f.hold(new, 80)?;
            // A hold placed after the burn is fully backed, even while the burned hold is live.
            f.capture(new, 80)?;
            assert_eq!(f.balance(f.payee)?, U256::from(80));
            assert_eq!(f.reserved()?, 0);

            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: f.owner,
                    amount: U256::from(50),
                },
            )?;
            let later = B256::random();
            f.hold(later, 50)?;
            // Releasing the burned hold leaves the newer hold's reservation in place.
            f.reservations.release(f.owner, old)?;
            assert_eq!(f.reserved()?, 50);
            assert_eq!(f.available()?, 0);
            Ok(())
        })
    }

    #[test]
    fn test_compliance_burns_take_reserved_funds() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let captured = B256::random();
            let released = B256::random();
            f.hold(captured, 600)?;
            f.hold(released, 300)?;
            f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
            f.blacklist(vec![f.owner])?;
            f.token
                .burn_blocked(f.admin, f.owner, U256::from(800), true)?;

            // The burn caps the reserved amount at the remaining balance; holds keep their amounts.
            assert_eq!(f.balance(f.owner)?, U256::from(200));
            assert_eq!(f.reserved()?, 200);
            assert_eq!(f.available()?, 0);
            assert_eq!(f.reservations.get_hold(f.owner, released)?.amount, 300);

            // Ending a hold consumes the burned part first, so what remains still backs the others.
            f.blacklist(vec![])?;
            f.reservations.release(f.owner, released)?;
            assert_eq!(f.reserved()?, 200);
            assert_eq!(f.available()?, 0);
            // A capture pays only the available balance; the rest needs debt headroom.
            assert_eq!(
                f.capture(captured, 600).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_debt_cap(f.payee, 400)?;
            f.capture(captured, 600)?;
            assert_eq!(f.balance(f.payee)?, U256::from(200));
            assert_eq!(f.debt()?.amount, 400);

            // Burns at an address are compliance burns too.
            let mut f = Fixture::new(1_000)?;
            f.hold(B256::random(), 700)?;
            f.token.grant_role_internal(f.admin, BURN_AT_ROLE)?;
            let burn_at = |f: &mut Fixture, amount: u64| {
                f.token.burn_at(
                    f.admin,
                    ITIP20::burnAtCall {
                        from: f.owner,
                        amount: U256::from(amount),
                    },
                )
            };
            burn_at(&mut f, 500)?;
            assert_eq!(f.balance(f.owner)?, U256::from(500));
            assert_eq!(f.reserved()?, 500);
            // Ordinary debits still respect the reservation.
            assert_eq!(
                f.transfer(f.owner, Address::random(), 1).unwrap_err(),
                TIP20Error::insufficient_balance(U256::ZERO, U256::ONE, f.token.address()).into()
            );
            assert_eq!(
                burn_at(&mut f, 501).unwrap_err(),
                TIP20Error::insufficient_balance(
                    U256::from(500),
                    U256::from(501),
                    f.token.address()
                )
                .into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_virtual_addresses_resolve_to_their_master() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut registry = AddressRegistry::new();
            registry.register_virtual_master_unchecked(MasterId::repeat_byte(1), f.payee)?;
            registry.register_virtual_master_unchecked(MasterId::repeat_byte(2), f.owner)?;
            let virtual_payee = Address::new_virtual(MasterId::repeat_byte(1), UserTag::ZERO);
            let virtual_owner = Address::new_virtual(MasterId::repeat_byte(2), UserTag::ZERO);

            // Debt caps are kept for the master, which is the creditor a virtual payee resolves to.
            f.set_debt_cap(virtual_payee, 300)?;
            let token = f.token.address();
            assert_eq!(f.reservations.debt_cap(f.owner, f.payee, token)?, 300);
            assert_eq!(f.reservations.debt_cap(f.owner, virtual_payee, token)?, 300);
            assert_eq!(
                f.set_debt_cap(virtual_owner, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            f.charge(B256::random(), 300, virtual_payee)?;
            assert_eq!(f.debt()?.creditor, f.payee);

            // A credit to the owner's virtual address repays after the forwarding event.
            let sender = Address::random();
            f.token.mint(
                f.admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: U256::from(50),
                },
            )?;
            f.token.clear_emitted_events();
            assert!(f.transfer(sender, virtual_owner, 50)?);
            f.token.assert_emitted_events(vec![
                TIP20Event::transfer(sender, virtual_owner, U256::from(50)),
                TIP20Event::transfer(virtual_owner, f.owner, U256::from(50)),
                TIP20Event::transfer(f.owner, f.payee, U256::from(50)),
            ]);
            assert_eq!(f.debt()?.amount, 150);
            Ok(())
        })
    }

    #[test]
    fn test_give_backs_never_unfreeze_a_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let released = B256::random();
            let expiring = B256::random();
            let captured = B256::random();
            f.hold(released, 20)?;
            f.hold(expiring, 20)?;
            f.hold(captured, 20)?;
            f.capture(captured, 20)?;

            // The owner freezes the key with its root key.
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.update_spending_limit(
                f.owner,
                IAccountKeychain::updateSpendingLimitCall {
                    keyId: key,
                    token: f.token.address(),
                    newLimit: U256::ZERO,
                },
            )?;
            f.reservations.release(f.owner, released)?;
            StorageCtx.set_timestamp(U256::from(EXPIRY));
            f.reservations.release_expired(f.owner, expiring)?;
            f.refund(f.payee, captured, 20)?;
            assert_eq!(
                remaining_limit(&keychain, f.owner, key, f.token.address())()?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn test_set_debt_cap_requires_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            assert_eq!(
                f.set_debt_cap(Address::ZERO, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.set_debt_cap(f.owner, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );

            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            assert_eq!(
                f.set_debt_cap(f.payee, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            // Calls from other accounts are not authorized by the origin's access key.
            keychain.set_tx_origin(Address::random())?;
            f.set_debt_cap(f.payee, 1)?;
            Ok(())
        })
    }

    #[test]
    fn test_holds_count_against_the_mandate_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            let first = B256::random();
            f.hold(first, 80)?;
            assert_eq!(remaining()?, U256::from(20));
            assert_eq!(
                f.hold(B256::random(), 30).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );

            // Releasing a hold gives its headroom back.
            f.reservations.release(f.owner, first)?;
            assert_eq!(remaining()?, U256::from(100));
            let second = B256::random();
            f.hold(second, 30)?;
            assert_eq!(remaining()?, U256::from(70));

            // Adjusting up spends the increase; adjusting down gives the decrease back.
            f.adjust(second, 90)?;
            assert_eq!(remaining()?, U256::from(10));
            assert_eq!(
                f.adjust(second, 101).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            f.adjust(second, 40)?;
            assert_eq!(remaining()?, U256::from(60));
            Ok(())
        })
    }

    #[test]
    fn test_capture_counts_only_the_excess_over_the_hold() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            f.set_debt_cap(f.payee, 1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            let tipped = B256::random();
            f.hold(tipped, 300)?;
            f.capture(tipped, 350)?;
            assert_eq!(remaining()?, U256::from(150));

            // A capture below the hold gives the rest back.
            let partial = B256::random();
            f.hold(partial, 100)?;
            f.capture(partial, 40)?;
            assert_eq!(remaining()?, U256::from(110));

            let over = B256::random();
            f.hold(over, 110)?;
            assert_eq!(
                f.capture(over, 111).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            f.capture(over, 110)?;
            assert_eq!(remaining()?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_charge_counts_the_full_amount() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            f.set_debt_cap(f.payee, 1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            // Debt counts too: the limit bounds what the key commits, not what the balance pays.
            assert_eq!(
                f.charge(B256::random(), 501, f.payee).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            let id = B256::random();
            f.charge(id, 300, f.payee)?;
            assert_eq!(remaining()?, U256::from(200));
            assert_eq!(f.debt()?.amount, 200);
            f.charge(id, 200, f.payee)?;
            assert_eq!(remaining()?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_refund_restores_the_mandate_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            let id = B256::random();
            f.hold(id, 300)?;
            f.capture(id, 300)?;
            assert_eq!(remaining()?, U256::from(200));
            f.refund(f.payee, id, 100)?;
            assert_eq!(remaining()?, U256::from(300));

            // A charge's refund goes back to the key that charged.
            let charged = B256::random();
            f.charge(charged, 50, f.payee)?;
            assert_eq!(remaining()?, U256::from(250));
            f.refund(f.payee, charged, 50)?;
            assert_eq!(remaining()?, U256::from(300));
            Ok(())
        })
    }

    #[test]
    fn test_refund_restores_a_later_period_charge() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            let id = B256::random();
            f.charge(id, 1, f.payee)?;
            StorageCtx.set_timestamp(U256::from(NOW + CARD_LIMIT_PERIOD));
            f.charge(id, 800, f.payee)?;
            assert_eq!(remaining()?, U256::from(200));
            // Refunds settle against what is still paid, so the earlier period's 1 stays counted.
            f.refund(f.payee, id, 800)?;
            assert_eq!(remaining()?, U256::from(999));
            Ok(())
        })
    }

    #[test]
    fn test_expired_hold_restores_within_its_period_only() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());

            let expiring = B256::random();
            f.hold(expiring, 40)?;
            StorageCtx.set_timestamp(U256::from(EXPIRY));
            f.reservations.release_expired(f.owner, expiring)?;
            assert_eq!(remaining()?, U256::from(100));

            // A hold counted in one period is not given back after a spend rolled the period.
            let old = B256::random();
            f.hold_until(old, 60, NOW + 2 * CARD_LIMIT_PERIOD)?;
            StorageCtx.set_timestamp(U256::from(NOW + CARD_LIMIT_PERIOD));
            f.hold_until(B256::random(), 70, NOW + 2 * CARD_LIMIT_PERIOD)?;
            assert_eq!(remaining()?, U256::from(30));
            f.reservations.release(f.owner, old)?;
            assert_eq!(remaining()?, U256::from(30));
            assert_eq!(
                f.hold_until(B256::random(), 31, NOW + 2 * CARD_LIMIT_PERIOD)
                    .unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_other_access_keys_cannot_act_on_a_hold() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let id = B256::random();
            f.hold(id, 80)?;

            let other = Address::random();
            keychain.set_transaction_key(Address::ZERO)?;
            authorize_card_key(f.owner, other, f.token.address(), 100)?;
            for result in [
                f.adjust(id, 10),
                f.capture(id, 10),
                f.capture_part(id, 10, false),
                f.reservations.release(f.owner, id),
            ] {
                assert_eq!(
                    result.unwrap_err(),
                    ReservationsError::unauthorized().into()
                );
            }

            // The root key may enlarge and release it; only what the key's limit counted comes back.
            keychain.set_transaction_key(Address::ZERO)?;
            f.adjust(id, 90)?;
            f.reservations.release(f.owner, id)?;
            assert_eq!(
                remaining_limit(&keychain, f.owner, key, f.token.address())()?,
                U256::from(100)
            );
            Ok(())
        })
    }

    #[test]
    fn test_capture_for_gives_back_to_the_live_placing_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let id = B256::random();
            f.hold(id, 100)?;

            // The payee's own transaction: the part of the hold left uncaptured returns to the key.
            keychain.set_tx_origin(f.payee)?;
            keychain.set_transaction_key(Address::ZERO)?;
            f.capture_for(f.payee, id, 40)?;
            assert_eq!(
                remaining_limit(&keychain, f.owner, key, f.token.address())()?,
                U256::from(60)
            );

            // An owner paying itself still cannot settle another access key's hold.
            keychain.set_tx_origin(f.owner)?;
            keychain.set_transaction_key(key)?;
            f.payee = f.owner;
            let own = B256::random();
            f.hold(own, 10)?;
            keychain.set_transaction_key(Address::ZERO)?;
            authorize_card_key(f.owner, Address::random(), f.token.address(), 100)?;
            assert_eq!(
                f.capture_for(f.owner, own, 10).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_root_top_ups_never_become_key_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let key = Address::random();
            let mut keychain = authorize_card_key(f.owner, key, f.token.address(), 100)?;
            let id = B256::random();
            f.hold(id, 100)?;

            keychain.set_transaction_key(Address::ZERO)?;
            f.adjust(id, 200)?;
            keychain.set_transaction_key(key)?;
            // The unused root top-up is released first; the key's own 100 was captured.
            f.capture(id, 100)?;
            assert_eq!(
                remaining_limit(&keychain, f.owner, key, f.token.address())()?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn test_card_key_scope_admits_only_reservation_calls() -> eyre::Result<()> {
        at_t15(|| {
            let f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let validate = |target: Address, input: Vec<u8>| {
                keychain.validate_call_scope_for_transaction(
                    f.owner,
                    key,
                    &TxKind::Call(target),
                    &input,
                )
            };

            let capture = IReservations::captureCall {
                id: B256::random(),
                amount: 1,
            };
            validate(RESERVATIONS_ADDRESS, capture.abi_encode())?;
            let set_debt_cap = IReservations::setDebtCapCall {
                creditor: f.payee,
                token: f.token.address(),
                cap: 1,
            };
            let transfer = ITIP20::transferCall {
                to: f.payee,
                amount: U256::ONE,
            };
            for (target, input) in [
                (RESERVATIONS_ADDRESS, set_debt_cap.abi_encode()),
                (f.token.address(), transfer.abi_encode()),
            ] {
                assert_eq!(
                    validate(target, input).unwrap_err(),
                    AccountKeychainError::call_not_allowed().into()
                );
            }
            Ok(())
        })
    }

    #[test]
    fn test_pre_t15_tip20_ignores_reservations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut f = Fixture::new(1_000)?;
            // The precompile is not callable before T15; write its state directly.
            f.reservations.positions[f.owner][f.token.address()].write(Position {
                reserved: 1_000,
                debt: 0,
            })?;
            assert_eq!(f.balance(f.owner)?, U256::from(1_000));
            assert!(f.transfer(f.owner, Address::random(), 1_000)?);
            Ok(())
        })
    }

    #[test]
    fn test_zone_tip20_ignores_reservations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15)
            .with_kind(tempo_primitives::TempoEvmKind::Zone);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut f = Fixture::new(1_000)?;
            f.reservations.positions[f.owner][f.token.address()].write(Position {
                reserved: 1_000,
                debt: 0,
            })?;
            assert_eq!(f.balance(f.owner)?, U256::from(1_000));
            assert!(f.transfer(f.owner, Address::random(), 1_000)?);
            Ok(())
        })
    }

    /// Sets `receiver`'s TIP-1028 receive policy to admit senders under `sender_policy_id`.
    fn set_receive_policy(receiver: Address, sender_policy_id: u64) -> Result<()> {
        TIP403Registry::new().set_receive_policy(
            receiver,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: sender_policy_id,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: Address::ZERO,
            },
        )
    }

    /// Returns a reader of @@key@@'s remaining @@token@@ limit on @@owner@@.
    fn remaining_limit(
        keychain: &AccountKeychain,
        owner: Address,
        key: Address,
        token: Address,
    ) -> impl Fn() -> Result<U256> + '_ {
        move || {
            keychain.get_remaining_limit(IAccountKeychain::getRemainingLimitCall {
                account: owner,
                keyId: key,
                token,
            })
        }
    }

    /// Authorizes an issuer access key on `account`, scoped to the reservations precompile with
    /// a `limit` on `token`, and makes it sign the current transaction.
    fn authorize_card_key(
        account: Address,
        key: Address,
        token: Address,
        limit: u64,
    ) -> Result<AccountKeychain> {
        let mut keychain = AccountKeychain::new();
        keychain.initialize()?;
        keychain.set_tx_origin(account)?;
        let selectors = [
            IReservations::holdCall::SELECTOR,
            IReservations::adjustCall::SELECTOR,
            IReservations::captureCall::SELECTOR,
            IReservations::capturePartCall::SELECTOR,
            IReservations::chargeCall::SELECTOR,
            IReservations::releaseCall::SELECTOR,
        ];
        keychain.authorize_key(
            account,
            key,
            IAccountKeychain::SignatureType::Secp256k1,
            IAccountKeychain::KeyRestrictions {
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![IAccountKeychain::TokenLimit {
                    token,
                    amount: U256::from(limit),
                    period: CARD_LIMIT_PERIOD,
                }],
                allowAnyCalls: false,
                allowedCalls: vec![IAccountKeychain::CallScope {
                    target: RESERVATIONS_ADDRESS,
                    selectorRules: selectors
                        .into_iter()
                        .map(|selector| IAccountKeychain::SelectorRule {
                            selector: selector.into(),
                            recipients: vec![],
                        })
                        .collect(),
                }],
            },
            None,
        )?;
        keychain.set_transaction_key(key)?;
        Ok(keychain)
    }
}
