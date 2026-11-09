//! Account reservations precompile: native holds on TIP-20 balances, capped debt and linked
//! refunds.
//!
//! Held funds never leave the owner's balance. From T15, every TIP-20 debit except compliance burns
//! requires the amount to fit in the balance minus the owner's reserved total, and every TIP-20
//! credit to an owner with debt in that token pays the creditor first when the token's and the
//! creditor's policies admit that payment. A capture or charge releases the hold before paying,
//! so it spends the reservation it consumes.
//!
//! Open holds count as spend of the access key that placed them (TIP-1011 limits), and every
//! amount a hold stops committing, or a payee refunds, is given back to that key's limit.

pub mod dispatch;

use crate::{
    account_keychain::{AccountKeychain, LimitSpend},
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, Mapping},
    tip20::{Recipient, TIP20Token},
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

/// Reserved and owed amounts of one owner in one token, packed in one slot.
///
/// TIP-20 reads this slot on every debit and credit from T15.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Sum of the owner's live holds in the token, less the burned part in `Shortfall`.
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

/// One authorization of an owner, from its hold to its refunds, in five slots.
///
/// The record exists while `token` is non-zero and the hold is live while `expires_at` is
/// non-zero. A live hold has nothing captured yet, since capturing ends the hold. The captured
/// slot is written on settlement and the key slot only for authorizations an access key placed.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Authorization {
    token: Address,
    /// Amount the live hold reserves.
    held: U96,
    /// Resolved payee, the only account allowed to refund.
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
}

impl Reservations {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the amount of `token` that `owner` has reserved.
    ///
    /// Called by TIP-20 on every debit from T15.
    pub(crate) fn reserved_of(&self, owner: Address, token: Address) -> Result<u128> {
        self.positions[owner][token].reserved.read()
    }

    /// Sets `owner`'s reserved amount of `token` without a hold, so test fixtures outside this
    /// crate can reserve funds.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_reserved_unchecked(
        &mut self,
        owner: Address,
        token: Address,
        reserved: u128,
    ) -> Result<()> {
        self.positions[owner][token].reserved.write(reserved)
    }

    /// Lowers `owner`'s reserved amount of `token` to at most `max`, leaving its holds as they are.
    ///
    /// Called by TIP-20 before a compliance burn from T15, so the burn may take reserved funds.
    /// Afterwards `reserved` may be below the sum of the owner's live holds.
    pub(crate) fn cap_reserved(&mut self, owner: Address, token: Address, max: U256) -> Result<()> {
        let mut position = self.positions[owner][token].read()?;
        if U256::from(position.reserved) <= max {
            return Ok(());
        }
        // `max` is below `reserved`, so it fits.
        let max: u128 = max.to();
        let mut shortfall = self.shortfalls[owner][token].read()?;
        shortfall.unbacked = shortfall.unbacked.saturating_add(position.reserved - max);
        shortfall.epoch = shortfall.epoch.saturating_add(1);
        self.shortfalls[owner][token].write(shortfall)?;
        position.reserved = max;
        self.positions[owner][token].write(position)
    }

    /// Settles up to `received` of `owner`'s debt in `token` and emits `DebtRepaid`.
    ///
    /// Called by TIP-20 after crediting `owner` from T15. `admits` tells from the creditor whether
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
        let token = TIP20Token::from_address(call.token)?;
        let payee = resolve_payee(call.payee)?;
        token.ensure_transfer_authorized(owner, payee)?;
        if self.authorizations[owner][call.id].token.read()? != Address::ZERO {
            return Err(ReservationsError::hold_exists().into());
        }

        let mut position = self.positions[owner][call.token].read()?;
        if call.amount > available(&token, owner, &position)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        position.reserved = position
            .reserved
            .checked_add(call.amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let spend =
            AccountKeychain::new().spend_limit(owner, call.token, U256::from(call.amount))?;
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
            let token = TIP20Token::from_address(auth.token)?;
            if increase > available(&token, owner, &position)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            position.reserved = position
                .reserved
                .checked_add(increase)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            let spend =
                AccountKeychain::new().spend_limit(owner, auth.token, U256::from(increase))?;
            record_spend(&mut auth, spend, increase);
        } else {
            self.unreserve(owner, &auth, &mut position, decrease)?;
        }
        self.positions[owner][auth.token].write(position)?;
        restore_limit(owner, &mut auth, decrease)?;
        auth.held = held;
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            call.id,
            auth.token,
            call.amount,
        ))
    }

    fn capture(&mut self, owner: Address, call: IReservations::captureCall) -> Result<()> {
        let mut auth = self.live_hold(owner, call.id)?;
        ensure_key_may_act(owner, &auth)?;
        let captured = amount_u96(call.amount)?;
        let held = auth.held.to::<u128>();
        let mut token = TIP20Token::from_address(auth.token)?;
        // The payee may have become forbidden since the hold was placed.
        token.ensure_transfer_authorized(owner, auth.payee)?;
        let mut position = self.positions[owner][auth.token].read()?;
        // Releasing the hold first lets the payment spend the reservation it consumes.
        self.unreserve(owner, &auth, &mut position, held)?;
        // The hold already counted against the key's limit; only an excess is new spend.
        let excess = call.amount.saturating_sub(held);
        let (debt, spend) =
            self.pay(&mut token, owner, auth.payee, call.amount, excess, position)?;
        record_spend(&mut auth, spend, excess);
        restore_limit(owner, &mut auth, held.saturating_sub(call.amount))?;

        auth.held = U96::ZERO;
        auth.expires_at = 0;
        auth.captured = captured;
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_captured(
            owner,
            call.id,
            auth.token,
            call.amount,
            debt,
        ))
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
        let (debt, spend) =
            self.pay(&mut token, owner, payee, call.amount, call.amount, position)?;

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
        restore_limit(call.owner, &mut auth, call.amount)?;

        auth.refunded = refunded;
        self.authorizations[call.owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::refunded(
            call.owner,
            call.id,
            call.amount,
        ))
    }

    fn set_debt_cap(&mut self, owner: Address, call: IReservations::setDebtCapCall) -> Result<()> {
        // Card access keys must never raise the debt they can create.
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(ReservationsError::unauthorized().into());
        }
        // Debt is owed to resolved payees, so a cap for a virtual address applies to its master.
        let creditor = Recipient::resolve(call.creditor)?.target;
        if creditor.is_zero() || creditor == owner {
            return Err(ReservationsError::unauthorized().into());
        }
        TIP20Token::from_address(call.token)?;
        self.debt_caps[owner][creditor][call.token].write(call.cap)
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
        let position = self.positions[owner][token].read()?;
        available(&TIP20Token::from_address(token)?, owner, &position)
    }

    fn debt_cap(&self, owner: Address, creditor: Address, token: Address) -> Result<u128> {
        self.debt_caps[owner][Recipient::resolve(creditor)?.target][token].read()
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

    /// Pays `amount` from `owner`'s available balance to `payee` and records the shortfall as
    /// debt towards `payee`, within the owner's cap. Writes `position`.
    ///
    /// Counts `spend`, debt included, against the access key signing for `owner`. Returns the
    /// new debt and the limit charge, if any.
    fn pay(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        payee: Address,
        amount: u128,
        spend: u128,
        mut position: Position,
    ) -> Result<(u128, Option<LimitSpend>)> {
        let token_address = token.address();
        let paid = amount.min(available(token, owner, &position)?);
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
        }
        // TIP-20 reads the position during the transfer, so it must be written first.
        self.positions[owner][token_address].write(position)?;
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
        }
        self.emit_event(ReservationsEvent::debt_repaid(
            owner, token, creditor, amount,
        ))
    }

    fn end_hold(&mut self, owner: Address, id: B256, mut auth: Authorization) -> Result<()> {
        let mut position = self.positions[owner][auth.token].read()?;
        self.unreserve(owner, &auth, &mut position, auth.held.to())?;
        self.positions[owner][auth.token].write(position)?;
        self.authorizations[owner][id].delete()?;
        let held = auth.held.to();
        restore_limit(owner, &mut auth, held)?;
        self.emit_event(ReservationsEvent::hold_released(owner, id, auth.token))
    }

    /// Removes `amount` of `auth`'s hold from `position`. A hold live at the latest burn first
    /// consumes the burned part, so the reservation behind the other holds stays in place.
    fn unreserve(
        &mut self,
        owner: Address,
        auth: &Authorization,
        position: &mut Position,
        amount: u128,
    ) -> Result<()> {
        let mut from_unbacked = 0;
        if amount != 0 {
            let mut shortfall = self.shortfalls[owner][auth.token].read()?;
            if shortfall.unbacked != 0 && auth.burn_epoch < shortfall.epoch {
                from_unbacked = shortfall.unbacked.min(amount);
                shortfall.unbacked -= from_unbacked;
                self.shortfalls[owner][auth.token].write(shortfall)?;
            }
        }
        position.reserved = position.reserved.saturating_sub(amount - from_unbacked);
        Ok(())
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

/// Gives `amount` back to the limit of the access key that placed `auth`, within the period
/// it was counted in.
fn restore_limit(owner: Address, auth: &mut Authorization, amount: u128) -> Result<()> {
    // Never more than the key's limit counted, so spend the root key added is not given back.
    let amount = amount.min(auth.counted.to());
    if amount == 0 {
        return Ok(());
    }
    auth.counted = U96::from(auth.counted.to::<u128>() - amount);
    AccountKeychain::new().restore_limit(
        owner,
        auth.key_id,
        auth.token,
        U256::from(amount),
        auth.limit_period_end,
    )
}

/// Converts a non-zero ABI amount to its stored width.
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

/// Returns `owner`'s balance of `token` minus its reserved amount.
fn available(token: &TIP20Token, owner: Address, position: &Position) -> Result<u128> {
    // Checked debits keep the balance at or above the reserved amount.
    Ok(token.balances[owner]
        .read()?
        .saturating_sub(U256::from(position.reserved))
        .saturating_to())
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
            self.reservations
                .capture(self.owner, IReservations::captureCall { id, amount })
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
            f.refund(f.payee, id, 800)?;
            assert_eq!(remaining()?, U256::from(1_000));
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
    fn test_pre_t15_debits_ignore_reservations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut f = Fixture::new(1_000)?;
            // The precompile is not callable before T15; write its state directly.
            f.hold(B256::random(), 1_000)?;
            assert!(f.transfer(f.owner, Address::random(), 1_000)?);
            Ok(())
        })
    }

    #[test]
    fn test_zone_debits_ignore_reservations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15)
            .with_kind(tempo_primitives::TempoEvmKind::Zone);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut f = Fixture::new(1_000)?;
            f.hold(B256::random(), 1_000)?;
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
