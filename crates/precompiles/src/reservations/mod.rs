//! Account reservations precompile: native holds on TIP-20 balances, capped debt and linked
//! refunds.
//!
//! Held funds never leave the owner's balance. From T15, every TIP-20 debit requires the amount to
//! fit in the balance minus the owner's reserved total, and every TIP-20 credit to an owner with
//! debt in that token pays the creditor first. A capture or charge releases the hold before paying,
//! so it spends the reservation it consumes.

pub mod dispatch;

use crate::{
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, Mapping},
    tip20::{Recipient, TIP20Token},
};
use alloy::primitives::{Address, B256, U256, aliases::U96};
pub use tempo_contracts::precompiles::{
    IReservations, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// Reserved and owed amounts of one owner in one token, packed in one slot.
///
/// TIP-20 reads this slot on every debit and credit from T15.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Sum of the owner's live holds in the token.
    reserved: u128,
    /// Debt owed to the creditor stored in `Reservations::creditors`.
    debt: u128,
}

/// One authorization of an owner, from its hold to its refunds, in three slots.
///
/// The record exists while `token` is non-zero and the hold is live while `expires_at` is
/// non-zero. A live hold has nothing captured yet, since capturing ends the hold.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Authorization {
    token: Address,
    /// Amount the live hold reserves.
    held: U96,
    /// Resolved payee, the only account allowed to refund.
    payee: Address,
    expires_at: u64,
    /// Total captured or charged under this id, including any part that became debt.
    captured: U96,
    /// Total refunded by the payee under this id.
    refunded: U96,
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

    /// Settles up to `received` of `owner`'s debt in `token` and emits `DebtRepaid`.
    ///
    /// Called by TIP-20 after crediting `owner` from T15. Returns the creditor and the amount
    /// TIP-20 must move from `owner` to it, or `None` when `owner` has no debt.
    pub(crate) fn take_repayment(
        &mut self,
        owner: Address,
        token: Address,
        received: U256,
    ) -> Result<Option<(Address, U256)>> {
        let position = self.positions[owner][token].read()?;
        if position.debt == 0 {
            return Ok(None);
        }
        let repaid = position.debt.min(received.saturating_to::<u128>());
        let creditor = self.creditors[owner][token].read()?;
        self.reduce_debt(owner, token, position, creditor, repaid)?;
        Ok(Some((creditor, U256::from(repaid))))
    }

    fn hold(&mut self, owner: Address, call: IReservations::holdCall) -> Result<()> {
        let held = amount_u96(call.amount)?;
        if call.expiresAt <= self.now() {
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
        self.positions[owner][call.token].write(position)?;
        self.authorizations[owner][call.id].write(Authorization {
            token: call.token,
            held,
            payee,
            expires_at: call.expiresAt,
            captured: U96::ZERO,
            refunded: U96::ZERO,
        })?;
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
        let auth = self.live_hold(owner, call.id)?;
        let held = amount_u96(call.amount)?;
        let previous = auth.held.to::<u128>();
        let mut position = self.positions[owner][auth.token].read()?;
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
        } else {
            position.reserved = position
                .reserved
                .checked_sub(previous - call.amount)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
        }
        self.positions[owner][auth.token].write(position)?;
        self.authorizations[owner][call.id].held.write(held)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            call.id,
            call.amount,
        ))
    }

    fn capture(&mut self, owner: Address, call: IReservations::captureCall) -> Result<()> {
        let mut auth = self.live_hold(owner, call.id)?;
        let captured = amount_u96(call.amount)?;
        let mut position = self.positions[owner][auth.token].read()?;
        // Releasing the hold first lets the payment spend the reservation it consumes.
        position.reserved = position
            .reserved
            .checked_sub(auth.held.to::<u128>())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let mut token = TIP20Token::from_address(auth.token)?;
        let debt = self.pay(&mut token, owner, auth.payee, call.amount, position)?;

        auth.held = U96::ZERO;
        auth.expires_at = 0;
        auth.captured = captured;
        self.authorizations[owner][call.id].write(auth)?;
        self.emit_event(ReservationsEvent::hold_captured(
            owner,
            call.id,
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

        let position = self.positions[owner][call.token].read()?;
        let debt = self.pay(&mut token, owner, payee, call.amount, position)?;

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
        let auth = self.authorizations[call.owner][call.id].read()?;
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

        self.authorizations[call.owner][call.id]
            .refunded
            .write(refunded)?;
        self.emit_event(ReservationsEvent::refunded(
            call.owner,
            call.id,
            call.amount,
        ))
    }

    fn set_debt_cap(&mut self, owner: Address, call: IReservations::setDebtCapCall) -> Result<()> {
        // Card access keys must never raise the debt they can create.
        if AccountKeychain::new().is_access_key_call(owner)? {
            return Err(ReservationsError::unauthorized().into());
        }
        if call.creditor.is_zero() || call.creditor == owner {
            return Err(ReservationsError::unauthorized().into());
        }
        TIP20Token::from_address(call.token)?;
        self.debt_caps[owner][call.creditor][call.token].write(call.cap)
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
        self.debt_caps[owner][creditor][token].read()
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
    /// debt towards `payee`, within the owner's cap. Writes `position` and returns the new debt.
    ///
    /// The full amount, debt included, counts against the access key signing the transaction.
    fn pay(
        &mut self,
        token: &mut TIP20Token,
        owner: Address,
        payee: Address,
        amount: u128,
        mut position: Position,
    ) -> Result<u128> {
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
        AccountKeychain::new().authorize_transfer(owner, token_address, U256::from(amount))?;
        if debt != 0 && new_creditor {
            self.creditors[owner][token_address].write(payee)?;
        }
        // TIP-20 reads the position during the transfer, so it must be written first.
        self.positions[owner][token_address].write(position)?;
        token.reservation_transfer(owner, payee, U256::from(paid))?;
        Ok(debt)
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

    fn end_hold(&mut self, owner: Address, id: B256, auth: Authorization) -> Result<()> {
        let mut position = self.positions[owner][auth.token].read()?;
        position.reserved = position
            .reserved
            .checked_sub(auth.held.to::<u128>())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.positions[owner][auth.token].write(position)?;
        self.authorizations[owner][id].delete()?;
        self.emit_event(ReservationsEvent::hold_released(owner, id))
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
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
        tip20::{ITIP20, TIP20Error, TIP20Event},
        tip403_registry::{ITIP403Registry, TIP403Registry},
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
            for (amount, expires_at) in [(0, EXPIRY), (1u128 << 96, EXPIRY), (1, NOW), (1, NOW - 1)]
            {
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
                .assert_emitted_events(vec![ReservationsEvent::hold_captured(f.owner, id, 550, 0)]);

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
                    f.owner, id, 600, 100,
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

            f.adjust(id, 800)?;
            assert_eq!(f.reserved()?, 800);
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
                .assert_emitted_events(vec![ReservationsEvent::hold_released(f.owner, id)]);
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
            let mut registry = TIP403Registry::new();
            registry.initialize()?;
            let policy = registry.create_policy_with_accounts(
                f.admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin: f.admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    accounts: vec![f.payee],
                },
            )?;
            f.token.change_transfer_policy_id(
                f.admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
            )?;

            assert_eq!(
                f.hold(B256::random(), 1).unwrap_err(),
                TIP20Error::policy_forbids().into()
            );
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
    fn test_access_key_limit_counts_captures_and_charges() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            f.set_debt_cap(f.payee, 1_000)?;
            let key = Address::random();
            let (owner, token) = (f.owner, f.token.address());
            let keychain = authorize_card_key(owner, key, token, 500)?;
            let remaining = || {
                keychain.get_remaining_limit(IAccountKeychain::getRemainingLimitCall {
                    account: owner,
                    keyId: key,
                    token,
                })
            };

            // Holds reserve without spending the limit.
            let id = B256::random();
            f.hold(id, 900)?;
            assert_eq!(remaining()?, U256::from(500));
            assert_eq!(
                f.capture(id, 501).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            f.capture(id, 400)?;
            assert_eq!(remaining()?, U256::from(100));

            // Debt counts too: the limit bounds what the key commits, not what the balance pays.
            assert_eq!(
                f.charge(B256::random(), 101, f.payee).unwrap_err(),
                AccountKeychainError::spending_limit_exceeded().into()
            );
            f.charge(B256::random(), 100, f.payee)?;
            assert_eq!(remaining()?, U256::ZERO);
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
                    period: 86_400,
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
