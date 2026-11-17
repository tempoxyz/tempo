//! Reservation core ([TIP-1153]): holds, captures, refunds, capped debt and liens on TIP-20
//! balances.
//!
//! A hold moves part of an owner's balance out of its TIP-20 balance slot and reserves it for a
//! payee until an expiry. Transfers, fees and the pool read only the balance slot, so they never
//! see reservations; `balanceOf` adds them back. A hold has one placer: the owner, or a holder
//! contract the owner approved for the token with an allowance bounding what that holder has
//! outstanding. The placer adjusts a hold, the placer or the payee captures or releases it, and
//! only the payee refunds. After its expiry a hold can only be released, by anyone.
//!
//! Captures may exceed the hold up to the owner's tolerance for that payee and token. The excess
//! comes from the available balance, then from debt within the owner's cap for that creditor; a
//! stand-in hold's shortfall may also reach the owner's offline cap. Debt is repaid first from the
//! owner's incoming credits of the token.
//!
//! Liens reserve balance for an authority: a role lien by a holder of the token's `LIEN_ROLE`, a
//! pledge by the owner, or a pledge a holder places on the owner's balance within the allowance the
//! owner approved for it. Pledges always expire. Only the authority releases, reduces or seizes a
//! lien, and seizure pays the authority. Anyone releases an expired lien: like a hold, it keeps its
//! funds reserved until someone does, since transfers never read the core.
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
use alloy::primitives::{Address, B256, U256, aliases::U96};
use keccak_const::Keccak256;
pub use tempo_contracts::precompiles::{
    IReservationCore, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoEvmKind;

/// Longest a hold may last, in seconds: 31 days.
pub const MAX_HOLD_DURATION: u64 = 31 * 24 * 60 * 60;

/// Longest a pledge a holder places may last, in seconds: 400 days, enough for a 90 to 120 day
/// reserve with room to spare.
pub const MAX_PLEDGE_DURATION: u64 = 400 * 24 * 60 * 60;

/// TIP-20 role whose holders may lien balances of that token, granted by the token's
/// administrator with `grantRole`. Computed as `keccak256("LIEN_ROLE")`.
pub const LIEN_ROLE: B256 = B256::new(Keccak256::new().update(b"LIEN_ROLE").finalize());

/// Basis points in one whole, for capture tolerances.
const BPS: u128 = 10_000;

/// Reserved and owed amounts of one owner in one token, in one slot.
///
/// TIP-20 reads it for `balanceOf` and, for owners the TIP-403 registry counts as debtors, after
/// credits.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Position {
    /// Funds held outside the owner's balance slot for its live holds and liens, less what
    /// compliance burns took (`Shortfall::unbacked`).
    reserved: u128,
    /// Debt owed to the creditor in `Reservations::creditors`.
    debt: U96,
    /// Whether `Shortfall::unbacked` may be non-zero, so hold changes skip that slot otherwise.
    short: bool,
}

/// Liens and burned reservations of one owner in one token, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Shortfall {
    /// Part of the live holds and liens that compliance burns took. Freed reservations repay it
    /// first.
    unbacked: u128,
    /// Sum of the owner's live liens in the token.
    liened: u128,
}

/// A holder's allowance from one owner in one token, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Allowance {
    /// Most the holder may have outstanding; zero means revoked.
    allowance: u128,
    /// Sum of what the holder's live holds and pledges still reserve.
    outstanding: u128,
}

/// First slot of a hold record. The record exists while `token` is non-zero.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct HoldHead {
    token: Address,
    /// Amount still reserved.
    held: u64,
    /// Expiry timestamp; a charge records its block time.
    expires_at: u32,
}

/// Second slot of a hold record.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct HoldTerms {
    payee: Address,
    /// Capture cap before tolerance.
    approved: u64,
    stand_in: bool,
    /// A final capture, a release or a charge ended the record; its id never reopens.
    settled: bool,
    /// Whether a holder placed it; its address is then in `Reservations::hold_placers`.
    delegated: bool,
}

/// Captured and refunded totals of a hold record, written on its first capture.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct HoldTotals {
    captured: u128,
    refunded: u128,
}

/// A lien on one owner's balance of one token, in two slots. It exists while `token` is
/// non-zero.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Lien {
    owner: Address,
    amount: U96,
    token: Address,
    /// Zero means no expiry; pledges always have one.
    expires_at: u64,
    pledged: bool,
    /// Whether the authority placed it as a holder, so it counts toward that holder's outstanding.
    delegated: bool,
}

/// A loaded hold record.
#[derive(Debug, Clone, Copy)]
struct Hold {
    head: HoldHead,
    terms: HoldTerms,
    placer: Address,
}

/// Reservation core precompile.
#[contract(addr = RESERVATIONS_ADDRESS)]
pub struct Reservations {
    /// Keyed by owner then token.
    positions: Mapping<Address, Mapping<Address, Position>>,
    /// Keyed by owner then token.
    shortfalls: Mapping<Address, Mapping<Address, Shortfall>>,
    /// Creditor of the outstanding debt, keyed by owner then token; zero without debt.
    creditors: Mapping<Address, Mapping<Address, Address>>,
    /// Keyed by owner, creditor, then token.
    debt_caps: Mapping<Address, Mapping<Address, Mapping<Address, u128>>>,
    /// Keyed by owner, payee, then token.
    offline_caps: Mapping<Address, Mapping<Address, Mapping<Address, u128>>>,
    /// Keyed by owner, payee, then token.
    capture_tolerances: Mapping<Address, Mapping<Address, Mapping<Address, u32>>>,
    /// Keyed by owner, holder, then token.
    allowances: Mapping<Address, Mapping<Address, Mapping<Address, Allowance>>>,
    /// Hold records keyed by owner then id, one mapping per slot.
    hold_heads: Mapping<Address, Mapping<B256, HoldHead>>,
    hold_terms: Mapping<Address, Mapping<B256, HoldTerms>>,
    hold_placers: Mapping<Address, Mapping<B256, Address>>,
    hold_totals: Mapping<Address, Mapping<B256, HoldTotals>>,
    /// Liens keyed by authority then id.
    liens: Mapping<Address, Mapping<B256, Lien>>,
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

    /// Returns the amount of `token` that `owner` has reserved for holds and liens.
    pub fn reserved_of(&self, owner: Address, token: Address) -> Result<u128> {
        self.positions[owner][token].reserved.read()
    }

    /// Sets `owner`'s reserved amount of `token` without a hold, moving the difference out of or
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
    /// it, and returns the amount taken. The holds and liens it backed settle against what remains.
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
        shortfall.unbacked = shortfall
            .unbacked
            .checked_add(taken)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.shortfalls[owner][token].write(shortfall)?;
        position.reserved -= taken;
        position.short = true;
        self.positions[owner][token].write(position)?;
        Ok(U256::from(taken))
    }

    /// Settles up to `received` of `owner`'s debt in `token` and emits `DebtRepaid`.
    ///
    /// Called by TIP-20 after crediting an owner counted as a debtor. `admits` tells from the
    /// creditor whether the repayment may move now. Returns the creditor and the amount TIP-20 must
    /// move from `owner` to it, or `None`, leaving the debt unchanged.
    pub(crate) fn take_repayment(
        &mut self,
        owner: Address,
        token: Address,
        received: U256,
        admits: impl FnOnce(Address) -> Result<bool>,
    ) -> Result<Option<(Address, U256)>> {
        let position = self.positions[owner][token].read()?;
        if position.debt.is_zero() {
            return Ok(None);
        }
        let creditor = self.creditors[owner][token].read()?;
        if !admits(creditor)? {
            return Ok(None);
        }
        let repaid = position.debt.to::<u128>().min(received.saturating_to());
        self.reduce_debt(owner, token, position, creditor, repaid)?;
        Ok(Some((creditor, U256::from(repaid))))
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
        self.allowances[owner][call.holder][call.token]
            .allowance
            .write(call.allowance)?;
        self.emit_event(ReservationsEvent::holder_approved(
            owner,
            call.holder,
            call.token,
            call.allowance,
        ))
    }

    fn set_debt_cap(
        &mut self,
        owner: Address,
        call: IReservationCore::setDebtCapCall,
    ) -> Result<()> {
        let creditor = resolve_counterparty_as_root(owner, call.creditor, call.token)?;
        self.debt_caps[owner][creditor][call.token].write(call.cap)
    }

    fn set_capture_tolerance(
        &mut self,
        owner: Address,
        call: IReservationCore::setCaptureToleranceCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        self.capture_tolerances[owner][payee][call.token].write(call.toleranceBps)
    }

    fn set_offline_cap(
        &mut self,
        owner: Address,
        call: IReservationCore::setOfflineCapCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        self.offline_caps[owner][payee][call.token].write(call.cap)
    }

    /// Places a hold on `owner`'s balance for `placer`: the owner itself, or a holder it approved.
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
        if !self.hold_heads[owner][request.id].token.read()?.is_zero() {
            return Err(ReservationsError::hold_exists().into());
        }
        let payee = resolve_payee(request.payee)?;
        let mut token = TIP20Token::from_address(request.token)?;
        ensure_payable(&token, owner, payee)?;
        let free = available(&token, owner)?;
        let held = if request.standIn {
            u64::try_from(free).unwrap_or(u64::MAX).min(amount)
        } else if u128::from(amount) > free {
            return Err(ReservationsError::insufficient_available().into());
        } else {
            amount
        };
        let delegated = placer != owner;
        if delegated {
            self.draw_allowance(owner, placer, request.token, amount.into(), held.into())?;
        } else {
            AccountKeychain::new().authorize_transfer(owner, request.token, U256::from(held))?;
        }
        self.reserve(&mut token, owner, held.into())?;
        self.hold_heads[owner][request.id].write(HoldHead {
            token: request.token,
            held,
            expires_at: request.expiresAt as u32,
        })?;
        self.hold_terms[owner][request.id].write(HoldTerms {
            payee,
            approved: amount,
            stand_in: request.standIn,
            settled: false,
            delegated,
        })?;
        if delegated {
            self.hold_placers[owner][request.id].write(placer)?;
        }
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            request.id,
            request.token,
            placer,
            payee,
            request.amount,
            held.into(),
            request.expiresAt,
            request.standIn,
        ))
    }

    fn adjust(&mut self, caller: Address, call: IReservationCore::adjustCall) -> Result<()> {
        let (owner, id) = (call.owner, call.id);
        let mut hold = self.live_hold(owner, id)?;
        if caller != hold.placer {
            return Err(ReservationsError::unauthorized().into());
        }
        let amount = amount_u64(call.amount)?;
        let held = hold.head.held;
        let token_address = hold.head.token;
        let mut token = TIP20Token::from_address(token_address)?;
        if amount > held {
            let increase = amount - held;
            let captured = self.hold_totals[owner][id].captured.read()?;
            let authorized = captured
                .checked_add(amount.into())
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            let raised = authorized > hold.terms.approved.into();
            // A stand-in's approval was fixed offline; raising another hold raises its approval.
            if raised && hold.terms.stand_in {
                return Err(ReservationsError::invalid_amount().into());
            }
            // Reserving more is a new authorization, so it checks the policy as a new hold does.
            ensure_payable(&token, owner, hold.terms.payee)?;
            if u128::from(increase) > available(&token, owner)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            if raised {
                hold.terms.approved =
                    u64::try_from(authorized).map_err(|_| ReservationsError::invalid_amount())?;
                self.hold_terms[owner][id].write(hold.terms)?;
            }
            if hold.terms.delegated {
                self.draw_allowance(
                    owner,
                    hold.placer,
                    token_address,
                    increase.into(),
                    increase.into(),
                )?;
            } else {
                AccountKeychain::new().authorize_transfer(
                    owner,
                    token_address,
                    U256::from(increase),
                )?;
            }
            self.reserve(&mut token, owner, increase.into())?;
        } else if amount < held {
            let decrease = held - amount;
            self.unreserve(&mut token, owner, decrease.into())?;
            if hold.terms.delegated {
                self.return_allowance(owner, hold.placer, token_address, decrease.into())?;
            }
        }
        hold.head.held = amount;
        self.hold_heads[owner][id].write(hold.head)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            id,
            token_address,
            amount.into(),
        ))
    }

    fn capture(&mut self, caller: Address, call: IReservationCore::captureCall) -> Result<()> {
        let (owner, id, amount, is_final) = (call.owner, call.id, call.amount, call.isFinal);
        let mut hold = self.live_hold(owner, id)?;
        let payee = hold.terms.payee;
        if caller != hold.placer && caller != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        if amount == 0 && !is_final {
            return Err(ReservationsError::invalid_amount().into());
        }
        let token_address = hold.head.token;
        let mut totals = self.hold_totals[owner][id].read()?;
        let captured = totals
            .captured
            .checked_add(amount)
            .ok_or_else(ReservationsError::tolerance_exceeded)?;
        let tolerance = self.capture_tolerances[owner][payee][token_address].read()?;
        let cap = u128::from(hold.terms.approved) * (BPS + u128::from(tolerance)) / BPS;
        if captured > cap {
            return Err(ReservationsError::tolerance_exceeded().into());
        }

        let held = u128::from(hold.head.held);
        let from_hold = amount.min(held);
        let excess = amount - from_hold;
        let rest = if is_final { held - from_hold } else { 0 };
        if excess != 0 {
            if hold.terms.delegated {
                // Beyond the hold, a holder's capture counts against its allowance like a charge.
                let allowance = self.allowances[owner][hold.placer][token_address].read()?;
                let outstanding = allowance.outstanding.saturating_sub(from_hold + rest);
                if outstanding.saturating_add(excess) > allowance.allowance {
                    return Err(ReservationsError::allowance_exceeded().into());
                }
            } else if caller == owner {
                AccountKeychain::new().authorize_transfer(
                    owner,
                    token_address,
                    U256::from(excess),
                )?;
            }
        }
        let mut token = TIP20Token::from_address(token_address)?;
        // Reserved funds were checked against the sender's policy when the hold was placed, so a
        // capture from the hold checks only the payee; an excess is a new payment and checks both.
        if excess == 0 {
            ensure_receivable(&token, owner, payee)?;
        } else {
            ensure_payable(&token, owner, payee)?;
        }
        self.unreserve(&mut token, owner, from_hold + rest)?;
        if hold.terms.delegated {
            self.return_allowance(owner, hold.placer, token_address, from_hold + rest)?;
        }
        let debt = self.pay(&mut token, owner, payee, amount, hold.terms.stand_in)?;

        hold.head.held -= (from_hold + rest) as u64;
        self.hold_heads[owner][id].write(hold.head)?;
        if is_final {
            hold.terms.settled = true;
            self.hold_terms[owner][id].write(hold.terms)?;
        }
        if amount != 0 {
            totals.captured = captured;
            self.hold_totals[owner][id].write(totals)?;
        }
        self.emit_event(ReservationsEvent::hold_captured(
            owner,
            id,
            token_address,
            payee,
            amount,
            debt,
            is_final,
        ))
    }

    fn release(&mut self, caller: Address, owner: Address, id: B256) -> Result<()> {
        let hold = self.unsettled_hold(owner, id)?;
        if caller != hold.placer && caller != hold.terms.payee {
            return Err(ReservationsError::unauthorized().into());
        }
        self.end_hold(owner, id, hold, false)
    }

    fn release_expired(&mut self, owner: Address, id: B256) -> Result<()> {
        let hold = self.unsettled_hold(owner, id)?;
        if self.now() < u64::from(hold.head.expires_at) {
            return Err(ReservationsError::hold_not_expired().into());
        }
        self.end_hold(owner, id, hold, true)
    }

    fn refund(&mut self, caller: Address, call: IReservationCore::refundCall) -> Result<()> {
        let (owner, id, amount) = (call.owner, call.id, call.amount);
        let token_address = self.hold_heads[owner][id].token.read()?;
        if token_address.is_zero() {
            return Err(ReservationsError::hold_not_found().into());
        }
        let payee = self.hold_terms[owner][id].payee.read()?;
        if caller != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        if amount == 0 {
            return Err(ReservationsError::invalid_amount().into());
        }
        let mut totals = self.hold_totals[owner][id].read()?;
        let refunded = totals
            .refunded
            .checked_add(amount)
            .filter(|refunded| *refunded <= totals.captured)
            .ok_or_else(ReservationsError::refund_exceeds_capture)?;
        let mut token = TIP20Token::from_address(token_address)?;
        ensure_payable(&token, payee, owner)?;
        totals.refunded = refunded;
        self.hold_totals[owner][id].write(totals)?;
        token.reservation_transfer(payee, owner, U256::from(amount))?;
        self.emit_event(ReservationsEvent::refunded(
            owner,
            id,
            token_address,
            payee,
            amount,
        ))
    }

    fn charge(&mut self, caller: Address, call: IReservationCore::chargeCall) -> Result<()> {
        let (owner, id, token_address) = (call.owner, call.id, call.token);
        let payee = resolve_payee(call.payee)?;
        let amount = amount_u64(call.amount)?;
        if !self.hold_heads[owner][id].token.read()?.is_zero() {
            return Err(ReservationsError::hold_exists().into());
        }
        let mut token = TIP20Token::from_address(token_address)?;
        ensure_payable(&token, owner, payee)?;
        let delegated = caller != owner;
        if delegated {
            self.draw_allowance(owner, caller, token_address, amount.into(), 0)?;
        } else {
            AccountKeychain::new().authorize_transfer(owner, token_address, U256::from(amount))?;
        }
        let debt = self.pay(&mut token, owner, payee, amount.into(), call.standIn)?;
        let now = u32::try_from(self.now()).unwrap_or(u32::MAX);
        self.hold_heads[owner][id].write(HoldHead {
            token: token_address,
            held: 0,
            expires_at: now,
        })?;
        self.hold_terms[owner][id].write(HoldTerms {
            payee,
            approved: amount,
            stand_in: call.standIn,
            settled: true,
            delegated,
        })?;
        if delegated {
            self.hold_placers[owner][id].write(caller)?;
        }
        self.hold_totals[owner][id].write(HoldTotals {
            captured: amount.into(),
            refunded: 0,
        })?;
        self.emit_event(ReservationsEvent::charged(
            owner,
            id,
            token_address,
            payee,
            amount.into(),
            debt,
        ))
    }

    fn lien(&mut self, authority: Address, call: IReservationCore::lienCall) -> Result<()> {
        root_only(authority)?;
        let token = TIP20Token::from_address(call.token)?;
        if !token.has_role_internal(authority, LIEN_ROLE)? {
            return Err(ReservationsError::unauthorized().into());
        }
        if call.expiresAt != 0 && call.expiresAt <= self.now() {
            return Err(ReservationsError::invalid_expiry().into());
        }
        // A lien on a virtual address applies to its master, whose balance holds the funds.
        let owner = resolve_payee(call.owner)?;
        self.place_lien(
            authority,
            owner,
            token,
            call.id,
            call.amount,
            call.expiresAt,
            false,
            false,
        )
    }

    fn pledge(&mut self, owner: Address, call: IReservationCore::pledgeCall) -> Result<()> {
        let authority = resolve_counterparty_as_root(owner, call.authority, call.token)?;
        if call.expiresAt <= self.now() {
            return Err(ReservationsError::invalid_expiry().into());
        }
        let token = TIP20Token::from_address(call.token)?;
        self.place_lien(
            authority,
            owner,
            token,
            call.id,
            call.amount,
            call.expiresAt,
            true,
            false,
        )
    }

    /// Places a pledge to `holder` on `owner`'s balance, within the allowance `owner` approved for
    /// it. A revoked holder places none, but its existing pledges still release and seize.
    fn pledge_from(
        &mut self,
        holder: Address,
        call: IReservationCore::pledgeFromCall,
    ) -> Result<()> {
        root_only(holder)?;
        let now = self.now();
        if call.expiresAt <= now || call.expiresAt > now.saturating_add(MAX_PLEDGE_DURATION) {
            return Err(ReservationsError::invalid_expiry().into());
        }
        let token = TIP20Token::from_address(call.token)?;
        let mut allowance = self.allowances[call.owner][holder][call.token].read()?;
        admit_draw(&allowance, call.amount)?;
        self.place_lien(
            holder,
            call.owner,
            token,
            call.id,
            call.amount,
            call.expiresAt,
            true,
            true,
        )?;
        allowance.outstanding += call.amount;
        self.allowances[call.owner][holder][call.token].write(allowance)
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of one lien")]
    fn place_lien(
        &mut self,
        authority: Address,
        owner: Address,
        mut token: TIP20Token,
        id: B256,
        amount: u128,
        expires_at: u64,
        pledged: bool,
        delegated: bool,
    ) -> Result<()> {
        let stored = amount_u96(amount)?;
        if !self.liens[authority][id].token.read()?.is_zero() {
            return Err(ReservationsError::lien_exists().into());
        }
        if amount > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        let token_address = token.address();
        self.reserve(&mut token, owner, amount)?;
        let mut shortfall = self.shortfalls[owner][token_address].read()?;
        shortfall.liened = shortfall
            .liened
            .checked_add(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.shortfalls[owner][token_address].write(shortfall)?;
        self.liens[authority][id].write(Lien {
            owner,
            amount: stored,
            token: token_address,
            expires_at,
            pledged,
            delegated,
        })?;
        self.emit_event(ReservationsEvent::liened(
            owner,
            authority,
            token_address,
            id,
            amount,
            expires_at,
            pledged,
        ))
    }

    fn release_lien(&mut self, authority: Address, id: B256) -> Result<()> {
        let lien = self.load_lien(authority, id)?;
        self.end_lien(authority, id, lien, false)
    }

    fn reduce_lien(
        &mut self,
        authority: Address,
        call: IReservationCore::reduceLienCall,
    ) -> Result<()> {
        let id = call.id;
        let lien = self.load_lien(authority, id)?;
        if call.amount == 0 {
            return Err(ReservationsError::invalid_amount().into());
        }
        let current = lien.amount.to::<u128>();
        let reduced = call.amount.min(current);
        self.free_lien(authority, &lien, reduced)?;
        let remaining = current - reduced;
        self.shrink_lien(authority, id, remaining)?;
        self.emit_event(ReservationsEvent::lien_reduced(
            lien.owner, authority, lien.token, id, remaining,
        ))
    }

    fn seize_lien(
        &mut self,
        authority: Address,
        call: IReservationCore::seizeLienCall,
    ) -> Result<()> {
        let id = call.id;
        root_only(authority)?;
        let lien = self.load_lien(authority, id)?;
        let current = lien.amount.to::<u128>();
        if call.amount == 0 || call.amount > current {
            return Err(ReservationsError::invalid_amount().into());
        }
        if lien.expires_at != 0 && self.now() >= lien.expires_at {
            return Err(ReservationsError::invalid_expiry().into());
        }
        let mut token = TIP20Token::from_address(lien.token)?;
        if !lien.pledged && !token.has_role_internal(authority, LIEN_ROLE)? {
            return Err(ReservationsError::unauthorized().into());
        }
        let backed = self.free_lien(authority, &lien, call.amount)?;
        let remaining = current - call.amount;
        self.shrink_lien(authority, id, remaining)?;
        // Seizure pays only the authority, from what the lien still backs.
        token.reservation_transfer(lien.owner, authority, U256::from(backed))?;
        self.emit_event(ReservationsEvent::lien_seized(
            lien.owner, authority, lien.token, id, backed, remaining,
        ))
    }

    fn release_expired_lien(&mut self, authority: Address, id: B256) -> Result<()> {
        let lien = self.load_lien(authority, id)?;
        if lien.expires_at == 0 || self.now() < lien.expires_at {
            return Err(ReservationsError::lien_not_expired().into());
        }
        self.end_lien(authority, id, lien, true)
    }

    pub fn get_hold(&self, owner: Address, id: B256) -> Result<IReservationCore::HoldRecord> {
        let head = self.hold_heads[owner][id].read()?;
        if head.token.is_zero() {
            return Ok(IReservationCore::HoldRecord {
                token: Address::ZERO,
                placer: Address::ZERO,
                payee: Address::ZERO,
                held: 0,
                approved: 0,
                captured: 0,
                refunded: 0,
                expiresAt: 0,
                standIn: false,
                settled: false,
            });
        }
        let terms = self.hold_terms[owner][id].read()?;
        let totals = self.hold_totals[owner][id].read()?;
        Ok(IReservationCore::HoldRecord {
            token: head.token,
            placer: if terms.delegated {
                self.hold_placers[owner][id].read()?
            } else {
                owner
            },
            payee: terms.payee,
            held: head.held.into(),
            approved: terms.approved.into(),
            captured: totals.captured,
            refunded: totals.refunded,
            expiresAt: head.expires_at.into(),
            standIn: terms.stand_in,
            settled: terms.settled,
        })
    }

    fn available_of(&self, owner: Address, token: Address) -> Result<u128> {
        available(&TIP20Token::from_address(token)?, owner)
    }

    pub fn allowance(
        &self,
        owner: Address,
        holder: Address,
        token: Address,
    ) -> Result<IReservationCore::allowanceReturn> {
        let allowance = self.allowances[owner][holder][token].read()?;
        Ok(IReservationCore::allowanceReturn {
            allowance: allowance.allowance,
            outstanding: allowance.outstanding,
        })
    }

    pub fn debt_of(
        &self,
        owner: Address,
        token: Address,
    ) -> Result<IReservationCore::debtOfReturn> {
        let debt = self.positions[owner][token].debt.read()?;
        Ok(IReservationCore::debtOfReturn {
            creditor: if debt.is_zero() {
                Address::ZERO
            } else {
                self.creditors[owner][token].read()?
            },
            amount: debt.to(),
        })
    }

    fn debt_cap(&self, owner: Address, creditor: Address, token: Address) -> Result<u128> {
        self.debt_caps[owner][Recipient::resolve(creditor)?.target][token].read()
    }

    fn capture_tolerance(&self, owner: Address, payee: Address, token: Address) -> Result<u32> {
        self.capture_tolerances[owner][Recipient::resolve(payee)?.target][token].read()
    }

    fn offline_cap(&self, owner: Address, payee: Address, token: Address) -> Result<u128> {
        self.offline_caps[owner][Recipient::resolve(payee)?.target][token].read()
    }

    pub fn lien_of(&self, authority: Address, id: B256) -> Result<IReservationCore::lienOfReturn> {
        let lien = self.liens[authority][id].read()?;
        Ok(IReservationCore::lienOfReturn {
            owner: lien.owner,
            token: lien.token,
            amount: lien.amount.to(),
            expiresAt: lien.expires_at,
            pledged: lien.pledged,
        })
    }

    fn liened_of(&self, owner: Address, token: Address) -> Result<u128> {
        self.shortfalls[owner][token].liened.read()
    }

    fn load_hold(&self, owner: Address, id: B256) -> Result<Hold> {
        let head = self.hold_heads[owner][id].read()?;
        if head.token.is_zero() {
            return Err(ReservationsError::hold_not_found().into());
        }
        let terms = self.hold_terms[owner][id].read()?;
        let placer = if terms.delegated {
            self.hold_placers[owner][id].read()?
        } else {
            owner
        };
        Ok(Hold {
            head,
            terms,
            placer,
        })
    }

    /// Loads a hold that has not settled.
    fn unsettled_hold(&self, owner: Address, id: B256) -> Result<Hold> {
        let hold = self.load_hold(owner, id)?;
        if hold.terms.settled {
            return Err(ReservationsError::hold_settled().into());
        }
        Ok(hold)
    }

    /// Loads a hold that has neither settled nor expired.
    fn live_hold(&self, owner: Address, id: B256) -> Result<Hold> {
        let hold = self.unsettled_hold(owner, id)?;
        if self.now() >= u64::from(hold.head.expires_at) {
            return Err(ReservationsError::hold_expired().into());
        }
        Ok(hold)
    }

    /// Releases what `hold` still reserves and settles it.
    fn end_hold(&mut self, owner: Address, id: B256, mut hold: Hold, expired: bool) -> Result<()> {
        let held = u128::from(hold.head.held);
        let token_address = hold.head.token;
        if held != 0 {
            let mut token = TIP20Token::from_address(token_address)?;
            self.unreserve(&mut token, owner, held)?;
            if hold.terms.delegated {
                self.return_allowance(owner, hold.placer, token_address, held)?;
            }
            hold.head.held = 0;
            self.hold_heads[owner][id].write(hold.head)?;
        }
        hold.terms.settled = true;
        self.hold_terms[owner][id].write(hold.terms)?;
        self.emit_event(ReservationsEvent::hold_released(
            owner,
            id,
            token_address,
            held,
            expired,
        ))
    }

    fn load_lien(&self, authority: Address, id: B256) -> Result<Lien> {
        let lien = self.liens[authority][id].read()?;
        if lien.token.is_zero() {
            return Err(ReservationsError::lien_not_found().into());
        }
        Ok(lien)
    }

    /// Frees `amount` of `authority`'s `lien` back to its owner's balance, returning it to the
    /// authority's allowance for a holder's pledge, and returns the part reserved funds still backed.
    fn free_lien(&mut self, authority: Address, lien: &Lien, amount: u128) -> Result<u128> {
        if lien.delegated {
            self.return_allowance(lien.owner, authority, lien.token, amount)?;
        }
        let mut token = TIP20Token::from_address(lien.token)?;
        let backed = self.unreserve(&mut token, lien.owner, amount)?;
        let mut shortfall = self.shortfalls[lien.owner][lien.token].read()?;
        shortfall.liened = shortfall
            .liened
            .checked_sub(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.shortfalls[lien.owner][lien.token].write(shortfall)?;
        Ok(backed)
    }

    /// Sets a lien's amount to `remaining`, deleting it at zero.
    fn shrink_lien(&mut self, authority: Address, id: B256, remaining: u128) -> Result<()> {
        if remaining == 0 {
            return self.liens[authority][id].delete();
        }
        self.liens[authority][id].amount.write(U96::from(remaining))
    }

    fn end_lien(&mut self, authority: Address, id: B256, lien: Lien, expired: bool) -> Result<()> {
        let amount = lien.amount.to::<u128>();
        self.free_lien(authority, &lien, amount)?;
        self.liens[authority][id].delete()?;
        self.emit_event(ReservationsEvent::lien_released(
            lien.owner, authority, lien.token, id, amount, expired,
        ))
    }

    /// Checks a holder's allowance for `check` and adds `add` to what it has outstanding.
    fn draw_allowance(
        &mut self,
        owner: Address,
        holder: Address,
        token: Address,
        check: u128,
        add: u128,
    ) -> Result<()> {
        let mut allowance = self.allowances[owner][holder][token].read()?;
        admit_draw(&allowance, check)?;
        if add != 0 {
            allowance.outstanding += add;
            self.allowances[owner][holder][token].write(allowance)?;
        }
        Ok(())
    }

    /// Lowers what a holder has outstanding by `amount` its holds and pledges no longer reserve.
    fn return_allowance(
        &mut self,
        owner: Address,
        holder: Address,
        token: Address,
        amount: u128,
    ) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let mut allowance = self.allowances[owner][holder][token].read()?;
        allowance.outstanding = allowance
            .outstanding
            .checked_sub(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.allowances[owner][holder][token].write(allowance)
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
            let mut shortfall = self.shortfalls[owner][token_address].read()?;
            let covered = shortfall.unbacked.min(amount);
            shortfall.unbacked -= covered;
            backed -= covered;
            position.short = shortfall.unbacked != 0;
            self.shortfalls[owner][token_address].write(shortfall)?;
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
    ) -> Result<u128> {
        let paid = amount.min(available(token, owner)?);
        let debt = amount - paid;
        if debt != 0 {
            self.add_debt(owner, token.address(), payee, debt, offline)?;
        }
        if paid != 0 {
            token.reservation_transfer(owner, payee, U256::from(paid))?;
        }
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
        let mut position = self.positions[owner][token].read()?;
        let owes = !position.debt.is_zero();
        if owes && self.creditors[owner][token].read()? != creditor {
            return Err(ReservationsError::debt_cap_exceeded().into());
        }
        let mut cap = self.debt_caps[owner][creditor][token].read()?;
        if offline {
            cap = cap.max(self.offline_caps[owner][creditor][token].read()?);
        }
        let debt = position.debt.to::<u128>().saturating_add(amount);
        if debt > cap {
            return Err(if cap == 0 {
                ReservationsError::insufficient_available().into()
            } else {
                ReservationsError::debt_cap_exceeded().into()
            });
        }
        position.debt = amount_u96(debt).map_err(|_| ReservationsError::debt_cap_exceeded())?;
        self.positions[owner][token].write(position)?;
        if !owes {
            self.creditors[owner][token].write(creditor)?;
            self.count_debt(owner, true)?;
        }
        Ok(())
    }

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
            .checked_sub(U96::from(amount))
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.positions[owner][token].write(position)?;
        if position.debt.is_zero() {
            self.creditors[owner][token].delete()?;
            self.count_debt(owner, false)?;
        }
        self.emit_event(ReservationsEvent::debt_repaid(
            owner, token, creditor, amount,
        ))
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to()
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

/// Resolves `account`, a counterparty the owner sets terms for, through the address registry as a
/// payee is, for an owner signing with its root key and a TIP-20 `token`.
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

/// Refuses payments `token` cannot move from `from` to `to` now: to nobody or oneself, while paused,
/// or against its TIP-403 policy.
fn ensure_payable(token: &TIP20Token, from: Address, to: Address) -> Result<()> {
    if to.is_zero() || to == from || token.paused()? || !token.is_transfer_authorized(from, to)? {
        return Err(ReservationsError::policy_forbids().into());
    }
    Ok(())
}

/// Refuses a payment of funds `from` reserved under its policy: to nobody or oneself, while
/// paused, or to a payee the token's TIP-403 policy does not let receive. A sender blocked after
/// the hold was placed does not stop it.
fn ensure_receivable(token: &TIP20Token, from: Address, to: Address) -> Result<()> {
    if to.is_zero() || to == from || token.paused()? || !token.is_recipient_authorized(to)? {
        return Err(ReservationsError::policy_forbids().into());
    }
    Ok(())
}

/// Refuses a holder drawing `check` more on `allowance`: revoked, or past its allowance.
fn admit_draw(allowance: &Allowance, check: u128) -> Result<()> {
    if allowance.allowance == 0 {
        return Err(ReservationsError::unauthorized().into());
    }
    if allowance.outstanding.saturating_add(check) > allowance.allowance {
        return Err(ReservationsError::allowance_exceeded().into());
    }
    Ok(())
}

/// Returns `owner`'s spendable balance of `token`: its balance slot, which excludes reservations.
fn available(token: &TIP20Token, owner: Address) -> Result<u128> {
    Ok(token.balances[owner].read()?.saturating_to())
}

/// Checks a hold or charge amount is non-zero and fits a record.
fn amount_u64(amount: u128) -> Result<u64> {
    match u64::try_from(amount) {
        Ok(amount) if amount != 0 => Ok(amount),
        _ => Err(ReservationsError::invalid_amount().into()),
    }
}

/// Checks a lien or debt amount is non-zero and fits 96 bits.
fn amount_u96(amount: u128) -> Result<U96> {
    if amount == 0 || amount >> 96 != 0 {
        return Err(ReservationsError::invalid_amount().into());
    }
    Ok(U96::from(amount))
}
