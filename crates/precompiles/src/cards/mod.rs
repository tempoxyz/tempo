//! Card records precompile: cards an issuer's settlement account (the payee) issues on an owner's
//! account, which card-scoped holds (`IReservations.holdCard`, `holdCardWithLine`,
//! `holdCardStandIn`) check.
//!
//! A card is keyed by (payee, card id). Each issued card starts a line holding its owner, status,
//! limit, expiry, program type, holder reference and network token hash; replacing a card maps a
//! new credential to the same line, so open holds, limits and token hashes follow it. A line's
//! `committed` counter follows the committed amount of every authorization held through it.
//!
//! Each owner has an account record: every hold needs it Active, closure sweeps the owner's
//! available balance (debts first) to a payout address, and an Estate authority from the
//! registry the admin keeps can hand the account to an executor, who settles it once no holds
//! are open.
//!
//! An owner can also bound what an issuer's card holds commit in each calendar month (a spend
//! window) and, within it, what each merchant may commit or whether it may hold at all.

pub mod dispatch;

use crate::{
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    reservations::Reservations,
    storage::{Handler, Mapping},
    validator_config::ValidatorConfig,
    validator_config_v2::ValidatorConfigV2,
};
use alloy::primitives::{Address, B256, aliases::U96};
pub use tempo_contracts::precompiles::{CARDS_ADDRESS, CardsError, CardsEvent, ICards};
use tempo_precompiles_macros::{Storable, contract};

/// One card's state, shared by every credential that replaced it, in six slots.
///
/// The first two slots are written at issue; `committed` on the first card hold, `current` on
/// the first replacement, and `holder` and `token_hash` only when set.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Line {
    owner: Address,
    /// Unix time from which the line declines holds; zero never expires.
    expires_at: u64,
    /// An [`ICards::Status`].
    status: u8,
    /// An [`ICards::Program`].
    program: u8,
    payee: Address,
    /// Most the line may commit; [`U96::MAX`] is no limit.
    limit: U96,
    /// What the line's authorizations commit: open holds plus captures net of refunds.
    committed: U96,
    /// Credential of the latest replacement; zero while the issued card is current.
    current: B256,
    /// Reference the issuer maps to the cardholder, such as an employee record.
    holder: B256,
    /// Hash of the network token reference provisioned for the line; zero without one.
    token_hash: B256,
}

/// The tokens a payee's cards may hold, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct TokenList {
    /// Raised by every `setProgramTokens`; a token is listed when its entry equals it.
    epoch: u32,
    /// Whether only listed tokens may be held.
    restricted: bool,
}

/// An owner's account record, in one slot; an owner never recorded reads Active.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct AccountRecord {
    /// An [`ICards::AccountStatus`].
    status: u8,
    /// Unix time of the owner's last recorded activity; zero when never stamped.
    last_active: u64,
    /// The executor in Estate, the payout address once Closed.
    agent: Address,
}

/// An authority's entry in one role, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Authority {
    listed: bool,
    /// Seconds without activity before an Escheat authority may mark an account dormant.
    dormancy: u32,
    /// Seconds without activity before an Escheat authority may take a dormant account's money.
    escheat_after: u32,
    /// Where an Escheat authority's remittances go.
    payout: Address,
}

/// What sweeps of one owner's token paid into one facility, for whom, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Payout {
    to: Address,
    amount: U96,
}

/// An owner's calendar-month window on one issuer's card holds, in one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct Window {
    limit: U96,
    /// What card holds counted in the current period commit now.
    committed: U96,
    /// End of the current period; zero is no window.
    period_end: u32,
}

/// An owner's mandate for one merchant under one issuer, in one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct MerchantMandate {
    revoked: bool,
    limit: U96,
    committed: U96,
    /// The window period `committed` counts in; zero while the issuer has no window.
    period_end: u32,
}

const ACTIVE: u8 = ICards::AccountStatus::Active as u8;
const DORMANT: u8 = ICards::AccountStatus::Dormant as u8;
const ESTATE: u8 = ICards::AccountStatus::Estate as u8;
const CLOSED: u8 = ICards::AccountStatus::Closed as u8;

/// Card records precompile.
#[contract(addr = CARDS_ADDRESS)]
pub struct Cards {
    /// Line of each credential, keyed by payee then card id; zero for an unknown card.
    credentials: Mapping<Address, Mapping<B256, u64>>,
    /// Lines by id, from one.
    lines: Mapping<u64, Line>,
    /// Id of the latest line issued.
    last_line: u64,
    /// Credential that replaced a card, keyed by payee then card id.
    replaced_by: Mapping<Address, Mapping<B256, B256>>,
    /// Current card of a network token hash, keyed by payee then hash.
    tokens: Mapping<Address, Mapping<B256, B256>>,
    /// Epoch of each payee's token list in which a token was listed, keyed by payee then token.
    listed: Mapping<Address, Mapping<Address, u32>>,
    /// Each payee's token list.
    programs: Mapping<Address, TokenList>,
    /// Each owner's account record.
    accounts: Mapping<Address, AccountRecord>,
    /// Registry entries keyed by role ([`ICards::Role`]) then authority.
    authorities: Mapping<u8, Mapping<Address, Authority>>,
    /// Spend windows keyed by owner then issuer.
    windows: Mapping<Address, Mapping<Address, Window>>,
    /// Merchant mandate ids keyed by owner, issuer then merchant reference; zero for none.
    merchant_ids: Mapping<Address, Mapping<Address, Mapping<B256, u64>>>,
    /// Merchant mandates by id, from one.
    merchants: Mapping<u64, MerchantMandate>,
    /// Id of the latest merchant mandate.
    last_merchant: u64,
    /// Payouts keyed by owner, token then the facility a sweep paid into.
    payouts: Mapping<Address, Mapping<Address, Mapping<Address, Payout>>>,
}

impl Cards {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Checks that `owner`'s card `card` under `payee` (its issuer) may hold `token` now, and
    /// returns its line. Called by `IReservations.holdCard`, `holdCardWithLine` and
    /// `holdCardStandIn` before they place the hold; all but `holdCardStandIn` then check the limit
    /// with [`Self::ensure_within_limit`].
    pub(crate) fn line_for_hold(
        &self,
        owner: Address,
        payee: Address,
        card: B256,
        token: Address,
    ) -> Result<u64> {
        let line = self.credentials[payee][card].read()?;
        if line == 0 || self.lines[line].owner.read()? != owner {
            return Err(CardsError::unknown_card().into());
        }
        let current = self.lines[line].current.read()?;
        if !current.is_zero() && current != card {
            return Err(CardsError::card_inactive().into());
        }
        self.ensure_active(line)?;
        if !self.program_allows(payee, token)? {
            return Err(CardsError::token_not_allowed().into());
        }
        Ok(line)
    }

    /// Checks that `line` may commit `amount` more now: active, unexpired and within its limit,
    /// and within its owner's window and `merchant`'s mandate while the authorization's period
    /// (`window_end`) is current. Called by `IReservations.adjust` before it raises a card hold.
    pub(crate) fn ensure_may_grow(
        &self,
        line: u64,
        merchant: u64,
        window_end: u32,
        amount: u128,
    ) -> Result<()> {
        self.ensure_active(line)?;
        self.ensure_within_limit(line, amount)?;
        let owner = self.lines[line].owner.read()?;
        let issuer = self.lines[line].payee.read()?;
        let window = rolled(self.windows[owner][issuer].read()?, self.now());
        if window.period_end != 0
            && window_end == window.period_end
            && exceeds(window.committed, amount, window.limit)
        {
            return Err(CardsError::window_limit_exceeded().into());
        }
        if merchant != 0 {
            let mandate = merchant_rolled(self.merchants[merchant].read()?, window.period_end);
            if mandate.revoked {
                return Err(CardsError::merchant_revoked().into());
            }
            if window_end == mandate.period_end && exceeds(mandate.committed, amount, mandate.limit)
            {
                return Err(CardsError::window_limit_exceeded().into());
            }
        }
        Ok(())
    }

    /// Moves `line`'s committed counter by an authorization's change of committed amount, from
    /// `before` to `after`, and its owner's window and `merchant` counters while the period it
    /// counted in (`window_end`) is current. Called by the reservations precompile after every
    /// change to a card authorization, without checks: captures, releases and refunds never depend
    /// on the card.
    pub(crate) fn follow_commitment(
        &mut self,
        line: u64,
        merchant: u64,
        window_end: u32,
        before: u128,
        after: u128,
    ) -> Result<()> {
        if before == after {
            return Ok(());
        }
        let committed = self.lines[line].committed.read()?;
        self.lines[line]
            .committed
            .write(moved(committed, before, after)?)?;
        let owner = self.lines[line].owner.read()?;
        self.note_activity(owner)?;
        let issuer = self.lines[line].payee.read()?;
        let stored = self.windows[owner][issuer].read()?;
        let mut window = rolled(stored, self.now());
        if window.period_end != 0 && window_end == window.period_end {
            window.committed = moved(window.committed, before, after)?;
        }
        if window != stored {
            self.windows[owner][issuer].write(window)?;
        }
        if merchant != 0 {
            let stored = self.merchants[merchant].read()?;
            let mut mandate = merchant_rolled(stored, window.period_end);
            if window_end == mandate.period_end {
                mandate.committed = moved(mandate.committed, before, after)?;
            }
            if mandate != stored {
                self.merchants[merchant].write(mandate)?;
            }
        }
        Ok(())
    }

    /// Checks that a card hold of `amount` by `owner` through `issuer`'s card fits its spend window
    /// and, for a non-zero `merchant`, that merchant's mandate (`MerchantRevoked`,
    /// `WindowLimitExceeded`), rolling both into the current period. Returns the mandate's id and
    /// the window's period end for the authorization. `check` false records a stand-in approval
    /// without the limits.
    pub(crate) fn count_window(
        &mut self,
        owner: Address,
        issuer: Address,
        merchant: B256,
        amount: u128,
        check: bool,
    ) -> Result<(u64, u32)> {
        let stored = self.windows[owner][issuer].read()?;
        let window = rolled(stored, self.now());
        if window != stored {
            self.windows[owner][issuer].write(window)?;
        }
        if check && window.period_end != 0 && exceeds(window.committed, amount, window.limit) {
            return Err(CardsError::window_limit_exceeded().into());
        }
        let id = if merchant.is_zero() {
            0
        } else {
            self.merchant_ids[owner][issuer][merchant].read()?
        };
        if id != 0 {
            let stored = self.merchants[id].read()?;
            let mandate = merchant_rolled(stored, window.period_end);
            if mandate != stored {
                self.merchants[id].write(mandate)?;
            }
            if mandate.revoked {
                return Err(CardsError::merchant_revoked().into());
            }
            if check && exceeds(mandate.committed, amount, mandate.limit) {
                return Err(CardsError::window_limit_exceeded().into());
            }
        }
        Ok((id, window.period_end))
    }

    pub(crate) fn set_spend_window(
        &mut self,
        owner: Address,
        call: ICards::setSpendWindowCall,
    ) -> Result<()> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        // A new anchor keeps what the current period counted, so re-anchoring cannot clear it.
        let mut window = if call.firstEnd == 0 {
            Window::default()
        } else {
            rolled(self.windows[owner][call.issuer].read()?, self.now())
        };
        if call.firstEnd != 0 {
            window.limit = call.limit;
            window.period_end = call.firstEnd;
        }
        self.windows[owner][call.issuer].write(window)?;
        self.emit_event(CardsEvent::spend_window_set(
            owner,
            call.issuer,
            call.firstEnd,
            call.limit,
        ))
    }

    pub(crate) fn set_merchant_mandate(
        &mut self,
        owner: Address,
        call: ICards::setMerchantMandateCall,
    ) -> Result<()> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        if call.merchant.is_zero() {
            return Err(CardsError::invalid_card().into());
        }
        let mut id = self.merchant_ids[owner][call.issuer][call.merchant].read()?;
        if id == 0 {
            id = self
                .last_merchant
                .read()?
                .checked_add(1)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            self.last_merchant.write(id)?;
            self.merchant_ids[owner][call.issuer][call.merchant].write(id)?;
        }
        let mut mandate = self.merchants[id].read()?;
        mandate.revoked = call.revoked;
        mandate.limit = call.limit;
        self.merchants[id].write(mandate)?;
        self.emit_event(CardsEvent::merchant_mandate_set(
            owner,
            call.issuer,
            call.merchant,
            call.revoked,
            call.limit,
        ))
    }

    pub(crate) fn spend_window(
        &self,
        owner: Address,
        issuer: Address,
    ) -> Result<ICards::spendWindowReturn> {
        let window = rolled(self.windows[owner][issuer].read()?, self.now());
        Ok(ICards::spendWindowReturn {
            periodEnd: window.period_end,
            limit: window.limit,
            committed: window.committed,
        })
    }

    pub(crate) fn merchant_mandate(
        &self,
        owner: Address,
        issuer: Address,
        merchant: B256,
    ) -> Result<ICards::merchantMandateReturn> {
        let id = self.merchant_ids[owner][issuer][merchant].read()?;
        let window = rolled(self.windows[owner][issuer].read()?, self.now());
        let mandate = if id == 0 {
            MerchantMandate::default()
        } else {
            merchant_rolled(self.merchants[id].read()?, window.period_end)
        };
        Ok(ICards::merchantMandateReturn {
            revoked: mandate.revoked,
            limit: mandate.limit,
            committed: mandate.committed,
        })
    }

    pub(crate) fn issue_card(&mut self, payee: Address, call: ICards::issueCardCall) -> Result<()> {
        let status = status_byte(call.status)?;
        if call.owner.is_zero() || call.card.is_zero() || call.status == ICards::Status::Closed {
            return Err(CardsError::invalid_card().into());
        }
        let program = program_byte(call.program)?;
        if self.accounts[call.owner].status.read()? == CLOSED {
            return Err(CardsError::account_inactive().into());
        }
        if self.credentials[payee][call.card].read()? != 0 {
            return Err(CardsError::card_exists().into());
        }
        let line = self
            .last_line
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.last_line.write(line)?;
        self.credentials[payee][call.card].write(line)?;
        // Issuance starts the owner's activity clock; only stamped accounts can become dormant.
        let mut account = self.accounts[call.owner].read()?;
        account.last_active = self.now();
        self.accounts[call.owner].write(account)?;
        let record = &mut self.lines[line];
        record.owner.write(call.owner)?;
        record.expires_at.write(call.expiresAt)?;
        record.status.write(status)?;
        record.program.write(program)?;
        record.payee.write(payee)?;
        record.limit.write(call.limit)?;
        if !call.holder.is_zero() {
            record.holder.write(call.holder)?;
        }
        self.emit_event(CardsEvent::card_issued(payee, call.card, call.owner, line))
    }

    pub(crate) fn update_card(
        &mut self,
        payee: Address,
        call: ICards::updateCardCall,
    ) -> Result<()> {
        let line = self.current_line(payee, call.card)?;
        let status = status_byte(call.status)?;
        let program = program_byte(call.program)?;
        let record = &mut self.lines[line];
        record.status.write(status)?;
        record.limit.write(call.limit)?;
        record.expires_at.write(call.expiresAt)?;
        record.program.write(program)?;
        if record.holder.read()? != call.holder {
            record.holder.write(call.holder)?;
        }
        self.emit_event(CardsEvent::card_updated(
            payee,
            call.card,
            call.status,
            call.limit,
            call.expiresAt,
            call.program,
        ))
    }

    pub(crate) fn replace_card(
        &mut self,
        payee: Address,
        call: ICards::replaceCardCall,
    ) -> Result<()> {
        let line = self.current_line(payee, call.card)?;
        if call.next.is_zero() {
            return Err(CardsError::invalid_card().into());
        }
        if self.credentials[payee][call.next].read()? != 0 {
            return Err(CardsError::card_exists().into());
        }
        self.replaced_by[payee][call.card].write(call.next)?;
        self.credentials[payee][call.next].write(line)?;
        self.lines[line].current.write(call.next)?;
        self.lines[line]
            .status
            .write(ICards::Status::Active as u8)?;
        // The token keeps resolving to the line's current card.
        let token_hash = self.lines[line].token_hash.read()?;
        if !token_hash.is_zero() {
            self.tokens[payee][token_hash].write(call.next)?;
        }
        self.emit_event(CardsEvent::card_replaced(payee, call.card, call.next))
    }

    pub(crate) fn set_token_hash(
        &mut self,
        payee: Address,
        call: ICards::setTokenHashCall,
    ) -> Result<()> {
        let line = self.current_line(payee, call.card)?;
        let previous = self.lines[line].token_hash.read()?;
        if previous != call.tokenHash {
            if !call.tokenHash.is_zero() && !self.tokens[payee][call.tokenHash].read()?.is_zero() {
                return Err(CardsError::card_exists().into());
            }
            if !previous.is_zero() {
                self.tokens[payee][previous].delete()?;
            }
            if !call.tokenHash.is_zero() {
                self.tokens[payee][call.tokenHash].write(call.card)?;
            }
            self.lines[line].token_hash.write(call.tokenHash)?;
        }
        self.emit_event(CardsEvent::card_token_set(payee, call.card, call.tokenHash))
    }

    pub(crate) fn set_program_tokens(
        &mut self,
        payee: Address,
        call: ICards::setProgramTokensCall,
    ) -> Result<()> {
        let epoch = self.programs[payee]
            .epoch
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.programs[payee].write(TokenList {
            epoch,
            restricted: !call.tokens.is_empty(),
        })?;
        for token in &call.tokens {
            self.listed[payee][*token].write(epoch)?;
        }
        self.emit_event(CardsEvent::program_tokens_set(payee, call.tokens))
    }

    pub(crate) fn set_card_status(
        &mut self,
        owner: Address,
        call: ICards::setCardStatusCall,
    ) -> Result<()> {
        let line = self.owned_line(owner, call.payee, call.card)?;
        let current = self.lines[line].status.read()?;
        let open =
            current == ICards::Status::Frozen as u8 || current == ICards::Status::Active as u8;
        let allowed = match call.status {
            ICards::Status::Frozen | ICards::Status::Active => open,
            ICards::Status::Closed => true,
            _ => false,
        };
        if !allowed {
            return Err(CardsError::unauthorized().into());
        }
        self.lines[line].status.write(status_byte(call.status)?)?;
        self.emit_updated(call.payee, call.card, line)
    }

    pub(crate) fn lower_card_limit(
        &mut self,
        owner: Address,
        call: ICards::lowerCardLimitCall,
    ) -> Result<()> {
        let line = self.owned_line(owner, call.payee, call.card)?;
        if call.limit > self.lines[line].limit.read()? {
            return Err(CardsError::unauthorized().into());
        }
        self.lines[line].limit.write(call.limit)?;
        self.emit_updated(call.payee, call.card, line)
    }

    pub(crate) fn get_card(&self, payee: Address, card: B256) -> Result<ICards::Card> {
        let id = self.credentials[payee][card].read()?;
        // An unknown card reads as a zero line: no owner, no current credential.
        let line = if id == 0 {
            Line::default()
        } else {
            self.lines[id].read()?
        };
        let replaced_by = self.replaced_by[payee][card].read()?;
        let account = if id == 0 {
            ACTIVE
        } else {
            self.accounts[line.owner].status.read()?
        };
        Ok(ICards::Card {
            owner: line.owner,
            payee: line.payee,
            // A replaced credential and a closed account's card read closed, whatever the line's
            // status; an estate's active card reads frozen.
            status: if !replaced_by.is_zero() || account == CLOSED {
                ICards::Status::Closed
            } else if account == ESTATE && line.status == ICards::Status::Active as u8 {
                ICards::Status::Frozen
            } else {
                status_of(line.status)
            },
            program: program_of(line.program),
            expiresAt: line.expires_at,
            limit: line.limit,
            committed: line.committed,
            holder: line.holder,
            current: if line.current.is_zero() && id != 0 {
                card
            } else {
                line.current
            },
            replacedBy: replaced_by,
            tokenHash: line.token_hash,
            line: id,
        })
    }

    fn card_by_token(&self, payee: Address, token_hash: B256) -> Result<B256> {
        self.tokens[payee][token_hash].read()
    }

    fn program_allows(&self, payee: Address, token: Address) -> Result<bool> {
        let list = self.programs[payee].read()?;
        Ok(!list.restricted || self.listed[payee][token].read()? == list.epoch)
    }

    /// Returns the line of `payee`'s card `card`, which must be its line's current credential
    /// on a line that is not closed (`CardClosed`).
    fn current_line(&self, payee: Address, card: B256) -> Result<u64> {
        let line = self.credentials[payee][card].read()?;
        if line == 0 {
            return Err(CardsError::unknown_card().into());
        }
        let current = self.lines[line].current.read()?;
        if (!current.is_zero() && current != card)
            || self.lines[line].status.read()? == ICards::Status::Closed as u8
        {
            return Err(CardsError::card_closed().into());
        }
        Ok(line)
    }

    /// Returns the line of `payee`'s current card `card` for its owner acting with its root key.
    fn owned_line(&self, owner: Address, payee: Address, card: B256) -> Result<u64> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        let line = self.current_line(payee, card)?;
        if self.lines[line].owner.read()? != owner {
            return Err(CardsError::unauthorized().into());
        }
        Ok(line)
    }

    /// Checks that `line` is Active and unexpired, and that its owner's account is neither
    /// Closed nor in Estate, which its card reads as.
    fn ensure_active(&self, line: u64) -> Result<()> {
        let expires_at = self.lines[line].expires_at.read()?;
        if self.lines[line].status.read()? != ICards::Status::Active as u8
            || (expires_at != 0 && self.now() >= expires_at)
        {
            return Err(CardsError::card_inactive().into());
        }
        let account = self.accounts[self.lines[line].owner.read()?]
            .status
            .read()?;
        if account == CLOSED || account == ESTATE {
            return Err(CardsError::card_inactive().into());
        }
        Ok(())
    }

    /// Reverts `AccountInactive` unless `owner`'s account is Active. Called by every
    /// `IReservations` hold selector after its card checks.
    pub(crate) fn ensure_account_active(&self, owner: Address) -> Result<()> {
        if self.accounts[owner].status.read()? != ACTIVE {
            return Err(CardsError::account_inactive().into());
        }
        Ok(())
    }

    pub(crate) fn close_account(
        &mut self,
        owner: Address,
        call: ICards::closeAccountCall,
    ) -> Result<u128> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        let mut record = self.accounts[owner].read()?;
        if record.status == ESTATE || call.payoutTo.is_zero() {
            return Err(CardsError::account_state_invalid().into());
        }
        if record.status != CLOSED || record.agent != call.payoutTo {
            record.status = CLOSED;
            record.agent = call.payoutTo;
            self.accounts[owner].write(record)?;
            self.emit_event(CardsEvent::account_status_set(
                owner,
                ICards::AccountStatus::Closed,
                call.payoutTo,
            ))?;
        }
        self.pay_out(owner, call.token, call.payoutTo)
    }

    pub(crate) fn sweep(&mut self, owner: Address, token: Address) -> Result<u128> {
        let record = self.accounts[owner].read()?;
        if record.status != CLOSED {
            return Err(CardsError::account_state_invalid().into());
        }
        self.pay_out(owner, token, record.agent)
    }

    /// Records activity for `owner` when its clock was started: holds and card authorization
    /// changes call it, so an account in use never becomes dormant.
    pub(crate) fn note_activity(&mut self, owner: Address) -> Result<()> {
        let mut record = self.accounts[owner].read()?;
        let now = self.now();
        if record.last_active == 0 || record.last_active == now {
            return Ok(());
        }
        record.last_active = now;
        self.accounts[owner].write(record)
    }

    pub(crate) fn mark_dormant(&mut self, authority: Address, owner: Address) -> Result<()> {
        let entry = self.authorities[ICards::Role::Escheat as u8][authority].read()?;
        if !entry.listed {
            return Err(CardsError::unauthorized().into());
        }
        let mut record = self.accounts[owner].read()?;
        if record.status != ACTIVE
            || record.last_active == 0
            || self.now() < record.last_active.saturating_add(entry.dormancy.into())
        {
            return Err(CardsError::account_state_invalid().into());
        }
        record.status = DORMANT;
        self.accounts[owner].write(record)?;
        self.emit_event(CardsEvent::account_status_set(
            owner,
            ICards::AccountStatus::Dormant,
            record.agent,
        ))
    }

    pub(crate) fn reactivate(&mut self, owner: Address) -> Result<()> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        let mut record = self.accounts[owner].read()?;
        if record.status != DORMANT {
            return Err(CardsError::account_state_invalid().into());
        }
        record.status = ACTIVE;
        record.last_active = self.now();
        self.accounts[owner].write(record)?;
        self.emit_event(CardsEvent::account_status_set(
            owner,
            ICards::AccountStatus::Active,
            record.agent,
        ))
    }

    pub(crate) fn touch(&mut self, owner: Address) -> Result<()> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() {
            return Err(CardsError::unauthorized().into());
        }
        let mut record = self.accounts[owner].read()?;
        if record.status != ACTIVE {
            return Err(CardsError::account_state_invalid().into());
        }
        record.last_active = self.now();
        self.accounts[owner].write(record)
    }

    pub(crate) fn escheat(
        &mut self,
        authority: Address,
        call: ICards::escheatCall,
    ) -> Result<u128> {
        let entry = self.authorities[ICards::Role::Escheat as u8][authority].read()?;
        if !entry.listed || entry.payout.is_zero() {
            return Err(CardsError::unauthorized().into());
        }
        let record = self.accounts[call.owner].read()?;
        if record.status != DORMANT
            || self.now()
                < record
                    .last_active
                    .saturating_add(entry.escheat_after.into())
        {
            return Err(CardsError::account_state_invalid().into());
        }
        if call.via.is_zero() {
            return self.pay_out(call.owner, call.token, entry.payout);
        }
        // Paid into a facility that redeems it for the payout address, such as Earn shares into
        // a savings facility, which reads the record to pay the cash on. The record keeps one
        // recipient, so the facility never pays an earlier escheat's value to another authority.
        let mut payout = self.payouts[call.owner][call.token][call.via].read()?;
        if !payout.amount.is_zero() && payout.to != entry.payout {
            return Err(CardsError::unauthorized().into());
        }
        let paid = self.pay_out(call.owner, call.token, call.via)?;
        let amount = payout
            .amount
            .to::<u128>()
            .checked_add(paid)
            .and_then(|total| U96::try_from(total).ok())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        payout = Payout {
            to: entry.payout,
            amount,
        };
        self.payouts[call.owner][call.token][call.via].write(payout)?;
        self.emit_event(CardsEvent::payout_recorded(
            call.owner,
            call.token,
            call.via,
            entry.payout,
            amount.to::<u128>(),
        ))?;
        Ok(paid)
    }

    pub(crate) fn payout_of(
        &self,
        owner: Address,
        token: Address,
        via: Address,
    ) -> Result<ICards::payoutOfReturn> {
        let payout = self.payouts[owner][token][via].read()?;
        Ok(ICards::payoutOfReturn {
            to: payout.to,
            amount: payout.amount.to::<u128>(),
        })
    }

    pub(crate) fn set_estate(
        &mut self,
        authority: Address,
        call: ICards::setEstateCall,
    ) -> Result<()> {
        if !self.authorities[ICards::Role::Estate as u8][authority]
            .listed
            .read()?
        {
            return Err(CardsError::unauthorized().into());
        }
        let mut record = self.accounts[call.owner].read()?;
        if (record.status != ACTIVE && record.status != DORMANT)
            || call.owner.is_zero()
            || call.executor.is_zero()
        {
            return Err(CardsError::account_state_invalid().into());
        }
        record.status = ESTATE;
        record.agent = call.executor;
        self.accounts[call.owner].write(record)?;
        self.emit_event(CardsEvent::account_status_set(
            call.owner,
            ICards::AccountStatus::Estate,
            call.executor,
        ))
    }

    pub(crate) fn settle_estate(
        &mut self,
        sender: Address,
        call: ICards::settleEstateCall,
    ) -> Result<u128> {
        let mut record = self.accounts[call.owner].read()?;
        if record.status != ESTATE {
            return Err(CardsError::account_state_invalid().into());
        }
        if sender != record.agent {
            return Err(CardsError::unauthorized().into());
        }
        if call.to.is_zero() {
            return Err(CardsError::account_state_invalid().into());
        }
        if Reservations::new().holds_open(call.owner, call.token)? {
            return Err(CardsError::holds_open().into());
        }
        let paid = self.pay_out(call.owner, call.token, call.to)?;
        record.status = CLOSED;
        record.agent = call.to;
        self.accounts[call.owner].write(record)?;
        self.emit_event(CardsEvent::account_status_set(
            call.owner,
            ICards::AccountStatus::Closed,
            call.to,
        ))?;
        Ok(paid)
    }

    pub(crate) fn set_authority(
        &mut self,
        sender: Address,
        call: ICards::setAuthorityCall,
    ) -> Result<()> {
        if sender.is_zero() || sender != self.admin()? {
            return Err(CardsError::unauthorized().into());
        }
        let role = call.role as u8;
        if role > ICards::Role::Estate as u8 {
            return Err(CardsError::account_state_invalid().into());
        }
        self.authorities[role][call.authority].write(Authority {
            listed: call.listed,
            dormancy: call.dormancy,
            escheat_after: call.escheatAfter,
            payout: call.payout,
        })?;
        self.emit_event(CardsEvent::authority_set(
            call.authority,
            call.role,
            call.listed,
            call.payout,
            call.dormancy,
            call.escheatAfter,
        ))
    }

    pub(crate) fn get_account(&self, owner: Address) -> Result<ICards::Account> {
        let record = self.accounts[owner].read()?;
        Ok(ICards::Account {
            status: ICards::AccountStatus::try_from(record.status)
                .unwrap_or(ICards::AccountStatus::Closed),
            lastActive: record.last_active,
            agent: record.agent,
        })
    }

    pub(crate) fn authority_of(
        &self,
        authority: Address,
        role: ICards::Role,
    ) -> Result<ICards::authorityOfReturn> {
        let entry = self.authorities[role as u8][authority].read()?;
        Ok(ICards::authorityOfReturn {
            listed: entry.listed,
            payout: entry.payout,
            dormancy: entry.dormancy,
            escheatAfter: entry.escheat_after,
        })
    }

    /// Repays `owner`'s debt in `token` from its available balance, pays the rest to `to` and
    /// emits `AccountSwept`. Liens and open holds stay reserved.
    fn pay_out(&mut self, owner: Address, token: Address, to: Address) -> Result<u128> {
        let (repaid, paid) = Reservations::new().sweep_available(owner, token, to)?;
        self.emit_event(CardsEvent::account_swept(owner, token, to, repaid, paid))?;
        Ok(paid)
    }

    /// The registry's admin: the validator config owner, Tempo governance (the dev key on the
    /// dev chain).
    fn admin(&self) -> Result<Address> {
        let owner = ValidatorConfigV2::new().owner()?;
        if !owner.is_zero() {
            return Ok(owner);
        }
        ValidatorConfig::new().owner()
    }

    /// Checks that `line` may commit `amount` more within its limit (`CardLimitExceeded`).
    pub(crate) fn ensure_within_limit(&self, line: u64, amount: u128) -> Result<()> {
        let limit = self.lines[line].limit.read()?;
        if limit == U96::MAX {
            return Ok(());
        }
        let committed = self.lines[line].committed.read()?.to::<u128>();
        if committed.saturating_add(amount) > limit.to::<u128>() {
            return Err(CardsError::card_limit_exceeded().into());
        }
        Ok(())
    }

    fn emit_updated(&mut self, payee: Address, card: B256, line: u64) -> Result<()> {
        let record = self.lines[line].read()?;
        self.emit_event(CardsEvent::card_updated(
            payee,
            card,
            status_of(record.status),
            record.limit,
            record.expires_at,
            program_of(record.program),
        ))
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to()
    }
}

/// A counter moved by an authorization's change of committed amount from `before` to `after`;
/// give-backs never take it below zero.
fn moved(counter: U96, before: u128, after: u128) -> Result<U96> {
    let counter = counter.to::<u128>();
    let next = if after > before {
        counter
            .checked_add(after - before)
            .ok_or_else(TempoPrecompileError::under_overflow)?
    } else {
        counter.saturating_sub(before - after)
    };
    U96::try_from(next).map_err(|_| TempoPrecompileError::under_overflow())
}

/// Whether `committed` plus `amount` passes `limit`; [`U96::MAX`] is no limit.
fn exceeds(committed: U96, amount: u128, limit: U96) -> bool {
    limit != U96::MAX && committed.to::<u128>().saturating_add(amount) > limit.to::<u128>()
}

/// `window` as of `now`: each period that ended starts the next a calendar month later, at zero.
fn rolled(mut window: Window, now: u64) -> Window {
    if window.period_end == 0 {
        return window;
    }
    while now >= u64::from(window.period_end) {
        let next = add_month(window.period_end);
        if next <= window.period_end {
            break;
        }
        window.period_end = next;
        window.committed = U96::ZERO;
    }
    window
}

/// `mandate` counted in the window period ending at `period_end`: a new period starts it at zero.
fn merchant_rolled(mut mandate: MerchantMandate, period_end: u32) -> MerchantMandate {
    if mandate.period_end != period_end {
        mandate.period_end = period_end;
        mandate.committed = U96::ZERO;
    }
    mandate
}

/// The same UTC time of day one calendar month after `timestamp`, on the last day of the month
/// when that day is missing; saturates at [`u32::MAX`].
fn add_month(timestamp: u32) -> u32 {
    let days = i64::from(timestamp / 86_400);
    let seconds = i64::from(timestamp % 86_400);
    let (year, month, day) = civil_from_days(days);
    let (year, month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let day = day.min(days_in_month(year, month));
    let next = days_from_civil(year, month, day) * 86_400 + seconds;
    u32::try_from(next).unwrap_or(u32::MAX)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day), after Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days since 1970-01-01 of a proleptic Gregorian date, after Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Stores a status, rejecting values outside the enum with `InvalidCard`.
fn status_byte(status: ICards::Status) -> Result<u8> {
    let byte = status as u8;
    if byte > ICards::Status::Closed as u8 {
        return Err(CardsError::invalid_card().into());
    }
    Ok(byte)
}

/// Stores a program type, rejecting values outside the enum with `InvalidCard`.
fn program_byte(program: ICards::Program) -> Result<u8> {
    let byte = program as u8;
    if byte > ICards::Program::Virtual as u8 {
        return Err(CardsError::invalid_card().into());
    }
    Ok(byte)
}

/// Reads a stored status; only `status_byte` writes it.
fn status_of(byte: u8) -> ICards::Status {
    ICards::Status::try_from(byte).unwrap_or(ICards::Status::Closed)
}

/// Reads a stored program type; only `program_byte` writes it.
fn program_of(byte: u8) -> ICards::Program {
    ICards::Program::try_from(byte).unwrap_or(ICards::Program::Debit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::primitives::{IntoLogData, U256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ICards::ICardsCalls;

    const NOW: u64 = 1_000;

    /// A payee's card on an owner's account.
    struct Fixture {
        cards: Cards,
        owner: Address,
        payee: Address,
        card: B256,
    }

    impl Fixture {
        /// Issues an active card with no limit or expiry.
        fn new() -> Result<Self> {
            let mut cards = Cards::new();
            cards.initialize()?;
            let mut f = Self {
                cards,
                owner: Address::random(),
                payee: Address::random(),
                card: B256::random(),
            };
            f.issue(f.card, ICards::Status::Active, U96::MAX)?;
            Ok(f)
        }

        fn issue(&mut self, card: B256, status: ICards::Status, limit: U96) -> Result<()> {
            self.cards.issue_card(
                self.payee,
                ICards::issueCardCall {
                    owner: self.owner,
                    card,
                    status,
                    limit,
                    expiresAt: 0,
                    program: ICards::Program::Debit,
                    holder: B256::ZERO,
                },
            )
        }

        fn update(&mut self, card: B256, status: ICards::Status, limit: U96) -> Result<()> {
            self.cards.update_card(
                self.payee,
                ICards::updateCardCall {
                    card,
                    status,
                    limit,
                    expiresAt: 0,
                    program: ICards::Program::Corporate,
                    holder: B256::repeat_byte(0x11),
                },
            )
        }

        fn set_status(&mut self, caller: Address, status: ICards::Status) -> Result<()> {
            self.cards.set_card_status(
                caller,
                ICards::setCardStatusCall {
                    payee: self.payee,
                    card: self.card,
                    status,
                },
            )
        }

        fn card(&self, card: B256) -> Result<ICards::Card> {
            self.cards.get_card(self.payee, card)
        }
    }

    fn at_t15(f: impl FnOnce() -> eyre::Result<()>) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, f)
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        at_t15(|| {
            let mut cards = Cards::new();
            let unsupported = check_selector_coverage(
                &mut cards,
                ICardsCalls::SELECTORS,
                "ICards",
                ICardsCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_issue_card_keys_cards_by_payee() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let card = f.card(f.card)?;
            assert_eq!(card.owner, f.owner);
            assert_eq!(card.payee, f.payee);
            assert_eq!(card.status, ICards::Status::Active);
            assert_eq!(card.limit, U96::MAX);
            assert_eq!(card.current, f.card);
            assert_eq!(card.line, 1);
            assert_eq!(
                f.issue(f.card, ICards::Status::Active, U96::MAX)
                    .unwrap_err(),
                CardsError::card_exists().into()
            );
            // Another payee's card with the same id is another card.
            assert_eq!(
                f.cards.get_card(Address::random(), f.card)?.owner,
                Address::ZERO
            );
            let other = Address::random();
            assert_eq!(
                f.cards
                    .update_card(
                        other,
                        ICards::updateCardCall {
                            card: f.card,
                            status: ICards::Status::Frozen,
                            limit: U96::MAX,
                            expiresAt: 0,
                            program: ICards::Program::Debit,
                            holder: B256::ZERO,
                        },
                    )
                    .unwrap_err(),
                CardsError::unknown_card().into()
            );
            for (card, status) in [
                (B256::ZERO, ICards::Status::Active),
                (B256::random(), ICards::Status::Closed),
            ] {
                assert_eq!(
                    f.issue(card, status, U96::MAX).unwrap_err(),
                    CardsError::invalid_card().into()
                );
            }
            assert_eq!(
                f.cards.emitted_events().first(),
                Some(&CardsEvent::card_issued(f.payee, f.card, f.owner, 1).into_log_data())
            );
            Ok(())
        })
    }

    #[test]
    fn test_payee_updates_every_issuer_field() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            f.update(f.card, ICards::Status::Frozen, U96::from(80))?;
            let card = f.card(f.card)?;
            assert_eq!(card.status, ICards::Status::Frozen);
            assert_eq!(card.limit, U96::from(80));
            assert_eq!(card.program, ICards::Program::Corporate);
            assert_eq!(card.holder, B256::repeat_byte(0x11));
            Ok(())
        })
    }

    #[test]
    fn test_replacement_closes_the_old_credential() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let token_hash = B256::random();
            f.cards.set_token_hash(
                f.payee,
                ICards::setTokenHashCall {
                    card: f.card,
                    tokenHash: token_hash,
                },
            )?;
            f.update(f.card, ICards::Status::Frozen, U96::from(80))?;
            let next = B256::random();
            f.cards
                .replace_card(f.payee, ICards::replaceCardCall { card: f.card, next })?;

            let old = f.card(f.card)?;
            assert_eq!(old.status, ICards::Status::Closed);
            assert_eq!(old.replacedBy, next);
            assert_eq!(old.current, next);
            let new = f.card(next)?;
            assert_eq!(new.status, ICards::Status::Active);
            assert_eq!(new.limit, U96::from(80));
            assert_eq!(new.line, old.line);
            assert_eq!(new.tokenHash, token_hash);
            assert_eq!(f.cards.card_by_token(f.payee, token_hash)?, next);

            // The old id never changes again, and a new credential must be fresh.
            assert_eq!(
                f.update(f.card, ICards::Status::Active, U96::MAX)
                    .unwrap_err(),
                CardsError::card_closed().into()
            );
            assert_eq!(
                f.set_status(f.owner, ICards::Status::Active).unwrap_err(),
                CardsError::card_closed().into()
            );
            assert_eq!(
                f.cards
                    .replace_card(f.payee, ICards::replaceCardCall { card: next, next })
                    .unwrap_err(),
                CardsError::card_exists().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_token_hashes_map_to_one_card() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let other = B256::random();
            f.issue(other, ICards::Status::Active, U96::MAX)?;
            let first = B256::random();
            let set = |cards: &mut Cards, payee, card, token_hash| {
                cards.set_token_hash(
                    payee,
                    ICards::setTokenHashCall {
                        card,
                        tokenHash: token_hash,
                    },
                )
            };
            set(&mut f.cards, f.payee, f.card, first)?;
            assert_eq!(
                set(&mut f.cards, f.payee, other, first).unwrap_err(),
                CardsError::card_exists().into()
            );
            // A new hash replaces the old one, and zero removes it.
            let second = B256::random();
            set(&mut f.cards, f.payee, f.card, second)?;
            assert_eq!(f.cards.card_by_token(f.payee, first)?, B256::ZERO);
            assert_eq!(f.cards.card_by_token(f.payee, second)?, f.card);
            set(&mut f.cards, f.payee, f.card, B256::ZERO)?;
            assert_eq!(f.cards.card_by_token(f.payee, second)?, B256::ZERO);
            assert_eq!(f.card(f.card)?.tokenHash, B256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_owner_freezes_unfreezes_and_closes() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            assert_eq!(
                f.set_status(Address::random(), ICards::Status::Frozen)
                    .unwrap_err(),
                CardsError::unauthorized().into()
            );
            f.set_status(f.owner, ICards::Status::Frozen)?;
            assert_eq!(f.card(f.card)?.status, ICards::Status::Frozen);
            f.set_status(f.owner, ICards::Status::Active)?;
            assert_eq!(
                f.set_status(f.owner, ICards::Status::Inactive).unwrap_err(),
                CardsError::unauthorized().into()
            );

            // The owner cannot activate a card the payee has not activated yet.
            f.update(f.card, ICards::Status::Inactive, U96::MAX)?;
            assert_eq!(
                f.set_status(f.owner, ICards::Status::Active).unwrap_err(),
                CardsError::unauthorized().into()
            );

            // Closed is final for the owner and the payee alike.
            f.set_status(f.owner, ICards::Status::Closed)?;
            assert_eq!(
                f.update(f.card, ICards::Status::Active, U96::MAX)
                    .unwrap_err(),
                CardsError::card_closed().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_owner_acts_with_its_root_key_only() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(f.owner)?;
            keychain.set_transaction_key(Address::random())?;
            assert_eq!(
                f.set_status(f.owner, ICards::Status::Frozen).unwrap_err(),
                CardsError::unauthorized().into()
            );
            assert_eq!(
                f.cards
                    .lower_card_limit(
                        f.owner,
                        ICards::lowerCardLimitCall {
                            payee: f.payee,
                            card: f.card,
                            limit: U96::from(1),
                        },
                    )
                    .unwrap_err(),
                CardsError::unauthorized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_add_month_keeps_the_time_and_clamps_the_day() {
        // 2024-01-31 to the leap day, 2025-01-31 to 2025-02-28, and 2026-12-15 12:00 to 2027.
        assert_eq!(add_month(1_706_659_200), 1_709_164_800);
        assert_eq!(add_month(1_738_281_600), 1_740_700_800);
        assert_eq!(add_month(1_797_336_000), 1_800_014_400);
        assert_eq!(add_month(u32::MAX - 1), u32::MAX);
    }

    #[test]
    fn test_owner_only_lowers_the_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let lower = |cards: &mut Cards, limit: u64| {
                cards.lower_card_limit(
                    f.owner,
                    ICards::lowerCardLimitCall {
                        payee: f.payee,
                        card: f.card,
                        limit: U96::from(limit),
                    },
                )
            };
            lower(&mut f.cards, 100)?;
            assert_eq!(f.card(f.card)?.limit, U96::from(100));
            assert_eq!(
                lower(&mut f.cards, 101).unwrap_err(),
                CardsError::unauthorized().into()
            );
            lower(&mut f.cards, 40)?;
            assert_eq!(f.card(f.card)?.limit, U96::from(40));
            Ok(())
        })
    }

    #[test]
    fn test_program_tokens_replace_the_list() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new()?;
            let (cash, shares) = (Address::random(), Address::random());
            assert!(f.cards.program_allows(f.payee, shares)?);
            let list = |cards: &mut Cards, tokens: Vec<Address>| {
                cards.set_program_tokens(f.payee, ICards::setProgramTokensCall { tokens })
            };
            list(&mut f.cards, vec![cash])?;
            assert!(f.cards.program_allows(f.payee, cash)?);
            assert!(!f.cards.program_allows(f.payee, shares)?);
            // Other payees' programs are unaffected.
            assert!(f.cards.program_allows(Address::random(), shares)?);
            list(&mut f.cards, vec![shares])?;
            assert!(!f.cards.program_allows(f.payee, cash)?);
            assert!(f.cards.program_allows(f.payee, shares)?);
            list(&mut f.cards, vec![])?;
            assert!(f.cards.program_allows(f.payee, cash)?);
            Ok(())
        })
    }
}
