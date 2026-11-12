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
//!
//! Credit lines let a lender pay for an owner's holds: the lender reserves its own balance for
//! every limit it lends and has not lent yet, a hold may put part of its amount on a line, and a
//! capture draws that part from the lender's reservation once the owner's available balance is
//! spent. Refunds of such a capture repay the line before landing as balance.
//!
//! A record's payee can open a dispute on it, give provisional credit within the refund room and
//! resolve it: a cardholder win refunds the rest and closes the record to refunds, and a merchant
//! win takes the provisional credit back, as debt past the cap where the balance falls short.
//! Holds naming an open dispute reserve the merchant side for the dispute's window.
//!
//! A holder of a token's `LIEN_ROLE` can lien an owner's available balance of that token: a
//! reservation with no expiry that only it releases, which captures, line draws and debt
//! repayments never take.

pub mod dispatch;

use crate::{
    account_keychain::{AccountKeychain, LimitSpend},
    cards::Cards,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, Handler, Mapping},
    tip20::{Recipient, TIP20Token},
    tip403_registry::TIP403Registry,
};
use alloy::primitives::{Address, B256, U256, aliases::U96};
use keccak_const::Keccak256;
pub use tempo_contracts::precompiles::{
    IReservations, RESERVATIONS_ADDRESS, ReservationsError, ReservationsEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// Longest a hold may last, in seconds: 31 days.
///
/// Card authorizations expire within 30 days under network rules, so a longer hold has no use
/// and would only lock funds; the bound also caps how long a hold outlives a policy change.
pub const MAX_HOLD_DURATION: u64 = 31 * 24 * 60 * 60;

/// Longest a hold naming an open dispute may last, in seconds: 120 days.
///
/// Card networks give a cardholder 120 days to dispute, and the merchant side's reserve must last
/// until the dispute resolves; only a hold tied to an open dispute of its payee may last this long.
pub const MAX_DISPUTE_HOLD_DURATION: u64 = 120 * 24 * 60 * 60;

/// TIP-20 role whose holders may lien balances of that token, granted by the token's
/// administrator with `grantRole`. Computed as `keccak256("LIEN_ROLE")`.
pub const LIEN_ROLE: B256 = B256::new(Keccak256::new().update(b"LIEN_ROLE").finalize());

/// Basis points in one whole, for capture tolerances.
const BPS: u64 = 10_000;

/// Dispute states: opened, then provisional credit, representment, pre-arbitration and
/// arbitration in that order while open, and won or lost once resolved. Zero means no dispute.
const DISPUTE_OPENED: u8 = 1;
const DISPUTE_ARBITRATION: u8 = 5;
const DISPUTE_WON: u8 = 6;
const DISPUTE_LOST: u8 = 7;

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

/// Part of an owner's holds in one token that compliance burns took, and its liens, in one slot.
///
/// Only hold and lien changes read it, keeping TIP-20 debits and credits at one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Shortfall {
    /// Amount of the holds and liens live at the last burn that `reserved` no longer backs.
    unbacked: u128,
    /// Count of burns that lowered `reserved`; holds and liens placed before the latest share
    /// `unbacked`.
    epoch: u32,
    /// Sum of the amounts of the owner's liens in the token. `Position::reserved` includes them,
    /// less any part a burn took.
    liened: U96,
}

/// A lien an authority placed on an owner's balance of one token, in two slots.
///
/// The lien exists while `token` is non-zero.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Lien {
    owner: Address,
    amount: U96,
    token: Address,
    /// `Shortfall::epoch` when the lien was placed; an earlier epoch means a burn took part of it.
    burn_epoch: u32,
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
    /// End of the owner's spend window period (TIP-1169) a card hold counted in; its window and
    /// merchant counters follow it only while that period is current. Zero when none counted it.
    window_end: u32,
    /// Amount `key_id`'s limit counted in that period and not yet given back. Spend the root key
    /// adds is never counted, so it is never given back.
    counted: U96,
    /// Whether `holdStandIn` or `holdCardStandIn` placed the hold, so its captures may owe up to
    /// the offline cap.
    stand_in: bool,
    /// Card line (TIP-1169) of a hold `holdCard`, `holdCardWithLine` or `holdCardStandIn` placed, whose committed
    /// amount this authorization's follows; zero for other authorizations. Packed beside `counted`,
    /// which a card mandate key with a spending limit writes on every hold anyway.
    card_line: u64,
    /// Whether `holdWithLine` or `holdCardWithLine` placed the hold, so part of it is on a credit
    /// line recorded in `Reservations::credit_holds`.
    line: bool,
    /// Whether a dispute was opened on this record, so refunds read `Reservations::disputes`.
    disputed: bool,
    /// Whether `holdForDispute` placed the hold, naming the dispute in `Reservations::dispute_holds`.
    dispute_reserve: bool,
    /// Merchant mandate (TIP-1169) a `holdCardForMerchant` hold counts against; zero for none.
    merchant: u64,
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

/// The dispute on one authorization, in two slots.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Dispute {
    /// Zero without a dispute, `DISPUTE_OPENED` to `DISPUTE_ARBITRATION` while open, then won or lost.
    state: u8,
    /// Disputed amount, at most what the record had captured and not refunded when opened.
    amount: U96,
    /// Provisional credit the payee gave that no refund has settled since.
    provisional: U96,
    /// Part of `provisional` that repaid the record's credit line instead of landing as balance.
    line_share: U96,
}

impl Dispute {
    fn is_open(&self) -> bool {
        (DISPUTE_OPENED..=DISPUTE_ARBITRATION).contains(&self.state)
    }
}

/// The dispute a reserve hold names, in two slots.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct DisputeHold {
    owner: Address,
    id: B256,
}

/// A lender's credit line in one token, in two slots.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Line {
    /// Token lent; zero while the line is not open.
    token: Address,
    /// Lender's balance reserved for the line, held in its `Position::reserved`.
    lien: U96,
    /// `Shortfall::epoch` when the lien last grew from zero; an earlier epoch means a burn took
    /// part of it.
    burn_epoch: u32,
}

/// One owner's credit on a lender's line, in two slots.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct Credit {
    /// Payee the lender pays when a hold draws the line.
    payee: Address,
    /// Most the owner may owe and hold on the line together.
    limit: U96,
    /// Drawn and not yet repaid.
    owed: U96,
    /// Line parts of the owner's live holds.
    held: U96,
}

impl Credit {
    /// What the lender keeps reserved for this credit: the undrawn limit, and never less than the
    /// open holds' line parts, so lowering a limit never strands an approved hold.
    fn lien(&self) -> u128 {
        (self.limit.saturating_sub(self.owed))
            .max(self.held)
            .to::<u128>()
    }

    /// What new holds may still put on the line.
    fn headroom(&self) -> u128 {
        self.limit
            .to::<u128>()
            .saturating_sub(self.owed.to::<u128>() + self.held.to::<u128>())
    }
}

/// A lender's standing offer of credit to one owner, in one slot.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct CreditOffer {
    /// Payee the lender agrees to pay.
    payee: Address,
    /// Most the owner may accept; zero without an offer.
    limit: U96,
}

/// The credit line part of one authorization, in three slots.
#[derive(Debug, Clone, Copy, Default, Storable)]
struct CreditHold {
    lender: Address,
    /// Part of the live hold on the line, included in `Authorization::held`.
    held: U96,
    line: B256,
    /// Drawn from the line by captures of this id and not yet repaid by its refunds.
    drawn: U96,
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
    /// Debt an owner accepts from stand-in holds and charges, keyed by owner, payee, then token.
    offline_caps: Mapping<Address, Mapping<Address, Mapping<Address, u128>>>,
    /// Credit lines keyed by lender then line id.
    lines: Mapping<Address, Mapping<B256, Line>>,
    /// Credit keyed by owner, lender, then line id.
    credits: Mapping<Address, Mapping<Address, Mapping<B256, Credit>>>,
    /// Credit offers keyed by lender, line id, then owner.
    credit_offers: Mapping<Address, Mapping<B256, Mapping<Address, CreditOffer>>>,
    /// Line parts of authorizations, keyed by owner then hold id; read only for holds placed with
    /// `holdWithLine`.
    credit_holds: Mapping<Address, Mapping<B256, CreditHold>>,
    /// Disputes keyed by the disputed record's owner then hold id.
    #[slot(20)]
    disputes: Mapping<Address, Mapping<B256, Dispute>>,
    /// The dispute each reserve hold names, keyed by the hold's owner then hold id.
    #[slot(21)]
    dispute_holds: Mapping<Address, Mapping<B256, DisputeHold>>,
    /// Liens keyed by the authority that placed them then lien id.
    #[slot(22)]
    liens: Mapping<Address, Mapping<B256, Lien>>,
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

    /// Repays `owner`'s debt in `token` from its available balance, then pays the rest of that
    /// balance to `to`, and returns what it repaid and paid. A repayment the token's policy
    /// refuses pays nothing, so debts stay first. Liens and holds stay reserved.
    ///
    /// Called by `ICards` sweeps of closed accounts and estates.
    pub(crate) fn sweep_available(
        &mut self,
        owner: Address,
        token: Address,
        to: Address,
    ) -> Result<(u128, u128)> {
        let mut tip20 = TIP20Token::from_address(token)?;
        let free = available(&tip20, owner)?;
        if free == 0 {
            return Ok((0, 0));
        }
        let position = self.positions[owner][token].read()?;
        let mut repaid = 0;
        if position.debt != 0 {
            let creditor = self.creditors[owner][token].read()?;
            if !tip20.is_transfer_authorized(owner, creditor)? {
                return Ok((0, 0));
            }
            repaid = position.debt.min(free);
            self.reduce_debt(owner, token, position, creditor, repaid)?;
            tip20.reservation_transfer(owner, creditor, U256::from(repaid))?;
        }
        let rest = free - repaid;
        if rest != 0 {
            tip20.ensure_transfer_authorized(owner, to)?;
            tip20.reservation_transfer(owner, to, U256::from(rest))?;
        }
        Ok((repaid, rest))
    }

    /// Whether `owner` has holds open that reserve its balance of `token`: reserved beyond its
    /// liens. Called by `ICards` before an estate settles.
    pub(crate) fn holds_open(&self, owner: Address, token: Address) -> Result<bool> {
        let reserved = self.positions[owner][token].reserved.read()?;
        let liened = self.shortfalls[owner][token].liened.read()?.to::<u128>();
        Ok(reserved > liened)
    }

    /// Places `hold`, `holdStandIn`, which reserves only what is available, `holdCard`, which
    /// first checks the card, `holdWithLine`, which puts part of the hold on a credit line,
    /// `holdCardWithLine`, which does both, `holdCardStandIn`, which checks the card but not
    /// its limit and then reserves as `holdStandIn`, or `holdForDispute`, which
    /// reserves for an open dispute.
    fn hold(
        &mut self,
        owner: Address,
        call: IReservations::holdCall,
        placement: Placement,
    ) -> Result<()> {
        amount_u96(call.amount)?;
        let now = self.now();
        let longest = match placement {
            Placement::Dispute { .. } => MAX_DISPUTE_HOLD_DURATION,
            _ => MAX_HOLD_DURATION,
        };
        if call.expiresAt <= now || call.expiresAt > now.saturating_add(longest) {
            return Err(ReservationsError::invalid_amount().into());
        }
        let mut token = TIP20Token::from_address(call.token)?;
        let payee = resolve_payee(call.payee)?;
        token.ensure_transfer_authorized(owner, payee)?;
        if self.authorizations[owner][call.id].token.read()? != Address::ZERO {
            return Err(ReservationsError::hold_exists().into());
        }
        // A reserve names an open dispute of its own payee and holds at most the disputed amount.
        if let Placement::Dispute {
            owner: disputed,
            id: disputed_id,
        } = placement
        {
            let dispute = self.disputes[disputed][disputed_id].read()?;
            if !dispute.is_open() {
                return Err(ReservationsError::dispute_not_found().into());
            }
            if self.authorizations[disputed][disputed_id].payee.read()? != payee {
                return Err(ReservationsError::unauthorized().into());
            }
            if call.amount > dispute.amount.to::<u128>() {
                return Err(ReservationsError::invalid_amount().into());
            }
        }
        let card = match placement {
            // The card counts the whole amount, line part included, against its limit.
            Placement::Card { issuer, card }
            | Placement::CardLine { issuer, card, .. }
            | Placement::CardMerchant { issuer, card, .. } => {
                let cards = Cards::new();
                let line = cards.line_for_hold(owner, issuer, card, call.token)?;
                cards.ensure_within_limit(line, call.amount)?;
                Some((card, line))
            }
            // The issuer approved offline within the offline limit, which bounds stand-in approvals
            // instead of the card's limit; the card's status still refuses one it froze or closed.
            Placement::CardStandIn { issuer, card } => Some((
                card,
                Cards::new().line_for_hold(owner, issuer, card, call.token)?,
            )),
            Placement::Plain
            | Placement::StandIn
            | Placement::Line { .. }
            | Placement::Dispute { .. } => None,
        };
        // Card holds count against the owner's spend window for the issuer, and a merchant's hold
        // against its merchant mandate too; a stand-in approval counts without the check.
        let (merchant, window_end) = match placement {
            Placement::Card { issuer, .. } | Placement::CardLine { issuer, .. } => {
                Cards::new().count_window(owner, issuer, B256::ZERO, call.amount, true)?
            }
            Placement::CardMerchant {
                issuer, merchant, ..
            } => Cards::new().count_window(owner, issuer, merchant, call.amount, true)?,
            Placement::CardStandIn { issuer, .. } => {
                Cards::new().count_window(owner, issuer, B256::ZERO, 0, false)?
            }
            _ => (0, 0),
        };
        // A dormant, closed or estate account takes no new holds; a card's checks above already
        // refuse one through a closed or estate account's card as inactive.
        Cards::new().ensure_account_active(owner)?;
        Cards::new().note_activity(owner)?;

        let mut position = self.positions[owner][call.token].read()?;
        let free = available(&token, owner)?;
        // `held` is what the hold commits, `reserved` the part of it taken from the owner's balance.
        let (held, reserved) = match placement {
            // A stand-in approval already happened offline, so the chain records it whatever is left.
            Placement::StandIn | Placement::CardStandIn { .. } => {
                (call.amount.min(free), call.amount.min(free))
            }
            Placement::Plain
            | Placement::Card { .. }
            | Placement::CardMerchant { .. }
            | Placement::Dispute { .. }
                if call.amount > free =>
            {
                return Err(ReservationsError::insufficient_available().into());
            }
            Placement::Plain
            | Placement::Card { .. }
            | Placement::CardMerchant { .. }
            | Placement::Dispute { .. } => (call.amount, call.amount),
            Placement::Line { part, line, lender }
            | Placement::CardLine {
                part, line, lender, ..
            } => {
                if part == 0 || part > call.amount {
                    return Err(ReservationsError::invalid_amount().into());
                }
                if call.amount - part > free {
                    return Err(ReservationsError::insufficient_available().into());
                }
                self.hold_line_part(owner, call.token, payee, lender, line, part)?;
                (call.amount, call.amount - part)
            }
        };
        position.reserved = position
            .reserved
            .checked_add(reserved)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let spend = AccountKeychain::new().spend_limit(owner, call.token, U256::from(held))?;
        token.decrement_balance(owner, U256::from(reserved))?;
        self.positions[owner][call.token].write(position)?;
        let mut auth = Authorization {
            token: call.token,
            // Fits: `held` is at most `call.amount`, checked above.
            held: U96::from(held),
            payee,
            expires_at: call.expiresAt,
            burn_epoch: self.shortfalls[owner][call.token].epoch.read()?,
            key_id: spend.map_or(Address::ZERO, |spend| spend.key_id),
            stand_in: matches!(
                placement,
                Placement::StandIn | Placement::CardStandIn { .. }
            ),
            card_line: card.map_or(0, |(_, line)| line),
            line: matches!(
                placement,
                Placement::Line { .. } | Placement::CardLine { .. }
            ),
            dispute_reserve: matches!(placement, Placement::Dispute { .. }),
            window_end,
            merchant,
            ..Default::default()
        };
        record_spend(&mut auth, spend, held);
        self.authorizations[owner][call.id].write(auth)?;
        follow_card(&auth, 0)?;
        self.emit_event(ReservationsEvent::hold_placed(
            owner,
            call.id,
            call.token,
            payee,
            held,
            call.expiresAt,
        ))?;
        if let Some((card, line)) = card {
            self.emit_event(ReservationsEvent::card_hold_placed(
                owner, call.id, card, line,
            ))?;
        }
        match placement {
            Placement::Plain | Placement::Card { .. } | Placement::CardMerchant { .. } => Ok(()),
            Placement::Dispute {
                owner: disputed,
                id: disputed_id,
            } => {
                self.dispute_holds[owner][call.id].write(DisputeHold {
                    owner: disputed,
                    id: disputed_id,
                })?;
                self.emit_event(ReservationsEvent::dispute_hold_placed(
                    owner,
                    call.id,
                    disputed,
                    disputed_id,
                ))
            }
            Placement::StandIn | Placement::CardStandIn { .. } => self.emit_event(
                ReservationsEvent::stand_in_hold_placed(owner, call.id, call.token, call.amount),
            ),
            Placement::Line { part, line, lender }
            | Placement::CardLine {
                part, line, lender, ..
            } => {
                self.credit_holds[owner][call.id].write(CreditHold {
                    lender,
                    held: U96::from(part),
                    line,
                    drawn: U96::ZERO,
                })?;
                self.emit_event(ReservationsEvent::credit_held(
                    owner, call.id, lender, line, part,
                ))
            }
        }
    }

    /// Puts `part` of a new hold for `payee` on `owner`'s credit on `lender`'s line in `token`.
    /// The lien already covers it, since it fits in the undrawn limit.
    fn hold_line_part(
        &mut self,
        owner: Address,
        token: Address,
        payee: Address,
        lender: Address,
        line: B256,
        part: u128,
    ) -> Result<()> {
        if self.lines[lender][line].token.read()? != token {
            return Err(ReservationsError::line_not_found().into());
        }
        let mut credit = self.credits[owner][lender][line].read()?;
        // The lender consented to pay only the payee it offered credit for.
        if credit.payee != payee {
            return Err(ReservationsError::credit_not_offered().into());
        }
        if part > credit.headroom() {
            return Err(ReservationsError::insufficient_available().into());
        }
        // Fits: at most the limit, a `U96`.
        credit.held += U96::from(part);
        self.credits[owner][lender][line].write(credit)
    }

    fn adjust(&mut self, owner: Address, call: IReservations::adjustCall) -> Result<()> {
        let mut auth = self.live_hold(owner, call.id)?;
        ensure_key_may_act(owner, &auth)?;
        let held = amount_u96(call.amount)?;
        let previous = auth.held.to::<u128>();
        let committed = auth.committed();
        let mut line_hold = self.credit_hold(owner, call.id, &auth)?;
        let line_before = line_hold.map_or(0, |hold| hold.held.to::<u128>());
        let mut position = self.positions[owner][auth.token].read()?;
        let decrease = previous.saturating_sub(call.amount);
        if call.amount > previous {
            let increase = call.amount - previous;
            // A card hold grows only while its card is active and within its limit.
            if auth.card_line != 0 {
                Cards::new().ensure_may_grow(
                    auth.card_line,
                    auth.merchant,
                    auth.window_end,
                    increase,
                )?;
            }
            let mut token = TIP20Token::from_address(auth.token)?;
            let free = available(&token, owner)?;
            // A hold with a line part takes an increase from the owner's balance first, then the line.
            let from_balance = match line_hold.as_mut() {
                Some(hold) if increase > free => {
                    let part = increase - free;
                    self.hold_line_part(
                        owner,
                        auth.token,
                        auth.payee,
                        hold.lender,
                        hold.line,
                        part,
                    )?;
                    // Fits: at most the credit's limit, a `U96`.
                    hold.held += U96::from(part);
                    free
                }
                _ if increase > free => {
                    return Err(ReservationsError::insufficient_available().into());
                }
                _ => increase,
            };
            position.reserved = position
                .reserved
                .checked_add(from_balance)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            let spend =
                AccountKeychain::new().spend_limit(owner, auth.token, U256::from(increase))?;
            record_spend(&mut auth, spend, increase);
            token.decrement_balance(owner, U256::from(from_balance))?;
        } else {
            // A decrease comes off the line part first, as the line pays after the balance.
            let from_line = line_before.min(decrease);
            if let Some(hold) = line_hold.as_mut() {
                let mut token = TIP20Token::from_address(auth.token)?;
                self.settle_line_part(owner, call.id, &mut token, auth.payee, hold, from_line, 0)?;
            }
            let returned = self.unreserve(
                owner,
                auth.token,
                auth.burn_epoch,
                &mut position,
                decrease - from_line,
            )?;
            return_to_balance(auth.token, owner, returned)?;
        }
        self.positions[owner][auth.token].write(position)?;
        auth.held = held;
        settle_limit(owner, &mut auth)?;
        self.authorizations[owner][call.id].write(auth)?;
        follow_card(&auth, committed)?;
        self.emit_event(ReservationsEvent::hold_adjusted(
            owner,
            call.id,
            auth.token,
            call.amount,
        ))?;
        let Some(hold) = line_hold else {
            return Ok(());
        };
        if hold.held.to::<u128>() == line_before {
            return Ok(());
        }
        self.credit_holds[owner][call.id].write(hold)?;
        self.emit_event(ReservationsEvent::credit_held(
            owner,
            call.id,
            hold.lender,
            hold.line,
            hold.held.to(),
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
        // A dispute reserve pays its payee only once the cardholder won the dispute it names.
        if auth.dispute_reserve {
            let named = self.dispute_holds[owner][id].read()?;
            if self.disputes[named.owner][named.id].state.read()? != DISPUTE_WON {
                return Err(ReservationsError::unauthorized().into());
            }
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

    /// Pays `charge`, or `chargeStandIn` when `stand_in`, whose shortfall may owe up to the offline cap.
    fn charge(
        &mut self,
        owner: Address,
        call: IReservations::chargeCall,
        stand_in: bool,
    ) -> Result<()> {
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
        let committed = auth.committed();

        let position = self.positions[owner][call.token].read()?;
        let (debt, spend) = self.pay(
            &mut token,
            owner,
            payee,
            Payment {
                amount: call.amount,
                released: 0,
                spend: call.amount,
                stand_in,
                line: None,
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
        follow_card(&auth, committed)?;
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

        // Provisional credit on an open dispute already returned what this refund takes past what
        // the purchase still nets: that part settles it instead of reaching the owner again.
        let settled = if auth.disputed {
            let mut dispute = self.disputes[call.owner][call.id].read()?;
            // A cardholder win already refunded the disputed amount and closed the record to refunds.
            if dispute.state == DISPUTE_WON {
                return Err(ReservationsError::refund_exceeds_capture().into());
            }
            let settled = if dispute.is_open() {
                (refunded.to::<u128>() + dispute.provisional.to::<u128>())
                    .saturating_sub(auth.captured.to::<u128>())
            } else {
                0
            };
            if settled != 0 {
                // Fits: `refunded <= captured`, so at most `provisional`.
                dispute.provisional -= U96::from(settled);
                // The balance part settles first; a line share stays repaid.
                dispute.line_share = dispute.line_share.min(dispute.provisional);
                self.disputes[call.owner][call.id].write(dispute)?;
                self.emit_event(ReservationsEvent::dispute_settled(
                    call.owner, call.id, settled,
                ))?;
            }
            settled
        } else {
            0
        };
        if call.amount != settled {
            self.pay_back(payee, call.owner, call.id, &auth, call.amount - settled)?;
        }
        let committed = auth.committed();
        // Refunds of non-final captures leave a live hold's amount committed.
        auth.refunded = refunded;
        settle_limit(call.owner, &mut auth)?;
        self.authorizations[call.owner][call.id].write(auth)?;
        follow_card(&auth, committed)?;
        self.emit_event(ReservationsEvent::refunded(
            call.owner,
            call.id,
            call.amount,
        ))
    }

    /// Pays `amount` of `owner`'s record `id` from its payee back to the owner, as a refund does: debt
    /// the owner owes the payee is cancelled first, then the part a credit line paid and the owner
    /// still owes repays the line, and the rest moves to the owner. Returns what repaid the line.
    fn pay_back(
        &mut self,
        payee: Address,
        owner: Address,
        id: B256,
        auth: &Authorization,
        amount: u128,
    ) -> Result<u128> {
        let mut token = TIP20Token::from_address(auth.token)?;
        token.ensure_transfer_authorized(payee, owner)?;
        // A refund to an owner in debt to the refunding payee first cancels that debt, so a
        // payee can refund a debt-financed payment without holding the unpaid part.
        let position = self.positions[owner][auth.token].read()?;
        let offset = if position.debt != 0 && self.creditors[owner][auth.token].read()? == payee {
            position.debt.min(amount)
        } else {
            0
        };
        let moved = amount - offset;
        // The part a credit line paid, and the owner still owes, repays the line first.
        let mut line_hold = self.credit_hold(owner, id, auth)?;
        let repaid = match line_hold {
            Some(hold) if moved != 0 && !hold.drawn.is_zero() => {
                let owed = self.credits[owner][hold.lender][hold.line].owed.read()?;
                moved.min(hold.drawn.min(owed).to::<u128>())
            }
            _ => 0,
        };
        if moved != 0 {
            AccountKeychain::new().authorize_transfer(payee, auth.token, U256::from(moved))?;
        }
        if offset != 0 {
            self.reduce_debt(owner, auth.token, position, payee, offset)?;
        }
        if let Some(hold) = line_hold.as_mut()
            && repaid != 0
        {
            token.ensure_transfer_authorized(payee, hold.lender)?;
            token.reservation_transfer(payee, hold.lender, U256::from(repaid))?;
            self.repay_line(owner, hold.lender, hold.line, repaid)?;
            // Fits: at most `hold.drawn`.
            hold.drawn -= U96::from(repaid);
            self.credit_holds[owner][id].write(*hold)?;
        }
        token.reservation_transfer(payee, owner, U256::from(moved - repaid))?;
        Ok(repaid)
    }

    /// Opens a dispute on `call.owner`'s record for its payee, the caller.
    fn open_dispute(&mut self, payee: Address, call: IReservations::openDisputeCall) -> Result<()> {
        let amount = amount_u96(call.amount)?;
        let auth = self.authorizations[call.owner][call.id].read()?;
        if !auth.exists() {
            return Err(ReservationsError::hold_not_found().into());
        }
        if auth.payee != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        // One dispute per record: a resolved one stays as its history.
        if auth.disputed {
            return Err(ReservationsError::dispute_exists().into());
        }
        if amount > auth.captured - auth.refunded {
            return Err(ReservationsError::refund_exceeds_capture().into());
        }
        self.authorizations[call.owner][call.id]
            .disputed
            .write(true)?;
        self.disputes[call.owner][call.id].write(Dispute {
            state: DISPUTE_OPENED,
            amount,
            ..Default::default()
        })?;
        self.emit_event(ReservationsEvent::dispute_opened(
            call.owner,
            call.id,
            call.amount,
            call.evidence,
        ))
    }

    /// Moves an open dispute forward for the record's payee, the caller, paying any provisional
    /// credit back as a refund would without counting it as refunded.
    fn dispute_step(&mut self, payee: Address, call: IReservations::disputeStepCall) -> Result<()> {
        let (auth, mut dispute) = self.open_dispute_of(call.owner, call.id, payee)?;
        // States only move forward, and a step never resolves the dispute.
        if call.state <= dispute.state || call.state > DISPUTE_ARBITRATION {
            return Err(ReservationsError::invalid_dispute_step().into());
        }
        if call.provisional != 0 {
            // Refunds and provisional credit together never return more than the purchase, nor
            // provisional credit more than the disputed amount.
            let provisional = U96::try_from(call.provisional)
                .ok()
                .and_then(|provisional| dispute.provisional.checked_add(provisional))
                .filter(|total| {
                    *total <= dispute.amount
                        && total.to::<u128>() + auth.refunded.to::<u128>()
                            <= auth.captured.to::<u128>()
                })
                .ok_or_else(ReservationsError::refund_exceeds_capture)?;
            let repaid = self.pay_back(payee, call.owner, call.id, &auth, call.provisional)?;
            dispute.provisional = provisional;
            // Fits: at most `provisional`.
            dispute.line_share += U96::from(repaid);
        }
        dispute.state = call.state;
        self.disputes[call.owner][call.id].write(dispute)?;
        self.emit_event(ReservationsEvent::dispute_stepped(
            call.owner,
            call.id,
            call.state,
            call.provisional,
            call.evidence,
            call.merchantEvidence,
        ))
    }

    /// Resolves an open dispute for the record's payee, the caller.
    fn resolve_dispute(
        &mut self,
        payee: Address,
        call: IReservations::resolveDisputeCall,
    ) -> Result<()> {
        let (owner, id) = (call.owner, call.id);
        let (mut auth, mut dispute) = self.open_dispute_of(owner, id, payee)?;
        let (amount, debt) = if call.cardholderWins {
            if call.collected != 0 {
                return Err(ReservationsError::invalid_amount().into());
            }
            // A win refunds what is still unrefunded of the disputed amount, of which the
            // provisional credit, within the refund room, was already paid.
            let credited = dispute.amount.min(auth.captured - auth.refunded);
            let rest = credited
                .checked_sub(dispute.provisional)
                .ok_or_else(TempoPrecompileError::under_overflow)?
                .to::<u128>();
            if rest != 0 {
                self.pay_back(payee, owner, id, &auth, rest)?;
            }
            let committed = auth.committed();
            // Fits: at most `captured`.
            auth.refunded += credited;
            settle_limit(owner, &mut auth)?;
            self.authorizations[owner][id].write(auth)?;
            follow_card(&auth, committed)?;
            dispute.state = DISPUTE_WON;
            (rest, 0)
        } else {
            let provisional = dispute.provisional.to::<u128>();
            let line_share = dispute.line_share.to::<u128>();
            // `collected` is what the payee already recovered elsewhere, such as the owner's
            // savings, so only the part that landed as balance can be collected that way.
            if call.collected > provisional - line_share {
                return Err(ReservationsError::invalid_amount().into());
            }
            let mut token = TIP20Token::from_address(auth.token)?;
            let redrawn = match self.credit_hold(owner, id, &auth)? {
                Some(hold) if line_share != 0 => {
                    self.redraw_line(owner, id, &mut token, payee, hold, line_share)?
                }
                _ => 0,
            };
            let owed = provisional - redrawn - call.collected;
            let (recovered, debt) = if owed == 0 {
                (0, 0)
            } else {
                token.ensure_transfer_authorized(owner, payee)?;
                let recovered = owed.min(available(&token, owner)?);
                let debt = owed - recovered;
                if debt != 0 {
                    self.owe_payee(owner, auth.token, payee, debt, provisional)?;
                }
                token.reservation_transfer(owner, payee, U256::from(recovered))?;
                (recovered, debt)
            };
            dispute.state = DISPUTE_LOST;
            (recovered, debt)
        };
        self.disputes[owner][id].write(dispute)?;
        self.emit_event(ReservationsEvent::dispute_resolved(
            owner,
            id,
            call.cardholderWins,
            amount,
            debt,
        ))
    }

    /// Draws up to `wanted` of `hold`'s line again within the credit's undrawn limit, the lender
    /// paying `payee` from its lien, and returns what was drawn. Called when a merchant wins a
    /// dispute whose provisional credit repaid the line.
    fn redraw_line(
        &mut self,
        owner: Address,
        id: B256,
        token: &mut TIP20Token,
        payee: Address,
        mut hold: CreditHold,
        wanted: u128,
    ) -> Result<u128> {
        let mut credit = self.credits[owner][hold.lender][hold.line].read()?;
        let planned = wanted.min(credit.headroom());
        if planned == 0 {
            return Ok(0);
        }
        let before = credit.lien();
        // Fits: within the limit, a `U96`.
        credit.owed += U96::from(planned);
        let mut line = self.lines[hold.lender][hold.line].read()?;
        // Drawing within the headroom lowers the lien by what it draws (see `Credit::lien`).
        let lowered = before
            .checked_sub(credit.lien())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let freed = self.shrink_lien(hold.lender, hold.line, &mut line, lowered)?;
        // A compliance burn of the lender's balance can leave the lien short.
        let drawn = planned.min(freed);
        credit.owed -= U96::from(planned - drawn);
        self.credits[owner][hold.lender][hold.line].write(credit)?;
        return_to_balance(line.token, hold.lender, freed)?;
        if drawn == 0 {
            return Ok(0);
        }
        // Fits: at most what the line was repaid for this record.
        hold.drawn += U96::from(drawn);
        self.credit_holds[owner][id].write(hold)?;
        token.ensure_transfer_authorized(hold.lender, payee)?;
        token.reservation_transfer(hold.lender, payee, U256::from(drawn))?;
        self.emit_event(ReservationsEvent::credit_drawn(
            owner,
            id,
            hold.lender,
            hold.line,
            drawn,
        ))?;
        Ok(drawn)
    }

    /// Adds `amount` to `owner`'s debt in `token` towards `payee` for a lost dispute: past the
    /// owner's debt cap only by the dispute's `provisional` credit, and only while the owner owes no
    /// other creditor in the token (one creditor per owner and token; the payee retries later).
    fn owe_payee(
        &mut self,
        owner: Address,
        token: Address,
        payee: Address,
        amount: u128,
        provisional: u128,
    ) -> Result<()> {
        let mut position = self.positions[owner][token].read()?;
        let new_creditor = position.debt == 0;
        if !new_creditor && self.creditors[owner][token].read()? != payee {
            return Err(ReservationsError::debt_cap_exceeded().into());
        }
        position.debt = position
            .debt
            .checked_add(amount)
            .ok_or_else(ReservationsError::debt_cap_exceeded)?;
        let cap = self.debt_caps[owner][payee][token].read()?;
        if U256::from(position.debt) > U256::from(cap) + U256::from(provisional) {
            return Err(ReservationsError::debt_cap_exceeded().into());
        }
        if new_creditor {
            self.creditors[owner][token].write(payee)?;
            TIP403Registry::new().count_reservation_debt(owner, true)?;
        }
        self.positions[owner][token].write(position)
    }

    /// Reads `owner`'s record `id` and its open dispute, for a call by the record's payee.
    fn open_dispute_of(
        &self,
        owner: Address,
        id: B256,
        payee: Address,
    ) -> Result<(Authorization, Dispute)> {
        let auth = self.authorizations[owner][id].read()?;
        if !auth.exists() {
            return Err(ReservationsError::hold_not_found().into());
        }
        if auth.payee != payee {
            return Err(ReservationsError::unauthorized().into());
        }
        let dispute = if auth.disputed {
            self.disputes[owner][id].read()?
        } else {
            Dispute::default()
        };
        if !dispute.is_open() {
            return Err(ReservationsError::dispute_not_found().into());
        }
        Ok((auth, dispute))
    }

    fn dispute_of(&self, owner: Address, id: B256) -> Result<IReservations::disputeOfReturn> {
        let dispute = self.disputes[owner][id].read()?;
        Ok(IReservations::disputeOfReturn {
            state: dispute.state,
            amount: dispute.amount.to(),
            provisional: dispute.provisional.to(),
            lineShare: dispute.line_share.to(),
        })
    }

    /// Liens `call.amount` of the owner's available balance for `authority`, a holder of the
    /// token's `LIEN_ROLE` signing with its root key. Neither the token's pause nor its TIP-403
    /// policy applies, since nothing moves until the authority releases the lien.
    fn lien(&mut self, authority: Address, call: IReservations::lienCall) -> Result<()> {
        let amount = amount_u96(call.amount)?;
        let mut token = TIP20Token::from_address(call.token)?;
        if AccountKeychain::new()
            .signing_access_key(authority)?
            .is_some()
            || !token.has_role_internal(authority, LIEN_ROLE)?
        {
            return Err(ReservationsError::unauthorized().into());
        }
        // A lien on a virtual address applies to its master, whose balance holds the funds.
        let owner = resolve_payee(call.owner)?;
        if !self.liens[authority][call.id].token.read()?.is_zero() {
            return Err(ReservationsError::lien_exists().into());
        }
        if call.amount > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        let mut position = self.positions[owner][call.token].read()?;
        let mut shortfall = self.shortfalls[owner][call.token].read()?;
        position.reserved = position
            .reserved
            .checked_add(call.amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        shortfall.liened = shortfall
            .liened
            .checked_add(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        token.decrement_balance(owner, U256::from(call.amount))?;
        self.positions[owner][call.token].write(position)?;
        self.shortfalls[owner][call.token].write(shortfall)?;
        self.liens[authority][call.id].write(Lien {
            owner,
            amount,
            token: call.token,
            burn_epoch: shortfall.epoch,
        })?;
        self.emit_event(ReservationsEvent::liened(
            owner,
            authority,
            call.token,
            call.id,
            call.amount,
        ))
    }

    /// Ends `authority`'s lien `id` and returns what it still reserves to the owner's available
    /// balance. Released funds are not a credit, so they repay no debt. Any key of the authority
    /// may release, and so may an authority whose role was revoked since.
    fn release_lien(&mut self, authority: Address, id: B256) -> Result<()> {
        let lien = self.liens[authority][id].read()?;
        if lien.token.is_zero() {
            return Err(ReservationsError::lien_not_found().into());
        }
        let mut position = self.positions[lien.owner][lien.token].read()?;
        let returned = self.unreserve(
            lien.owner,
            lien.token,
            lien.burn_epoch,
            &mut position,
            lien.amount.to(),
        )?;
        self.positions[lien.owner][lien.token].write(position)?;
        // Read after `unreserve`, which may have lowered `unbacked` in the same slot.
        let mut shortfall = self.shortfalls[lien.owner][lien.token].read()?;
        shortfall.liened = shortfall
            .liened
            .checked_sub(lien.amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.shortfalls[lien.owner][lien.token].write(shortfall)?;
        self.liens[authority][id].delete()?;
        return_to_balance(lien.token, lien.owner, returned)?;
        self.emit_event(ReservationsEvent::lien_released(
            lien.owner,
            authority,
            lien.token,
            id,
            lien.amount.to(),
        ))
    }

    fn lien_of(&self, authority: Address, id: B256) -> Result<IReservations::lienOfReturn> {
        let lien = self.liens[authority][id].read()?;
        Ok(IReservations::lienOfReturn {
            owner: lien.owner,
            token: lien.token,
            amount: lien.amount.to(),
        })
    }

    fn liened_of(&self, owner: Address, token: Address) -> Result<u128> {
        Ok(self.shortfalls[owner][token].liened.read()?.to())
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

    fn set_offline_cap(
        &mut self,
        owner: Address,
        call: IReservations::setOfflineCapCall,
    ) -> Result<()> {
        let payee = resolve_counterparty_as_root(owner, call.payee, call.token)?;
        self.offline_caps[owner][payee][call.token].write(call.cap)
    }

    fn open_line(&mut self, lender: Address, call: IReservations::openLineCall) -> Result<()> {
        TIP20Token::from_address(call.token)?;
        if !self.lines[lender][call.line].token.read()?.is_zero() {
            return Err(ReservationsError::line_exists().into());
        }
        self.lines[lender][call.line].token.write(call.token)?;
        self.emit_event(ReservationsEvent::line_opened(
            lender, call.line, call.token,
        ))
    }

    /// Records the lender's offer and lowers a granted limit above it, releasing the lien for the
    /// undrawn part. Owed amounts and open holds' line parts stay.
    fn offer_credit(
        &mut self,
        lender: Address,
        call: IReservations::offerCreditCall,
    ) -> Result<()> {
        // The offer commits the lender's balance once accepted, so only its root key makes one.
        if AccountKeychain::new().signing_access_key(lender)?.is_some()
            || call.owner.is_zero()
            || call.owner == lender
        {
            return Err(ReservationsError::unauthorized().into());
        }
        let mut line = self.lines[lender][call.line].read()?;
        if line.token.is_zero() {
            return Err(ReservationsError::line_not_found().into());
        }
        let limit = U96::try_from(call.limit).map_err(|_| ReservationsError::invalid_amount())?;
        // A withdrawn offer names no payee.
        let payee = if limit.is_zero() {
            Address::ZERO
        } else {
            resolve_payee(call.payee)?
        };
        self.credit_offers[lender][call.line][call.owner].write(CreditOffer { payee, limit })?;
        self.emit_event(ReservationsEvent::credit_offered(
            lender, call.line, call.owner, payee, call.limit,
        ))?;
        let mut credit = self.credits[call.owner][lender][call.line].read()?;
        if credit.limit <= limit {
            return Ok(());
        }
        let before = credit.lien();
        credit.limit = limit;
        // A lower limit never needs a larger lien.
        let lowered = before
            .checked_sub(credit.lien())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let returned = self.shrink_lien(lender, call.line, &mut line, lowered)?;
        return_to_balance(line.token, lender, returned)?;
        self.credits[call.owner][lender][call.line].write(credit)?;
        self.emit_event(ReservationsEvent::credit_granted(
            call.owner,
            lender,
            call.line,
            credit.payee,
            call.limit,
        ))
    }

    /// Sets the owner's credit within the lender's offer, or below what it already has, and moves
    /// the lender's lien to the new undrawn limit.
    fn grant_credit(&mut self, owner: Address, call: IReservations::grantCreditCall) -> Result<()> {
        if AccountKeychain::new().signing_access_key(owner)?.is_some() || call.lender == owner {
            return Err(ReservationsError::unauthorized().into());
        }
        let mut line = self.lines[call.lender][call.line].read()?;
        if line.token.is_zero() {
            return Err(ReservationsError::line_not_found().into());
        }
        let limit = U96::try_from(call.limit).map_err(|_| ReservationsError::invalid_amount())?;
        let payee = resolve_payee(call.payee)?;
        let mut credit = self.credits[owner][call.lender][call.line].read()?;
        let offer = self.credit_offers[call.lender][call.line][owner].read()?;
        // The lender consents to each owner, payee and limit; lowering one's own limit needs none.
        let offered = !offer.limit.is_zero() && offer.payee == payee && limit <= offer.limit;
        let lowered = credit.payee == payee && limit <= credit.limit;
        if !offered && !lowered {
            return Err(ReservationsError::credit_not_offered().into());
        }
        let mut token = TIP20Token::from_address(line.token)?;
        token.ensure_transfer_authorized(call.lender, payee)?;
        let before = credit.lien();
        credit.payee = payee;
        credit.limit = limit;
        let after = credit.lien();
        if after > before {
            if after - before > available(&token, call.lender)? {
                return Err(ReservationsError::insufficient_available().into());
            }
            self.grow_lien(
                call.lender,
                call.line,
                &mut line,
                &mut token,
                after - before,
            )?;
        } else {
            let returned = self.shrink_lien(call.lender, call.line, &mut line, before - after)?;
            return_to_balance(line.token, call.lender, returned)?;
        }
        // Accepting an offer uses it up, so a limit the lender later lowers stays lowered.
        if !lowered {
            self.credit_offers[call.lender][call.line][owner].delete()?;
        }
        self.credits[owner][call.lender][call.line].write(credit)?;
        self.emit_event(ReservationsEvent::credit_granted(
            owner,
            call.lender,
            call.line,
            payee,
            call.limit,
        ))
    }

    /// Repays up to `amount` of what `owner` owes on the line from its available balance.
    fn repay_credit(&mut self, owner: Address, call: IReservations::repayCreditCall) -> Result<()> {
        amount_u96(call.amount)?;
        let line_token = self.lines[call.lender][call.line].token.read()?;
        if line_token.is_zero() {
            return Err(ReservationsError::line_not_found().into());
        }
        let owed = self.credits[owner][call.lender][call.line].owed.read()?;
        let repaid = call.amount.min(owed.to());
        if repaid == 0 {
            return Ok(());
        }
        let mut token = TIP20Token::from_address(line_token)?;
        token.ensure_transfer_authorized(owner, call.lender)?;
        if repaid > available(&token, owner)? {
            return Err(ReservationsError::insufficient_available().into());
        }
        AccountKeychain::new().authorize_transfer(owner, line_token, U256::from(repaid))?;
        token.reservation_transfer(owner, call.lender, U256::from(repaid))?;
        self.repay_line(owner, call.lender, call.line, repaid)
    }

    fn credit_of(
        &self,
        owner: Address,
        lender: Address,
        line: B256,
    ) -> Result<IReservations::creditOfReturn> {
        let credit = self.credits[owner][lender][line].read()?;
        Ok(IReservations::creditOfReturn {
            limit: credit.limit.to(),
            owed: credit.owed.to(),
            held: credit.held.to(),
        })
    }

    fn get_line(&self, lender: Address, line: B256) -> Result<IReservations::getLineReturn> {
        let line = self.lines[lender][line].read()?;
        Ok(IReservations::getLineReturn {
            token: line.token,
            lien: line.lien.to(),
        })
    }

    fn credit_offer(
        &self,
        lender: Address,
        line: B256,
        owner: Address,
    ) -> Result<IReservations::creditOfferReturn> {
        let offer = self.credit_offers[lender][line][owner].read()?;
        Ok(IReservations::creditOfferReturn {
            payee: offer.payee,
            limit: offer.limit.to(),
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

    fn offline_cap(&self, owner: Address, payee: Address, token: Address) -> Result<u128> {
        self.offline_caps[owner][Recipient::resolve(payee)?.target][token].read()
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
        let line = self.credit_hold(owner, id, &auth)?.map(|hold| LineDraw {
            id,
            consumed: hold.held.to(),
            hold,
        });
        let line_part = line.as_ref().map_or(0, |line| line.consumed);
        // Releasing the hold first returns the reservation it consumes to the spendable balance.
        let released = self.unreserve(
            owner,
            auth.token,
            auth.burn_epoch,
            &mut position,
            held - line_part,
        )?;
        // The hold already counted against the key's limit; only an excess is new spend.
        let excess = amount.saturating_sub(held);
        let committed = auth.committed();
        let (debt, spend) = self.pay(
            &mut token,
            owner,
            auth.payee,
            Payment {
                amount,
                released,
                spend: excess,
                stand_in: auth.stand_in,
                line,
            },
            position,
        )?;
        record_spend(&mut auth, spend, excess);
        auth.held = U96::ZERO;
        auth.expires_at = 0;
        auth.captured = captured;
        settle_limit(owner, &mut auth)?;
        self.authorizations[owner][id].write(auth)?;
        follow_card(&auth, committed)?;
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
        // A part takes the hold's balance part first and its line part after it.
        let line_hold = self.credit_hold(owner, id, &auth)?;
        let balance_part =
            auth.held.to::<u128>() - line_hold.map_or(0, |hold| hold.held.to::<u128>());
        let from_balance = amount.min(balance_part);
        let line = line_hold.map(|hold| LineDraw {
            id,
            consumed: amount - from_balance,
            hold,
        });
        let released = self.unreserve(
            owner,
            auth.token,
            auth.burn_epoch,
            &mut position,
            from_balance,
        )?;
        // A compliance burn can leave less than `amount` reserved; the rest is paid as in a capture.
        let (debt, _) = self.pay(
            &mut token,
            owner,
            auth.payee,
            Payment {
                amount,
                released,
                spend: 0,
                stand_in: auth.stand_in,
                line,
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
    /// `payee` and records the shortfall as debt towards `payee`, within the owner's debt cap or,
    /// for a stand-in payment, the larger of it and the offline cap. Writes
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
            stand_in,
            line,
        } = payment;
        let token_address = token.address();
        let paid = amount.min(available(token, owner)?.saturating_add(released));
        // The hold's line part pays after the owner's balance and before debt.
        let drawn = match line {
            Some(LineDraw {
                id,
                mut hold,
                consumed,
            }) => {
                let drawn = self.settle_line_part(
                    owner,
                    id,
                    token,
                    payee,
                    &mut hold,
                    consumed,
                    amount - paid,
                )?;
                self.credit_holds[owner][id].write(hold)?;
                drawn
            }
            None => 0,
        };
        let debt = amount - paid - drawn;
        let new_creditor = position.debt == 0;
        if debt != 0 {
            if !new_creditor && self.creditors[owner][token_address].read()? != payee {
                return Err(ReservationsError::debt_cap_exceeded().into());
            }
            position.debt = position
                .debt
                .checked_add(debt)
                .ok_or_else(ReservationsError::debt_cap_exceeded)?;
            // The offline cap is read only when the debt cap alone falls short.
            if position.debt > self.debt_caps[owner][payee][token_address].read()?
                && (!stand_in
                    || position.debt > self.offline_caps[owner][payee][token_address].read()?)
            {
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
        let mut line_part = 0;
        if let Some(mut hold) = self.credit_hold(owner, id, &auth)? {
            line_part = hold.held.to::<u128>();
            let mut token = TIP20Token::from_address(auth.token)?;
            self.settle_line_part(owner, id, &mut token, auth.payee, &mut hold, line_part, 0)?;
            if auth.captured.is_zero() {
                self.credit_holds[owner][id].delete()?;
            } else {
                self.credit_holds[owner][id].write(hold)?;
            }
        }
        let returned = self.unreserve(
            owner,
            auth.token,
            auth.burn_epoch,
            &mut position,
            auth.held.to::<u128>() - line_part,
        )?;
        return_to_balance(auth.token, owner, returned)?;
        self.positions[owner][auth.token].write(position)?;
        let committed = auth.committed();
        auth.held = U96::ZERO;
        auth.expires_at = 0;
        settle_limit(owner, &mut auth)?;
        if auth.captured.is_zero() {
            self.authorizations[owner][id].delete()?;
            if auth.dispute_reserve {
                self.dispute_holds[owner][id].delete()?;
            }
        } else {
            self.authorizations[owner][id].write(auth)?;
        }
        follow_card(&auth, committed)?;
        self.emit_event(ReservationsEvent::hold_released(owner, id, auth.token))
    }

    /// Removes `amount` of a hold, line lien or lien in `token` from `position` and returns the
    /// reserved amount it frees, which the caller adds back to the spendable balance. One placed
    /// before the latest burn (`burn_epoch` below the shortfall's) first consumes the burned part,
    /// which no longer exists, so the reservation behind the other holds stays in place.
    fn unreserve(
        &mut self,
        owner: Address,
        token: Address,
        burn_epoch: u32,
        position: &mut Position,
        amount: u128,
    ) -> Result<u128> {
        let mut from_unbacked = 0;
        if amount != 0 {
            let mut shortfall = self.shortfalls[owner][token].read()?;
            if shortfall.unbacked != 0 && burn_epoch < shortfall.epoch {
                from_unbacked = shortfall.unbacked.min(amount);
                shortfall.unbacked -= from_unbacked;
                self.shortfalls[owner][token].write(shortfall)?;
            }
        }
        let returned = position.reserved.min(amount - from_unbacked);
        position.reserved -= returned;
        Ok(returned)
    }

    /// Returns the line part of `auth`, the authorization `id` of `owner`, if it has one.
    fn credit_hold(
        &self,
        owner: Address,
        id: B256,
        auth: &Authorization,
    ) -> Result<Option<CreditHold>> {
        if !auth.line {
            return Ok(None);
        }
        Ok(Some(self.credit_holds[owner][id].read()?))
    }

    /// Ends `consumed` of `hold`'s line part and draws up to `wanted` of it from the lender's
    /// lien to `payee`, returning what was drawn. The lien shrinks to what the credit still needs
    /// and the rest of what it frees returns to the lender's balance. The caller writes `hold`.
    #[expect(clippy::too_many_arguments, reason = "one call per settled line part")]
    fn settle_line_part(
        &mut self,
        owner: Address,
        id: B256,
        token: &mut TIP20Token,
        payee: Address,
        hold: &mut CreditHold,
        consumed: u128,
        wanted: u128,
    ) -> Result<u128> {
        if consumed == 0 {
            return Ok(0);
        }
        let mut credit = self.credits[owner][hold.lender][hold.line].read()?;
        let before = credit.lien();
        let planned = wanted.min(consumed);
        // `credit.held` includes this hold's line part, of which `consumed` is a part.
        credit.held = credit
            .held
            .checked_sub(U96::from(consumed))
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        credit.owed = credit
            .owed
            .checked_add(U96::from(planned))
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        // Ending a line part lowers the lien by at least what it draws (see `Credit::lien`).
        let mut line = self.lines[hold.lender][hold.line].read()?;
        let lowered = before
            .checked_sub(credit.lien())
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let freed = self.shrink_lien(hold.lender, hold.line, &mut line, lowered)?;
        // A compliance burn of the lender's balance can leave the lien short; a line pays only
        // what it still reserves.
        let drawn = planned.min(freed);
        credit.owed -= U96::from(planned - drawn);
        self.credits[owner][hold.lender][hold.line].write(credit)?;
        hold.held -= U96::from(consumed);
        // Fits: at most what was drawn on the credit.
        hold.drawn += U96::from(drawn);
        return_to_balance(line.token, hold.lender, freed)?;
        if drawn == 0 {
            return Ok(0);
        }
        token.ensure_transfer_authorized(hold.lender, payee)?;
        token.reservation_transfer(hold.lender, payee, U256::from(drawn))?;
        self.emit_event(ReservationsEvent::credit_drawn(
            owner,
            id,
            hold.lender,
            hold.line,
            drawn,
        ))?;
        Ok(drawn)
    }

    /// Lowers what `owner` owes on the line by `amount`, which the lender already received, and
    /// grows the lien towards the new undrawn limit from the lender's available balance.
    fn repay_line(
        &mut self,
        owner: Address,
        lender: Address,
        id: B256,
        amount: u128,
    ) -> Result<()> {
        let mut credit = self.credits[owner][lender][id].read()?;
        let before = credit.lien();
        credit.owed = credit
            .owed
            .checked_sub(U96::from(amount))
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.credits[owner][lender][id].write(credit)?;
        let mut line = self.lines[lender][id].read()?;
        let mut token = TIP20Token::from_address(line.token)?;
        // A repayment first repays the lender's own debt, so the lien grows by what is left.
        let growth = credit
            .lien()
            .checked_sub(before)
            .ok_or_else(TempoPrecompileError::under_overflow)?
            .min(available(&token, lender)?);
        self.grow_lien(lender, id, &mut line, &mut token, growth)?;
        self.emit_event(ReservationsEvent::credit_repaid(owner, lender, id, amount))
    }

    /// Moves `amount` of the lender's available balance into the line's lien.
    fn grow_lien(
        &mut self,
        lender: Address,
        id: B256,
        line: &mut Line,
        token: &mut TIP20Token,
        amount: u128,
    ) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let mut position = self.positions[lender][line.token].read()?;
        position.reserved = position
            .reserved
            .checked_add(amount)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        token.decrement_balance(lender, U256::from(amount))?;
        self.positions[lender][line.token].write(position)?;
        if line.lien.is_zero() {
            line.burn_epoch = self.shortfalls[lender][line.token].epoch.read()?;
        }
        line.lien = U96::try_from(amount)
            .ok()
            .and_then(|amount| line.lien.checked_add(amount))
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.lines[lender][id].write(*line)?;
        self.emit_event(ReservationsEvent::line_reserved(
            lender,
            id,
            line.token,
            line.lien.to(),
        ))
    }

    /// Lowers the line's lien by up to `amount` and returns the reservation it frees, which the
    /// caller pays out or adds back to the lender's balance.
    fn shrink_lien(
        &mut self,
        lender: Address,
        id: B256,
        line: &mut Line,
        amount: u128,
    ) -> Result<u128> {
        let release = line.lien.to::<u128>().min(amount);
        if release == 0 {
            return Ok(0);
        }
        let mut position = self.positions[lender][line.token].read()?;
        let freed = self.unreserve(lender, line.token, line.burn_epoch, &mut position, release)?;
        self.positions[lender][line.token].write(position)?;
        line.lien -= U96::from(release);
        self.lines[lender][id].write(*line)?;
        self.emit_event(ReservationsEvent::line_reserved(
            lender,
            id,
            line.token,
            line.lien.to(),
        ))?;
        Ok(freed)
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

/// Moves the card line of `auth`, if any, from the authorization's earlier committed amount
/// `before` to what it commits now.
fn follow_card(auth: &Authorization, before: u128) -> Result<()> {
    if auth.card_line == 0 {
        return Ok(());
    }
    Cards::new().follow_commitment(
        auth.card_line,
        auth.merchant,
        auth.window_end,
        before,
        auth.committed(),
    )
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
    /// Whether the payment settles a stand-in approval, whose debt may reach the offline cap.
    stand_in: bool,
    /// The hold's line part this payment ends, which pays after the owner's balance.
    line: Option<LineDraw>,
}

/// The line part of a hold that a capture ends.
struct LineDraw {
    id: B256,
    hold: CreditHold,
    /// Part of `hold.held` the capture ends; it may draw up to this.
    consumed: u128,
}

/// How a hold is placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// `hold`: reserves the whole amount or reverts.
    Plain,
    /// `holdStandIn`: reserves what is available of an approval made offline.
    StandIn,
    /// `holdCard`: `hold` through the caller's card `card` issued by `issuer`, its `ICards` payee.
    Card { issuer: Address, card: B256 },
    /// `holdCardStandIn`: `holdStandIn` through the caller's card `card` issued by `issuer`.
    CardStandIn { issuer: Address, card: B256 },
    /// `holdWithLine`: reserves the amount less `part`, which goes on `lender`'s line `line`.
    Line {
        part: u128,
        line: B256,
        lender: Address,
    },
    /// `holdCardWithLine`: `holdWithLine` through the caller's card `card` issued by `issuer`.
    CardLine {
        issuer: Address,
        card: B256,
        part: u128,
        line: B256,
        lender: Address,
    },
    /// `holdForDispute`: `hold` for the open dispute on `owner`'s record `id`, for up to 120 days.
    Dispute { owner: Address, id: B256 },
    /// `holdCardForMerchant`: `holdCard` for a charge from `merchant`, checked against its mandate.
    CardMerchant {
        issuer: Address,
        card: B256,
        merchant: B256,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_keychain::AccountKeychain,
        address_registry::{AddressRegistry, MasterId, TempoAddressExt, UserTag},
        cards::{Cards, CardsError, CardsEvent, ICards},
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
        tip20::{
            BURN_AT_ROLE, BURN_BLOCKED_ROLE, IRolesAuth, ITIP20, PAUSE_ROLE, TIP20Error, TIP20Event,
        },
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
            self.place(id, amount, expires_at, false)
        }

        fn hold_stand_in(&mut self, id: B256, amount: u128) -> Result<()> {
            self.place(id, amount, EXPIRY, true)
        }

        fn place(&mut self, id: B256, amount: u128, expires_at: u64, stand_in: bool) -> Result<()> {
            self.reservations.hold(
                self.owner,
                IReservations::holdCall {
                    token: self.token.address(),
                    id,
                    amount,
                    expiresAt: expires_at,
                    payee: self.payee,
                },
                if stand_in {
                    Placement::StandIn
                } else {
                    Placement::Plain
                },
            )
        }

        /// Places a hold of `amount` with `part` of it on `lender`'s `line`.
        fn hold_on_line(
            &mut self,
            id: B256,
            amount: u128,
            part: u128,
            lender: Address,
            line: B256,
        ) -> Result<()> {
            self.reservations.hold(
                self.owner,
                IReservations::holdCall {
                    token: self.token.address(),
                    id,
                    amount,
                    expiresAt: EXPIRY,
                    payee: self.payee,
                },
                Placement::Line { part, line, lender },
            )
        }

        /// Mints `balance` to a fresh lender, opens its line in the fixture's token, offers the
        /// owner `limit` for the fixture's payee and grants it.
        fn open_credit(&mut self, balance: u64, limit: u128) -> Result<(Address, B256)> {
            let lender = Address::random();
            let line = B256::random();
            self.mint(lender, balance)?;
            self.reservations.open_line(
                lender,
                IReservations::openLineCall {
                    line,
                    token: self.token.address(),
                },
            )?;
            self.offer_credit(lender, line, self.payee, limit)?;
            self.grant_credit(lender, line, self.payee, limit)?;
            Ok((lender, line))
        }

        fn offer_credit(
            &mut self,
            lender: Address,
            line: B256,
            payee: Address,
            limit: u128,
        ) -> Result<()> {
            self.reservations.offer_credit(
                lender,
                IReservations::offerCreditCall {
                    line,
                    owner: self.owner,
                    payee,
                    limit,
                },
            )
        }

        fn grant_credit(
            &mut self,
            lender: Address,
            line: B256,
            payee: Address,
            limit: u128,
        ) -> Result<()> {
            self.reservations.grant_credit(
                self.owner,
                IReservations::grantCreditCall {
                    line,
                    lender,
                    payee,
                    limit,
                },
            )
        }

        fn repay_credit(&mut self, lender: Address, line: B256, amount: u128) -> Result<()> {
            self.reservations.repay_credit(
                self.owner,
                IReservations::repayCreditCall {
                    lender,
                    line,
                    amount,
                },
            )
        }

        /// The owner's limit, owed and held amounts on the line.
        fn credit(&self, lender: Address, line: B256) -> Result<(u128, u128, u128)> {
            let credit = self.reservations.credit_of(self.owner, lender, line)?;
            Ok((credit.limit, credit.owed, credit.held))
        }

        fn mint(&mut self, to: Address, amount: u64) -> Result<()> {
            self.token.mint(
                self.admin,
                ITIP20::mintCall {
                    to,
                    amount: U256::from(amount),
                },
            )
        }

        /// `account`'s reserved and available amounts of the fixture's token.
        fn reservation_of(&self, account: Address) -> Result<(u128, u128)> {
            Ok((
                self.reservations
                    .reserved_of(account, self.token.address())?,
                self.reservations
                    .available_of(account, self.token.address())?,
            ))
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
            self.pay(id, amount, payee, false)
        }

        fn charge_stand_in(&mut self, id: B256, amount: u128) -> Result<()> {
            self.pay(id, amount, self.payee, true)
        }

        fn pay(&mut self, id: B256, amount: u128, payee: Address, stand_in: bool) -> Result<()> {
            self.reservations.charge(
                self.owner,
                IReservations::chargeCall {
                    token: self.token.address(),
                    id,
                    amount,
                    payee,
                },
                stand_in,
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

        fn set_offline_cap(&mut self, payee: Address, cap: u128) -> Result<()> {
            self.reservations.set_offline_cap(
                self.owner,
                IReservations::setOfflineCapCall {
                    payee,
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
                        Placement::Plain,
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
                Placement::Plain,
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
    fn test_stand_in_hold_reserves_what_is_available() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            let id = B256::random();
            f.hold_stand_in(id, 400)?;

            assert_eq!(f.reserved()?, 300);
            assert_eq!(f.available()?, 0);
            assert_eq!(f.reservations.get_hold(f.owner, id)?.amount, 300);
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_placed(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    300,
                    EXPIRY,
                ),
                ReservationsEvent::stand_in_hold_placed(f.owner, id, f.token.address(), 400),
            ]);

            // With nothing available the hold reserves nothing and stays live.
            let empty = B256::random();
            f.hold_stand_in(empty, 50)?;
            assert_eq!(f.reservations.get_hold(f.owner, empty)?.amount, 0);
            assert_eq!(f.reserved()?, 300);
            assert_eq!(
                f.hold_stand_in(B256::random(), 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_stand_in_capture_owes_up_to_the_offline_cap() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            let id = B256::random();
            f.hold_stand_in(id, 400)?;
            assert_eq!(
                f.capture(id, 400).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_offline_cap(f.payee, 100)?;
            assert_eq!(
                f.capture(id, 401).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.reservations.clear_emitted_events();
            f.capture(id, 400)?;

            assert_eq!(f.balance(f.payee)?, U256::from(300));
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
                    400,
                    100,
                )]);
            Ok(())
        })
    }

    #[test]
    fn test_offline_cap_leaves_ordinary_payments_at_the_debt_cap() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            f.set_offline_cap(f.payee, 100)?;
            let id = B256::random();
            f.hold(id, 300)?;
            assert_eq!(
                f.capture(id, 350).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            assert_eq!(
                f.charge(B256::random(), 350, f.payee).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );

            // A debt cap above the offline cap still bounds stand-in payments.
            f.set_debt_cap(f.payee, 150)?;
            let stand_in = B256::random();
            f.hold_stand_in(stand_in, 200)?;
            f.reservations.release(f.owner, id)?;
            f.capture(stand_in, 450)?;
            assert_eq!(f.debt()?.amount, 150);
            Ok(())
        })
    }

    #[test]
    fn test_stand_in_charge_owes_up_to_the_offline_cap() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            let id = B256::random();
            assert_eq!(
                f.charge_stand_in(id, 350).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_offline_cap(f.payee, 50)?;
            f.charge_stand_in(id, 350)?;

            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.debt()?.amount, 50);
            assert_eq!(f.captured(id)?, (350, 0));
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::charged(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    350,
                    50,
                )]);
            assert_eq!(
                f.charge_stand_in(B256::random(), 1).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_stand_in_hold_counts_only_what_it_reserves() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            f.set_offline_cap(f.payee, 100)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());
            let id = B256::random();
            f.hold_stand_in(id, 400)?;
            assert_eq!(remaining()?, U256::from(700));
            // The shortfall is new spend when captured, debt included.
            f.capture(id, 400)?;
            assert_eq!(remaining()?, U256::from(600));
            Ok(())
        })
    }

    #[test]
    fn test_set_offline_cap_requires_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            assert_eq!(
                f.set_offline_cap(Address::ZERO, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.set_offline_cap(f.owner, 1).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            f.set_offline_cap(f.payee, 7)?;
            assert_eq!(
                f.reservations
                    .offline_cap(f.owner, f.payee, f.token.address())?,
                7
            );

            authorize_card_key(f.owner, Address::random(), f.token.address(), 1_000)?;
            assert_eq!(
                f.set_offline_cap(f.payee, 100).unwrap_err(),
                ReservationsError::unauthorized().into()
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
    fn test_card_hold_checks_the_card() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Inactive,
                U96::MAX,
            )?;
            for (card, error) in [
                (card, CardsError::card_inactive()),
                (B256::random(), CardsError::unknown_card()),
            ] {
                assert_eq!(
                    hold_card(&mut f, B256::random(), 10, card).unwrap_err(),
                    error.into()
                );
            }
            // A card on another account is unknown to this owner.
            let foreign = B256::random();
            issue_card(
                &mut cards,
                &f,
                Address::random(),
                foreign,
                ICards::Status::Active,
                U96::MAX,
            )?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 10, foreign).unwrap_err(),
                CardsError::unknown_card().into()
            );

            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Active,
                U96::from(100),
                NOW,
            )?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 10, card).unwrap_err(),
                CardsError::card_inactive().into()
            );
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Active,
                U96::from(100),
                0,
            )?;
            cards.set_program_tokens(
                f.payee,
                ICards::setProgramTokensCall {
                    tokens: vec![Address::random()],
                },
            )?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 10, card).unwrap_err(),
                CardsError::token_not_allowed().into()
            );
            cards.set_program_tokens(
                f.payee,
                ICards::setProgramTokensCall {
                    tokens: vec![f.token.address()],
                },
            )?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 101, card).unwrap_err(),
                CardsError::card_limit_exceeded().into()
            );

            let id = B256::random();
            hold_card(&mut f, id, 100, card)?;
            assert_eq!(f.reserved()?, 100);
            assert_eq!(cards.get_card(f.payee, card)?.committed, U96::from(100));
            assert!(f.reservations.emitted_events().contains(
                &ReservationsEvent::card_hold_placed(f.owner, id, card, 1).into_log_data()
            ));

            // After a replacement only the new credential holds.
            let next = B256::random();
            cards.replace_card(f.payee, ICards::replaceCardCall { card, next })?;
            f.reservations.release(f.owner, id)?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 10, card).unwrap_err(),
                CardsError::card_inactive().into()
            );
            hold_card(&mut f, B256::random(), 10, next)?;
            Ok(())
        })
    }

    #[test]
    fn test_card_stand_in_hold_checks_the_card_but_not_its_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(300)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Frozen,
                U96::from(100),
            )?;
            let foreign = B256::random();
            issue_card(
                &mut cards,
                &f,
                Address::random(),
                foreign,
                ICards::Status::Active,
                U96::MAX,
            )?;
            for (card, error) in [
                (card, CardsError::card_inactive()),
                (B256::random(), CardsError::unknown_card()),
                (foreign, CardsError::unknown_card()),
            ] {
                assert_eq!(
                    hold_card_stand_in(&mut f, B256::random(), 10, card).unwrap_err(),
                    error.into()
                );
            }
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Active,
                U96::from(100),
                NOW,
            )?;
            assert_eq!(
                hold_card_stand_in(&mut f, B256::random(), 10, card).unwrap_err(),
                CardsError::card_inactive().into()
            );
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Active,
                U96::from(100),
                0,
            )?;
            cards.set_program_tokens(
                f.payee,
                ICards::setProgramTokensCall {
                    tokens: vec![Address::random()],
                },
            )?;
            assert_eq!(
                hold_card_stand_in(&mut f, B256::random(), 10, card).unwrap_err(),
                CardsError::token_not_allowed().into()
            );
            cards.set_program_tokens(f.payee, ICards::setProgramTokensCall { tokens: vec![] })?;

            // Approved offline past the card's limit, it reserves what is available and the card
            // commits what the authorization does.
            let id = B256::random();
            f.reservations.clear_emitted_events();
            hold_card_stand_in(&mut f, id, 400, card)?;
            assert_eq!(f.reserved()?, 300);
            assert_eq!(cards.get_card(f.payee, card)?.committed, U96::from(300));
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_placed(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    300,
                    EXPIRY,
                ),
                ReservationsEvent::card_hold_placed(f.owner, id, card, 1),
                ReservationsEvent::stand_in_hold_placed(f.owner, id, f.token.address(), 400),
            ]);
            // Online holds still meet the limit, which the stand-in hold now fills.
            f.mint(f.owner, 10)?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 1, card).unwrap_err(),
                CardsError::card_limit_exceeded().into()
            );

            // Its capture owes up to the offline cap after the card froze, and the card follows it.
            cards.set_card_status(
                f.owner,
                ICards::setCardStatusCall {
                    payee: f.payee,
                    card,
                    status: ICards::Status::Frozen,
                },
            )?;
            f.set_offline_cap(f.payee, 100)?;
            f.capture(id, 400)?;
            assert_eq!(f.debt()?.amount, 90);
            assert_eq!(cards.get_card(f.payee, card)?.committed, U96::from(400));
            Ok(())
        })
    }

    #[test]
    fn test_card_scoped_key_records_stand_ins_only_through_cards() -> eyre::Result<()> {
        at_t15(|| {
            let f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_key_for(
                f.owner,
                key,
                f.token.address(),
                500,
                &[
                    IReservations::holdCardCall::SELECTOR,
                    IReservations::holdCardStandInCall::SELECTOR,
                    IReservations::chargeStandInCall::SELECTOR,
                ],
            )?;
            let validate = |input: Vec<u8>| {
                keychain.validate_call_scope_for_transaction(
                    f.owner,
                    key,
                    &TxKind::Call(RESERVATIONS_ADDRESS),
                    &input,
                )
            };
            validate(
                IReservations::holdCardStandInCall {
                    token: f.token.address(),
                    id: B256::random(),
                    amount: 1,
                    expiresAt: EXPIRY,
                    payee: f.payee,
                    issuer: f.payee,
                    card: B256::random(),
                }
                .abi_encode(),
            )?;
            assert_eq!(
                validate(
                    IReservations::holdStandInCall {
                        token: f.token.address(),
                        id: B256::random(),
                        amount: 1,
                        expiresAt: EXPIRY,
                        payee: f.payee,
                    }
                    .abi_encode()
                )
                .unwrap_err(),
                AccountKeychainError::call_not_allowed().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_card_hold_may_pay_another_payee() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::from(100),
            )?;
            // The hold pays a facility that pays the card's issuer, as a savings leg does.
            let issuer = f.payee;
            let facility = Address::random();
            let place = |f: &mut Fixture, issuer: Address, amount: u128| {
                f.reservations.hold(
                    f.owner,
                    IReservations::holdCall {
                        token: f.token.address(),
                        id: B256::random(),
                        amount,
                        expiresAt: EXPIRY,
                        payee: facility,
                    },
                    Placement::Card { issuer, card },
                )
            };
            place(&mut f, issuer, 60)?;
            assert_eq!(cards.get_card(issuer, card)?.committed, U96::from(60));
            // The card is keyed by its issuer, never by the hold's payee.
            assert_eq!(
                place(&mut f, facility, 10).unwrap_err(),
                CardsError::unknown_card().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_card_line_follows_what_its_holds_commit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::from(100),
            )?;
            let payee = f.payee;
            let committed =
                |cards: &Cards, card| -> Result<U96> { Ok(cards.get_card(payee, card)?.committed) };

            let first = B256::random();
            hold_card(&mut f, first, 50, card)?;
            f.adjust(first, 60)?;
            assert_eq!(committed(&cards, card)?, U96::from(60));
            assert_eq!(
                hold_card(&mut f, B256::random(), 50, card).unwrap_err(),
                CardsError::card_limit_exceeded().into()
            );
            let second = B256::random();
            hold_card(&mut f, second, 40, card)?;
            assert_eq!(committed(&cards, card)?, U96::from(100));
            f.reservations.release(f.owner, second)?;
            assert_eq!(committed(&cards, card)?, U96::from(60));

            // A frozen card's holds cannot grow, but they shrink, capture and refund.
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Frozen,
                U96::from(100),
                0,
            )?;
            assert_eq!(
                f.adjust(first, 61).unwrap_err(),
                CardsError::card_inactive().into()
            );
            f.adjust(first, 55)?;
            assert_eq!(committed(&cards, card)?, U96::from(55));
            f.capture(first, 70)?;
            assert_eq!(committed(&cards, card)?, U96::from(70));
            f.refund(f.payee, first, 20)?;
            assert_eq!(committed(&cards, card)?, U96::from(50));

            // The replacement keeps the line's limit and what it committed.
            let next = B256::random();
            cards.replace_card(f.payee, ICards::replaceCardCall { card, next })?;
            hold_card(&mut f, B256::random(), 50, next)?;
            assert_eq!(committed(&cards, next)?, U96::from(100));
            assert_eq!(
                hold_card(&mut f, B256::random(), 1, next).unwrap_err(),
                CardsError::card_limit_exceeded().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_card_scoped_key_holds_only_through_cards() -> eyre::Result<()> {
        at_t15(|| {
            let f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_key_for(
                f.owner,
                key,
                f.token.address(),
                500,
                &[
                    IReservations::holdCardCall::SELECTOR,
                    IReservations::captureCall::SELECTOR,
                    IReservations::releaseCall::SELECTOR,
                ],
            )?;
            let validate = |input: Vec<u8>| {
                keychain.validate_call_scope_for_transaction(
                    f.owner,
                    key,
                    &TxKind::Call(RESERVATIONS_ADDRESS),
                    &input,
                )
            };
            validate(
                IReservations::holdCardCall {
                    token: f.token.address(),
                    id: B256::random(),
                    amount: 1,
                    expiresAt: EXPIRY,
                    payee: f.payee,
                    issuer: f.payee,
                    card: B256::random(),
                }
                .abi_encode(),
            )?;
            assert_eq!(
                validate(
                    IReservations::holdCall {
                        token: f.token.address(),
                        id: B256::random(),
                        amount: 1,
                        expiresAt: EXPIRY,
                        payee: f.payee,
                    }
                    .abi_encode()
                )
                .unwrap_err(),
                AccountKeychainError::call_not_allowed().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_card_line_hold_checks_the_card_and_the_line() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::from(300),
            )?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let payee = f.payee;
            let committed =
                |cards: &Cards| -> Result<U96> { Ok(cards.get_card(payee, card)?.committed) };

            // The card checks run first and count the line part against the card's limit.
            for (card, amount, error) in [
                (B256::random(), 10, CardsError::unknown_card()),
                (card, 301, CardsError::card_limit_exceeded()),
            ] {
                assert_eq!(
                    hold_card_on_line(&mut f, B256::random(), amount, 10, lender, line, card)
                        .unwrap_err(),
                    error.into()
                );
            }
            cards.set_program_tokens(
                f.payee,
                ICards::setProgramTokensCall {
                    tokens: vec![Address::random()],
                },
            )?;
            assert_eq!(
                hold_card_on_line(&mut f, B256::random(), 10, 10, lender, line, card).unwrap_err(),
                CardsError::token_not_allowed().into()
            );
            cards.set_program_tokens(f.payee, ICards::setProgramTokensCall { tokens: vec![] })?;

            // The line hold checks still apply: its part, the balance part and the bound payee.
            for (amount, part, error) in [
                (10, 11, ReservationsError::invalid_amount()),
                (200, 50, ReservationsError::insufficient_available()),
            ] {
                assert_eq!(
                    hold_card_on_line(&mut f, B256::random(), amount, part, lender, line, card)
                        .unwrap_err(),
                    error.into()
                );
            }
            assert_eq!(
                f.reservations
                    .hold(
                        f.owner,
                        IReservations::holdCall {
                            token: f.token.address(),
                            id: B256::random(),
                            amount: 10,
                            expiresAt: EXPIRY,
                            payee: Address::random(),
                        },
                        Placement::CardLine {
                            issuer: f.payee,
                            card,
                            part: 10,
                            line,
                            lender,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );

            // A frozen card stops holds its credit line would fund.
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Frozen,
                U96::from(300),
                0,
            )?;
            assert_eq!(
                hold_card_on_line(&mut f, B256::random(), 300, 200, lender, line, card)
                    .unwrap_err(),
                CardsError::card_inactive().into()
            );
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Active,
                U96::from(300),
                0,
            )?;

            let id = B256::random();
            f.reservations.clear_emitted_events();
            hold_card_on_line(&mut f, id, 300, 200, lender, line, card)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_placed(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    300,
                    EXPIRY,
                ),
                ReservationsEvent::card_hold_placed(f.owner, id, card, 1),
                ReservationsEvent::credit_held(f.owner, id, lender, line, 200),
            ]);
            assert_eq!(f.reserved()?, 100);
            assert_eq!(f.credit(lender, line)?, (500, 0, 200));
            assert_eq!(committed(&cards)?, U96::from(300));

            // An increase rechecks the card; a frozen card's hold still shrinks, captures and refunds.
            assert_eq!(
                f.adjust(id, 301).unwrap_err(),
                CardsError::card_limit_exceeded().into()
            );
            update_card(
                &mut cards,
                &f,
                card,
                ICards::Status::Frozen,
                U96::from(300),
                0,
            )?;
            f.adjust(id, 250)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 150));
            assert_eq!(committed(&cards)?, U96::from(250));
            f.capture(id, 250)?;
            assert_eq!(f.balance(f.payee)?, U256::from(250));
            assert_eq!(f.credit(lender, line)?, (500, 150, 0));
            assert_eq!(committed(&cards)?, U96::from(250));
            // Refunds repay the line first and give back the card's committed amount.
            f.refund(f.payee, id, 100)?;
            assert_eq!(f.credit(lender, line)?, (500, 50, 0));
            assert_eq!(committed(&cards)?, U96::from(150));
            f.refund(f.payee, id, 150)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(committed(&cards)?, U96::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_card_scoped_key_holds_lines_only_through_cards() -> eyre::Result<()> {
        at_t15(|| {
            let f = Fixture::new(1_000)?;
            let key = Address::random();
            let keychain = authorize_key_for(
                f.owner,
                key,
                f.token.address(),
                500,
                &[
                    IReservations::holdCardCall::SELECTOR,
                    IReservations::holdCardWithLineCall::SELECTOR,
                    IReservations::captureCall::SELECTOR,
                    IReservations::releaseCall::SELECTOR,
                ],
            )?;
            let validate = |input: Vec<u8>| {
                keychain.validate_call_scope_for_transaction(
                    f.owner,
                    key,
                    &TxKind::Call(RESERVATIONS_ADDRESS),
                    &input,
                )
            };
            let (line, lender) = (B256::random(), Address::random());
            validate(
                IReservations::holdCardWithLineCall {
                    token: f.token.address(),
                    id: B256::random(),
                    amount: 1,
                    linePart: 1,
                    line,
                    lender,
                    expiresAt: EXPIRY,
                    payee: f.payee,
                    issuer: f.payee,
                    card: B256::random(),
                }
                .abi_encode(),
            )?;
            assert_eq!(
                validate(
                    IReservations::holdWithLineCall {
                        token: f.token.address(),
                        id: B256::random(),
                        amount: 1,
                        linePart: 1,
                        line,
                        lender,
                        expiresAt: EXPIRY,
                        payee: f.payee,
                    }
                    .abi_encode()
                )
                .unwrap_err(),
                AccountKeychainError::call_not_allowed().into()
            );
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

    #[test]
    fn test_card_and_line_holds_add_no_authorization_slot() {
        use __packing_authorization::{
            CARD_LINE_LOC, COUNTED_LOC, LINE_LOC, SLOT_COUNT, STAND_IN_LOC,
        };
        assert_eq!(SLOT_COUNT, 5);
        for loc in [STAND_IN_LOC, CARD_LINE_LOC, LINE_LOC] {
            assert_eq!(loc.offset_slots, COUNTED_LOC.offset_slots);
        }
        const {
            assert!(CARD_LINE_LOC.offset_bytes + CARD_LINE_LOC.size <= LINE_LOC.offset_bytes);
            assert!(LINE_LOC.offset_bytes + LINE_LOC.size <= 32);
        }
    }

    #[test]
    fn test_spend_window_and_merchant_mandates_bound_card_holds() -> eyre::Result<()> {
        // 1970-02-01 and 1970-03-01, UTC.
        const FEB: u32 = 2_678_400;
        const MAR: u32 = 5_097_600;
        const LATE: u64 = FEB as u64 + 600;
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::from(1_000),
            )?;
            let (owner, payee) = (f.owner, f.payee);
            let merchant = B256::random();
            cards.set_spend_window(
                owner,
                ICards::setSpendWindowCall {
                    issuer: payee,
                    firstEnd: FEB,
                    limit: U96::from(100),
                },
            )?;
            cards.set_merchant_mandate(
                owner,
                ICards::setMerchantMandateCall {
                    issuer: payee,
                    merchant,
                    revoked: false,
                    limit: U96::from(30),
                },
            )?;
            let window = |cards: &Cards| -> Result<(u32, U96)> {
                let w = cards.spend_window(owner, payee)?;
                Ok((w.periodEnd, w.committed))
            };
            let at_merchant = |cards: &Cards| -> Result<U96> {
                Ok(cards.merchant_mandate(owner, payee, merchant)?.committed)
            };

            // The merchant's limit and the window's both bound new holds.
            let streaming = B256::random();
            hold_card_for(&mut f, streaming, 20, card, merchant, LATE)?;
            assert_eq!(
                hold_card_for(&mut f, B256::random(), 11, card, merchant, LATE).unwrap_err(),
                CardsError::window_limit_exceeded().into()
            );
            assert_eq!(
                f.adjust(streaming, 31).unwrap_err(),
                CardsError::window_limit_exceeded().into()
            );
            let gym = B256::random();
            hold_card_for(&mut f, gym, 70, card, B256::random(), LATE)?;
            assert_eq!(
                hold_card(&mut f, B256::random(), 11, card).unwrap_err(),
                CardsError::window_limit_exceeded().into()
            );
            assert_eq!(window(&cards)?, (FEB, U96::from(90)));
            assert_eq!(at_merchant(&cards)?, U96::from(20));

            // Give-backs restore both.
            f.reservations.release(owner, streaming)?;
            assert_eq!(window(&cards)?, (FEB, U96::from(70)));
            assert_eq!(at_merchant(&cards)?, U96::ZERO);

            // A revoked merchant can neither hold nor grow a hold; its holds still shrink.
            let next = B256::random();
            hold_card_for(&mut f, next, 10, card, merchant, LATE)?;
            cards.set_merchant_mandate(
                owner,
                ICards::setMerchantMandateCall {
                    issuer: payee,
                    merchant,
                    revoked: true,
                    limit: U96::from(30),
                },
            )?;
            assert_eq!(
                hold_card_for(&mut f, B256::random(), 1, card, merchant, LATE).unwrap_err(),
                CardsError::merchant_revoked().into()
            );
            assert_eq!(
                f.adjust(next, 11).unwrap_err(),
                CardsError::merchant_revoked().into()
            );
            f.adjust(next, 5)?;
            assert_eq!(window(&cards)?, (FEB, U96::from(75)));

            // A new month starts at zero; holds counted in the last one give nothing back to it.
            StorageCtx.set_timestamp(U256::from(FEB));
            assert_eq!(window(&cards)?, (MAR, U96::ZERO));
            f.reservations.release(owner, gym)?;
            assert_eq!(window(&cards)?, (MAR, U96::ZERO));

            // The window follows the account, not the card, across a replacement.
            let replacement = B256::random();
            cards.replace_card(
                payee,
                ICards::replaceCardCall {
                    card,
                    next: replacement,
                },
            )?;
            hold_card_for(
                &mut f,
                B256::random(),
                100,
                replacement,
                B256::random(),
                LATE,
            )?;
            assert_eq!(
                hold_card_for(&mut f, B256::random(), 1, replacement, B256::ZERO, LATE)
                    .unwrap_err(),
                CardsError::window_limit_exceeded().into()
            );

            // Stand-in approvals are recorded past the window, and counted in it.
            f.reservations.hold(
                owner,
                IReservations::holdCall {
                    token: f.token.address(),
                    id: B256::random(),
                    amount: 5,
                    expiresAt: LATE,
                    payee,
                },
                Placement::CardStandIn {
                    issuer: payee,
                    card: replacement,
                },
            )?;
            assert_eq!(window(&cards)?, (MAR, U96::from(105)));

            // Only the root key sets windows and mandates.
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(owner)?;
            keychain.set_transaction_key(Address::random())?;
            assert_eq!(
                cards
                    .set_spend_window(
                        owner,
                        ICards::setSpendWindowCall {
                            issuer: payee,
                            firstEnd: 0,
                            limit: U96::ZERO,
                        },
                    )
                    .unwrap_err(),
                CardsError::unauthorized().into()
            );
            Ok(())
        })
    }

    /// Holds `amount` through the owner's `card` for `merchant` under the fixture's payee.
    fn hold_card_for(
        f: &mut Fixture,
        id: B256,
        amount: u128,
        card: B256,
        merchant: B256,
        expires_at: u64,
    ) -> Result<()> {
        f.reservations.hold(
            f.owner,
            IReservations::holdCall {
                token: f.token.address(),
                id,
                amount,
                expiresAt: expires_at,
                payee: f.payee,
            },
            Placement::CardMerchant {
                issuer: f.payee,
                card,
                merchant,
            },
        )
    }

    /// Has the fixture's payee issue `card` on `owner`'s account.
    fn issue_card(
        cards: &mut Cards,
        f: &Fixture,
        owner: Address,
        card: B256,
        status: ICards::Status,
        limit: U96,
    ) -> Result<()> {
        cards.issue_card(
            f.payee,
            ICards::issueCardCall {
                owner,
                card,
                status,
                limit,
                expiresAt: 0,
                program: ICards::Program::Debit,
                holder: B256::ZERO,
            },
        )
    }

    /// Has the fixture's payee set `card`'s status, limit and expiry.
    fn update_card(
        cards: &mut Cards,
        f: &Fixture,
        card: B256,
        status: ICards::Status,
        limit: U96,
        expires_at: u64,
    ) -> Result<()> {
        cards.update_card(
            f.payee,
            ICards::updateCardCall {
                card,
                status,
                limit,
                expiresAt: expires_at,
                program: ICards::Program::Debit,
                holder: B256::ZERO,
            },
        )
    }

    /// Holds `amount` of the fixture's token through the owner's `card` under the fixture's payee.
    fn hold_card(f: &mut Fixture, id: B256, amount: u128, card: B256) -> Result<()> {
        f.reservations.hold(
            f.owner,
            IReservations::holdCall {
                token: f.token.address(),
                id,
                amount,
                expiresAt: EXPIRY,
                payee: f.payee,
            },
            Placement::Card {
                issuer: f.payee,
                card,
            },
        )
    }

    /// Records a stand-in approval of `amount` through the owner's `card` under the fixture's payee.
    fn hold_card_stand_in(f: &mut Fixture, id: B256, amount: u128, card: B256) -> Result<()> {
        f.reservations.hold(
            f.owner,
            IReservations::holdCall {
                token: f.token.address(),
                id,
                amount,
                expiresAt: EXPIRY,
                payee: f.payee,
            },
            Placement::CardStandIn {
                issuer: f.payee,
                card,
            },
        )
    }

    /// Holds `amount` through the owner's `card` under the fixture's payee, with `part` of it on
    /// `lender`'s `line`.
    fn hold_card_on_line(
        f: &mut Fixture,
        id: B256,
        amount: u128,
        part: u128,
        lender: Address,
        line: B256,
        card: B256,
    ) -> Result<()> {
        f.reservations.hold(
            f.owner,
            IReservations::holdCall {
                token: f.token.address(),
                id,
                amount,
                expiresAt: EXPIRY,
                payee: f.payee,
            },
            Placement::CardLine {
                issuer: f.payee,
                card,
                part,
                line,
                lender,
            },
        )
    }

    #[test]
    fn test_credit_line_liens_the_lender_and_pays_a_hold() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(5_000, 1_000)?;
            // The undrawn limit is reserved on the lender's own balance, which still counts it.
            assert_eq!(f.reservation_of(lender)?, (1_000, 4_000));
            assert_eq!(f.balance(lender)?, U256::from(5_000));
            assert_eq!(
                f.reservations.get_line(lender, line)?,
                IReservations::getLineReturn {
                    token: f.token.address(),
                    lien: 1_000
                }
            );
            // The lender cannot transfer the liened part.
            assert_eq!(
                f.transfer(lender, Address::random(), 4_500).unwrap_err(),
                TIP20Error::insufficient_balance(
                    U256::from(4_000),
                    U256::from(4_500),
                    f.token.address()
                )
                .into()
            );

            let id = B256::random();
            f.reservations.clear_emitted_events();
            f.hold_on_line(id, 400, 400, lender, line)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_placed(
                    f.owner,
                    id,
                    f.token.address(),
                    f.payee,
                    400,
                    EXPIRY,
                ),
                ReservationsEvent::credit_held(f.owner, id, lender, line, 400),
            ]);
            assert_eq!(f.credit(lender, line)?, (1_000, 0, 400));
            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.reservations.get_hold(f.owner, id)?.amount, 400);

            f.reservations.clear_emitted_events();
            f.capture(id, 400)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 600),
                ReservationsEvent::credit_drawn(f.owner, id, lender, line, 400),
                ReservationsEvent::hold_captured(f.owner, id, f.token.address(), 400, 0),
            ]);
            // The lender paid the payee; the owner owes the line and has no debt.
            assert_eq!(f.balance(f.payee)?, U256::from(400));
            assert_eq!(f.balance(lender)?, U256::from(4_600));
            assert_eq!(f.reservation_of(lender)?, (600, 4_000));
            assert_eq!(f.credit(lender, line)?, (1_000, 400, 0));
            assert_eq!(f.debt()?.amount, 0);
            // A credit to the owner does not repay the line.
            f.mint(f.owner, 100)?;
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(f.credit(lender, line)?, (1_000, 400, 0));
            Ok(())
        })
    }

    #[test]
    fn test_line_pays_after_the_balance_and_before_debt() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 300, 200, lender, line)?;
            assert_eq!(f.reserved()?, 100);
            assert_eq!(f.available()?, 0);
            // Money arriving after the hold pays before the line.
            f.mint(f.owner, 50)?;
            f.capture(id, 300)?;
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.credit(lender, line)?, (500, 150, 0));
            assert_eq!(f.reservation_of(lender)?, (350, 500));

            // Past the hold's line part, the rest is debt within the cap.
            f.set_debt_cap(f.payee, 30)?;
            let over = B256::random();
            f.hold_on_line(over, 100, 100, lender, line)?;
            f.reservations.clear_emitted_events();
            f.capture(over, 130)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 250),
                ReservationsEvent::credit_drawn(f.owner, over, lender, line, 100),
                ReservationsEvent::hold_captured(f.owner, over, f.token.address(), 130, 30),
            ]);
            assert_eq!(f.credit(lender, line)?, (500, 250, 0));
            assert_eq!(f.debt()?.amount, 30);
            assert_eq!(f.balance(f.payee)?, U256::from(400));

            // A capture below the hold leaves the unused line part undrawn and the lien in place.
            let under = B256::random();
            f.hold_on_line(under, 200, 200, lender, line)?;
            f.capture(under, 50)?;
            assert_eq!(f.credit(lender, line)?, (500, 300, 0));
            assert_eq!(f.reservation_of(lender)?, (200, 500));
            Ok(())
        })
    }

    #[test]
    fn test_part_capture_takes_the_balance_part_first() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 300, 200, lender, line)?;
            f.capture_part(id, 150, false)?;
            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.credit(lender, line)?, (500, 50, 150));
            assert_eq!(f.reservations.get_hold(f.owner, id)?.amount, 150);
            f.capture(id, 150)?;
            assert_eq!(f.credit(lender, line)?, (500, 200, 0));
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.captured(id)?, (300, 0));
            Ok(())
        })
    }

    #[test]
    fn test_refund_repays_the_line_first() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 300, 200, lender, line)?;
            f.capture(id, 300)?;
            assert_eq!(f.credit(lender, line)?, (500, 200, 0));
            assert_eq!(f.reservation_of(lender)?, (300, 500));

            f.reservations.clear_emitted_events();
            f.refund(f.payee, id, 50)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 350),
                ReservationsEvent::credit_repaid(f.owner, lender, line, 50),
                ReservationsEvent::refunded(f.owner, id, 50),
            ]);
            // The line is repaid and its lien restored; nothing lands with the owner.
            assert_eq!(f.credit(lender, line)?, (500, 150, 0));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(f.balance(lender)?, U256::from(850));
            assert_eq!(f.reservation_of(lender)?, (350, 500));

            // Past what the line paid, the refund lands as balance.
            f.refund(f.payee, id, 250)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(f.reservation_of(lender)?, (500, 500));
            assert_eq!(f.balance(f.payee)?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_refund_repays_only_what_the_line_is_still_owed() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 200, 200, lender, line)?;
            f.capture(id, 200)?;
            f.mint(f.owner, 150)?;
            f.repay_credit(lender, line, 150)?;
            assert_eq!(f.credit(lender, line)?, (500, 50, 0));
            f.refund(f.payee, id, 200)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(150));
            assert_eq!(f.reservation_of(lender)?, (500, 500));
            Ok(())
        })
    }

    #[test]
    fn test_repay_credit_from_the_available_balance() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 200, 200, lender, line)?;
            f.capture(id, 200)?;
            f.mint(f.owner, 300)?;
            let held = B256::random();
            f.hold(held, 250)?;
            assert_eq!(
                f.repay_credit(lender, line, 100).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            f.reservations.release(f.owner, held)?;
            f.reservations.clear_emitted_events();
            // Repayment stops at what is owed.
            f.repay_credit(lender, line, 1_000)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 500),
                ReservationsEvent::credit_repaid(f.owner, lender, line, 200),
            ]);
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(f.reservation_of(lender)?, (500, 500));
            // Nothing owed repays nothing.
            f.repay_credit(lender, line, 10)?;
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(
                f.repay_credit(lender, line, 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            assert_eq!(
                f.repay_credit(lender, B256::random(), 10).unwrap_err(),
                ReservationsError::line_not_found().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_line_holds_stay_within_the_limits() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            assert_eq!(
                f.hold_on_line(B256::random(), 501, 501, lender, line)
                    .unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            assert_eq!(
                f.hold_on_line(B256::random(), 650, 500, lender, line)
                    .unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            for part in [0, 101] {
                assert_eq!(
                    f.hold_on_line(B256::random(), 100, part, lender, line)
                        .unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
            }
            assert_eq!(
                f.hold_on_line(B256::random(), 100, 50, lender, B256::random())
                    .unwrap_err(),
                ReservationsError::line_not_found().into()
            );
            // A line in another token pays nothing in this one.
            let other = TIP20Setup::create("Other USD", "OUSD", f.admin).apply()?;
            let elsewhere = B256::random();
            f.reservations.open_line(
                lender,
                IReservations::openLineCall {
                    line: elsewhere,
                    token: other.address(),
                },
            )?;
            assert_eq!(
                f.hold_on_line(B256::random(), 100, 50, lender, elsewhere)
                    .unwrap_err(),
                ReservationsError::line_not_found().into()
            );
            // The lender agreed to pay only its payee.
            assert_eq!(
                f.reservations
                    .hold(
                        f.owner,
                        IReservations::holdCall {
                            token: f.token.address(),
                            id: B256::random(),
                            amount: 100,
                            expiresAt: EXPIRY,
                            payee: Address::random(),
                        },
                        Placement::Line {
                            part: 50,
                            line,
                            lender,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            // Holds share the line: the second gets only what the first left.
            f.hold_on_line(B256::random(), 400, 400, lender, line)?;
            assert_eq!(
                f.hold_on_line(B256::random(), 101, 101, lender, line)
                    .unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            f.hold_on_line(B256::random(), 100, 100, lender, line)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 500));
            Ok(())
        })
    }

    #[test]
    fn test_grant_needs_the_lenders_offer() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let lender = Address::random();
            let line = B256::random();
            f.mint(lender, 1_000)?;
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 100).unwrap_err(),
                ReservationsError::line_not_found().into()
            );
            let open = IReservations::openLineCall {
                line,
                token: f.token.address(),
            };
            f.reservations.open_line(lender, open.clone())?;
            assert_eq!(
                f.reservations.open_line(lender, open).unwrap_err(),
                ReservationsError::line_exists().into()
            );
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 100).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            f.offer_credit(lender, line, f.payee, 300)?;
            assert_eq!(
                f.reservations.credit_offer(lender, line, f.owner)?,
                IReservations::creditOfferReturn {
                    payee: f.payee,
                    limit: 300
                }
            );
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 301).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            assert_eq!(
                f.grant_credit(lender, line, Address::random(), 100)
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            // The lender's offer does not let anyone else borrow on it.
            assert_eq!(
                f.reservations
                    .grant_credit(
                        Address::random(),
                        IReservations::grantCreditCall {
                            line,
                            lender,
                            payee: f.payee,
                            limit: 100,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            assert_eq!(
                f.reservations
                    .grant_credit(
                        lender,
                        IReservations::grantCreditCall {
                            line,
                            lender,
                            payee: f.payee,
                            limit: 100,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            // Only the owner's root key accepts credit.
            let key = Address::random();
            authorize_card_key(f.owner, key, f.token.address(), 1_000)?;
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 100).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            AccountKeychain::new().set_transaction_key(Address::ZERO)?;
            f.grant_credit(lender, line, f.payee, 300)?;
            assert_eq!(f.credit(lender, line)?, (300, 0, 0));
            assert_eq!(f.reservation_of(lender)?, (300, 700));
            // The owner may lower its own limit without a new offer, never raise it.
            f.offer_credit(lender, line, f.payee, 0)?;
            assert_eq!(f.credit(lender, line)?, (0, 0, 0));
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 1).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            f.grant_credit(lender, line, f.payee, 0)?;
            // A grant past what the lender has available reverts.
            f.offer_credit(lender, line, f.payee, 2_000)?;
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 1_001).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            f.grant_credit(lender, line, f.payee, 1_000)?;
            assert_eq!(f.reservation_of(lender)?, (1_000, 0));
            // Acceptance consumes the offer: raising again needs a fresh one.
            assert_eq!(
                f.reservations.credit_offer(lender, line, f.owner)?,
                IReservations::creditOfferReturn {
                    payee: Address::ZERO,
                    limit: 0
                }
            );
            f.mint(lender, 1_000)?;
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 1_500).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_offer_credit_requires_the_lenders_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let lender = Address::random();
            let line = B256::random();
            assert_eq!(
                f.offer_credit(lender, line, f.payee, 100).unwrap_err(),
                ReservationsError::line_not_found().into()
            );
            f.reservations.open_line(
                lender,
                IReservations::openLineCall {
                    line,
                    token: f.token.address(),
                },
            )?;
            assert_eq!(
                f.reservations
                    .offer_credit(
                        lender,
                        IReservations::offerCreditCall {
                            line,
                            owner: lender,
                            payee: f.payee,
                            limit: 100,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            authorize_card_key(lender, Address::random(), f.token.address(), 1_000)?;
            assert_eq!(
                f.offer_credit(lender, line, f.payee, 100).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_lowering_a_limit_keeps_open_holds_funded() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let first = B256::random();
            let second = B256::random();
            f.hold_on_line(first, 200, 200, lender, line)?;
            f.hold_on_line(second, 100, 100, lender, line)?;
            // The lender cuts the line to 50: open holds keep their 300 reserved.
            f.reservations.clear_emitted_events();
            f.offer_credit(lender, line, f.payee, 50)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::credit_offered(lender, line, f.owner, f.payee, 50),
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 300),
                ReservationsEvent::credit_granted(f.owner, lender, line, f.payee, 50),
            ]);
            assert_eq!(f.credit(lender, line)?, (50, 0, 300));
            assert_eq!(f.reservation_of(lender)?, (300, 700));
            assert_eq!(
                f.hold_on_line(B256::random(), 1, 1, lender, line)
                    .unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            // A capture still draws in full; the rest of the lien goes back as holds settle.
            f.capture(first, 200)?;
            assert_eq!(f.credit(lender, line)?, (50, 200, 100));
            assert_eq!(f.reservation_of(lender)?, (100, 700));
            f.reservations.release(f.owner, second)?;
            assert_eq!(f.credit(lender, line)?, (50, 200, 0));
            assert_eq!(f.reservation_of(lender)?, (0, 800));
            // Repayments below the limit restore its undrawn part only.
            f.mint(f.owner, 200)?;
            f.repay_credit(lender, line, 180)?;
            assert_eq!(f.credit(lender, line)?, (50, 20, 0));
            assert_eq!(f.reservation_of(lender)?, (30, 950));
            Ok(())
        })
    }

    #[test]
    fn test_adjust_moves_a_line_hold_after_the_balance() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 150, 100, lender, line)?;
            assert_eq!(f.reserved()?, 50);
            f.reservations.clear_emitted_events();
            // An increase takes the free balance first, then the line.
            f.adjust(id, 250)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_adjusted(f.owner, id, f.token.address(), 250),
                ReservationsEvent::credit_held(f.owner, id, lender, line, 150),
            ]);
            assert_eq!(f.reserved()?, 100);
            assert_eq!(f.credit(lender, line)?, (500, 0, 150));
            assert_eq!(
                f.adjust(id, 601).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            // A decrease comes off the line first.
            f.adjust(id, 120)?;
            assert_eq!(f.reserved()?, 100);
            assert_eq!(f.credit(lender, line)?, (500, 0, 20));
            f.adjust(id, 60)?;
            assert_eq!(f.reserved()?, 60);
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            f.reservations.release(f.owner, id)?;
            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.reservation_of(lender)?, (500, 500));
            Ok(())
        })
    }

    #[test]
    fn test_line_holds_count_against_the_mandate_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let key = Address::random();
            let keychain = authorize_card_key(f.owner, key, f.token.address(), 500)?;
            let remaining = remaining_limit(&keychain, f.owner, key, f.token.address());
            let id = B256::random();
            f.hold_on_line(id, 400, 300, lender, line)?;
            assert_eq!(remaining()?, U256::from(100));
            f.capture(id, 400)?;
            assert_eq!(remaining()?, U256::from(100));
            // A refund gives back the line's part as well, once it repaid the line.
            f.refund(f.payee, id, 400)?;
            assert_eq!(remaining()?, U256::from(500));
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            Ok(())
        })
    }

    #[test]
    fn test_payee_captures_a_line_hold() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 200, 200, lender, line)?;
            assert_eq!(
                f.capture_for(f.payee, id, 201).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.capture_for(f.payee, id, 200)?;
            assert_eq!(f.credit(lender, line)?, (500, 200, 0));
            assert_eq!(f.balance(f.payee)?, U256::from(200));
            Ok(())
        })
    }

    #[test]
    fn test_expired_line_hold_releases_the_line() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 200, 200, lender, line)?;
            StorageCtx.set_timestamp(U256::from(EXPIRY));
            f.reservations.release_expired(f.owner, id)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.reservation_of(lender)?, (500, 500));
            // The id is free again, and a plain hold under it never reads the old line part.
            f.mint(f.owner, 50)?;
            f.hold_until(id, 50, EXPIRY + 10)?;
            f.capture(id, 50)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            Ok(())
        })
    }

    #[test]
    fn test_grant_consumes_the_offer() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(0)?;
            let lender = Address::random();
            let line = B256::random();
            f.mint(lender, 1_000)?;
            f.reservations.open_line(
                lender,
                IReservations::openLineCall {
                    line,
                    token: f.token.address(),
                },
            )?;
            f.offer_credit(lender, line, f.payee, 300)?;
            f.grant_credit(lender, line, f.payee, 200)?;
            // The rest of the offer is gone once accepted.
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 300).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            // Once the lender lowers the line, the owner cannot restore it alone.
            f.offer_credit(lender, line, f.payee, 50)?;
            assert_eq!(f.credit(lender, line)?, (50, 0, 0));
            assert_eq!(f.reservation_of(lender)?, (50, 950));
            assert_eq!(
                f.grant_credit(lender, line, f.payee, 200).unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            // Re-granting the current limit needs no offer; a payee change needs one.
            f.grant_credit(lender, line, f.payee, 50)?;
            assert_eq!(
                f.grant_credit(lender, line, Address::random(), 50)
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
            // A line bound to its payee funds no hold for another.
            assert_eq!(
                f.reservations
                    .hold(
                        f.owner,
                        IReservations::holdCall {
                            token: f.token.address(),
                            id: B256::random(),
                            amount: 10,
                            expiresAt: EXPIRY,
                            payee: Address::random(),
                        },
                        Placement::Line {
                            part: 10,
                            line,
                            lender,
                        },
                    )
                    .unwrap_err(),
                ReservationsError::credit_not_offered().into()
            );
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
        authorize_key_for(
            account,
            key,
            token,
            limit,
            &[
                IReservations::holdCall::SELECTOR,
                IReservations::holdStandInCall::SELECTOR,
                IReservations::adjustCall::SELECTOR,
                IReservations::captureCall::SELECTOR,
                IReservations::capturePartCall::SELECTOR,
                IReservations::chargeCall::SELECTOR,
                IReservations::chargeStandInCall::SELECTOR,
                IReservations::releaseCall::SELECTOR,
            ],
        )
    }

    /// Authorizes an access key on `account` with a `limit` on `token`, scoped to `selectors` of
    /// the reservations precompile, and makes it sign the current transaction.
    fn authorize_key_for(
        account: Address,
        key: Address,
        token: Address,
        limit: u64,
        selectors: &[[u8; 4]],
    ) -> Result<AccountKeychain> {
        let mut keychain = AccountKeychain::new();
        keychain.initialize()?;
        keychain.set_tx_origin(account)?;
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
                        .iter()
                        .map(|selector| IAccountKeychain::SelectorRule {
                            selector: (*selector).into(),
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

    impl Fixture {
        fn open_dispute(&mut self, id: B256, amount: u128) -> Result<()> {
            self.reservations.open_dispute(
                self.payee,
                IReservations::openDisputeCall {
                    owner: self.owner,
                    id,
                    amount,
                    evidence: B256::repeat_byte(0xc1),
                },
            )
        }

        fn dispute_step(&mut self, id: B256, state: u8, provisional: u128) -> Result<()> {
            self.reservations.dispute_step(
                self.payee,
                IReservations::disputeStepCall {
                    owner: self.owner,
                    id,
                    state,
                    provisional,
                    evidence: B256::ZERO,
                    merchantEvidence: false,
                },
            )
        }

        fn resolve_dispute(
            &mut self,
            id: B256,
            cardholder_wins: bool,
            collected: u128,
        ) -> Result<()> {
            self.reservations.resolve_dispute(
                self.payee,
                IReservations::resolveDisputeCall {
                    owner: self.owner,
                    id,
                    cardholderWins: cardholder_wins,
                    collected,
                },
            )
        }

        /// The dispute's state, amount, provisional credit and line share.
        fn dispute(&self, id: B256) -> Result<(u8, u128, u128, u128)> {
            let dispute = self.reservations.dispute_of(self.owner, id)?;
            Ok((
                dispute.state,
                dispute.amount,
                dispute.provisional,
                dispute.lineShare,
            ))
        }

        /// Places a reserve of `amount` on `account` for `payee` naming the dispute on the owner's `disputed` record.
        fn reserve(
            &mut self,
            account: Address,
            id: B256,
            amount: u128,
            expires_at: u64,
            payee: Address,
            disputed: B256,
        ) -> Result<()> {
            self.reservations.hold(
                account,
                IReservations::holdCall {
                    token: self.token.address(),
                    id,
                    amount,
                    expiresAt: expires_at,
                    payee,
                },
                Placement::Dispute {
                    owner: self.owner,
                    id: disputed,
                },
            )
        }
    }

    #[test]
    fn test_lost_dispute_takes_the_provisional_credit_back() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            f.hold(id, 80)?;
            f.capture(id, 80)?;
            f.reservations.clear_emitted_events();
            f.open_dispute(id, 80)?;
            f.dispute_step(id, 2, 80)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::dispute_opened(f.owner, id, 80, B256::repeat_byte(0xc1)),
                ReservationsEvent::dispute_stepped(f.owner, id, 2, 80, B256::ZERO, false),
            ]);
            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(f.balance(f.payee)?, U256::ZERO);
            // Provisional credit is not refunded: the record still nets the purchase.
            assert_eq!(f.captured(id)?, (80, 0));
            f.transfer(f.owner, Address::random(), 90)?;
            f.dispute_step(id, 3, 0)?;
            // States only move forward, and a step never resolves.
            for state in [3, 2, 6, 7] {
                assert_eq!(
                    f.dispute_step(id, state, 0).unwrap_err(),
                    ReservationsError::invalid_dispute_step().into()
                );
            }
            f.dispute_step(id, 5, 0)?;

            f.reservations.clear_emitted_events();
            f.resolve_dispute(id, false, 0)?;
            // The balance comes back first and the rest is debt past the zero cap.
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::dispute_resolved(
                    f.owner, id, false, 10, 70,
                )]);
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(
                f.debt()?,
                IReservations::debtOfReturn {
                    creditor: f.payee,
                    amount: 70
                }
            );
            assert_eq!(f.dispute(id)?, (7, 80, 80, 0));
            assert_eq!(
                f.dispute_step(id, 5, 0).unwrap_err(),
                ReservationsError::dispute_not_found().into()
            );
            assert_eq!(
                f.resolve_dispute(id, true, 0).unwrap_err(),
                ReservationsError::dispute_not_found().into()
            );
            // The next credit repays the payee first, with no fee.
            f.mint(f.owner, 100)?;
            assert_eq!(f.balance(f.owner)?, U256::from(30));
            assert_eq!(f.balance(f.payee)?, U256::from(80));
            assert_eq!(f.debt()?.amount, 0);
            // A lost dispute leaves the record open to refunds.
            f.refund(f.payee, id, 10)?;
            assert_eq!(f.captured(id)?, (80, 10));
            Ok(())
        })
    }

    #[test]
    fn test_dispute_calls_are_the_payees_within_the_refund_room() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            f.hold(id, 60)?;
            f.capture(id, 60)?;
            assert_eq!(
                f.dispute_step(id, 2, 0).unwrap_err(),
                ReservationsError::dispute_not_found().into()
            );
            let stranger = Address::random();
            let call = IReservations::openDisputeCall {
                owner: f.owner,
                id,
                amount: 10,
                evidence: B256::ZERO,
            };
            assert_eq!(
                f.reservations.open_dispute(stranger, call).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.open_dispute(B256::random(), 10).unwrap_err(),
                ReservationsError::hold_not_found().into()
            );
            assert_eq!(
                f.open_dispute(id, 0).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.refund(f.payee, id, 20)?;
            assert_eq!(
                f.open_dispute(id, 41).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            f.open_dispute(id, 30)?;
            assert_eq!(
                f.open_dispute(id, 30).unwrap_err(),
                ReservationsError::dispute_exists().into()
            );
            // Provisional credit stops at the disputed amount.
            assert_eq!(
                f.dispute_step(id, 2, 31).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            f.dispute_step(id, 2, 30)?;
            assert_eq!(f.dispute(id)?, (2, 30, 30, 0));

            // A refund past what the purchase still nets settles provisional credit instead of
            // paying it again: 20 refunded and 30 provisional leave 10 of the 60 captured.
            let before = f.balance(f.owner)?;
            f.reservations.clear_emitted_events();
            f.refund(f.payee, id, 15)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::dispute_settled(f.owner, id, 5),
                ReservationsEvent::refunded(f.owner, id, 15),
            ]);
            assert_eq!(f.balance(f.owner)?, before + U256::from(10));
            assert_eq!(f.dispute(id)?, (2, 30, 25, 0));
            // With no room left, provisional credit stops too.
            assert_eq!(
                f.dispute_step(id, 3, 1).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );

            let resolve = IReservations::resolveDisputeCall {
                owner: f.owner,
                id,
                cardholderWins: true,
                collected: 0,
            };
            assert_eq!(
                f.reservations
                    .resolve_dispute(stranger, resolve)
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.resolve_dispute(id, true, 1).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            // The win pays nothing more: the provisional credit already covers what is unrefunded.
            f.resolve_dispute(id, true, 0)?;
            assert_eq!(f.captured(id)?, (60, 60));
            assert_eq!(f.balance(f.owner)?, before + U256::from(10));
            assert_eq!(f.dispute(id)?, (6, 30, 25, 0));
            Ok(())
        })
    }

    #[test]
    fn test_won_dispute_refunds_the_rest_and_closes_the_record() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            f.hold(id, 50)?;
            f.capture(id, 50)?;
            f.open_dispute(id, 40)?;
            f.dispute_step(id, 2, 10)?;
            assert_eq!(f.balance(f.owner)?, U256::from(60));
            f.reservations.clear_emitted_events();
            f.resolve_dispute(id, true, 0)?;
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::dispute_resolved(
                    f.owner, id, true, 30, 0,
                )]);
            assert_eq!(f.balance(f.owner)?, U256::from(90));
            assert_eq!(f.balance(f.payee)?, U256::from(10));
            assert_eq!(f.captured(id)?, (50, 40));
            // The record is closed to refunds, even within what was never disputed.
            assert_eq!(
                f.refund(f.payee, id, 5).unwrap_err(),
                ReservationsError::refund_exceeds_capture().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_lost_dispute_debt_is_bounded() -> eyre::Result<()> {
        at_t15(|| {
            // Another creditor in the token blocks the clawback until it is repaid.
            let mut f = Fixture::new(50)?;
            let id = B256::random();
            f.hold(id, 50)?;
            f.capture(id, 50)?;
            f.open_dispute(id, 50)?;
            f.dispute_step(id, 2, 50)?;
            f.transfer(f.owner, Address::random(), 50)?;
            let other = Address::random();
            f.set_debt_cap(other, 10)?;
            f.charge(B256::random(), 10, other)?;
            assert_eq!(
                f.resolve_dispute(id, false, 0).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            assert_eq!(
                f.resolve_dispute(id, false, 51).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            f.mint(f.owner, 10)?;
            assert_eq!(f.debt()?.amount, 0);
            // What the payee collected elsewhere is not taken again.
            f.resolve_dispute(id, false, 20)?;
            assert_eq!(
                f.debt()?,
                IReservations::debtOfReturn {
                    creditor: f.payee,
                    amount: 30
                }
            );

            // Past the cap, debt grows only by the provisional credit the payee paid.
            let mut f = Fixture::new(10)?;
            f.set_debt_cap(f.payee, 100)?;
            let id = B256::random();
            f.charge(id, 100, f.payee)?;
            assert_eq!(f.debt()?.amount, 90);
            f.set_debt_cap(f.payee, 0)?;
            f.open_dispute(id, 100)?;
            // Provisional credit cancels debt owed to the payee first, as a refund does.
            f.dispute_step(id, 2, 5)?;
            assert_eq!(f.debt()?.amount, 85);
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(
                f.resolve_dispute(id, false, 0).unwrap_err(),
                ReservationsError::debt_cap_exceeded().into()
            );
            f.set_debt_cap(f.payee, 85)?;
            f.resolve_dispute(id, false, 0)?;
            assert_eq!(f.debt()?.amount, 90);
            Ok(())
        })
    }

    #[test]
    fn test_dispute_line_share_repays_and_redraws_the_line() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 300, 200, lender, line)?;
            f.capture(id, 300)?;
            assert_eq!(f.credit(lender, line)?, (500, 200, 0));
            f.open_dispute(id, 300)?;
            // Provisional credit repays the line first, as a refund does; the rest lands.
            f.dispute_step(id, 2, 250)?;
            assert_eq!(f.credit(lender, line)?, (500, 0, 0));
            assert_eq!(f.balance(f.owner)?, U256::from(50));
            assert_eq!(f.dispute(id)?, (2, 300, 250, 200));
            assert_eq!(f.balance(f.payee)?, U256::from(50));
            // Only the part that landed can have been collected elsewhere.
            assert_eq!(
                f.resolve_dispute(id, false, 51).unwrap_err(),
                ReservationsError::invalid_amount().into()
            );

            f.reservations.clear_emitted_events();
            f.resolve_dispute(id, false, 0)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::line_reserved(lender, line, f.token.address(), 300),
                ReservationsEvent::credit_drawn(f.owner, id, lender, line, 200),
                ReservationsEvent::dispute_resolved(f.owner, id, false, 50, 0),
            ]);
            assert_eq!(f.credit(lender, line)?, (500, 200, 0));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(f.balance(f.payee)?, U256::from(300));
            assert_eq!(f.reservation_of(lender)?, (300, 500));
            Ok(())
        })
    }

    #[test]
    fn test_dispute_line_share_redraws_only_the_undrawn_limit() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let (lender, line) = f.open_credit(1_000, 500)?;
            let id = B256::random();
            f.hold_on_line(id, 300, 200, lender, line)?;
            f.capture(id, 300)?;
            f.open_dispute(id, 300)?;
            f.dispute_step(id, 2, 250)?;
            // The lender lowers the limit, so only 100 goes back on the line.
            f.offer_credit(lender, line, f.payee, 100)?;
            f.resolve_dispute(id, false, 0)?;
            assert_eq!(f.credit(lender, line)?, (100, 100, 0));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            assert_eq!(f.debt()?.amount, 100);
            assert_eq!(f.balance(f.payee)?, U256::from(200));
            Ok(())
        })
    }

    #[test]
    fn test_dispute_reserve_holds() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            f.hold(id, 80)?;
            f.capture(id, 80)?;
            let merchant = Address::random();
            f.mint(merchant, 50)?;
            let reserve = B256::random();
            let longest = NOW + MAX_DISPUTE_HOLD_DURATION;
            assert_eq!(
                f.reserve(merchant, reserve, 30, longest, f.payee, id)
                    .unwrap_err(),
                ReservationsError::dispute_not_found().into()
            );
            f.open_dispute(id, 40)?;
            assert_eq!(
                f.reserve(merchant, reserve, 30, longest + 1, f.payee, id)
                    .unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            assert_eq!(
                f.reserve(merchant, reserve, 30, longest, Address::random(), id)
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            assert_eq!(
                f.reserve(merchant, reserve, 41, longest, f.payee, id)
                    .unwrap_err(),
                ReservationsError::invalid_amount().into()
            );
            // Only a hold naming an open dispute lasts past an authorization's 31 days.
            let plain = IReservations::holdCall {
                token: f.token.address(),
                id: reserve,
                amount: 30,
                expiresAt: longest,
                payee: f.payee,
            };
            assert_eq!(
                f.reservations
                    .hold(merchant, plain, Placement::Plain)
                    .unwrap_err(),
                ReservationsError::invalid_amount().into()
            );

            f.reservations.clear_emitted_events();
            f.reserve(merchant, reserve, 30, longest, f.payee, id)?;
            f.reservations.assert_emitted_events(vec![
                ReservationsEvent::hold_placed(
                    merchant,
                    reserve,
                    f.token.address(),
                    f.payee,
                    30,
                    longest,
                ),
                ReservationsEvent::dispute_hold_placed(merchant, reserve, f.owner, id),
            ]);
            assert_eq!(f.reservation_of(merchant)?, (30, 20));
            // The payee captures a reserve only once the cardholder won.
            assert_eq!(
                f.reservations
                    .capture_for_part(f.payee, merchant, reserve, 30, true)
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            f.resolve_dispute(id, true, 0)?;
            f.reservations
                .capture_for_part(f.payee, merchant, reserve, 30, true)?;
            assert_eq!(f.reservation_of(merchant)?, (0, 20));
            assert_eq!(f.balance(f.payee)?, U256::from(70));

            // A merchant win leaves the reserve to be released, which clears it.
            let second = B256::random();
            f.hold(second, 10)?;
            f.capture(second, 10)?;
            f.open_dispute(second, 10)?;
            let released = B256::random();
            f.reserve(merchant, released, 10, longest, f.payee, second)?;
            f.resolve_dispute(second, false, 0)?;
            assert_eq!(
                f.reservations
                    .capture_for_part(f.payee, merchant, released, 10, true)
                    .unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            f.reservations.release(merchant, released)?;
            assert_eq!(f.reservation_of(merchant)?, (0, 20));
            assert!(
                f.reservations.dispute_holds[merchant][released]
                    .read()?
                    .owner
                    .is_zero()
            );
            Ok(())
        })
    }

    impl Fixture {
        /// Grants a fresh authority the fixture token's `LIEN_ROLE`.
        fn lien_authority(&mut self) -> Result<Address> {
            let authority = Address::random();
            self.token.grant_role_internal(authority, LIEN_ROLE)?;
            Ok(authority)
        }

        fn lien(&mut self, authority: Address, id: B256, amount: u128) -> Result<()> {
            self.reservations.lien(
                authority,
                IReservations::lienCall {
                    owner: self.owner,
                    token: self.token.address(),
                    id,
                    amount,
                },
            )
        }

        fn liened(&self) -> Result<u128> {
            self.reservations
                .liened_of(self.owner, self.token.address())
        }
    }

    #[test]
    fn test_lien_reserves_ahead_of_holds_until_its_authority_releases() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let authority = f.lien_authority()?;
            let other = f.lien_authority()?;
            let id = B256::random();
            f.lien(authority, id, 60)?;

            assert_eq!(f.balance(f.owner)?, U256::from(100));
            assert_eq!(f.reserved()?, 60);
            assert_eq!(f.available()?, 40);
            assert_eq!(f.liened()?, 60);
            assert_eq!(
                f.reservations.lien_of(authority, id)?,
                IReservations::lienOfReturn {
                    owner: f.owner,
                    token: f.token.address(),
                    amount: 60,
                }
            );
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::liened(
                    f.owner,
                    authority,
                    f.token.address(),
                    id,
                    60,
                )]);
            assert_eq!(
                f.hold(B256::random(), 41).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            assert_eq!(
                f.transfer(f.owner, Address::random(), 41).unwrap_err(),
                TIP20Error::insufficient_balance(U256::from(40), U256::from(41), f.token.address())
                    .into()
            );
            assert_eq!(
                f.lien(authority, id, 1).unwrap_err(),
                ReservationsError::lien_exists().into()
            );
            // Ids are scoped per authority, and a lien takes only what is available.
            assert_eq!(
                f.lien(other, id, 41).unwrap_err(),
                ReservationsError::insufficient_available().into()
            );
            f.lien(other, id, 10)?;
            assert_eq!(f.liened()?, 70);

            // Only the placing authority finds its lien.
            assert_eq!(
                f.reservations.release_lien(f.owner, id).unwrap_err(),
                ReservationsError::lien_not_found().into()
            );
            f.reservations.clear_emitted_events();
            f.reservations.release_lien(authority, id)?;
            f.reservations
                .assert_emitted_events(vec![ReservationsEvent::lien_released(
                    f.owner,
                    authority,
                    f.token.address(),
                    id,
                    60,
                )]);
            assert_eq!(f.reserved()?, 10);
            assert_eq!(f.available()?, 90);
            assert_eq!(f.liened()?, 10);
            assert!(f.reservations.lien_of(authority, id)?.token.is_zero());
            assert_eq!(
                f.reservations.release_lien(authority, id).unwrap_err(),
                ReservationsError::lien_not_found().into()
            );
            // A released id can be used again.
            f.lien(authority, id, 90)?;
            assert_eq!(f.available()?, 0);
            Ok(())
        })
    }

    #[test]
    fn test_lien_needs_the_role_and_the_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let id = B256::random();
            let stranger = Address::random();
            assert_eq!(
                f.lien(stranger, id, 10).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            // The role is per token: another token's role does not count.
            let mut other_token = TIP20Setup::create("Other USD", "OUSD", f.admin).apply()?;
            other_token.grant_role_internal(stranger, LIEN_ROLE)?;
            assert_eq!(
                f.lien(stranger, id, 10).unwrap_err(),
                ReservationsError::unauthorized().into()
            );

            let authority = f.lien_authority()?;
            for amount in [0, 1u128 << 96] {
                assert_eq!(
                    f.lien(authority, id, amount).unwrap_err(),
                    ReservationsError::invalid_amount().into()
                );
            }
            assert_eq!(
                f.reservations
                    .lien(
                        authority,
                        IReservations::lienCall {
                            owner: Address::ZERO,
                            token: f.token.address(),
                            id,
                            amount: 1,
                        },
                    )
                    .unwrap_err(),
                TIP20Error::invalid_recipient().into()
            );

            // An access key of the authority cannot lien, whatever its scope.
            let key = Address::random();
            let mut keychain = authorize_key_for(
                authority,
                key,
                f.token.address(),
                1_000,
                &[IReservations::lienCall::SELECTOR],
            )?;
            assert_eq!(
                f.lien(authority, id, 10).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            keychain.set_tx_origin(Address::random())?;
            f.lien(authority, id, 10)?;

            // Revoking the role stops new liens but never strands placed ones.
            f.token.revoke_role(
                f.admin,
                IRolesAuth::revokeRoleCall {
                    role: LIEN_ROLE,
                    account: authority,
                },
            )?;
            assert_eq!(
                f.lien(authority, B256::random(), 10).unwrap_err(),
                ReservationsError::unauthorized().into()
            );
            f.reservations.release_lien(authority, id)?;
            assert_eq!(f.available()?, 100);
            Ok(())
        })
    }

    #[test]
    fn test_lien_on_a_virtual_address_applies_to_its_master() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            AddressRegistry::new()
                .register_virtual_master_unchecked(MasterId::repeat_byte(2), f.owner)?;
            let virtual_owner = Address::new_virtual(MasterId::repeat_byte(2), UserTag::ZERO);
            let authority = f.lien_authority()?;
            let id = B256::random();
            f.reservations.lien(
                authority,
                IReservations::lienCall {
                    owner: virtual_owner,
                    token: f.token.address(),
                    id,
                    amount: 30,
                },
            )?;
            assert_eq!(f.reservations.lien_of(authority, id)?.owner, f.owner);
            assert_eq!(f.liened()?, 30);
            assert_eq!(f.available()?, 70);
            Ok(())
        })
    }

    #[test]
    fn test_payments_and_debt_never_take_a_lien() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let authority = f.lien_authority()?;
            let lien = B256::random();
            let held = B256::random();
            f.hold(held, 40)?;
            f.lien(authority, lien, 60)?;

            // A capture above the hold pays from the available balance, then owes; never the lien.
            f.set_debt_cap(f.payee, 50)?;
            f.capture(held, 70)?;
            assert_eq!(f.balance(f.payee)?, U256::from(40));
            assert_eq!(f.debt()?.amount, 30);
            assert_eq!(f.reserved()?, 60);
            f.charge(B256::random(), 20, f.payee)?;
            assert_eq!(f.debt()?.amount, 50);
            assert_eq!(f.reserved()?, 60);
            // A stand-in hold records only what is available, which the lien is not.
            f.hold_stand_in(B256::random(), 10)?;
            assert_eq!(f.reserved()?, 60);

            // Credits repay debt first and land beside the lien, which does not grow.
            f.mint(f.owner, 30)?;
            assert_eq!(f.debt()?.amount, 20);
            assert_eq!(f.available()?, 0);
            assert_eq!(f.liened()?, 60);

            // A release is not a credit: the owner may spend it, and the debt stays.
            f.reservations.release_lien(authority, lien)?;
            assert_eq!(f.available()?, 60);
            assert_eq!(f.debt()?.amount, 20);
            assert_eq!(f.balance(f.payee)?, U256::from(70));
            Ok(())
        })
    }

    #[test]
    fn test_compliance_burns_take_liens_as_they_take_holds() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(1_000)?;
            let authority = f.lien_authority()?;
            let lien = B256::random();
            let held = B256::random();
            f.lien(authority, lien, 600)?;
            f.hold(held, 300)?;
            f.token.grant_role_internal(f.admin, BURN_BLOCKED_ROLE)?;
            f.blacklist(vec![f.owner])?;
            f.token
                .burn_blocked(f.admin, f.owner, U256::from(800), true)?;
            f.blacklist(vec![])?;
            assert_eq!(f.balance(f.owner)?, U256::from(200));
            assert_eq!(f.reserved()?, 200);
            // The lien keeps its amount; what is left of the reservation backs it and the hold together.
            assert_eq!(f.liened()?, 600);
            assert_eq!(f.reservations.lien_of(authority, lien)?.amount, 600);

            // Ending the hold first consumes the burned part, so the release returns what is left.
            f.reservations.release(f.owner, held)?;
            assert_eq!(f.reserved()?, 200);
            f.reservations.release_lien(authority, lien)?;
            assert_eq!(f.reserved()?, 0);
            assert_eq!(f.available()?, 200);
            assert_eq!(f.liened()?, 0);

            // A lien placed after the burn is fully backed.
            let later = B256::random();
            f.lien(authority, later, 150)?;
            f.reservations.release_lien(authority, later)?;
            assert_eq!(f.available()?, 200);
            Ok(())
        })
    }

    #[test]
    fn test_liens_share_the_shortfall_slot() {
        use __packing_shortfall::{LIENED_LOC, SLOT_COUNT, UNBACKED_LOC};
        assert_eq!(SLOT_COUNT, 1);
        assert_eq!(LIENED_LOC.offset_slots, UNBACKED_LOC.offset_slots);
        assert_eq!(__packing_lien::SLOT_COUNT, 2);
    }

    impl Fixture {
        fn close(&mut self, cards: &mut Cards, payout: Address) -> Result<u128> {
            cards.close_account(
                self.owner,
                ICards::closeAccountCall {
                    token: self.token.address(),
                    payoutTo: payout,
                },
            )
        }

        fn account_status(&self, cards: &Cards) -> Result<ICards::AccountStatus> {
            Ok(cards.get_account(self.owner)?.status)
        }
    }

    #[test]
    fn test_closed_account_refuses_holds_and_sweeps_debt_first() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(200)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::MAX,
            )?;
            let court = f.lien_authority()?;
            let order = B256::random();
            f.lien(court, order, 20)?;
            let dinner = B256::random();
            let hotel = B256::random();
            hold_card(&mut f, dinner, 100, card)?;
            hold_card(&mut f, hotel, 50, card)?;
            f.set_debt_cap(f.payee, 100)?;
            f.charge(B256::random(), 60, f.payee)?;
            assert_eq!(f.available()?, 0);
            assert_eq!(f.debt()?.amount, 30);

            // Nothing is available, so closing pays nothing; the card and the account stop holds.
            let bank = Address::random();
            assert_eq!(f.close(&mut cards, bank)?, 0);
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Closed);
            assert_eq!(cards.get_account(f.owner)?.agent, bank);
            assert_eq!(
                cards.get_card(f.payee, card)?.status,
                ICards::Status::Closed
            );
            assert_eq!(
                hold_card(&mut f, B256::random(), 1, card).unwrap_err(),
                CardsError::card_inactive().into()
            );
            assert_eq!(
                f.hold(B256::random(), 1).unwrap_err(),
                CardsError::account_inactive().into()
            );
            assert_eq!(
                issue_card(
                    &mut cards,
                    &f,
                    f.owner,
                    B256::random(),
                    ICards::Status::Active,
                    U96::MAX
                )
                .unwrap_err(),
                CardsError::account_inactive().into()
            );

            // Open holds still settle, and a sweep of what a release frees repays the debt first.
            f.capture(dinner, 100)?;
            f.reservations.release(f.owner, hotel)?;
            cards.clear_emitted_events();
            assert_eq!(cards.sweep(f.owner, f.token.address())?, 20);
            cards.assert_emitted_events(vec![CardsEvent::account_swept(
                f.owner,
                f.token.address(),
                bank,
                30,
                20,
            )]);
            assert_eq!(f.debt()?.amount, 0);
            assert_eq!(f.balance(bank)?, U256::from(20));
            assert_eq!(f.reserved()?, 20);

            // A late refund lands and pays out; the lien stays until its authority releases it.
            f.refund(f.payee, dinner, 40)?;
            assert_eq!(cards.sweep(f.owner, f.token.address())?, 40);
            f.reservations.release_lien(court, order)?;
            assert_eq!(f.close(&mut cards, bank)?, 20);
            assert_eq!(f.balance(bank)?, U256::from(80));
            assert_eq!(f.balance(f.owner)?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_closure_needs_the_root_key_and_sweeps_need_a_closed_account() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            assert_eq!(
                cards.sweep(f.owner, f.token.address()).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            assert_eq!(
                f.close(&mut cards, Address::ZERO).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(f.owner)?;
            keychain.set_transaction_key(Address::random())?;
            assert_eq!(
                f.close(&mut cards, Address::random()).unwrap_err(),
                CardsError::unauthorized().into()
            );
            keychain.set_transaction_key(Address::ZERO)?;
            let first = Address::random();
            assert_eq!(f.close(&mut cards, first)?, 100);
            // A later close changes the payout address.
            f.mint(f.owner, 10)?;
            let second = Address::random();
            assert_eq!(f.close(&mut cards, second)?, 10);
            assert_eq!(f.balance(first)?, U256::from(100));
            assert_eq!(f.balance(second)?, U256::from(10));
            Ok(())
        })
    }

    #[test]
    fn test_dormancy_follows_activity_and_escheat_pays_the_authority() -> eyre::Result<()> {
        const DORMANCY: u32 = 1_000;
        const ESCHEAT_AFTER: u32 = 3_000;
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let admin = Address::random();
            crate::validator_config_v2::ValidatorConfigV2::new().initialize(admin)?;
            let (authority, state, facility) =
                (Address::random(), Address::random(), Address::random());
            cards.set_authority(
                admin,
                ICards::setAuthorityCall {
                    authority,
                    role: ICards::Role::Escheat,
                    listed: true,
                    payout: state,
                    dormancy: DORMANCY,
                    escheatAfter: ESCHEAT_AFTER,
                },
            )?;
            let owner = f.owner;
            let mark = |cards: &mut Cards, sender: Address| cards.mark_dormant(sender, owner);

            // An account whose clock never started cannot become dormant.
            StorageCtx.set_timestamp(U256::from(NOW + u64::from(DORMANCY)));
            assert_eq!(
                mark(&mut cards, authority).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            StorageCtx.set_timestamp(U256::from(NOW));
            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                owner,
                card,
                ICards::Status::Active,
                U96::MAX,
            )?;
            assert_eq!(cards.get_account(owner)?.lastActive, NOW);

            // Card activity moves the clock.
            let later = NOW + 100;
            StorageCtx.set_timestamp(U256::from(later));
            let id = B256::random();
            f.reservations.hold(
                owner,
                IReservations::holdCall {
                    token: f.token.address(),
                    id,
                    amount: 10,
                    expiresAt: later + 600,
                    payee: f.payee,
                },
                Placement::Card {
                    issuer: f.payee,
                    card,
                },
            )?;
            assert_eq!(cards.get_account(owner)?.lastActive, later);
            f.capture(id, 10)?;

            let idle = later + u64::from(DORMANCY);
            StorageCtx.set_timestamp(U256::from(idle - 1));
            assert_eq!(
                mark(&mut cards, authority).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            StorageCtx.set_timestamp(U256::from(idle));
            assert_eq!(
                mark(&mut cards, Address::random()).unwrap_err(),
                CardsError::unauthorized().into()
            );
            mark(&mut cards, authority)?;
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Dormant);
            assert_eq!(
                f.hold_until(B256::random(), 1, idle + 600).unwrap_err(),
                CardsError::account_inactive().into()
            );

            // Reactivation restarts the clock.
            cards.reactivate(owner)?;
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Active);
            assert_eq!(cards.get_account(owner)?.lastActive, idle);
            assert_eq!(
                cards.reactivate(owner).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            let idle = idle + u64::from(DORMANCY);
            StorageCtx.set_timestamp(U256::from(idle));
            mark(&mut cards, authority)?;

            let token = f.token.address();
            let escheat = |cards: &mut Cards, sender: Address, via: Address| {
                cards.escheat(sender, ICards::escheatCall { owner, token, via })
            };
            assert_eq!(
                escheat(&mut cards, authority, Address::ZERO).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            let due = idle - u64::from(DORMANCY) + u64::from(ESCHEAT_AFTER);
            StorageCtx.set_timestamp(U256::from(due));
            assert_eq!(
                escheat(&mut cards, Address::random(), Address::ZERO).unwrap_err(),
                CardsError::unauthorized().into()
            );
            // Paid into a facility, the record names the authority's payout address.
            assert_eq!(escheat(&mut cards, authority, facility)?, 90);
            assert_eq!(f.balance(facility)?, U256::from(90));
            let payout = cards.payout_of(owner, token, facility)?;
            assert_eq!((payout.to, payout.amount), (state, 90));
            // Another authority cannot escheat into the same record, which names the first.
            let other = Address::random();
            cards.set_authority(
                admin,
                ICards::setAuthorityCall {
                    authority: other,
                    role: ICards::Role::Escheat,
                    listed: true,
                    payout: Address::random(),
                    dormancy: DORMANCY,
                    escheatAfter: ESCHEAT_AFTER,
                },
            )?;
            assert_eq!(
                escheat(&mut cards, other, facility).unwrap_err(),
                CardsError::unauthorized().into()
            );
            assert_eq!(escheat(&mut cards, authority, Address::ZERO)?, 0);
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Dormant);
            assert_eq!(f.balance(state)?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_touch_and_reactivate_need_the_root_key() -> eyre::Result<()> {
        at_t15(|| {
            let f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            assert_eq!(
                cards.reactivate(f.owner).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            cards.touch(f.owner)?;
            assert_eq!(cards.get_account(f.owner)?.lastActive, NOW);
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(f.owner)?;
            keychain.set_transaction_key(Address::random())?;
            assert_eq!(
                cards.touch(f.owner).unwrap_err(),
                CardsError::unauthorized().into()
            );
            assert_eq!(
                cards.reactivate(f.owner).unwrap_err(),
                CardsError::unauthorized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_estate_settles_through_its_executor_once_holds_end() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let admin = Address::random();
            crate::validator_config_v2::ValidatorConfigV2::new().initialize(admin)?;
            let authority = Address::random();
            let list = |cards: &mut Cards, sender: Address| {
                cards.set_authority(
                    sender,
                    ICards::setAuthorityCall {
                        authority,
                        role: ICards::Role::Estate,
                        listed: true,
                        payout: Address::ZERO,
                        dormancy: 0,
                        escheatAfter: 0,
                    },
                )
            };
            assert_eq!(
                list(&mut cards, authority).unwrap_err(),
                CardsError::unauthorized().into()
            );
            list(&mut cards, admin)?;
            assert!(cards.authority_of(authority, ICards::Role::Estate)?.listed);
            assert!(!cards.authority_of(authority, ICards::Role::Escheat)?.listed);

            let card = B256::random();
            issue_card(
                &mut cards,
                &f,
                f.owner,
                card,
                ICards::Status::Active,
                U96::MAX,
            )?;
            let open = B256::random();
            hold_card(&mut f, open, 30, card)?;
            let executor = Address::random();
            let owner = f.owner;
            let estate = |cards: &mut Cards, sender: Address| {
                cards.set_estate(sender, ICards::setEstateCall { owner, executor })
            };
            assert_eq!(
                estate(&mut cards, Address::random()).unwrap_err(),
                CardsError::unauthorized().into()
            );
            estate(&mut cards, authority)?;
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Estate);
            assert_eq!(cards.get_account(f.owner)?.agent, executor);
            assert_eq!(
                cards.get_card(f.payee, card)?.status,
                ICards::Status::Frozen
            );
            assert_eq!(
                hold_card(&mut f, B256::random(), 1, card).unwrap_err(),
                CardsError::card_inactive().into()
            );
            assert_eq!(
                f.hold(B256::random(), 1).unwrap_err(),
                CardsError::account_inactive().into()
            );
            assert_eq!(
                f.close(&mut cards, Address::random()).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            assert_eq!(
                estate(&mut cards, authority).unwrap_err(),
                CardsError::account_state_invalid().into()
            );

            let heir = Address::random();
            let settle = |cards: &mut Cards, sender: Address, token: Address| {
                cards.settle_estate(
                    sender,
                    ICards::settleEstateCall {
                        owner,
                        token,
                        to: heir,
                    },
                )
            };
            let token = f.token.address();
            assert_eq!(
                settle(&mut cards, heir, token).unwrap_err(),
                CardsError::unauthorized().into()
            );
            assert_eq!(
                settle(&mut cards, executor, token).unwrap_err(),
                CardsError::holds_open().into()
            );
            // A lien alone does not hold up the estate.
            let court = f.lien_authority()?;
            f.lien(court, B256::random(), 10)?;
            f.capture(open, 30)?;
            assert_eq!(settle(&mut cards, executor, token)?, 60);
            assert_eq!(f.balance(heir)?, U256::from(60));
            assert_eq!(f.account_status(&cards)?, ICards::AccountStatus::Closed);
            assert_eq!(cards.get_account(f.owner)?.agent, heir);
            assert_eq!(
                cards.get_card(f.payee, card)?.status,
                ICards::Status::Closed
            );
            assert_eq!(
                settle(&mut cards, executor, token).unwrap_err(),
                CardsError::account_state_invalid().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_sweep_repays_nothing_the_policy_refuses() -> eyre::Result<()> {
        at_t15(|| {
            let mut f = Fixture::new(100)?;
            let mut cards = Cards::new();
            cards.initialize()?;
            let held = B256::random();
            f.hold(held, 100)?;
            f.set_debt_cap(f.payee, 50)?;
            f.capture(held, 120)?;
            assert_eq!(f.debt()?.amount, 20);
            let bank = Address::random();
            assert_eq!(f.close(&mut cards, bank)?, 0);
            f.blacklist(vec![f.payee])?;
            // The credit cannot repay the blocked creditor, so it lands and the sweep keeps it.
            f.mint(f.owner, 30)?;
            assert_eq!(f.debt()?.amount, 20);
            assert_eq!(cards.sweep(f.owner, f.token.address())?, 0);
            assert_eq!(f.balance(bank)?, U256::ZERO);
            Ok(())
        })
    }
}
