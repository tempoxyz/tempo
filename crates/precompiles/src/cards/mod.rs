//! Card records precompile: cards an issuer's settlement account (the payee) issues on an owner's
//! account, which card-scoped holds (`IReservations.holdCard`, `holdCardWithLine`,
//! `holdCardStandIn`) check.
//!
//! A card is keyed by (payee, card id). Each issued card starts a line holding its owner, status,
//! limit, expiry, program type, holder reference and network token hash; replacing a card maps a
//! new credential to the same line, so open holds, limits and token hashes follow it. A line's
//! `committed` counter follows the committed amount of every authorization held through it.

pub mod dispatch;

use crate::{
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
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

    /// Checks that `line` may commit `amount` more now: active, unexpired and within its limit.
    /// Called by `IReservations.adjust` before it raises a card hold.
    pub(crate) fn ensure_may_grow(&self, line: u64, amount: u128) -> Result<()> {
        self.ensure_active(line)?;
        self.ensure_within_limit(line, amount)
    }

    /// Moves `line`'s committed counter by an authorization's change of committed amount, from
    /// `before` to `after`. Called by the reservations precompile after every change to a card
    /// authorization, without checks: captures, releases and refunds never depend on the card.
    pub(crate) fn follow_commitment(&mut self, line: u64, before: u128, after: u128) -> Result<()> {
        if before == after {
            return Ok(());
        }
        let committed = self.lines[line].committed.read()?.to::<u128>();
        let next = if after > before {
            committed
                .checked_add(after - before)
                .ok_or_else(TempoPrecompileError::under_overflow)?
        } else {
            // Give-backs never exceed what the same authorizations added.
            committed.saturating_sub(before - after)
        };
        let next = U96::try_from(next).map_err(|_| TempoPrecompileError::under_overflow())?;
        self.lines[line].committed.write(next)
    }

    pub(crate) fn issue_card(&mut self, payee: Address, call: ICards::issueCardCall) -> Result<()> {
        let status = status_byte(call.status)?;
        if call.owner.is_zero() || call.card.is_zero() || call.status == ICards::Status::Closed {
            return Err(CardsError::invalid_card().into());
        }
        let program = program_byte(call.program)?;
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
        Ok(ICards::Card {
            owner: line.owner,
            payee: line.payee,
            // A replaced credential reads closed, whatever its line's status.
            status: if replaced_by.is_zero() {
                status_of(line.status)
            } else {
                ICards::Status::Closed
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

    fn ensure_active(&self, line: u64) -> Result<()> {
        let expires_at = self.lines[line].expires_at.read()?;
        if self.lines[line].status.read()? != ICards::Status::Active as u8
            || (expires_at != 0 && self.now() >= expires_at)
        {
            return Err(CardsError::card_inactive().into());
        }
        Ok(())
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
