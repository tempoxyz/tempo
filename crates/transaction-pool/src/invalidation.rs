//! Which pending transactions a set of state changes may have made unexecutable.
//!
//! Pool maintenance feeds [`Invalidations`] a committed chain segment and checks the whole
//! pool; the payload builder's [`StateAwareBestTransactions`](crate::StateAwareBestTransactions)
//! feeds it each transaction it executes and checks every candidate. Both ask
//! [`Invalidations::verdict`], which reads no state: it combines what the changes wrote with
//! what validation cached on each transaction. The callers differ only in how they check fee AMM
//! liquidity and in what they do with the answer.

use crate::{
    TempoPoolUpdates,
    transaction::{KeychainSubject, TempoPooledTransaction},
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, U256,
    map::{AddressMap, AddressSet, HashMap, U256Map},
};
use evm2::evm::{AccountChangeRef, AccountInfo, StateChangeSink, StateChangeSource, StorageChange};
use reth_evm::BlockTransactionResult;
use reth_provider::Chain;
use reth_transaction_pool::PoolTransaction;
use tempo_evm::TempoEvmTypes;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    storage::StorageKey,
    tip_fee_manager::{
        TipFeeManager,
        amm::{Pool, compute_amount_out},
    },
    tip20::is_tip20_prefix,
};
use tempo_primitives::TempoPrimitives;

/// What a block, a chain segment or the transactions executed so far changed that pending
/// transactions may depend on.
#[derive(Debug, Default)]
pub struct Invalidations {
    /// Invalidation events the changes emitted.
    pub events: TempoPoolUpdates,
    /// Decreased TIP-20 balance slots: `(token, slot) -> current balance`.
    pub(crate) decreased_balances: HashMap<(Address, U256), U256>,
    /// Accounts whose configuration commitment changed (TIP-1112).
    pub(crate) changed_commitments: AddressSet,
    /// Current protocol nonce of every account whose nonce changed.
    pub(crate) nonces: AddressMap<u64>,
    /// Fee manager slots whose decoded validator-token reserve decreased, with their current
    /// value. Slots that are not pools may appear; lookups are by pool slot.
    pub(crate) decreased_reserves: U256Map<U256>,
    /// Current value of every account keychain slot the changes wrote.
    pub(crate) keychain_writes: U256Map<U256>,
}

impl From<TempoPoolUpdates> for Invalidations {
    fn from(events: TempoPoolUpdates) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl Invalidations {
    /// Collects the events and state changes of a committed chain segment.
    pub fn from_chain(chain: &Chain<TempoPrimitives>) -> Self {
        let mut this = Self::from(TempoPoolUpdates::from_chain(chain));
        for (&address, account) in chain.execution_outcome().state().state() {
            this.record_account(
                address,
                account_fields(account.original_info.as_ref()),
                account_fields(account.info.as_ref()),
            );
            for (&slot, value) in &account.storage {
                this.record_storage(address, slot, value.original_value(), value.present_value);
            }
        }
        this
    }

    /// Collects the events and state changes of a transaction the payload builder executed.
    pub fn on_transaction_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        let result = result.result();
        result.pending_state.visit(&mut *self).unwrap();
        for log in &result.result.logs {
            self.events.apply_log(log);
        }
    }

    /// Returns whether a fee AMM reserve decreased or a validator changed its fee token.
    pub(crate) fn fee_liquidity_may_have_decreased(&self) -> bool {
        !self.decreased_reserves.is_empty() || !self.events.validator_token_changes.is_empty()
    }

    /// Returns `subject`'s remaining spending limit if the changes wrote it.
    ///
    /// Spends and limit updates write the remaining amount of the current period. A period that
    /// rolls over before the next block is not accounted for: admission would reject the
    /// transaction at this state too.
    pub(crate) fn written_spending_limit(&self, subject: &KeychainSubject) -> Option<U256> {
        let slot = AccountKeychain::new().spending_limits
            [AccountKeychain::spending_limit_key(subject.account, subject.key_id)]
            [subject.fee_token]
            .remaining
            .slot();
        self.keychain_writes.get(&slot).copied()
    }

    /// Returns whether the changes drained every fee AMM route that swaps `fee` of `tx`'s fee token
    /// into `validator_token`.
    ///
    /// A route through a pool these changes did not decrease counts as open: execution decides.
    pub(crate) fn drained_fee_routes(
        &self,
        tx: &TempoPooledTransaction,
        validator_token: Address,
        fee: U256,
    ) -> bool {
        let token = tx.effective_fee_token();
        if token == validator_token {
            return false;
        }
        let open = |user_token, validator_token, amount_in| {
            let Ok(amount_out) = compute_amount_out(amount_in) else {
                return true;
            };
            self.decreased_reserves
                .get(&fee_pool_slot(user_token, validator_token))
                .is_none_or(|&value| {
                    Pool::decode_from_slot(value).has_enough_reserve_validator_token(amount_out)
                })
        };
        if open(token, validator_token, fee) {
            return false;
        }
        // TIP-1033 two-hop route through the fee token's quote token.
        let Some(quote_token) = tx
            .fee_token_state()
            .map(|state| state.quote_token)
            .filter(|&quote| !quote.is_zero() && quote != validator_token)
        else {
            return true;
        };
        let Ok(hop_amount) = compute_amount_out(fee) else {
            return false;
        };
        !(open(token, quote_token, fee) && open(quote_token, validator_token, hop_amount))
    }

    /// Returns whether `tx` may have become unexecutable through these changes.
    ///
    /// `fallback_fee_tokens` lists the tokens execution may fall back to when no transaction field
    /// or fee-manager rule selects the fee token. `has_fee_liquidity` answers whether the fee AMM can
    /// still swap a fee amount of a token; it is called only when a reserve decreased or a validator
    /// changed its token.
    pub(crate) fn verdict(
        &self,
        tx: &TempoPooledTransaction,
        fallback_fee_tokens: &[Address],
        mut has_fee_liquidity: impl FnMut(&TempoPooledTransaction, Address, U256) -> bool,
    ) -> Verdict {
        // Recovery fails only for a transaction that validation already rejects.
        let Some(key) = tx.fee_balance_slot() else {
            return Verdict::Valid;
        };
        let fee = tx.fee_token_cost();
        if let Some(&balance) = self.decreased_balances.get(&key)
            && balance < fee
            && !self.may_use_other_fallback_token(tx, key, fee, fallback_fee_tokens)
        {
            return Verdict::Invalid(Reason::InsolventFeePayer);
        }

        // Another transaction can raise an account's protocol nonce only through an
        // authorization list (EIP-7702 or Tempo authorizations). 2D and expiring nonces live in
        // the nonce manager, which only the sender's own transaction on that lane advances, and
        // the 2D pool already orders those.
        if !tx.is_aa_2d()
            && self
                .nonces
                .get(tx.sender_ref())
                .is_some_and(|&nonce| tx.nonce() < nonce)
        {
            return Verdict::StaleNonce;
        }

        let events = &self.events;
        let fee_token = tx.effective_fee_token();
        if events.paused_tokens.contains(&fee_token) {
            return Verdict::Invalid(Reason::PausedFeeToken);
        }

        if events.has_keychain_subject_updates()
            || !events.key_authorization_target_changes.is_empty()
            || !events.key_authorization_witness_burns.is_empty()
        {
            let keychain_subject = tx.keychain_subject();
            if !events.revoked_keys.is_empty()
                && (keychain_subject
                    .as_ref()
                    .is_some_and(|subject| subject.matches_revoked(&events.revoked_keys))
                    || tx
                        .key_authorization_signer_subject()
                        .is_some_and(|subject| subject.matches_revoked(&events.revoked_keys)))
            {
                return Verdict::Invalid(Reason::RevokedKey);
            }
            if tx
                .key_authorization_target_subject()
                .is_some_and(|subject| {
                    subject.matches_key_update(&events.key_authorization_target_changes)
                })
            {
                return Verdict::Invalid(Reason::KeyAuthorizationTarget);
            }
            if tx
                .key_authorization_witness_subject()
                .is_some_and(|subject| {
                    events
                        .key_authorization_witness_burns
                        .get(&subject.account)
                        .is_some_and(|witnesses| witnesses.contains(&subject.witness))
                })
            {
                return Verdict::Invalid(Reason::KeyAuthorizationWitness);
            }
            if let Some(subject) = &keychain_subject
                && tx.is_sender_paid_fee()
                && (subject.matches_spending_limit_update(&events.spending_limit_changes)
                    || subject.matches_spending_limit_update(&events.spending_limit_spends))
                && self
                    .written_spending_limit(subject)
                    .is_some_and(|remaining| remaining < fee)
            {
                return Verdict::Invalid(Reason::SpendingLimit);
            }
        }

        // Only transactions that rely on the stored preference can resolve another token.
        if !events.user_token_changes.is_empty()
            && tx.inner().fee_token().is_none()
            && tx
                .fee_payer()
                .is_ok_and(|fee_payer| events.user_token_changes.contains(&fee_payer))
        {
            return Verdict::Invalid(Reason::UserToken);
        }

        if let Some(restricted) = tx
            .fee_payer()
            .ok()
            .and_then(|fee_payer| events.policy_restrictions.get(&fee_payer))
            && tx.fee_token_state().is_some_and(|state| {
                state
                    .sender_policy_ids
                    .iter()
                    .any(|id| restricted.contains(id))
            })
        {
            return Verdict::Invalid(Reason::PolicyRestricted);
        }

        if self.fee_liquidity_may_have_decreased() && !has_fee_liquidity(tx, fee_token, fee) {
            return Verdict::Invalid(Reason::FeeLiquidity);
        }

        // The new configuration, policy or route may still accept the transaction.
        if !self.changed_commitments.is_empty() && tx.has_authority_in(&self.changed_commitments) {
            return Verdict::Revalidate(Reason::Commitment);
        }
        if events.transfer_policy_updates.contains(&fee_token) {
            return Verdict::Revalidate(Reason::TransferPolicy);
        }
        if events.quote_token_updates.contains(&fee_token) {
            return Verdict::Revalidate(Reason::QuoteToken);
        }

        Verdict::Valid
    }

    /// Returns whether execution may pay the fee with another fallback token.
    ///
    /// Untracked balances may have grown, so they count as sufficient.
    fn may_use_other_fallback_token(
        &self,
        tx: &TempoPooledTransaction,
        (token, slot): (Address, U256),
        fee: U256,
        fallback_fee_tokens: &[Address],
    ) -> bool {
        tx.is_fallback_fee_token()
            && fallback_fee_tokens.iter().any(|&candidate| {
                // TIP-20 balance slots share a layout.
                candidate != token
                    && self
                        .decreased_balances
                        .get(&(candidate, slot))
                        .is_none_or(|&balance| balance >= fee)
            })
    }

    fn record_account(
        &mut self,
        address: Address,
        original: Option<(&[u8], u64)>,
        current: Option<(&[u8], u64)>,
    ) {
        if original.map(|(extension, _)| extension).unwrap_or_default()
            != current.map(|(extension, _)| extension).unwrap_or_default()
        {
            self.changed_commitments.insert(address);
        }
        if let Some((_, nonce)) = current
            && original.is_none_or(|(_, original)| original != nonce)
        {
            self.nonces.insert(address, nonce);
        }
    }

    pub(crate) fn record_storage(
        &mut self,
        address: Address,
        slot: U256,
        original: U256,
        current: U256,
    ) {
        if address == TIP_FEE_MANAGER_ADDRESS {
            if Pool::decode_from_slot(current).reserve_validator_token
                < Pool::decode_from_slot(original).reserve_validator_token
            {
                self.decreased_reserves.insert(slot, current);
            } else if let Some(value) = self.decreased_reserves.get_mut(&slot) {
                *value = current;
            }
        } else if address == ACCOUNT_KEYCHAIN_ADDRESS {
            self.keychain_writes.insert(slot, current);
        } else if is_tip20_prefix(address) {
            if current < original {
                self.decreased_balances.insert((address, slot), current);
            } else if let Some(balance) = self.decreased_balances.get_mut(&(address, slot)) {
                *balance = current;
            }
        }
    }
}

impl StateChangeSink for Invalidations {
    type Error = core::convert::Infallible;

    fn account(&mut self, change: AccountChangeRef<'_>) -> Result<(), Self::Error> {
        self.record_account(
            change.address,
            account_fields(change.original),
            account_fields(change.current),
        );
        Ok(())
    }

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        self.record_storage(change.address, change.key, change.original, change.current);
        Ok(())
    }

    fn storage_read(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), Self::Error> {
        if is_tip20_prefix(address)
            && let Some(balance) = self.decreased_balances.get_mut(&(address, key))
        {
            *balance = value;
        }
        Ok(())
    }
}

/// Whether a pending transaction may still execute after some state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The changes did not affect it.
    Valid,
    /// It cannot execute.
    Invalid(Reason),
    /// It may not execute: validation must run again.
    Revalidate(Reason),
    /// The sender's protocol nonce moved past it. Its descendants may still execute.
    StaleNonce,
}

/// What made a pending transaction invalid or in need of revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    InsolventFeePayer,
    PausedFeeToken,
    RevokedKey,
    KeyAuthorizationTarget,
    KeyAuthorizationWitness,
    SpendingLimit,
    UserToken,
    PolicyRestricted,
    FeeLiquidity,
    Commitment,
    TransferPolicy,
    QuoteToken,
}

impl Reason {
    /// Returns a short description, used in errors and logs.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InsolventFeePayer => "fee payer balance too low",
            Self::PausedFeeToken => "fee token paused",
            Self::RevokedKey => "access key revoked",
            Self::KeyAuthorizationTarget => "key authorization target changed",
            Self::KeyAuthorizationWitness => "key authorization witness burned",
            Self::SpendingLimit => "spending limit exceeded",
            Self::UserToken => "fee payer changed its fee token",
            Self::PolicyRestricted => "fee token policy no longer authorizes the fee transfer",
            Self::FeeLiquidity => "insufficient fee AMM liquidity",
            Self::Commitment => "configuration commitment changed",
            Self::TransferPolicy => "fee token transfer policy changed",
            Self::QuoteToken => "fee token quote token changed",
        }
    }
}

/// Returns the storage slot of the fee AMM pool that swaps `user_token` into `validator_token`.
fn fee_pool_slot(user_token: Address, validator_token: Address) -> U256 {
    let fee_manager = TipFeeManager::new();
    fee_manager
        .pool_id(user_token, validator_token)
        .mapping_slot(fee_manager.pools.slot())
}

/// Returns the account fields that pending transactions depend on: the configuration commitment
/// extension and the protocol nonce.
fn account_fields(info: Option<&AccountInfo>) -> Option<(&[u8], u64)> {
    info.map(|info| (info.extension.as_ref(), info.nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use evm2::evm::AccountExtension;

    #[test]
    fn block_changes_track_commitments_nonces_and_fee_amm_reserves() {
        let account = Address::random();
        let original = AccountInfo::default();
        let mut current = AccountInfo {
            nonce: 1,
            ..Default::default()
        };
        let mut changes = Invalidations::default();
        let record =
            |changes: &mut Invalidations, original: &AccountInfo, current: &AccountInfo| {
                changes
                    .account(AccountChangeRef {
                        address: account,
                        original: Some(original),
                        current: Some(current),
                        created: false,
                        selfdestructed: false,
                    })
                    .unwrap();
            };
        record(&mut changes, &original, &current);
        assert!(changes.changed_commitments.is_empty());
        assert_eq!(changes.nonces.get(&account), Some(&1));

        current.extension = AccountExtension::copy_from_slice(&[1]);
        record(&mut changes, &original, &current);
        assert!(changes.changed_commitments.contains(&account));

        let pool = |reserve_validator_token| {
            tempo_precompiles::tip_fee_manager::amm::Pool {
                reserve_user_token: 0,
                reserve_validator_token,
            }
            .encode_to_slot()
            .unwrap()
        };
        let fee_manager_write = |changes: &mut Invalidations, original, current| {
            changes
                .storage(StorageChange {
                    address: TIP_FEE_MANAGER_ADDRESS,
                    key: U256::ZERO,
                    original,
                    current,
                })
                .unwrap();
        };
        fee_manager_write(&mut changes, pool(1), pool(2));
        assert!(changes.decreased_reserves.is_empty());
        fee_manager_write(&mut changes, pool(2), pool(1));
        assert!(!changes.decreased_reserves.is_empty());
    }

    #[test]
    fn lifting_a_policy_restriction_in_the_same_changes_cancels_it() {
        let account = Address::random();
        let mut events = TempoPoolUpdates::default();
        events.set_policy_restriction(7, account, true);
        events.set_policy_restriction(7, account, true);
        events.set_policy_restriction(8, account, true);
        events.set_policy_restriction(7, account, false);
        assert_eq!(
            events
                .policy_restrictions
                .get(&account)
                .map(|ids| ids.len()),
            Some(1)
        );
        events.set_policy_restriction(8, account, false);
        assert!(events.policy_restrictions.is_empty());
    }
}
