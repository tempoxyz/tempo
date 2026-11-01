//! Durable bridge accounting derived from authenticated protocol effects.

pub(crate) mod effects;

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// One user's independently derived entitlement to one Zone token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct AccountKey {
    pub(crate) token: Address,
    pub(crate) account: Address,
}

impl AccountKey {
    pub(crate) const fn new(token: Address, account: Address) -> Self {
        Self { token, account }
    }
}

/// Aggregate circulating and in-flight liabilities for one token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TokenState {
    /// Sum of all nonzero account entitlements.
    pub(crate) account_total: U256,
    /// Liability from deposits authenticated on Tempo but not yet reflected on the Zone.
    pub(crate) pending_deposits: U256,
    /// Liability from withdrawals accepted on the Zone but not yet settled on Tempo.
    pub(crate) pending_withdrawals: U256,
    /// Liability from refunds parked on Tempo.
    pub(crate) pending_tempo_refunds: U256,
    /// Liability from withdrawal bounce-backs queued to or parked on the Zone.
    pub(crate) pending_zone_refunds: U256,
}

impl TokenState {
    /// Total amount the Portal must currently cover.
    pub(crate) fn liability(self) -> Result<U256, AccountingError> {
        self.account_total
            .checked_add(self.pending_deposits)
            .and_then(|value| value.checked_add(self.pending_withdrawals))
            .and_then(|value| value.checked_add(self.pending_tempo_refunds))
            .and_then(|value| value.checked_add(self.pending_zone_refunds))
            .ok_or(AccountingError::Overflow)
    }
}

/// Direction and amount of one account or liability change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BalanceChange {
    Credit(U256),
    Debit(U256),
}

impl BalanceChange {
    fn apply(self, value: U256) -> Result<U256, AccountingError> {
        match self {
            Self::Credit(amount) => value.checked_add(amount).ok_or(AccountingError::Overflow),
            Self::Debit(amount) => value.checked_sub(amount).ok_or(AccountingError::Underflow),
        }
    }
}

/// In-flight liability tracked for one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiabilityKind {
    Deposit,
    Withdrawal,
    TempoRefund,
    ZoneRefund,
}

impl LiabilityKind {
    fn balance(self, state: &mut TokenState) -> &mut U256 {
        match self {
            Self::Deposit => &mut state.pending_deposits,
            Self::Withdrawal => &mut state.pending_withdrawals,
            Self::TempoRefund => &mut state.pending_tempo_refunds,
            Self::ZoneRefund => &mut state.pending_zone_refunds,
        }
    }
}

/// One accounting mutation derived from authenticated evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    EnableToken(Address),
    Account {
        key: AccountKey,
        change: BalanceChange,
    },
    Liability {
        token: Address,
        kind: LiabilityKind,
        change: BalanceChange,
    },
}

/// Rows changed by one successfully applied Zone block.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChangedRows {
    pub(crate) accounts: Vec<AccountKey>,
    pub(crate) tokens: Vec<Address>,
}

/// Current independently derived bridge accounting state.
///
/// Membership in `tokens` means the token was authenticated through Portal
/// creation or enablement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct State {
    accounts: BTreeMap<AccountKey, U256>,
    tokens: BTreeMap<Address, TokenState>,
}

impl State {
    pub(crate) fn accounts(&self) -> impl Iterator<Item = (AccountKey, U256)> + '_ {
        self.accounts.iter().map(|(&key, &value)| (key, value))
    }

    pub(crate) fn tokens(&self) -> impl Iterator<Item = (Address, TokenState)> + '_ {
        self.tokens.iter().map(|(&token, &state)| (token, state))
    }

    pub(crate) fn account(&self, key: AccountKey) -> Option<U256> {
        self.accounts.get(&key).copied()
    }

    pub(crate) fn token(&self, token: Address) -> Option<TokenState> {
        self.tokens.get(&token).copied()
    }

    /// Build state from raw rows, dropping zero accounts and asserting aggregate consistency.
    pub(crate) fn from_rows(
        accounts: impl IntoIterator<Item = (AccountKey, U256)>,
        tokens: impl IntoIterator<Item = (Address, TokenState)>,
    ) -> Result<Self, AccountingError> {
        let state = Self {
            accounts: accounts
                .into_iter()
                .filter(|(_, value)| !value.is_zero())
                .collect(),
            tokens: tokens.into_iter().collect(),
        };
        let all_tokens: BTreeSet<Address> = state
            .tokens
            .keys()
            .copied()
            .chain(state.accounts.keys().map(|key| key.token))
            .collect();
        state.validate_aggregates(all_tokens)?;
        Ok(state)
    }

    /// Apply ordered effects atomically and return the changed rows.
    ///
    /// Mutates in place and tracks each touched entry's prior value; on any
    /// failure those values are used to roll the mutation back
    /// before returning the error, so no upfront full-state clone is needed
    /// to guarantee `self` is unchanged when this returns `Err`.
    pub(crate) fn apply(&mut self, effects: &[Effect]) -> Result<ChangedRows, AccountingError> {
        let mut accounts = BTreeMap::new();
        let mut tokens = BTreeMap::new();

        let result = effects
            .iter()
            .try_for_each(|effect| self.apply_effect(*effect, &mut accounts, &mut tokens))
            .and_then(|()| self.validate_changed_aggregates(&accounts, &tokens));

        if let Err(error) = result {
            restore(&mut self.accounts, accounts.iter().map(|(&k, &v)| (k, v)));
            restore(&mut self.tokens, tokens.iter().map(|(&k, &v)| (k, v)));
            return Err(error);
        }

        Ok(ChangedRows {
            accounts: accounts.into_keys().collect(),
            tokens: tokens.into_keys().collect(),
        })
    }

    /// Verify exact post-state balances and supplies for the supplied observations.
    pub(crate) fn verify_zone_state(
        &self,
        observed: impl IntoIterator<Item = (Address, U256, BTreeMap<Address, U256>)>,
    ) -> Result<(), AccountingError> {
        for (token, total_supply, balances) in observed {
            let expected_supply = self
                .tokens
                .get(&token)
                .ok_or(AccountingError::UnknownToken { token })?
                .account_total;
            for (account, actual) in balances {
                let key = AccountKey::new(token, account);
                let expected = self.accounts.get(&key).copied().unwrap_or_default();
                if actual != expected {
                    return Err(AccountingError::BalanceMismatch {
                        key,
                        expected,
                        actual,
                    });
                }
            }
            if total_supply != expected_supply {
                return Err(AccountingError::SupplyMismatch {
                    token,
                    expected: expected_supply,
                    actual: total_supply,
                });
            }
        }
        Ok(())
    }

    /// Verify exact L1 Portal custody against every supplied token liability.
    pub(crate) fn verify_portal_balances(
        &self,
        balances: impl IntoIterator<Item = (Address, U256)>,
    ) -> Result<(), AccountingError> {
        for (token, available) in balances {
            let required = self
                .tokens
                .get(&token)
                .copied()
                .ok_or(AccountingError::UnknownToken { token })?
                .liability()?;
            if available < required {
                return Err(AccountingError::CollateralShortfall {
                    token,
                    required,
                    available,
                });
            }
        }
        Ok(())
    }

    fn apply_effect(
        &mut self,
        effect: Effect,
        accounts: &mut BTreeMap<AccountKey, Option<U256>>,
        tokens: &mut BTreeMap<Address, Option<TokenState>>,
    ) -> Result<(), AccountingError> {
        match effect {
            Effect::EnableToken(token) => {
                if self.tokens.contains_key(&token) {
                    return Ok(());
                }
                tokens.insert(token, None);
                self.tokens.insert(token, TokenState::default());
                Ok(())
            }
            Effect::Account { key, change } => self.change_account(key, change, accounts, tokens),
            Effect::Liability {
                token,
                kind,
                change,
            } => self.change_liability(token, kind, change, tokens),
        }
    }

    fn change_account(
        &mut self,
        key: AccountKey,
        change: BalanceChange,
        accounts: &mut BTreeMap<AccountKey, Option<U256>>,
        tokens: &mut BTreeMap<Address, Option<TokenState>>,
    ) -> Result<(), AccountingError> {
        let previous_token = self
            .tokens
            .get(&key.token)
            .copied()
            .ok_or(AccountingError::UnknownToken { token: key.token })?;
        let mut next_token = previous_token;
        next_token.account_total = change.apply(next_token.account_total)?;
        let current = self.accounts.get(&key).copied().unwrap_or_default();
        let next = change.apply(current)?;

        accounts
            .entry(key)
            .or_insert_with(|| self.accounts.get(&key).copied());
        tokens.entry(key.token).or_insert(Some(previous_token));
        write_nonzero(&mut self.accounts, key, next);
        self.tokens.insert(key.token, next_token);
        Ok(())
    }

    fn change_liability(
        &mut self,
        token: Address,
        kind: LiabilityKind,
        change: BalanceChange,
        previous: &mut BTreeMap<Address, Option<TokenState>>,
    ) -> Result<(), AccountingError> {
        let previous_state = self
            .tokens
            .get(&token)
            .copied()
            .ok_or(AccountingError::UnknownToken { token })?;
        let mut state = previous_state;
        let value = kind.balance(&mut state);
        *value = change.apply(*value)?;

        previous.entry(token).or_insert(Some(previous_state));
        self.tokens.insert(token, state);
        Ok(())
    }

    /// Validate cached aggregates from only the account rows changed by this transition.
    fn validate_changed_aggregates(
        &self,
        accounts: &BTreeMap<AccountKey, Option<U256>>,
        tokens: &BTreeMap<Address, Option<TokenState>>,
    ) -> Result<(), AccountingError> {
        for (&token, previous_token) in tokens {
            let mut previous_changed = U256::ZERO;
            let mut current_changed = U256::ZERO;
            let start = AccountKey::new(token, Address::ZERO);
            for (key, previous_balance) in accounts
                .range(start..)
                .take_while(|(key, _)| key.token == token)
            {
                previous_changed = previous_changed
                    .checked_add(previous_balance.unwrap_or_default())
                    .ok_or(AccountingError::Overflow)?;
                current_changed = current_changed
                    .checked_add(self.accounts.get(key).copied().unwrap_or_default())
                    .ok_or(AccountingError::Overflow)?;
            }
            let expected = previous_token
                .unwrap_or_default()
                .account_total
                .checked_sub(previous_changed)
                .ok_or(AccountingError::Underflow)?
                .checked_add(current_changed)
                .ok_or(AccountingError::Overflow)?;
            self.ensure_aggregate(token, expected)?;
        }
        Ok(())
    }

    /// Validate that every one of `tokens`' cached aggregate matches the sum
    /// of its accounts.
    fn validate_aggregates(
        &self,
        tokens: impl IntoIterator<Item = Address>,
    ) -> Result<(), AccountingError> {
        for token in tokens {
            let start = AccountKey::new(token, Address::ZERO);
            let mut total = U256::ZERO;
            for (_, balance) in self
                .accounts
                .range(start..)
                .take_while(|(key, _)| key.token == token)
            {
                total = total
                    .checked_add(*balance)
                    .ok_or(AccountingError::Overflow)?;
            }
            if !self.tokens.contains_key(&token) && total.is_zero() {
                continue;
            }
            self.ensure_aggregate(token, total)?;
        }
        Ok(())
    }

    fn ensure_aggregate(&self, token: Address, expected: U256) -> Result<(), AccountingError> {
        let actual = self
            .tokens
            .get(&token)
            .ok_or(AccountingError::UnknownToken { token })?
            .account_total;
        if actual == expected {
            Ok(())
        } else {
            Err(AccountingError::AggregateMismatch {
                token,
                expected,
                actual,
            })
        }
    }
}

fn write_nonzero<K: Ord>(values: &mut BTreeMap<K, U256>, key: K, value: U256) {
    if value.is_zero() {
        values.remove(&key);
    } else {
        values.insert(key, value);
    }
}

fn write_optional<K: Ord, V>(values: &mut BTreeMap<K, V>, key: K, value: Option<V>) {
    match value {
        Some(value) => {
            values.insert(key, value);
        }
        None => {
            values.remove(&key);
        }
    }
}

/// Restore each entry's prior value after a failed transition.
fn restore<K: Ord, V>(map: &mut BTreeMap<K, V>, entries: impl IntoIterator<Item = (K, Option<V>)>) {
    for (key, previous) in entries {
        write_optional(map, key, previous);
    }
}

/// Deterministic accounting or externally observed invariant failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AccountingError {
    #[error("token {token} is not enabled")]
    UnknownToken { token: Address },
    #[error("accounting arithmetic overflow")]
    Overflow,
    #[error("accounting arithmetic underflow")]
    Underflow,
    #[error("account {key:?} balance mismatch: expected {expected}, observed {actual}")]
    BalanceMismatch {
        key: AccountKey,
        expected: U256,
        actual: U256,
    },
    #[error("token {token} supply mismatch: expected {expected}, observed {actual}")]
    SupplyMismatch {
        token: Address,
        expected: U256,
        actual: U256,
    },
    #[error("token {token} aggregate mismatch: expected {expected}, stored {actual}")]
    AggregateMismatch {
        token: Address,
        expected: U256,
        actual: U256,
    },
    #[error("token {token} collateral shortfall: required {required}, available {available}")]
    CollateralShortfall {
        token: Address,
        required: U256,
        available: U256,
    },
}

#[cfg(test)]
mod tests;
