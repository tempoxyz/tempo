//! TIP-1017: Protocol-Enshrined Subaccounts — Reference Implementation
//!
//! This module extends the AccountKeychain precompile with sub-balance isolation,
//! deterministic subaccount addresses, a subaccount registry, and auto-funding.
//!
//! This is a reference implementation illustrating the logic. It is NOT compiled
//! as part of the production precompile; production integration requires extending
//! the existing `AccountKeychain` struct in `crates/precompiles/src/account_keychain/`.
//!
//! # Overview
//!
//! Subaccounts give each access key an isolated token balance carved from the root
//! account. When a transaction is signed by an access key whose subaccount is
//! enabled, TIP-20 transfers debit the sub-balance instead of the root balance.
//! The root key can deposit/withdraw tokens to/from any sub-balance at will.
//!
//! ## Key design decisions
//!
//! 1. **Deterministic addresses** — Each subaccount has a derived address computed
//!    as `keccak256(0xff ‖ account ‖ keyId)[12..]`. This allows external contracts
//!    and indexers to reference a subaccount without on-chain lookups.
//!
//! 2. **Registry for reverse lookups** — Although addresses are deterministic, the
//!    hash is not reversible. The on-chain registry maps `derivedAddr → (account, keyId)`
//!    so that the protocol can resolve which root account owns a given subaccount.
//!    *(Audit finding D1: without the registry, the protocol cannot enforce access
//!    control on incoming transfers or resolve ownership disputes.)*
//!
//! 3. **Approve/permit blocking** — When a subaccount key is active, `approve` and
//!    `permit` calls where `msg_sender == tx_origin` are blocked. Without this,
//!    a compromised key could set a large allowance to an attacker-controlled
//!    spender, then the attacker could drain the sub-balance via `transferFrom`
//!    without further key involvement — effectively bypassing spending limits.
//!    *(Audit finding A1: the allowance vector is the primary bypass risk.)*
//!
//! 4. **Auto-fund counts against spending limits** — When auto-fund moves tokens
//!    from the root balance into a sub-balance, the transferred amount is deducted
//!    from the key's TIP-1011 spending limit. This prevents a misconfigured
//!    auto-fund rule from draining the root balance beyond the intended limit.
//!    *(Audit finding B1: without this, auto-fund is an unlimited spending vector.)*
//!
//! ## Enforcement order
//!
//! During a TIP-20 `transfer` call the checks execute in this order:
//!
//! 1. `maybe_auto_fund` — top up sub-balance if below threshold (pre-tx hook).
//! 2. `enforce_approve_block` — revert if this is an approve/permit and the key
//!    has an active subaccount.
//! 3. `enforce_sub_balance` — debit the sub-balance instead of the root balance.
//! 4. TIP-1011 spending-limit check (existing `verify_and_update_spending`).
//!
//! ## Gas cost implications
//!
//! Each sub-balance check adds roughly:
//! - 1 transient SLOAD (`transaction_key`)
//! - 1 cold SLOAD (`subaccount_enabled`)
//! - 1 cold SLOAD + SSTORE (`sub_balances` read + write)
//!
//! Auto-fund adds up to `MAX_AUTO_FUND_RULES` additional SLOAD pairs (min_balance
//! + root balance check) per rule, but only fires when the balance is actually
//! below the threshold.

use alloy::primitives::{Address, B256, U256};

use crate::{
    error::Result,
    storage::Mapping,
};
use tempo_contracts::precompiles::{AccountKeychainError, AccountKeychainEvent};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Configuration for a subaccount associated with an access key.
#[derive(Debug, Clone, Default)]
pub struct SubaccountConfig {
    pub enabled: bool,
    pub auto_fund_rules: Vec<AutoFundRule>,
}

/// Rule for automatically refilling a subaccount from the root balance.
/// Auto-fund amounts count against the key's spending limits (TIP-1011).
#[derive(Debug, Clone)]
pub struct AutoFundRule {
    /// TIP-20 token address. Use `Address::ZERO` for the native token.
    pub token: Address,
    /// When the sub-balance drops below this value, trigger a refill.
    pub min_balance: U256,
    /// Amount to transfer from the root balance into the sub-balance.
    pub refill_amount: U256,
}

/// Maximum number of auto-fund rules per key (protocol-enforced).
///
/// Keeping this small bounds the worst-case gas overhead of `maybe_auto_fund`
/// to a predictable constant (4 × ~2 SLOADs per rule ≈ 8 extra SLOADs).
pub const MAX_AUTO_FUND_RULES: usize = 4;

// ---------------------------------------------------------------------------
// Storage extensions (to be added to the AccountKeychain struct)
// ---------------------------------------------------------------------------
//
// The fields below show what would be added to the `#[contract(addr = …)]`
// struct. They are written as comments because this file is a reference
// implementation — the real storage lives in AccountKeychain.
//
// ```rust
// #[contract(addr = ACCOUNT_KEYCHAIN_ADDRESS)]
// pub struct AccountKeychain {
//     // … existing fields …
//
//     // Sub-balance: hash(account, keyId) → token → amount
//     sub_balances: Mapping<B256, Mapping<Address, U256>>,
//
//     // Whether a subaccount is enabled for a given key.
//     // account → keyId → enabled
//     subaccount_enabled: Mapping<Address, Mapping<Address, bool>>,
//
//     // Reverse registry: derivedAddr → (account, keyId).
//     // Needed because keccak256 is not reversible (audit finding D1).
//     subaccount_registry: Mapping<Address, (Address, Address)>,
//
//     // Auto-fund rule storage (flattened — Solidity-style dynamic arrays
//     // are not available, so we store length + indexed fields separately).
//     //
//     // hash(account, keyId) → rule count
//     auto_fund_rules_len: Mapping<B256, u64>,
//     // hash(account, keyId) → index → token
//     auto_fund_token: Mapping<B256, Mapping<u64, Address>>,
//     // hash(account, keyId) → index → min_balance
//     auto_fund_min_balance: Mapping<B256, Mapping<u64, U256>>,
//     // hash(account, keyId) → index → refill_amount
//     auto_fund_refill_amount: Mapping<B256, Mapping<u64, U256>>,
// }
// ```

// ---------------------------------------------------------------------------
// Implementation (reference — methods to be added to `impl AccountKeychain`)
// ---------------------------------------------------------------------------

impl AccountKeychain {
    // ------------------------------------------------------------------
    // Address derivation
    // ------------------------------------------------------------------

    /// Compute the deterministic subaccount address for a given (account, keyId).
    ///
    /// The derivation mirrors CREATE2 style addressing:
    ///   `keccak256(0xff ‖ account ‖ keyId)[12..]`
    ///
    /// The `0xff` prefix prevents collisions with regular EOA addresses and
    /// with CREATE2 (which uses `0xff ‖ deployer ‖ salt ‖ initCodeHash`).
    pub fn subaccount_address(account: Address, key_id: Address) -> Address {
        use alloy::primitives::keccak256;
        let mut data = [0u8; 41];
        data[0] = 0xff;
        data[1..21].copy_from_slice(account.as_slice());
        data[21..41].copy_from_slice(key_id.as_slice());
        Address::from_slice(&keccak256(data)[12..])
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Enable a subaccount for a key during (or after) key authorization.
    ///
    /// Must be called by the root key (`transaction_key == Address::ZERO`).
    ///
    /// # What this does
    /// 1. Sets `subaccount_enabled[account][keyId] = true`.
    /// 2. Derives the subaccount address and writes the registry entry
    ///    `subaccount_registry[derivedAddr] = (account, keyId)`.
    /// 3. Persists the auto-fund rules (up to `MAX_AUTO_FUND_RULES`).
    /// 4. Emits `SubaccountEnabled`.
    pub fn enable_subaccount(
        &mut self,
        account: Address,
        key_id: Address,
        config: SubaccountConfig,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        if config.auto_fund_rules.len() > MAX_AUTO_FUND_RULES {
            return Err(AccountKeychainError::too_many_auto_fund_rules().into());
        }

        // 1. Mark as enabled
        self.subaccount_enabled[account][key_id].write(true)?;

        // 2. Register derived address for reverse lookups
        let derived = Self::subaccount_address(account, key_id);
        self.subaccount_registry[derived].write((account, key_id))?;

        // 3. Persist auto-fund rules
        let composite = Self::spending_limit_key(account, key_id);
        let rule_count = config.auto_fund_rules.len() as u64;
        self.auto_fund_rules_len[composite].write(rule_count)?;

        for (i, rule) in config.auto_fund_rules.iter().enumerate() {
            let idx = i as u64;
            self.auto_fund_token[composite][idx].write(rule.token)?;
            self.auto_fund_min_balance[composite][idx].write(rule.min_balance)?;
            self.auto_fund_refill_amount[composite][idx].write(rule.refill_amount)?;
        }

        // 4. Emit event
        self.emit_event(AccountKeychainEvent::SubaccountEnabled(
            IAccountKeychain::SubaccountEnabled {
                account,
                keyId: key_id,
                subaccountAddr: derived,
            },
        ))
    }

    // ------------------------------------------------------------------
    // Deposits & withdrawals (root-only)
    // ------------------------------------------------------------------

    /// Move tokens from the root TIP-20 balance into a sub-balance.
    ///
    /// Only the root key may call this. The root's TIP-20 balance is debited
    /// and the sub-balance is credited by `amount`.
    ///
    /// In production this would invoke the TIP-20 precompile to debit the
    /// root balance. Here we represent that as a conceptual step.
    pub fn deposit_to_subaccount(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // --- Root-only guard ---
        let transaction_key = self.transaction_key.t_read()?;
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // --- Subaccount must be enabled ---
        let enabled = self.subaccount_enabled[account][key_id].read()?;
        if !enabled {
            return Err(AccountKeychainError::subaccount_not_enabled().into());
        }

        // --- Debit root balance (conceptual — calls TIP-20 precompile) ---
        // let root_balance = tip20.balance_of(account, token)?;
        // if root_balance < amount {
        //     return Err(AccountKeychainError::insufficient_root_balance().into());
        // }
        // tip20.internal_debit(account, token, amount)?;

        // --- Credit sub-balance ---
        let composite = Self::spending_limit_key(account, key_id);
        let current = self.sub_balances[composite][token].read()?;
        self.sub_balances[composite][token].write(current + amount)?;

        self.emit_event(AccountKeychainEvent::SubaccountDeposit(
            IAccountKeychain::SubaccountDeposit {
                account,
                keyId: key_id,
                token,
                amount,
            },
        ))
    }

    /// Move tokens from a sub-balance back to the root TIP-20 balance.
    ///
    /// Only the root key may call this. Notably, withdrawal is permitted even
    /// if the key has been revoked — this allows the root account to recover
    /// any remaining funds from a decommissioned key's sub-balance.
    pub fn withdraw_from_subaccount(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        // --- Root-only guard ---
        let transaction_key = self.transaction_key.t_read()?;
        if transaction_key != Address::ZERO {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }

        // --- No enabled check: allow withdrawal even for revoked keys ---

        // --- Debit sub-balance ---
        let composite = Self::spending_limit_key(account, key_id);
        let current = self.sub_balances[composite][token].read()?;
        if current < amount {
            return Err(AccountKeychainError::insufficient_sub_balance().into());
        }
        self.sub_balances[composite][token].write(current - amount)?;

        // --- Credit root balance (conceptual — calls TIP-20 precompile) ---
        // tip20.internal_credit(account, token, amount)?;

        self.emit_event(AccountKeychainEvent::SubaccountWithdrawal(
            IAccountKeychain::SubaccountWithdrawal {
                account,
                keyId: key_id,
                token,
                amount,
            },
        ))
    }

    // ------------------------------------------------------------------
    // View functions
    // ------------------------------------------------------------------

    /// Return the sub-balance for a given (account, keyId, token) triple.
    pub fn get_sub_balance(
        &self,
        account: Address,
        key_id: Address,
        token: Address,
    ) -> Result<U256> {
        let composite = Self::spending_limit_key(account, key_id);
        self.sub_balances[composite][token].read()
    }

    /// Resolve a derived subaccount address back to its (account, keyId).
    ///
    /// Returns `(Address::ZERO, Address::ZERO)` if the address is not
    /// registered (i.e., it is not a known subaccount).
    ///
    /// This registry lookup is the only way to reverse the derivation since
    /// keccak256 is a one-way function (audit finding D1).
    pub fn resolve_subaccount_address(
        &self,
        sub_addr: Address,
    ) -> Result<(Address, Address)> {
        self.subaccount_registry[sub_addr].read()
    }

    // ------------------------------------------------------------------
    // Enforcement hooks (called during TIP-20 operations)
    // ------------------------------------------------------------------

    /// Enforce sub-balance debit during a TIP-20 transfer.
    ///
    /// This is the critical security function invoked by the TIP-20 precompile
    /// on every `transfer` / `transferFrom` call. It runs **after** auto-fund
    /// and **after** the approve block check.
    ///
    /// # Logic
    ///
    /// 1. Read `transaction_key` from transient storage.
    /// 2. If ZERO (root key) → skip. Root transfers debit the normal balance.
    /// 3. If subaccount is not enabled for this key → skip. This preserves
    ///    backward compatibility for keys authorized before TIP-1017.
    /// 4. Debit `amount` from `sub_balances[hash(account, keyId)][token]`.
    /// 5. If insufficient → revert with `InsufficientSubBalance`.
    pub fn enforce_sub_balance(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        // Root key: normal balance path
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        // Backward compat: key without subaccount uses root balance
        let enabled = self.subaccount_enabled[account][transaction_key].read()?;
        if !enabled {
            return Ok(());
        }

        // Debit sub-balance
        let composite = Self::spending_limit_key(account, transaction_key);
        let current = self.sub_balances[composite][token].read()?;
        if current < amount {
            return Err(AccountKeychainError::insufficient_sub_balance().into());
        }
        self.sub_balances[composite][token].write(current - amount)
    }

    /// Block `approve` and `permit` calls for subaccount keys.
    ///
    /// **Why this exists (audit finding A1):**
    ///
    /// Without this check a compromised access key could call
    /// `token.approve(attacker, type(uint256).max)` and then the attacker
    /// could drain the sub-balance via `transferFrom` at leisure — completely
    /// bypassing spending limits since `transferFrom` is initiated by the
    /// spender (attacker), not the key holder.
    ///
    /// The block only applies when:
    /// - `transaction_key != Address::ZERO` (access key is active), AND
    /// - subaccount is enabled for this key, AND
    /// - `account == tx_origin` (the EOA itself is calling approve, not a
    ///   contract acting on its own behalf).
    ///
    /// If the caller is a contract (`account != tx_origin`), the approve is
    /// allowed because the contract is managing its own allowances.
    pub fn enforce_approve_block(
        &mut self,
        account: Address,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;

        if transaction_key == Address::ZERO {
            return Ok(());
        }

        let enabled = self.subaccount_enabled[account][transaction_key].read()?;
        if !enabled {
            return Ok(());
        }

        let tx_origin = self.tx_origin.t_read()?;
        if account == tx_origin {
            return Err(AccountKeychainError::approve_blocked_for_subaccount().into());
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Auto-fund
    // ------------------------------------------------------------------

    /// Pre-transaction hook: automatically refill sub-balances that have
    /// dropped below their configured thresholds.
    ///
    /// Called by the transaction execution pipeline **before** the user's
    /// call is executed, only when `transaction_key != Address::ZERO` and
    /// the key has a subaccount enabled.
    ///
    /// For each auto-fund rule where `sub_balance < min_balance`:
    ///
    /// 1. Compute the effective refill: `min(refill_amount, remaining_spend_limit, root_balance)`.
    /// 2. If effective refill > 0, transfer from root → sub-balance.
    /// 3. **Deduct the transfer from the key's TIP-1011 spending limit**
    ///    (audit finding B1). This is critical — without it, auto-fund
    ///    becomes an unlimited spending vector that can drain the root.
    /// 4. Emit `SubaccountAutoFunded` event.
    ///
    /// # Gas considerations
    ///
    /// Each rule costs ~2 SLOADs (min_balance + sub_balance read). Rules
    /// that do not trigger a refill are cheap. The protocol caps the number
    /// of rules at `MAX_AUTO_FUND_RULES` to bound worst-case gas.
    pub fn maybe_auto_fund(
        &mut self,
        account: Address,
    ) -> Result<()> {
        let transaction_key = self.transaction_key.t_read()?;
        if transaction_key == Address::ZERO {
            return Ok(());
        }

        let enabled = self.subaccount_enabled[account][transaction_key].read()?;
        if !enabled {
            return Ok(());
        }

        let composite = Self::spending_limit_key(account, transaction_key);
        let rule_count = self.auto_fund_rules_len[composite].read()?;

        for i in 0..rule_count {
            let token = self.auto_fund_token[composite][i].read()?;
            let min_balance = self.auto_fund_min_balance[composite][i].read()?;
            let refill_amount = self.auto_fund_refill_amount[composite][i].read()?;

            let sub_bal = self.sub_balances[composite][token].read()?;
            if sub_bal >= min_balance {
                continue;
            }

            // --- Determine effective refill amount ---
            // Cap at remaining spending limit (TIP-1011 integration).
            let remaining_limit = self.spending_limits[composite][token].read()?;
            let capped = refill_amount.min(remaining_limit);

            // Cap at available root balance (conceptual — real impl queries TIP-20).
            // let root_balance = tip20.balance_of(account, token)?;
            // let effective = capped.min(root_balance);
            let effective = capped; // placeholder — root balance check omitted

            if effective.is_zero() {
                continue;
            }

            // --- Transfer root → sub-balance ---
            // tip20.internal_debit(account, token, effective)?;
            self.sub_balances[composite][token].write(sub_bal + effective)?;

            // --- Deduct from spending limit (audit finding B1) ---
            self.spending_limits[composite][token].write(remaining_limit - effective)?;

            self.emit_event(AccountKeychainEvent::SubaccountAutoFunded(
                IAccountKeychain::SubaccountAutoFunded {
                    account,
                    keyId: transaction_key,
                    token,
                    amount: effective,
                },
            ))?;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Key revocation hook
    // ------------------------------------------------------------------

    /// Called when a key is revoked via `revoke_key`.
    ///
    /// Cleans up the subaccount registry entry and disables the subaccount,
    /// but intentionally **preserves the sub-balance** so the root key can
    /// withdraw remaining funds via `withdraw_from_subaccount`.
    pub fn on_key_revoked(
        &mut self,
        account: Address,
        key_id: Address,
    ) -> Result<()> {
        let enabled = self.subaccount_enabled[account][key_id].read()?;
        if !enabled {
            return Ok(());
        }

        // Remove from registry
        let derived = Self::subaccount_address(account, key_id);
        self.subaccount_registry[derived].write((Address::ZERO, Address::ZERO))?;

        // Disable (but keep sub-balance intact for withdrawal)
        self.subaccount_enabled[account][key_id].write(false)?;

        self.emit_event(AccountKeychainEvent::SubaccountDisabled(
            IAccountKeychain::SubaccountDisabled {
                account,
                keyId: key_id,
                subaccountAddr: derived,
            },
        ))
    }
}
