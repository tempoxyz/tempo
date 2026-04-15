//! [TIP-20] token standard — Tempo's native fungible token implementation.
//!
//! Provides ERC-20-like balances, allowances, and transfers with Tempo extensions:
//! role-based access control, pausability, supply caps, transfer policies ([TIP-403]), opt-in
//! staking rewards, EIP-2612 permits (T2+), quote-token graphs, and virtual addresses ([TIP-1022]).
//!
//! [TIP-20]: <https://docs.tempo.xyz/protocol/tip20>
//! [TIP-403]: <https://docs.tempo.xyz/protocol/tip403>
//! [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>

pub mod dispatch;
pub mod rewards;
pub mod roles;

use tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event, USD_CURRENCY,
};

// Re-export the generated slots module for external access to storage slot constants
pub use slots as tip20_slots;

use crate::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{rewards::UserRewardInfo, roles::DEFAULT_ADMIN_ROLE},
    tip20_factory::TIP20Factory,
    tip403_registry::{AuthRole, ITIP403Registry, TIP403Registry},
};
use alloy::{
    hex,
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use std::sync::LazyLock;
use tempo_precompiles_macros::contract;
use tracing::trace;

/// u128::MAX as U256
pub const U128_MAX: U256 = uint!(0xffffffffffffffffffffffffffffffff_U256);

use tempo_contracts::precompiles::DECIMALS as TIP20_DECIMALS;

/// TIP20 token address prefix (12 bytes)
/// The full address is: TIP20_TOKEN_PREFIX (12 bytes) || derived_bytes (8 bytes)
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Returns true if the address has the TIP20 prefix.
///
/// NOTE: This only checks the prefix, not whether the token was actually created.
/// Use `TIP20Factory::is_tip20()` for full validation.
pub fn is_tip20_prefix(token: Address) -> bool {
    token.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// Validates that the given token's currency is `"USD"`.
///
/// # Errors
/// - `InvalidToken` — address does not have the TIP-20 prefix
/// - `InvalidCurrency` — token currency is not `"USD"`
pub fn validate_usd_currency(token: Address) -> Result<()> {
    if TIP20Token::from_address(token)?.currency()? != USD_CURRENCY {
        return Err(TIP20Error::invalid_currency().into());
    }
    Ok(())
}

/// TIP-20 token contract — the native token standard on Tempo.
///
/// Implements ERC-20-like functionality (balances, allowances, transfers) with additional
/// features: role-based access control, pausability, supply caps, transfer policies ([TIP-403]),
/// virtual addresses ([TIP-1022]), and opt-in staking rewards.
///
/// [TIP-403]: <https://docs.tempo.xyz/protocol/tip403>
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
///
/// Each token lives at a deterministic address with the `0x20C0` prefix.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract]
pub struct TIP20Token {
    // RolesAuth
    roles: Mapping<Address, Mapping<B256, bool>>,
    role_admins: Mapping<B256, B256>,

    // TIP20 Metadata
    name: String,
    symbol: String,
    currency: String,
    // Unused slot, kept for storage layout compatibility
    _domain_separator: B256,
    quote_token: Address,
    next_quote_token: Address,
    transfer_policy_id: u64,

    // TIP20 Token
    total_supply: U256,
    balances: Mapping<Address, U256>,
    allowances: Mapping<Address, Mapping<Address, U256>>,
    permit_nonces: Mapping<Address, U256>,
    paused: bool,
    supply_cap: U256,
    // Unused slot, kept for storage layout compatibility
    _salts: Mapping<B256, bool>,

    // TIP20 Rewards
    global_reward_per_token: U256,
    opted_in_supply: u128,
    user_reward_info: Mapping<Address, UserRewardInfo>,
}

/// EIP-712 Permit typehash: keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
pub static PERMIT_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
});

/// EIP-712 domain separator typehash
pub static EIP712_DOMAIN_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
});

/// EIP-712 version hash: keccak256("1")
pub static VERSION_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(b"1"));

/// Role hash for pausing token transfers.
pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
/// Role hash for unpausing token transfers.
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
/// Role hash for minting new tokens.
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
/// Role hash that authorizes burning tokens from blocked accounts.
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

impl TIP20Token {
    /// Returns the token name.
    pub fn name(&self) -> Result<String> {
        self.name.read()
    }

    /// Returns the token symbol.
    pub fn symbol(&self) -> Result<String> {
        self.symbol.read()
    }

    /// Returns the token decimals (always 6 for TIP-20).
    pub fn decimals(&self) -> Result<u8> {
        Ok(TIP20_DECIMALS)
    }

    /// Returns the token's currency denomination (e.g. `"USD"`).
    pub fn currency(&self) -> Result<String> {
        self.currency.read()
    }

    /// Returns the current total supply.
    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    /// Returns the active quote token address used for pricing.
    pub fn quote_token(&self) -> Result<Address> {
        self.quote_token.read()
    }

    /// Returns the pending next quote token address (set but not yet finalized).
    pub fn next_quote_token(&self) -> Result<Address> {
        self.next_quote_token.read()
    }

    /// Returns the maximum mintable supply.
    pub fn supply_cap(&self) -> Result<U256> {
        self.supply_cap.read()
    }

    /// Returns whether the token is currently paused.
    pub fn paused(&self) -> Result<bool> {
        self.paused.read()
    }

    /// Returns the TIP-403 transfer policy ID governing this token's transfers.
    pub fn transfer_policy_id(&self) -> Result<u64> {
        self.transfer_policy_id.read()
    }

    /// Returns the PAUSE_ROLE constant
    ///
    /// This role identifier grants permission to pause the token contract.
    /// The role is computed as `keccak256("PAUSE_ROLE")`.
    pub fn pause_role() -> B256 {
        *PAUSE_ROLE
    }

    /// Returns the UNPAUSE_ROLE constant
    ///
    /// This role identifier grants permission to unpause the token contract.
    /// The role is computed as `keccak256("UNPAUSE_ROLE")`.
    pub fn unpause_role() -> B256 {
        *UNPAUSE_ROLE
    }

    /// Returns the ISSUER_ROLE constant
    ///
    /// This role identifier grants permission to mint and burn tokens.
    /// The role is computed as `keccak256("ISSUER_ROLE")`.
    pub fn issuer_role() -> B256 {
        *ISSUER_ROLE
    }

    /// Returns the BURN_BLOCKED_ROLE constant
    ///
    /// This role identifier grants permission to burn tokens from blocked accounts.
    /// The role is computed as `keccak256("BURN_BLOCKED_ROLE")`.
    pub fn burn_blocked_role() -> B256 {
        *BURN_BLOCKED_ROLE
    }

    /// Returns the token balance of `account`.
    pub fn balance_of(&self, call: ITIP20::balanceOfCall) -> Result<U256> {
        self.balances[call.account].read()
    }

    /// Returns the remaining allowance that `spender` can transfer on behalf of `owner`.
    pub fn allowance(&self, call: ITIP20::allowanceCall) -> Result<U256> {
        self.allowances[call.owner][call.spender].read()
    }

    /// Updates the [`TIP403Registry`] transfer policy governing this token's transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidTransferPolicyId` — policy does not exist in the [`TIP403Registry`]
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Validate that the policy exists
        if !TIP403Registry::new().policy_exists(ITIP403Registry::policyExistsCall {
            policyId: call.newPolicyId,
        })? {
            return Err(TIP20Error::invalid_transfer_policy_id().into());
        }

        self.transfer_policy_id.write(call.newPolicyId)?;

        self.emit_event(TIP20Event::TransferPolicyUpdate(
            ITIP20::TransferPolicyUpdate {
                updater: msg_sender,
                newPolicyId: call.newPolicyId,
            },
        ))
    }

    /// Sets a new supply cap. Must be ≥ current total supply and ≤ [`U128_MAX`].
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidSupplyCap` — new cap is below current total supply
    /// - `SupplyCapExceeded` — new cap exceeds [`U128_MAX`]
    pub fn set_supply_cap(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self.total_supply()? {
            return Err(TIP20Error::invalid_supply_cap().into());
        }

        if call.newSupplyCap > U128_MAX {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.supply_cap.write(call.newSupplyCap)?;

        self.emit_event(TIP20Event::SupplyCapUpdate(ITIP20::SupplyCapUpdate {
            updater: msg_sender,
            newSupplyCap: call.newSupplyCap,
        }))
    }

    /// Pauses all token transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `PAUSE_ROLE`
    pub fn pause(&mut self, msg_sender: Address, _call: ITIP20::pauseCall) -> Result<()> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.paused.write(true)?;

        self.emit_event(TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
            updater: msg_sender,
            isPaused: true,
        }))
    }

    /// Unpauses token transfers.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `UNPAUSE_ROLE`
    pub fn unpause(&mut self, msg_sender: Address, _call: ITIP20::unpauseCall) -> Result<()> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.paused.write(false)?;

        self.emit_event(TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
            updater: msg_sender,
            isPaused: false,
        }))
    }

    /// Stages a new quote token. Must be finalized via [`Self::complete_quote_token_update`].
    /// Validates that the candidate is a deployed TIP-20 token (via [`TIP20Factory`]) and, for
    /// USD-denominated tokens, that the candidate is also USD-denominated.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidQuoteToken` — token is pathUSD, candidate is not a deployed TIP-20, or
    ///   USD currency mismatch
    pub fn set_next_quote_token(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setNextQuoteTokenCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        if self.address == PATH_USD_ADDRESS {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Verify the new quote token is a valid TIP20 token that has been deployed
        // use factory's `is_tip20()` which checks both prefix and counter
        if !TIP20Factory::new().is_tip20(call.newQuoteToken)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Check if the currency is USD, if so then the quote token's currency MUST also be USD
        let currency = self.currency()?;
        if currency == USD_CURRENCY {
            let quote_token_currency = Self::from_address(call.newQuoteToken)?.currency()?;
            if quote_token_currency != USD_CURRENCY {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        self.next_quote_token.write(call.newQuoteToken)?;

        self.emit_event(TIP20Event::NextQuoteTokenSet(ITIP20::NextQuoteTokenSet {
            updater: msg_sender,
            nextQuoteToken: call.newQuoteToken,
        }))
    }

    /// Finalizes the staged quote token update. Walks the quote-token chain to detect cycles
    /// before committing the change.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `DEFAULT_ADMIN_ROLE`
    /// - `InvalidQuoteToken` — update would create a cycle in the quote-token graph
    pub fn complete_quote_token_update(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::completeQuoteTokenUpdateCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self.next_quote_token()?;

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (pathUSD)
        let mut current = next_quote_token;
        while current != PATH_USD_ADDRESS {
            if current == self.address {
                return Err(TIP20Error::invalid_quote_token().into());
            }

            current = Self::from_address(current)?.quote_token()?;
        }

        // Update the quote token
        self.quote_token.write(next_quote_token)?;

        self.emit_event(TIP20Event::QuoteTokenUpdate(ITIP20::QuoteTokenUpdate {
            updater: msg_sender,
            newQuoteToken: next_quote_token,
        }))
    }

    // Token operations

    /// Mints `amount` tokens to the resolved target `to` address:
    /// - Enforces mint-recipient compliance via [`TIP403Registry`] and validates against supply cap
    /// - Resolves `to` via the [`AddressRegistry`]. If `to` is a virtual address, credits the
    ///   resolved master and emits a two-hop `Transfer` and `Mint(virtual, amount)` events
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold the `ISSUER_ROLE` role
    /// - `ContractPaused` — (+T3) token is paused
    /// - `InvalidRecipient` — (+T3) recipient is zero or a TIP-20 prefix address
    /// - `PolicyForbids` — TIP-403 policy rejects the mint recipient
    /// - `SupplyCapExceeded` — minting would push total supply above the cap
    pub fn mint(&mut self, msg_sender: Address, call: ITIP20::mintCall) -> Result<()> {
        let to = Recipient::resolve(call.to)?;
        self._mint(msg_sender, &to, call.amount)?;

        self.emit_event(TIP20Event::Mint(ITIP20::Mint {
            to: call.to,
            amount: call.amount,
        }))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }

        Ok(())
    }

    /// Like [`Self::mint`], but attaches a 32-byte memo.
    pub fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<()> {
        let to = Recipient::resolve(call.to)?;
        self._mint(msg_sender, &to, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: Address::ZERO,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;
        self.emit_event(TIP20Event::Mint(ITIP20::Mint {
            to: call.to,
            amount: call.amount,
        }))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(())
    }

    /// Internal helper to mint new tokens and update balances.
    fn _mint(&mut self, msg_sender: Address, to: &Recipient, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

        // Check if the resolved target address is authorized to receive minted tokens
        self.validate_mint(to)?;

        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let supply_cap = self.supply_cap()?;
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.handle_rewards_on_mint(to.target, amount)?;

        self.set_total_supply(new_supply)?;
        let to_balance = self.get_balance(to.target)?;
        let new_to_balance: alloy::primitives::Uint<256, 4> = to_balance
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_balance(to.target, new_to_balance)?;

        self.emit_event(to.build_transfer_event(Address::ZERO, amount))
    }

    /// Burns `amount` from the caller's balance and reduces total supply.
    ///
    /// # Errors
    /// - `ContractPaused` — (+T3) token is paused
    /// - `Unauthorized` — caller does not hold the `ISSUER_ROLE` role
    /// - `InsufficientBalance` — caller balance lower than burn amount
    pub fn burn(&mut self, msg_sender: Address, call: ITIP20::burnCall) -> Result<()> {
        self._burn(msg_sender, call.amount)?;
        self.emit_event(TIP20Event::Burn(ITIP20::Burn {
            from: msg_sender,
            amount: call.amount,
        }))
    }

    /// Like [`Self::burn`], but attaches a 32-byte memo.
    pub fn burn_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnWithMemoCall,
    ) -> Result<()> {
        self._burn(msg_sender, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: msg_sender,
            to: Address::ZERO,
            amount: call.amount,
            memo: call.memo,
        }))?;
        self.emit_event(TIP20Event::Burn(ITIP20::Burn {
            from: msg_sender,
            amount: call.amount,
        }))
    }

    /// Burns tokens from addresses blocked by [`TIP403Registry`] policy.
    ///
    /// # Errors
    /// - `ContractPaused` — (+T3) token is paused
    /// - `Unauthorized` — caller does not hold `BURN_BLOCKED_ROLE`
    /// - `PolicyForbids` — target address is not blocked by policy
    /// - `ProtectedAddress` — cannot burn from fee manager or stablecoin DEX addresses
    pub fn burn_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<()> {
        // Validate burner role and (+T3) ensure token is not paused
        if self.storage.spec().is_t3() {
            self.check_not_paused()?;
        }
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Prevent burning from `FeeManager` and `StablecoinDEX` to protect accounting invariants
        if matches!(call.from, TIP_FEE_MANAGER_ADDRESS | STABLECOIN_DEX_ADDRESS) {
            return Err(TIP20Error::protected_address().into());
        }

        // Check if the address is blocked from transferring (sender authorization)
        let policy_id = self.transfer_policy_id()?;
        if TIP403Registry::new().is_authorized_as(policy_id, call.from, AuthRole::sender())? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        self._transfer(call.from, &Recipient::direct(Address::ZERO), call.amount)?;

        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(call.amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    call.amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)?;

        self.emit_event(TIP20Event::BurnBlocked(ITIP20::BurnBlocked {
            from: call.from,
            amount: call.amount,
        }))
    }

    fn _burn(&mut self, msg_sender: Address, amount: U256) -> Result<()> {
        // Validate issuer role and (+T3) ensure token is not paused
        if self.storage.spec().is_t3() {
            self.check_not_paused()?;
        }
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, &Recipient::direct(Address::ZERO), amount)?;

        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)
    }

    /// Sets `spender`'s allowance to `amount` for the caller's tokens.
    /// Deducts from the caller's [`AccountKeychain`] spending limit
    /// when the new allowance exceeds the previous one.
    ///
    /// # Errors
    /// - `SpendingLimitExceeded` — new allowance exceeds access key spending limit
    pub fn approve(&mut self, msg_sender: Address, call: ITIP20::approveCall) -> Result<bool> {
        // Check and update spending limits for access keys
        AccountKeychain::new().authorize_approve(
            msg_sender,
            self.address,
            self.get_allowance(msg_sender, call.spender)?,
            call.amount,
        )?;

        // Set the new allowance
        self.set_allowance(msg_sender, call.spender, call.amount)?;

        self.emit_event(TIP20Event::Approval(ITIP20::Approval {
            owner: msg_sender,
            spender: call.spender,
            amount: call.amount,
        }))?;

        Ok(true)
    }

    // EIP-2612 Permit

    /// Returns the current nonce for an address (EIP-2612)
    pub fn nonces(&self, call: ITIP20::noncesCall) -> Result<U256> {
        self.permit_nonces[call.owner].read()
    }

    /// Returns the EIP-712 domain separator, computed dynamically from the token name and chain ID.
    pub fn domain_separator(&self) -> Result<B256> {
        let name = self.name()?;
        let name_hash = self.storage.keccak256(name.as_bytes())?;
        let chain_id = U256::from(self.storage.chain_id());

        let encoded = (
            *EIP712_DOMAIN_TYPEHASH,
            name_hash,
            *VERSION_HASH,
            chain_id,
            self.address,
        )
            .abi_encode();

        self.storage.keccak256(&encoded)
    }

    /// Sets allowance via a signed [EIP-2612] permit. Validates the ECDSA signature, checks the
    /// deadline, and increments the nonce. Allowed even when the token is paused.
    ///
    /// [EIP-2612]: https://eips.ethereum.org/EIPS/eip-2612
    ///
    /// # Errors
    /// - `PermitExpired` — current timestamp exceeds permit deadline
    /// - `InvalidSignature` — ECDSA recovery failed or recovered signer ≠ owner
    pub fn permit(&mut self, call: ITIP20::permitCall) -> Result<()> {
        // 1. Check deadline
        if self.storage.timestamp() > call.deadline {
            return Err(TIP20Error::permit_expired().into());
        }

        // 2. Construct EIP-712 struct hash
        let nonce = self.permit_nonces[call.owner].read()?;
        let struct_hash = self.storage.keccak256(
            &(
                *PERMIT_TYPEHASH,
                call.owner,
                call.spender,
                call.value,
                nonce,
                call.deadline,
            )
                .abi_encode(),
        )?;

        // 3. Construct EIP-712 digest
        let domain_separator = self.domain_separator()?;
        let digest = self.storage.keccak256(
            &[
                &[0x19, 0x01],
                domain_separator.as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        )?;

        // 4. Validate ECDSA signature
        // Only v=27/28 is accepted; v=0/1 is intentionally NOT normalized (see TIP-1004 spec).
        let recovered = self
            .storage
            .recover_signer(digest, call.v, call.r, call.s)?
            .ok_or(TIP20Error::invalid_signature())?;
        if recovered != call.owner {
            return Err(TIP20Error::invalid_signature().into());
        }

        // 5. Increment nonce
        self.permit_nonces[call.owner].write(
            nonce
                .checked_add(U256::from(1))
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // 6. Set allowance
        self.set_allowance(call.owner, call.spender, call.value)?;

        // 7. Emit Approval event
        self.emit_event(TIP20Event::Approval(ITIP20::Approval {
            owner: call.owner,
            spender: call.spender,
            amount: call.value,
        }))
    }

    /// Transfers `amount` tokens from the caller to `to`. Enforces compliance via the
    /// [`TIP403Registry`] and deducts from the caller's [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    /// - `InsufficientBalance` — sender balance lower than transfer amount
    pub fn transfer(&mut self, msg_sender: Address, call: ITIP20::transferCall) -> Result<bool> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        let to = Recipient::resolve(call.to)?;
        self.validate_transfer(msg_sender, &to)?;
        self.check_and_update_spending_limit(msg_sender, call.amount)?;

        self._transfer(msg_sender, &to, call.amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(true)
    }

    /// Transfers `amount` on behalf of `from` using the caller's allowance.
    /// Enforces compliance via the [`TIP403Registry`].
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `InsufficientAllowance` — caller allowance lower than transfer amount
    /// - `InsufficientBalance` — `from` balance lower than transfer amount
    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool> {
        let to = Recipient::resolve(call.to)?;
        self._transfer_from(msg_sender, call.from, &to, call.amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(true)
    }

    /// Like [`Self::transfer_from`], but attaches a 32-byte memo.
    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool> {
        let to = Recipient::resolve(call.to)?;
        self._transfer_from(msg_sender, call.from, &to, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: call.from,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(true)
    }

    /// Transfers `amount` from `from` to `to` without approval, for use
    /// by other precompiles only (not exposed via ABI). Enforces
    /// compliance via the [`TIP403Registry`] and [`AccountKeychain`].
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InvalidRecipient` — recipient address is zero
    /// - `PolicyForbids` — TIP-403 policy rejects sender or recipient
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    /// - `InsufficientBalance` — `from` balance lower than transfer amount
    pub fn system_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        let to = Recipient::resolve(to)?;
        self.validate_transfer(from, &to)?;
        self.check_and_update_spending_limit(from, amount)?;

        self._transfer(from, &to, amount)?;
        if let Some(hop) = to.build_virtual_transfer_event(amount) {
            self.emit_event(hop)?;
        }

        Ok(true)
    }

    fn _transfer_from(
        &mut self,
        msg_sender: Address,
        from: Address,
        to: &Recipient,
        amount: U256,
    ) -> Result<bool> {
        self.validate_transfer(from, to)?;

        let allowed = self.get_allowance(from, msg_sender)?;
        if amount > allowed {
            return Err(TIP20Error::insufficient_allowance().into());
        }

        if allowed != U256::MAX {
            let new_allowance = allowed
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_allowance())?;
            self.set_allowance(from, msg_sender, new_allowance)?;
        }

        self._transfer(from, to, amount)?;

        Ok(true)
    }

    /// Like [`Self::transfer`], but attaches a 32-byte memo.
    pub fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<()> {
        let to = Recipient::resolve(call.to)?;
        self.validate_transfer(msg_sender, &to)?;
        self.check_and_update_spending_limit(msg_sender, call.amount)?;

        self._transfer(msg_sender, &to, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: msg_sender,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;
        if let Some(hop) = to.build_virtual_transfer_event(call.amount) {
            self.emit_event(hop)?;
        }
        Ok(())
    }
}

// Utility functions
impl TIP20Token {
    /// Creates a `TIP20Token` handle from a raw address.
    ///
    /// # Errors
    /// - `InvalidToken` — address does not carry the `0x20C0` TIP-20 prefix
    pub fn from_address(address: Address) -> Result<Self> {
        if !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }
        Ok(Self::__new(address))
    }

    /// Creates a TIP20Token without validating the prefix.
    ///
    /// # Safety
    /// Caller must ensure `is_tip20_prefix(address)` returns true.
    #[inline]
    pub fn from_address_unchecked(address: Address) -> Self {
        debug_assert!(is_tip20_prefix(address), "address must have TIP20 prefix");
        Self::__new(address)
    }

    /// Initializes the TIP-20 token precompile with metadata, quote token, supply cap, and
    /// default admin role. Called once by [`TIP20Factory`] during token creation.
    pub fn initialize(
        &mut self,
        msg_sender: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: Address,
    ) -> Result<()> {
        trace!(%name, address=%self.address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.__initialize()?;

        self.name.write(name.to_string())?;
        self.symbol.write(symbol.to_string())?;
        self.currency.write(currency.to_string())?;

        self.quote_token.write(quote_token)?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.next_quote_token.write(quote_token)?;

        // Set default values
        self.supply_cap.write(U128_MAX)?;
        self.transfer_policy_id.write(1)?;

        // Initialize roles system and grant admin role
        self.initialize_roles()?;
        self.grant_default_admin(msg_sender, admin)
    }

    fn get_balance(&self, account: Address) -> Result<U256> {
        self.balances[account].read()
    }

    fn set_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances[account].write(amount)
    }

    fn get_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        self.allowances[owner][spender].read()
    }

    fn set_allowance(&mut self, owner: Address, spender: Address, amount: U256) -> Result<()> {
        self.allowances[owner][spender].write(amount)
    }

    fn set_total_supply(&mut self, amount: U256) -> Result<()> {
        self.total_supply.write(amount)
    }

    pub fn check_not_paused(&self) -> Result<()> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    /// Checks pause state, validates the effective recipient, and ensures the transfer
    /// is authorized. Shared by public entrypoints that resolve a [`Recipient`] up front.
    fn validate_transfer(&self, from: Address, to: &Recipient) -> Result<()> {
        self.check_not_paused()?;
        to.validate()?;
        self.ensure_transfer_authorized(from, to.target)
    }

    /// Ensures that the recipient is authorized to receive mints.
    /// Additionally (+T3) checks pause state, validates the effective recipient.
    fn validate_mint(&self, to: &Recipient) -> Result<()> {
        if self.storage.spec().is_t3() {
            self.check_not_paused()?;
            to.validate()?;
        }

        // Check if the resolved target address is authorized to receive minted tokens
        if !TIP403Registry::new().is_authorized_as(
            self.transfer_policy_id()?,
            to.target,
            AuthRole::mint_recipient(),
        )? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    /// Check whether a transfer is authorized by the token's [`TIP403Registry`] policy.
    /// [TIP-1015]: For T2+, uses directional sender/recipient checks.
    ///
    /// [TIP-1015]: <https://docs.tempo.xyz/protocol/tips/tip-1015>
    pub fn is_transfer_authorized(&self, from: Address, to: Address) -> Result<bool> {
        let policy_id = self.transfer_policy_id()?;
        let registry = TIP403Registry::new();

        // (spec: +T2) short-circuit and skip recipient check if sender fails
        let sender_auth = registry.is_authorized_as(policy_id, from, AuthRole::sender())?;
        if self.storage.spec().is_t2() && !sender_auth {
            return Ok(false);
        }
        let recipient_auth = registry.is_authorized_as(policy_id, to, AuthRole::recipient())?;
        Ok(sender_auth && recipient_auth)
    }

    /// Ensures the transfer is authorized by the token's [`TIP403Registry`] policy.
    ///
    /// # Errors
    /// - `PolicyForbids` — sender or recipient is not authorized by the active transfer policy
    pub fn ensure_transfer_authorized(&self, from: Address, to: Address) -> Result<()> {
        if !self.is_transfer_authorized(from, to)? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    /// Checks and deducts `amount` from the caller's [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    pub fn check_and_update_spending_limit(&mut self, from: Address, amount: U256) -> Result<()> {
        AccountKeychain::new().authorize_transfer(from, self.address, amount)
    }

    /// Core transfer: debits `from`, credits `to.target`, emits `Transfer(from, event_addr, amount)`.
    ///
    /// For virtual recipients the event address is the virtual alias; the balance update always
    /// targets `to.target` (the resolved master).
    fn _transfer(&mut self, from: Address, to: &Recipient, amount: U256) -> Result<()> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
            );
        }

        self.handle_rewards_on_transfer(from, to.target, amount)?;

        // Adjust balances
        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        self.set_balance(from, new_from_balance)?;

        if to.target != Address::ZERO {
            let to_balance = self.get_balance(to.target)?;
            let new_to_balance = to_balance
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.set_balance(to.target, new_to_balance)?;
        }

        self.emit_event(to.build_transfer_event(from, amount))
    }

    /// Transfers fee tokens from `from` to the fee manager before transaction execution.
    /// Respects the token's pause state and deducts from the [`AccountKeychain`] spending limit.
    ///
    /// # Errors
    /// - `Paused` — token transfers are currently paused
    /// - `InsufficientBalance` — sender balance lower than fee amount
    /// - `SpendingLimitExceeded` — access key spending limit exceeded
    pub fn transfer_fee_pre_tx(&mut self, from: Address, amount: U256) -> Result<()> {
        // This function respects the token's pause state and will revert if the token is paused.
        // transfer_fee_post_tx is intentionally allowed to execute even when the token is paused.
        // This ensures that a transaction which pauses the token can still complete successfully and receive its fee refund.
        // Apart from this specific refund transfer, no other token transfers can occur after a pause event.
        self.check_not_paused()?;
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
            );
        }

        self.check_and_update_spending_limit(from, amount)?;

        // Update rewards for the sender and get their reward recipient
        let from_reward_recipient = self.update_rewards(from)?;

        // If user is opted into rewards, decrease opted-in supply
        if from_reward_recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_sub(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        let new_from_balance =
            from_balance
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_balance(
                    from_balance,
                    amount,
                    self.address,
                ))?;

        self.set_balance(from, new_from_balance)?;

        let to_balance = self.get_balance(TIP_FEE_MANAGER_ADDRESS)?;
        let new_to_balance = to_balance
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self.set_balance(TIP_FEE_MANAGER_ADDRESS, new_to_balance)
    }

    /// Refunds unused fee tokens from the fee manager back to `to` and emits a transfer event for
    /// the actual gas spent. Intentionally allowed when paused so that a pause transaction can
    /// still receive its fee refund. On T1C+, also restores the [`AccountKeychain`] spending limit
    /// by the refund amount.
    pub fn transfer_fee_post_tx(
        &mut self,
        to: Address,
        refund: U256,
        actual_spending: U256,
    ) -> Result<()> {
        self.emit_event(TIP20Event::Transfer(ITIP20::Transfer {
            from: to,
            to: TIP_FEE_MANAGER_ADDRESS,
            amount: actual_spending,
        }))?;

        // Exit early if there is no refund
        if refund.is_zero() {
            return Ok(());
        }

        if self.storage.spec().is_t1c() {
            AccountKeychain::new().refund_spending_limit(to, self.address, refund)?;
        }

        // Update rewards for the recipient and get their reward recipient
        let to_reward_recipient = self.update_rewards(to)?;

        // If user is opted into rewards, increase opted-in supply by refund amount
        if to_reward_recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_add(refund)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        let from_balance = self.get_balance(TIP_FEE_MANAGER_ADDRESS)?;
        let new_from_balance =
            from_balance
                .checked_sub(refund)
                .ok_or(TIP20Error::insufficient_balance(
                    from_balance,
                    refund,
                    self.address,
                ))?;

        self.set_balance(TIP_FEE_MANAGER_ADDRESS, new_from_balance)?;

        let to_balance = self.get_balance(to)?;
        let new_to_balance = to_balance
            .checked_add(refund)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self.set_balance(to, new_to_balance)
    }
}

/// Resolved transfer recipient for [TIP-1022] virtual address support.
///
/// `to` is always the effective (resolved) address where the balance is credited. For virtual
/// recipients, `virtual_addr` carries the original virtual address for event emission.
///
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
#[derive(Debug, PartialEq)]
pub(crate) struct Recipient {
    /// The effective (resolved) address where the balance is credited.
    pub(crate) target: Address,
    /// The virtual address, if registered.
    pub(crate) virtual_addr: Option<Address>,
}

impl Recipient {
    /// Creates a [`Recipient`] with no virtual indirection.
    #[inline]
    pub(crate) fn direct(addr: Address) -> Self {
        Self {
            target: addr,
            virtual_addr: None,
        }
    }

    /// Resolves a recipient via the [`AddressRegistry`].
    ///
    /// If `addr` is a virtual address its registered master is looked up and stored in `target`,
    /// with the original virtual address preserved in `virtual_addr`.
    pub(crate) fn resolve(addr: Address) -> Result<Self> {
        let effective = AddressRegistry::new().resolve_recipient(addr)?;
        Ok(if effective == addr {
            Self::direct(addr)
        } else {
            Self {
                target: effective,
                virtual_addr: Some(addr),
            }
        })
    }

    /// Validates that the recipient is not:
    /// - the zero address (preventing accidental burns)
    /// - an address with the TIP-20 prefix (preventing transfers to token contracts)
    pub(crate) fn validate(&self) -> Result<()> {
        if self.target.is_zero() || is_tip20_prefix(self.target) {
            return Err(TIP20Error::invalid_recipient().into());
        }
        Ok(())
    }

    /// Builds the primary `Transfer(from, to, amount)` event.
    ///
    /// For virtual recipients `to` is the virtual address (first hop); for regular
    /// recipients this is the only `Transfer` event needed.
    pub(crate) fn build_transfer_event(&self, from: Address, amount: U256) -> TIP20Event {
        TIP20Event::Transfer(ITIP20::Transfer {
            from,
            to: self.virtual_addr.unwrap_or(self.target),
            amount,
        })
    }

    /// Builds the forwarding `Transfer(virtual, master, amount)` event for virtual recipients.
    /// Returns `None` for non-virtual recipients.
    pub(crate) fn build_virtual_transfer_event(&self, amount: U256) -> Option<TIP20Event> {
        self.virtual_addr.map(|virtual_addr| {
            TIP20Event::Transfer(ITIP20::Transfer {
                from: virtual_addr,
                to: self.target,
                amount,
            })
        })
    }
}

#[cfg(test)]
mod recipient_tests {
    use super::*;
    use crate::{
        address_registry::{AddressRegistry, MasterId, UserTag},
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{VIRTUAL_MASTER, make_virtual_address, register_virtual_master},
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_resolve() -> eyre::Result<()> {
        // direct (non-virtual)
        let addr = Address::repeat_byte(0x11);
        assert_eq!(
            Recipient::direct(addr),
            Recipient {
                target: addr,
                virtual_addr: None
            }
        );

        // T3: non-virtual → direct
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let r = Recipient::resolve(addr)?;
            assert_eq!(
                r,
                Recipient {
                    target: addr,
                    virtual_addr: None
                }
            );

            // T3: registered virtual → master
            let mut registry = AddressRegistry::new();
            let (_, virtual_addr) = register_virtual_master(&mut registry)?;
            let r = Recipient::resolve(virtual_addr)?;
            assert_eq!(
                r,
                Recipient {
                    target: VIRTUAL_MASTER,
                    virtual_addr: Some(virtual_addr)
                }
            );

            // T3: unregistered virtual → error
            let unregistered = make_virtual_address(MasterId::ZERO, UserTag::ZERO);
            assert!(Recipient::resolve(unregistered).is_err());

            Ok::<_, TempoPrecompileError>(())
        })?;

        // Pre-T3: virtual address passed through as literal
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let virtual_addr = make_virtual_address(MasterId::ZERO, UserTag::ZERO);
            let r = Recipient::resolve(virtual_addr)?;
            assert_eq!(
                r,
                Recipient {
                    target: virtual_addr,
                    virtual_addr: None
                }
            );
            Ok::<_, TempoPrecompileError>(())
        })?;
        Ok(())
    }

    #[test]
    fn test_validate() {
        assert!(Recipient::direct(Address::ZERO).validate().is_err());
        assert!(
            Recipient::direct(crate::PATH_USD_ADDRESS)
                .validate()
                .is_err()
        );
        assert!(
            Recipient::direct(Address::repeat_byte(0x11))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn test_build_events() {
        let from = Address::repeat_byte(0x01);
        let target = Address::repeat_byte(0x02);
        let vaddr = Address::repeat_byte(0x03);
        let amount = U256::from(42);

        let direct = Recipient::direct(target);
        let virt = Recipient {
            target,
            virtual_addr: Some(vaddr),
        };

        // transfer event uses virtual_addr when present, target otherwise
        assert!(matches!(direct.build_transfer_event(from, amount),
            TIP20Event::Transfer(ITIP20::Transfer { to, .. }) if to == target));
        assert!(matches!(virt.build_transfer_event(from, amount),
            TIP20Event::Transfer(ITIP20::Transfer { to, .. }) if to == vaddr));

        // virtual transfer event: None for direct, Some(virtual→master) for virtual
        assert!(direct.build_virtual_transfer_event(amount).is_none());
        let hop = virt.build_virtual_transfer_event(amount).unwrap();
        assert!(matches!(hop,
            TIP20Event::Transfer(ITIP20::Transfer { from, to, .. })
            if from == vaddr && to == target));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloy::primitives::{Address, FixedBytes, IntoLogData, U256};
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20Factory};

    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        account_keychain::{
            AccountKeychain, KeyRestrictions, SignatureType, TokenLimit, authorizeKeyCall,
            getRemainingLimitCall,
        },
        address_registry::{AddressRegistry, MasterId, UserTag},
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{
            TIP20Setup, VIRTUAL_MASTER, make_virtual_address, register_virtual_master,
            setup_storage,
        },
    };
    use rand_08::{Rng, distributions::Alphanumeric, thread_rng};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_mint_increases_balance_and_supply() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let addr = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .clear_events()
                .apply()?;

            token.mint(admin, ITIP20::mintCall { to: addr, amount })?;

            assert_eq!(token.get_balance(addr)?, amount);
            assert_eq!(token.total_supply()?, amount);

            token.assert_emitted_events(vec![
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: Address::ZERO,
                    to: addr,
                    amount,
                }),
                TIP20Event::Mint(ITIP20::Mint { to: addr, amount }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_moves_balance() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(from, amount)
                .clear_events()
                .apply()?;

            token.transfer(from, ITIP20::transferCall { to, amount })?;

            assert_eq!(token.get_balance(from)?, U256::ZERO);
            assert_eq!(token.get_balance(to)?, amount);
            assert_eq!(token.total_supply()?, amount); // Supply unchanged

            token.assert_emitted_events(vec![TIP20Event::Transfer(ITIP20::Transfer {
                from,
                to,
                amount,
            })]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            let result = token.transfer(from, ITIP20::transferCall { to, amount });
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(
                    TIP20Error::InsufficientBalance(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_mint_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);
        let to = Address::random();
        let memo = FixedBytes::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .clear_events()
                .apply()?;

            token.mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo })?;

            // TransferWithMemo event should have Address::ZERO as from for mint
            token.assert_emitted_events(vec![
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: Address::ZERO,
                    to,
                    amount,
                }),
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: Address::ZERO,
                    to,
                    amount,
                    memo,
                }),
                TIP20Event::Mint(ITIP20::Mint { to, amount }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_burn_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);
        let memo = FixedBytes::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, amount)
                .clear_events()
                .apply()?;

            token.burn_with_memo(admin, ITIP20::burnWithMemoCall { amount, memo })?;
            token.assert_emitted_events(vec![
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: admin,
                    to: Address::ZERO,
                    amount,
                }),
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: admin,
                    to: Address::ZERO,
                    amount,
                    memo,
                }),
                TIP20Event::Burn(ITIP20::Burn {
                    from: admin,
                    amount,
                }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_from_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let memo = FixedBytes::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(owner, amount)
                .with_approval(owner, spender, amount)
                .clear_events()
                .apply()?;

            token.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to,
                    amount,
                    memo,
                },
            )?;

            // TransferWithMemo event should have use call.from in transfer event
            token.assert_emitted_events(vec![
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: owner,
                    to,
                    amount,
                }),
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: owner,
                    to,
                    amount,
                    memo,
                }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let amount = U256::from(100);
        let fee_amount = amount / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(user, amount)
                .apply()?;

            token.transfer_fee_pre_tx(user, fee_amount)?;

            assert_eq!(token.get_balance(user)?, fee_amount);
            assert_eq!(token.get_balance(TIP_FEE_MANAGER_ADDRESS)?, fee_amount);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let amount = U256::from(100);
        let fee_amount = amount / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;

            assert_eq!(
                token.transfer_fee_pre_tx(user, fee_amount),
                Err(TempoPrecompileError::TIP20(
                    TIP20Error::insufficient_balance(U256::ZERO, fee_amount, token.address)
                ))
            );
            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx_paused() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let amount = U256::from(100);
        let fee_amount = amount / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_role(admin, *PAUSE_ROLE)
                .with_mint(user, amount)
                .apply()?;

            // Pause the token
            token.pause(admin, ITIP20::pauseCall {})?;

            // transfer_fee_pre_tx should fail when paused
            assert_eq!(
                token.transfer_fee_pre_tx(user, fee_amount),
                Err(TempoPrecompileError::TIP20(TIP20Error::contract_paused()))
            );
            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let initial_fee = U256::from(100);
        let refund_amount = U256::from(30);
        let gas_used = U256::from(10);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, initial_fee)
                .apply()?;

            token.transfer_fee_post_tx(user, refund_amount, gas_used)?;

            assert_eq!(token.get_balance(user)?, refund_amount);
            assert_eq!(
                token.get_balance(TIP_FEE_MANAGER_ADDRESS)?,
                initial_fee - refund_amount
            );
            assert_eq!(
                token.emitted_events().last().unwrap(),
                &TIP20Event::Transfer(ITIP20::Transfer {
                    from: user,
                    to: TIP_FEE_MANAGER_ADDRESS,
                    amount: gas_used
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_post_tx_refunds_spending_limit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let admin = Address::random();
        let user = Address::random();
        let access_key = Address::random();
        let max_fee = U256::from(1000);
        let refund_amount = U256::from(300);
        let gas_used = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, max_fee)
                .apply()?;

            let token_address = token.address;
            let spending_limit = U256::from(2000);

            // Set up keychain: authorize an access key with a spending limit
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            keychain.authorize_key(
                user,
                authorizeKeyCall {
                    keyId: access_key,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token: token_address,
                            amount: spending_limit,
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            // Simulate pre-tx: access key deducts max fee from spending limit
            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(user)?;
            keychain.authorize_transfer(user, token_address, max_fee)?;

            let remaining_after_deduction =
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account: user,
                    keyId: access_key,
                    token: token_address,
                })?;
            assert_eq!(remaining_after_deduction, spending_limit - max_fee);

            // Call transfer_fee_post_tx — should refund the spending limit via is_t1c() gate
            token.transfer_fee_post_tx(user, refund_amount, gas_used)?;

            let remaining_after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: user,
                keyId: access_key,
                token: token_address,
            })?;
            assert_eq!(
                remaining_after_refund,
                spending_limit - max_fee + refund_amount,
                "spending limit should be restored by refund amount"
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_post_tx_pre_t1c() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1B);
        let admin = Address::random();
        let user = Address::random();
        let access_key = Address::random();
        let max_fee = U256::from(1000);
        let refund_amount = U256::from(300);
        let gas_used = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, max_fee)
                .apply()?;

            let token_address = token.address;
            let spending_limit = U256::from(2000);

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;

            keychain.authorize_key(
                user,
                authorizeKeyCall {
                    keyId: access_key,
                    signatureType: SignatureType::Secp256k1,
                    config: KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token: token_address,
                            amount: spending_limit,
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                },
            )?;

            keychain.set_transaction_key(access_key)?;
            keychain.set_tx_origin(user)?;
            keychain.authorize_transfer(user, token_address, max_fee)?;

            let remaining_after_deduction =
                keychain.get_remaining_limit(getRemainingLimitCall {
                    account: user,
                    keyId: access_key,
                    token: token_address,
                })?;
            assert_eq!(remaining_after_deduction, spending_limit - max_fee);

            token.transfer_fee_post_tx(user, refund_amount, gas_used)?;

            // spending limit unchanged pre-t1c
            let remaining_after_refund = keychain.get_remaining_limit(getRemainingLimitCall {
                account: user,
                keyId: access_key,
                token: token_address,
            })?;
            assert_eq!(remaining_after_refund, spending_limit - max_fee);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_insufficient_allowance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(from, amount)
                .apply()?;

            assert!(matches!(
                token.transfer_from(spender, ITIP20::transferFromCall { from, to, amount }),
                Err(TempoPrecompileError::TIP20(
                    TIP20Error::InsufficientAllowance(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_system_transfer_from() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(from, amount)
                .apply()?;

            assert!(token.system_transfer_from(from, to, amount).is_ok());
            assert_eq!(
                token.emitted_events().last().unwrap(),
                &TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_initialize_sets_next_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Verify both quoteToken and nextQuoteToken are set to the same value
            assert_eq!(token.quote_token()?, PATH_USD_ADDRESS);
            assert_eq!(token.next_quote_token()?, PATH_USD_ADDRESS);

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Create a new USD token to use as the new quote token
            let new_quote_token = TIP20Setup::create("New Quote", "NQ", admin).apply()?;
            let new_quote_token_address = new_quote_token.address;

            // Verify initial quote token is PATH_USD
            assert_eq!(token.quote_token()?, PATH_USD_ADDRESS);

            // Set next quote token to the new token
            token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: new_quote_token_address,
                },
            )?;

            // Verify next quote token was set to the new token
            assert_eq!(token.next_quote_token()?, new_quote_token_address);

            // Verify event was emitted
            assert_eq!(
                token.emitted_events().last().unwrap(),
                &TIP20Event::NextQuoteTokenSet(ITIP20::NextQuoteTokenSet {
                    updater: admin,
                    nextQuoteToken: new_quote_token_address,
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token_requires_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Use the token's own quote token for the test
            let quote_token_address = token.quote_token()?;

            // Try to set next quote token as non-admin
            let result = token.set_next_quote_token(
                non_admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::RolesAuthError(
                    RolesAuthError::Unauthorized(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token_rejects_non_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Try to set a non-TIP20 address (random address that doesn't match TIP20 pattern)
            let non_tip20_address = Address::random();
            let result = token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: non_tip20_address,
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                    _
                )))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token_rejects_undeployed_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Try to set a TIP20 address that hasn't been deployed yet
            // This has the correct TIP20 address pattern but hasn't been created
            let undeployed_token_address =
                Address::from(hex!("20C0000000000000000000000000000000000999"));
            let result = token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: undeployed_token_address,
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                    _
                )))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_finalize_quote_token_update() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let quote_token_address = token.quote_token()?;

            // Set next quote token
            token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )?;

            // Complete the update
            token.complete_quote_token_update(admin, ITIP20::completeQuoteTokenUpdateCall {})?;

            // Verify quote token was updated
            assert_eq!(token.quote_token()?, quote_token_address);

            // Verify event was emitted
            assert_eq!(
                token.emitted_events().last().unwrap(),
                &TIP20Event::QuoteTokenUpdate(ITIP20::QuoteTokenUpdate {
                    updater: admin,
                    newQuoteToken: quote_token_address,
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_finalize_quote_token_update_detects_loop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create token_b first (links to LINKING_USD)
            let mut token_b = TIP20Setup::create("Token B", "TKB", admin).apply()?;
            // Create token_a (links to token_b)
            let token_a = TIP20Setup::create("Token A", "TKA", admin)
                .quote_token(token_b.address)
                .apply()?;

            // Now try to set token_a as the next quote token for token_b (would create A -> B -> A loop)
            token_b.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: token_a.address,
                },
            )?;

            // Try to complete the update - should fail due to loop detection
            let result =
                token_b.complete_quote_token_update(admin, ITIP20::completeQuoteTokenUpdateCall {});

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                    _
                )))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_finalize_quote_token_update_requires_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let quote_token_address = token.quote_token()?;

            // Set next quote token as admin
            token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )?;

            // Try to complete update as non-admin
            let result = token
                .complete_quote_token_update(non_admin, ITIP20::completeQuoteTokenUpdateCall {});

            assert!(matches!(
                result,
                Err(TempoPrecompileError::RolesAuthError(
                    RolesAuthError::Unauthorized(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_tip20_token_prefix() {
        assert_eq!(
            TIP20_TOKEN_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..12], &TIP20_TOKEN_PREFIX);
    }

    #[test]
    fn test_arbitrary_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            for _ in 0..50 {
                let currency: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(31)
                    .map(char::from)
                    .collect();

                // Initialize token with the random currency
                let token = TIP20Setup::create("Test", "TST", admin)
                    .currency(&currency)
                    .apply()?;

                // Verify the currency was stored and can be retrieved correctly
                let stored_currency = token.currency()?;
                assert_eq!(stored_currency, currency,);
            }

            Ok(())
        })
    }

    #[test]
    fn test_from_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Test with factory-created token (hash-derived address)
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let via_from_address = TIP20Token::from_address(token.address)?.address;

            assert_eq!(
                via_from_address, token.address,
                "from_address should use the provided address directly"
            );

            // Test with reserved token (pathUSD)
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;
            let via_from_address_reserved = TIP20Token::from_address(PATH_USD_ADDRESS)?.address;

            assert_eq!(
                via_from_address_reserved, PATH_USD_ADDRESS,
                "from_address should work for reserved addresses too"
            );

            Ok(())
        })
    }

    #[test]
    fn test_new_invalid_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let currency: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let token = TIP20Setup::create("Token", "T", admin)
                .currency(&currency)
                .apply()?;

            // Try to create a new USD token with the arbitrary token as the quote token, this should fail
            TIP20Setup::create("USD Token", "USDT", admin)
                .currency(USD_CURRENCY)
                .quote_token(token.address)
                .expect_tip20_err(TIP20Error::invalid_quote_token());

            Ok(())
        })
    }

    #[test]
    fn test_new_valid_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let usd_token1 = TIP20Setup::create("USD Token", "USDT", admin).apply()?;

            // USD token with USD token as quote
            let _usd_token2 = TIP20Setup::create("USD Token", "USDT", admin)
                .quote_token(usd_token1.address)
                .apply()?;

            // Create non USD token
            let currency_1: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let token_1 = TIP20Setup::create("USD Token", "USDT", admin)
                .currency(currency_1)
                .apply()?;

            // Create a non USD token with non USD quote token
            let currency_2: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let _token_2 = TIP20Setup::create("USD Token", "USDT", admin)
                .currency(currency_2)
                .quote_token(token_1.address)
                .apply()?;

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token_invalid_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;

            let currency: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let token_1 = TIP20Setup::create("Token 1", "TK1", admin)
                .currency(&currency)
                .apply()?;

            // Create a new USD token
            let mut usd_token = TIP20Setup::create("USD Token", "USDT", admin).apply()?;

            // Try to update the USD token's quote token to the arbitrary currency token, this should fail
            let result = usd_token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: token_1.address,
                },
            );

            assert!(result.is_err_and(
                |err| err == TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            ));

            Ok(())
        })
    }

    #[test]
    fn test_is_tip20_prefix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            let _path_usd = TIP20Setup::path_usd(sender).apply()?;

            let created_tip20 = TIP20Factory::new().create_token(
                sender,
                ITIP20Factory::createTokenCall {
                    name: "Test Token".to_string(),
                    symbol: "TEST".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: crate::PATH_USD_ADDRESS,
                    admin: sender,
                    salt: B256::random(),
                },
            )?;
            let non_tip20 = Address::random();

            assert!(is_tip20_prefix(PATH_USD_ADDRESS));
            assert!(is_tip20_prefix(created_tip20));
            assert!(!is_tip20_prefix(non_tip20));
            Ok(())
        })
    }

    #[test]
    fn test_initialize_supply_cap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Token", "TKN", admin).apply()?;

            let supply_cap = token.supply_cap()?;
            assert_eq!(supply_cap, U256::from(u128::MAX));

            Ok(())
        })
    }

    #[test]
    fn test_unable_to_burn_blocked_from_protected_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let burner = Address::random();
        let amount = (U256::random() % U256::from(u128::MAX)) / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                // Grant BURN_BLOCKED_ROLE to burner
                .with_role(burner, *BURN_BLOCKED_ROLE)
                // Simulate collected fees
                .with_mint(TIP_FEE_MANAGER_ADDRESS, amount)
                // Mint tokens to StablecoinDEX
                .with_mint(STABLECOIN_DEX_ADDRESS, amount)
                .apply()?;

            // Attempt to burn from FeeManager
            let result = token.burn_blocked(
                burner,
                ITIP20::burnBlockedCall {
                    from: TIP_FEE_MANAGER_ADDRESS,
                    amount: amount / U256::from(2),
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ProtectedAddress(_)))
            ));

            // Verify FeeManager balance is unchanged
            let balance = token.balance_of(ITIP20::balanceOfCall {
                account: TIP_FEE_MANAGER_ADDRESS,
            })?;
            assert_eq!(balance, amount);

            // Attempt to burn from StablecoinDEX
            let result = token.burn_blocked(
                burner,
                ITIP20::burnBlockedCall {
                    from: STABLECOIN_DEX_ADDRESS,
                    amount: amount / U256::from(2),
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ProtectedAddress(_)))
            ));

            // Verify StablecoinDEX balance is unchanged
            let balance = token.balance_of(ITIP20::balanceOfCall {
                account: STABLECOIN_DEX_ADDRESS,
            })?;
            assert_eq!(balance, amount);

            Ok(())
        })
    }

    #[test]
    fn test_initialize_usd_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // USD token with zero quote token should succeed
            let _token = TIP20Setup::create("TestToken", "TEST", admin).apply()?;

            // Non-USD token with zero quote token should succeed
            let eur_token = TIP20Setup::create("EuroToken", "EUR", admin)
                .currency("EUR")
                .apply()?;

            // USD token with non-USD quote token should fail
            TIP20Setup::create("USDToken", "USD", admin)
                .quote_token(eur_token.address)
                .expect_tip20_err(TIP20Error::invalid_quote_token());

            Ok(())
        })
    }

    #[test]
    fn test_change_transfer_policy_id_invalid_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(admin).apply()?;

            // Initialize the TIP403 registry
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            // Try to change to a non-existent policy ID (should fail)
            let invalid_policy_id = 999u64;
            let result = token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: invalid_policy_id,
                },
            );

            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::InvalidTransferPolicyId(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_transfer_invalid_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let bob = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_mint(admin, amount)
                .with_approval(admin, bob, amount)
                .apply()?;

            let result = token.transfer(
                admin,
                ITIP20::transferCall {
                    to: Address::ZERO,
                    amount,
                },
            );
            assert!(result.is_err_and(|err| err.to_string().contains("InvalidRecipient")));

            let result = token.transfer_from(
                bob,
                ITIP20::transferFromCall {
                    from: admin,
                    to: Address::ZERO,
                    amount,
                },
            );
            assert!(result.is_err_and(|err| err.to_string().contains("InvalidRecipient")));

            Ok(())
        })
    }

    #[test]
    fn test_change_transfer_policy_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::path_usd(admin).apply()?;

            // Initialize the TIP403 registry
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            // Test special policies 0 and 1 (should always work)
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall { newPolicyId: 0 },
            )?;
            assert_eq!(token.transfer_policy_id()?, 0);

            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall { newPolicyId: 1 },
            )?;
            assert_eq!(token.transfer_policy_id()?, 1);

            // Test random invalid policy IDs should fail
            let mut rng = rand_08::thread_rng();
            for _ in 0..20 {
                let invalid_policy_id = rng.gen_range(2..u64::MAX);
                let result = token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: invalid_policy_id,
                    },
                );
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::TIP20(TIP20Error::InvalidTransferPolicyId(_))
                ));
            }

            // Create some valid policies
            let mut valid_policy_ids = Vec::new();
            for i in 0..10 {
                let policy_id = registry.create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: if i % 2 == 0 {
                            ITIP403Registry::PolicyType::WHITELIST
                        } else {
                            ITIP403Registry::PolicyType::BLACKLIST
                        },
                    },
                )?;
                valid_policy_ids.push(policy_id);
            }

            // Test that all created policies can be set
            for policy_id in valid_policy_ids {
                let result = token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: policy_id,
                    },
                );
                assert!(result.is_ok());
                assert_eq!(token.transfer_policy_id()?, policy_id);
            }

            Ok(())
        })
    }

    #[test]
    fn test_is_transfer_authorized() -> eyre::Result<()> {
        use tempo_chainspec::hardfork::TempoHardfork;

        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();

        for hardfork in [TempoHardfork::T0, TempoHardfork::T1] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);

            StorageCtx::enter(&mut storage, || {
                let token = TIP20Setup::path_usd(admin).apply()?;

                // Initialize TIP403 registry and create a whitelist policy
                let mut registry = TIP403Registry::new();
                registry.initialize()?;

                let policy_id = registry.create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::WHITELIST,
                    },
                )?;

                // Assign token to use this policy
                let mut token = token;
                token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: policy_id,
                    },
                )?;

                // Sender not whitelisted, recipient whitelisted
                registry.modify_policy_whitelist(
                    admin,
                    ITIP403Registry::modifyPolicyWhitelistCall {
                        policyId: policy_id,
                        account: recipient,
                        allowed: true,
                    },
                )?;
                assert!(!token.is_transfer_authorized(sender, recipient)?);

                // Sender whitelisted, recipient not whitelisted
                registry.modify_policy_whitelist(
                    admin,
                    ITIP403Registry::modifyPolicyWhitelistCall {
                        policyId: policy_id,
                        account: sender,
                        allowed: true,
                    },
                )?;
                registry.modify_policy_whitelist(
                    admin,
                    ITIP403Registry::modifyPolicyWhitelistCall {
                        policyId: policy_id,
                        account: recipient,
                        allowed: false,
                    },
                )?;
                assert!(!token.is_transfer_authorized(sender, recipient)?);

                // Both whitelisted
                registry.modify_policy_whitelist(
                    admin,
                    ITIP403Registry::modifyPolicyWhitelistCall {
                        policyId: policy_id,
                        account: recipient,
                        allowed: true,
                    },
                )?;
                assert!(token.is_transfer_authorized(sender, recipient)?);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_set_next_quote_token_rejects_path_usd() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = TIP20Setup::path_usd(admin).apply()?;
            let other_token = TIP20Setup::create("Test", "T", admin).apply()?;

            // pathUSD cannot update its quote token
            let result = path_usd.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: other_token.address,
                },
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                    _
                )))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_non_path_usd_cycle_detection() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            TIP20Setup::path_usd(admin).apply()?;

            let mut token_b = TIP20Setup::create("TokenB", "TKNB", admin).apply()?;
            let token_a = TIP20Setup::create("TokenA", "TKNA", admin)
                .quote_token(token_b.address)
                .apply()?;

            // Verify chain where token_a -> token_b -> PATH_USD
            assert_eq!(token_a.quote_token()?, token_b.address);
            assert_eq!(token_b.quote_token()?, PATH_USD_ADDRESS);

            // Try to create cycle where token_b -> token_a
            token_b.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: token_a.address,
                },
            )?;

            let result =
                token_b.complete_quote_token_update(admin, ITIP20::completeQuoteTokenUpdateCall {});

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                    _
                )))
            ));

            // assert that quote tokens are unchanged
            assert_eq!(token_a.quote_token()?, token_b.address);
            assert_eq!(token_b.quote_token()?, PATH_USD_ADDRESS);

            Ok(())
        })
    }

    // ═══════════════════════════════════════════════════════════
    //  TIP-1022 Virtual Address Tests
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_mint_to_virtual_address_credits_master() -> eyre::Result<()> {
        let amount = U256::from(1000);

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();

            StorageCtx::enter(&mut storage, || {
                let mut registry = AddressRegistry::new();
                let (_, virtual_addr) = register_virtual_master(&mut registry)?;
                let credited = if hardfork.is_t3() {
                    VIRTUAL_MASTER
                } else {
                    virtual_addr
                };

                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .clear_events()
                    .apply()?;

                // mint
                token.mint(
                    admin,
                    ITIP20::mintCall {
                        to: virtual_addr,
                        amount,
                    },
                )?;

                if hardfork.is_t3() {
                    // T3: master is credited, virtual balance stays zero
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, amount);
                    assert_eq!(token.get_balance(virtual_addr)?, U256::ZERO);
                    assert_eq!(token.total_supply()?, amount);

                    // Events: Transfer(0→virtual) + Mint(virtual) + Transfer(virtual→master)
                    token.assert_emitted_events(vec![
                        TIP20Event::Transfer(ITIP20::Transfer {
                            from: Address::ZERO,
                            to: virtual_addr,
                            amount,
                        }),
                        TIP20Event::Mint(ITIP20::Mint {
                            to: virtual_addr,
                            amount,
                        }),
                        TIP20Event::Transfer(ITIP20::Transfer {
                            from: virtual_addr,
                            to: VIRTUAL_MASTER,
                            amount,
                        }),
                    ]);
                } else {
                    // Pre-T3: virtual address treated as literal, balance goes there
                    assert_eq!(token.get_balance(virtual_addr)?, amount);
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, U256::ZERO);
                }

                // mintWithMemo: same resolution behavior
                let pre = token.get_balance(credited)?;
                token.mint_with_memo(
                    admin,
                    ITIP20::mintWithMemoCall {
                        to: virtual_addr,
                        amount,
                        memo: FixedBytes::ZERO,
                    },
                )?;
                assert_eq!(token.get_balance(credited)? - pre, amount);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_transfer_to_virtual_address_credits_master() -> eyre::Result<()> {
        let amount = U256::from(500);

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();
            let sender = Address::random();

            StorageCtx::enter(&mut storage, || {
                let mut registry = AddressRegistry::new();
                let (_, virtual_addr) = register_virtual_master(&mut registry)?;
                let credited = if hardfork.is_t3() {
                    VIRTUAL_MASTER
                } else {
                    virtual_addr
                };

                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .with_mint(sender, amount * U256::from(2))
                    .clear_events()
                    .apply()?;

                // transfer
                token.transfer(
                    sender,
                    ITIP20::transferCall {
                        to: virtual_addr,
                        amount,
                    },
                )?;

                if hardfork.is_t3() {
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, amount);
                    assert_eq!(token.get_balance(virtual_addr)?, U256::ZERO);

                    // Events: Transfer(sender→virtual) + Transfer(virtual→master)
                    token.assert_emitted_events(vec![
                        TIP20Event::Transfer(ITIP20::Transfer {
                            from: sender,
                            to: virtual_addr,
                            amount,
                        }),
                        TIP20Event::Transfer(ITIP20::Transfer {
                            from: virtual_addr,
                            to: VIRTUAL_MASTER,
                            amount,
                        }),
                    ]);
                } else {
                    assert_eq!(token.get_balance(virtual_addr)?, amount);
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, U256::ZERO);
                }

                // transferWithMemo: same resolution behavior
                let pre = token.get_balance(credited)?;
                token.transfer_with_memo(
                    sender,
                    ITIP20::transferWithMemoCall {
                        to: virtual_addr,
                        amount,
                        memo: FixedBytes::ZERO,
                    },
                )?;
                assert_eq!(token.get_balance(credited)? - pre, amount);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_transfer_from_to_virtual_address_credits_master() -> eyre::Result<()> {
        let amount = U256::from(300);

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();
            let owner = Address::random();
            let spender = Address::random();

            StorageCtx::enter(&mut storage, || {
                let mut registry = AddressRegistry::new();
                let (_, virtual_addr) = register_virtual_master(&mut registry)?;
                let credited = if hardfork.is_t3() {
                    VIRTUAL_MASTER
                } else {
                    virtual_addr
                };

                let total = amount * U256::from(2);
                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .with_mint(owner, total)
                    .with_approval(owner, spender, total)
                    .clear_events()
                    .apply()?;

                // transferFrom
                token.transfer_from(
                    spender,
                    ITIP20::transferFromCall {
                        from: owner,
                        to: virtual_addr,
                        amount,
                    },
                )?;

                if hardfork.is_t3() {
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, amount);
                    assert_eq!(token.get_balance(virtual_addr)?, U256::ZERO);
                } else {
                    assert_eq!(token.get_balance(virtual_addr)?, amount);
                    assert_eq!(token.get_balance(VIRTUAL_MASTER)?, U256::ZERO);
                }

                // transferFromWithMemo: same resolution behavior
                let pre = token.get_balance(credited)?;
                token.transfer_from_with_memo(
                    spender,
                    ITIP20::transferFromWithMemoCall {
                        from: owner,
                        to: virtual_addr,
                        amount,
                        memo: FixedBytes::ZERO,
                    },
                )?;
                assert_eq!(token.get_balance(credited)? - pre, amount);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    #[rustfmt::skip]
    fn test_unregistered_virtual_reverts_on_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let admin = Address::random();
        let sender = Address::random();
        let spender = Address::random();
        let to = make_virtual_address(MasterId::ZERO, UserTag::ZERO);
        let amount = U256::from(100);
        let memo = FixedBytes::ZERO;

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, amount)
                .with_approval(sender, spender, amount)
                .apply()?;

            // All 6 entrypoints should revert for an unregistered virtual address
            assert!(token.mint(admin, ITIP20::mintCall { to, amount }).is_err());
            assert!(token.mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo }).is_err());
            assert!(token.transfer(sender, ITIP20::transferCall { to, amount }).is_err());
            assert!(token.transfer_with_memo(sender, ITIP20::transferWithMemoCall { to, amount, memo }).is_err());
            assert!(token.transfer_from(spender, ITIP20::transferFromCall { from: sender, to, amount }).is_err());
            assert!(token.transfer_from_with_memo(spender, ITIP20::transferFromWithMemoCall { from: sender, to, amount, memo }).is_err());

            Ok(())
        })
    }

    // ═══════════════════════════════════════════════════════════
    //  EIP-2612 Permit Tests (TIP-1004)
    // ═══════════════════════════════════════════════════════════

    mod permit_tests {
        use super::*;
        use alloy::sol_types::SolValue;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use tempo_chainspec::hardfork::TempoHardfork;

        const CHAIN_ID: u64 = 42;

        /// Create a T2 storage provider for permit tests
        fn setup_t2_storage() -> HashMapStorageProvider {
            HashMapStorageProvider::new_with_spec(CHAIN_ID, TempoHardfork::T2)
        }

        /// Helper to create a valid permit signature
        fn sign_permit(
            signer: &PrivateKeySigner,
            token_name: &str,
            token_address: Address,
            spender: Address,
            value: U256,
            nonce: U256,
            deadline: U256,
        ) -> (u8, B256, B256) {
            let domain_separator = compute_domain_separator(token_name, token_address);
            let struct_hash = keccak256(
                (
                    *PERMIT_TYPEHASH,
                    signer.address(),
                    spender,
                    value,
                    nonce,
                    deadline,
                )
                    .abi_encode(),
            );
            let digest = keccak256(
                [
                    &[0x19, 0x01],
                    domain_separator.as_slice(),
                    struct_hash.as_slice(),
                ]
                .concat(),
            );

            let sig = signer.sign_hash_sync(&digest).unwrap();
            let v = sig.v() as u8 + 27;
            let r: B256 = sig.r().into();
            let s: B256 = sig.s().into();
            (v, r, s)
        }

        fn compute_domain_separator(token_name: &str, token_address: Address) -> B256 {
            keccak256(
                (
                    *EIP712_DOMAIN_TYPEHASH,
                    keccak256(token_name.as_bytes()),
                    *VERSION_HASH,
                    U256::from(CHAIN_ID),
                    token_address,
                )
                    .abi_encode(),
            )
        }

        struct PermitFixture {
            storage: HashMapStorageProvider,
            admin: Address,
            signer: PrivateKeySigner,
            spender: Address,
        }

        impl PermitFixture {
            fn new() -> Self {
                Self {
                    storage: setup_t2_storage(),
                    admin: Address::random(),
                    signer: PrivateKeySigner::random(),
                    spender: Address::random(),
                }
            }
        }

        fn make_permit_call(
            signer: &PrivateKeySigner,
            spender: Address,
            token_address: Address,
            value: U256,
            nonce: U256,
            deadline: U256,
        ) -> ITIP20::permitCall {
            let (v, r, s) = sign_permit(
                signer,
                "Test",
                token_address,
                spender,
                value,
                nonce,
                deadline,
            );
            ITIP20::permitCall {
                owner: signer.address(),
                spender,
                value,
                deadline,
                v,
                r,
                s,
            }
        }

        #[test]
        fn test_permit_happy_path() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let owner = signer.address();
            let value = U256::from(1000);

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
                let call =
                    make_permit_call(signer, spender, token.address, value, U256::ZERO, U256::MAX);
                token.permit(call)?;

                // Verify allowance was set
                let allowance = token.allowance(ITIP20::allowanceCall { owner, spender })?;
                assert_eq!(allowance, value);

                // Verify nonce was incremented
                let nonce = token.nonces(ITIP20::noncesCall { owner })?;
                assert_eq!(nonce, U256::from(1));

                Ok(())
            })
        }

        #[test]
        fn test_permit_expired() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let value = U256::from(1000);
            // Deadline in the past
            let deadline = U256::ZERO;

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
                let call =
                    make_permit_call(signer, spender, token.address, value, U256::ZERO, deadline);

                let result = token.permit(call);

                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::PermitExpired(_)))
                ));

                Ok(())
            })
        }

        #[test]
        fn test_permit_invalid_signature() -> eyre::Result<()> {
            let mut storage = setup_t2_storage();
            let admin = Address::random();
            let owner = Address::random();
            let spender = Address::random();
            let value = U256::from(1000);
            let deadline = U256::MAX;

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                // Use garbage signature bytes
                let result = token.permit(ITIP20::permitCall {
                    owner,
                    spender,
                    value,
                    deadline,
                    v: 27,
                    r: B256::ZERO,
                    s: B256::ZERO,
                });

                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSignature(_)))
                ));

                Ok(())
            })
        }

        #[test]
        fn test_permit_wrong_signer() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let wrong_owner = Address::random(); // Not the signer's address
            let value = U256::from(1000);
            let deadline = U256::MAX;

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                // Sign with signer but claim wrong_owner
                let (v, r, s) = sign_permit(
                    signer,
                    "Test",
                    token.address,
                    spender,
                    value,
                    U256::ZERO,
                    deadline,
                );

                let result = token.permit(ITIP20::permitCall {
                    owner: wrong_owner, // Different from signer
                    spender,
                    value,
                    deadline,
                    v,
                    r,
                    s,
                });

                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSignature(_)))
                ));

                Ok(())
            })
        }

        #[test]
        fn test_permit_replay_protection() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let value = U256::from(1000);

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
                let call =
                    make_permit_call(signer, spender, token.address, value, U256::ZERO, U256::MAX);

                // First use should succeed
                token.permit(call.clone())?;

                // Second use of same signature should fail (nonce incremented)
                let result = token.permit(call);

                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSignature(_)))
                ));

                Ok(())
            })
        }

        #[test]
        fn test_permit_nonce_tracking() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let owner = signer.address();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                // Initial nonce should be 0
                assert_eq!(token.nonces(ITIP20::noncesCall { owner })?, U256::ZERO);

                // Do 3 permits, each with correct nonce
                for i in 0u64..3 {
                    let nonce = U256::from(i);
                    let value = U256::from(100 * (i + 1));
                    let call =
                        make_permit_call(signer, spender, token.address, value, nonce, U256::MAX);
                    token.permit(call)?;

                    assert_eq!(
                        token.nonces(ITIP20::noncesCall { owner })?,
                        U256::from(i + 1)
                    );
                }

                Ok(())
            })
        }

        #[test]
        fn test_permit_works_when_paused() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let owner = signer.address();
            let value = U256::from(1000);

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_role(admin, *PAUSE_ROLE)
                    .apply()?;

                // Pause the token
                token.pause(admin, ITIP20::pauseCall {})?;
                assert!(token.paused()?);

                let call =
                    make_permit_call(signer, spender, token.address, value, U256::ZERO, U256::MAX);

                // Permit should work even when paused
                token.permit(call)?;

                assert_eq!(
                    token.allowance(ITIP20::allowanceCall { owner, spender })?,
                    value
                );

                Ok(())
            })
        }

        #[test]
        fn test_permit_domain_separator() -> eyre::Result<()> {
            let PermitFixture {
                mut storage, admin, ..
            } = PermitFixture::new();

            StorageCtx::enter(&mut storage, || {
                let token = TIP20Setup::create("Test", "TST", admin).apply()?;

                let ds = token.domain_separator()?;
                let expected = compute_domain_separator("Test", token.address);
                assert_eq!(ds, expected);

                Ok(())
            })
        }

        #[test]
        fn test_permit_max_allowance() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let owner = signer.address();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
                let call = make_permit_call(
                    signer,
                    spender,
                    token.address,
                    U256::MAX,
                    U256::ZERO,
                    U256::MAX,
                );
                token.permit(call)?;

                assert_eq!(
                    token.allowance(ITIP20::allowanceCall { owner, spender })?,
                    U256::MAX
                );

                Ok(())
            })
        }

        #[test]
        fn test_permit_allowance_override() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                ref signer,
                spender,
            } = PermitFixture::new();
            let owner = signer.address();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                // First permit: set allowance to 1000
                let call = make_permit_call(
                    signer,
                    spender,
                    token.address,
                    U256::from(1000),
                    U256::ZERO,
                    U256::MAX,
                );
                token.permit(call)?;
                assert_eq!(
                    token.allowance(ITIP20::allowanceCall { owner, spender })?,
                    U256::from(1000)
                );

                // Second permit: override to 0
                let call = make_permit_call(
                    signer,
                    spender,
                    token.address,
                    U256::ZERO,
                    U256::from(1),
                    U256::MAX,
                );
                token.permit(call)?;
                assert_eq!(
                    token.allowance(ITIP20::allowanceCall { owner, spender })?,
                    U256::ZERO
                );

                Ok(())
            })
        }

        #[test]
        fn test_permit_invalid_v_values() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                spender,
                ..
            } = PermitFixture::new();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                for v in [0u8, 1] {
                    let result = token.permit(ITIP20::permitCall {
                        owner: admin,
                        spender,
                        value: U256::from(1000),
                        deadline: U256::MAX,
                        v,
                        r: B256::ZERO,
                        s: B256::ZERO,
                    });

                    assert!(
                        matches!(
                            result,
                            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSignature(_)))
                        ),
                        "v={v} should revert with InvalidSignature"
                    );
                }

                Ok(())
            })
        }

        #[test]
        fn test_permit_zero_address_recovery_reverts() -> eyre::Result<()> {
            let PermitFixture {
                mut storage,
                admin,
                spender,
                ..
            } = PermitFixture::new();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

                let result = token.permit(ITIP20::permitCall {
                    owner: Address::ZERO,
                    spender,
                    value: U256::from(1000),
                    deadline: U256::MAX,
                    v: 27,
                    r: B256::ZERO,
                    s: B256::ZERO,
                });

                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSignature(_)))
                ));

                Ok(())
            })
        }

        #[test]
        fn test_permit_domain_separator_changes_with_chain_id() -> eyre::Result<()> {
            let PermitFixture { admin, .. } = PermitFixture::new();

            let mut storage_a = setup_t2_storage();
            let mut storage_b =
                HashMapStorageProvider::new_with_spec(CHAIN_ID + 1, TempoHardfork::T2);

            let ds_a = StorageCtx::enter(&mut storage_a, || {
                TIP20Setup::create("Test", "TST", admin)
                    .apply()?
                    .domain_separator()
            })?;

            let ds_b = StorageCtx::enter(&mut storage_b, || {
                TIP20Setup::create("Test", "TST", admin)
                    .apply()?
                    .domain_separator()
            })?;

            assert_ne!(
                ds_a, ds_b,
                "domain separator must change when chainId changes"
            );

            Ok(())
        }
    }

    #[test]
    fn test_mint_rejects_when_paused_on_t3() -> eyre::Result<()> {
        let to = Address::random();
        let amount = U256::from(1000);
        let memo = FixedBytes::random();

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .with_role(admin, *PAUSE_ROLE)
                    .apply()?;

                token.pause(admin, ITIP20::pauseCall {})?;

                let mint_result = token.mint(admin, ITIP20::mintCall { to, amount });
                let mint_memo_result =
                    token.mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo });

                if hardfork.is_t3() {
                    let expected = TempoPrecompileError::TIP20(TIP20Error::contract_paused());
                    assert_eq!(mint_result, Err(expected.clone()));
                    assert_eq!(mint_memo_result, Err(expected));
                } else {
                    assert!(mint_result.is_ok());
                    assert!(mint_memo_result.is_ok());
                }

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_burn_rejects_when_paused_on_t3() -> eyre::Result<()> {
        let amount = U256::from(500);
        let memo = FixedBytes::random();

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .with_role(admin, *PAUSE_ROLE)
                    .with_mint(admin, amount * U256::from(2))
                    .apply()?;

                token.pause(admin, ITIP20::pauseCall {})?;

                let burn_result = token.burn(admin, ITIP20::burnCall { amount });
                let burn_memo_result =
                    token.burn_with_memo(admin, ITIP20::burnWithMemoCall { amount, memo });

                if hardfork.is_t3() {
                    let expected = TempoPrecompileError::TIP20(TIP20Error::contract_paused());
                    assert_eq!(burn_result, Err(expected.clone()));
                    assert_eq!(burn_memo_result, Err(expected));
                } else {
                    assert!(burn_result.is_ok());
                    assert!(burn_memo_result.is_ok());
                }

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_burn_blocked_rejects_when_paused_on_t3() -> eyre::Result<()> {
        let amount = U256::from(500);
        let blocked = Address::random();

        for hardfork in [TempoHardfork::T2, TempoHardfork::T3] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            let admin = Address::random();

            StorageCtx::enter(&mut storage, || {
                // Create a blacklist policy and block the address
                let mut registry = TIP403Registry::new();
                registry.initialize()?;
                let policy_id = registry.create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    },
                )?;
                registry.modify_policy_blacklist(
                    admin,
                    ITIP403Registry::modifyPolicyBlacklistCall {
                        policyId: policy_id,
                        account: blocked,
                        restricted: true,
                    },
                )?;

                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .with_role(admin, *PAUSE_ROLE)
                    .with_role(admin, *BURN_BLOCKED_ROLE)
                    .with_mint(blocked, amount)
                    .apply()?;

                // Point the token's transfer policy at our blacklist
                token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: policy_id,
                    },
                )?;

                // Pause the token
                token.pause(admin, ITIP20::pauseCall {})?;

                let result = token.burn_blocked(
                    admin,
                    ITIP20::burnBlockedCall {
                        from: blocked,
                        amount,
                    },
                );

                if hardfork.is_t3() {
                    assert_eq!(
                        result,
                        Err(TempoPrecompileError::TIP20(TIP20Error::contract_paused()))
                    );
                } else {
                    // T2: pause not enforced, burn succeeds
                    assert!(result.is_ok());
                    assert_eq!(token.get_balance(blocked)?, U256::ZERO);
                }

                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }
}
