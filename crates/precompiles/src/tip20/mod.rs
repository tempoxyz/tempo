pub mod dispatch;
pub mod rewards;
pub mod roles;

use tempo_contracts::precompiles::{FeeManagerError, STABLECOIN_EXCHANGE_ADDRESS};
pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event,
};

use crate::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
    tip20::{
        rewards::{RewardStream, UserRewardInfo},
        roles::DEFAULT_ADMIN_ROLE,
    },
    tip20_factory::TIP20Factory,
    tip403_registry::{ITIP403Registry, TIP403Registry},
};
use alloy::{
    hex,
    primitives::{Address, B256, U256, keccak256, uint},
};
use std::sync::LazyLock;
use tempo_precompiles_macros::contract;
use tracing::trace;

/// u128::MAX as U256
pub const U128_MAX: U256 = uint!(0xffffffffffffffffffffffffffffffff_U256);

/// Decimal precision for TIP-20 tokens
const TIP20_DECIMALS: u8 = 6;

/// USD currency string constant
pub const USD_CURRENCY: &str = "USD";

/// TIP20 token address prefix (12 bytes for token ID encoding)
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Returns true if the address has the TIP20 prefix.
///
/// Note: This only checks the prefix, not whether the token was actually created.
/// Use `TIP20Factory::is_tip20()` for full validation (post-AllegroModerato).
pub fn is_tip20_prefix(token: Address) -> bool {
    token.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// Converts a token ID to its corresponding contract address
/// Uses the pattern: TIP20_TOKEN_PREFIX ++ token_id
pub fn token_id_to_address(token_id: u64) -> Address {
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
    address_bytes[12..20].copy_from_slice(&token_id.to_be_bytes());
    Address::from(address_bytes)
}

pub fn address_to_token_id_unchecked(address: Address) -> u64 {
    u64::from_be_bytes(address.as_slice()[12..20].try_into().unwrap())
}

#[contract]
pub struct TIP20Token {
    // RolesAuth
    roles: Mapping<Address, Mapping<B256, bool>>,
    role_admins: Mapping<B256, B256>,

    // TIP20 Metadata
    name: String,
    symbol: String,
    currency: String,
    domain_separator: B256,
    quote_token: Address,
    next_quote_token: Address,
    transfer_policy_id: u64,

    // TIP20 Token
    total_supply: U256,
    balances: Mapping<Address, U256>,
    allowances: Mapping<Address, Mapping<Address, U256>>,
    nonces: Mapping<Address, U256>,
    paused: bool,
    supply_cap: U256,
    salts: Mapping<B256, bool>,

    // TIP20 Rewards
    global_reward_per_token: U256,
    last_update_time: u64,
    total_reward_per_second: U256,
    opted_in_supply: u128,
    next_stream_id: u64,
    streams: Mapping<u64, RewardStream>,
    scheduled_rate_decrease: Mapping<u128, U256>,
    user_reward_info: Mapping<Address, UserRewardInfo>,

    // Fee recipient
    fee_recipient: Address,
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

/// Validates that a token has USD currency
pub fn validate_usd_currency(token: Address, storage: StorageCtx) -> Result<()> {
    if storage.spec().is_moderato() && !is_tip20_prefix(token) {
        return Err(FeeManagerError::invalid_token().into());
    }

    let tip20_token = TIP20Token::from_address(token)?;
    let currency = tip20_token.currency()?;
    if currency != USD_CURRENCY {
        return Err(TIP20Error::invalid_currency().into());
    }
    Ok(())
}

impl TIP20Token {
    pub fn name(&self) -> Result<String> {
        self.name.read()
    }

    pub fn symbol(&self) -> Result<String> {
        self.symbol.read()
    }

    pub fn decimals(&self) -> Result<u8> {
        Ok(TIP20_DECIMALS)
    }

    pub fn currency(&self) -> Result<String> {
        self.currency.read()
    }

    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    pub fn quote_token(&self) -> Result<Address> {
        self.quote_token.read()
    }

    pub fn next_quote_token(&self) -> Result<Address> {
        self.next_quote_token.read()
    }

    pub fn supply_cap(&self) -> Result<U256> {
        self.supply_cap.read()
    }

    pub fn paused(&self) -> Result<bool> {
        self.paused.read()
    }

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

    // View functions
    pub fn balance_of(&self, call: ITIP20::balanceOfCall) -> Result<U256> {
        self.balances.at(call.account).read()
    }

    pub fn allowance(&self, call: ITIP20::allowanceCall) -> Result<U256> {
        self.allowances.at(call.owner).at(call.spender).read()
    }

    // Admin functions
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Validate that the policy exists (only after AllegroModerato hardfork)
        if self.storage.spec().is_allegro_moderato() {
            let registry = TIP403Registry::new();
            if !registry.policy_exists(ITIP403Registry::policyExistsCall {
                policyId: call.newPolicyId,
            })? {
                return Err(TIP20Error::invalid_transfer_policy_id().into());
            }
        }

        self.transfer_policy_id.write(call.newPolicyId)?;

        self.emit_event(TIP20Event::TransferPolicyUpdate(
            ITIP20::TransferPolicyUpdate {
                updater: msg_sender,
                newPolicyId: call.newPolicyId,
            },
        ))
    }

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

    pub fn pause(&mut self, msg_sender: Address, _call: ITIP20::pauseCall) -> Result<()> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.paused.write(true)?;

        self.emit_event(TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
            updater: msg_sender,
            isPaused: true,
        }))
    }

    pub fn unpause(&mut self, msg_sender: Address, _call: ITIP20::unpauseCall) -> Result<()> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.paused.write(false)?;

        self.emit_event(TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
            updater: msg_sender,
            isPaused: false,
        }))
    }

    pub fn set_next_quote_token(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setNextQuoteTokenCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Verify the new quote token is a valid TIP20 token that has been deployed
        if self.storage.spec().is_allegro_moderato() {
            // Post-AllegroModerato: use factory's is_tip20 which checks both prefix and counter
            if !TIP20Factory::new().is_tip20(call.newQuoteToken)? {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else {
            // Pre-AllegroModerato: use original logic (prefix check + separate counter check)
            if !is_tip20_prefix(call.newQuoteToken) {
                return Err(TIP20Error::invalid_quote_token().into());
            }

            let new_token_id = address_to_token_id_unchecked(call.newQuoteToken);
            let factory_token_id_counter = TIP20Factory::new().token_id_counter()?.to::<u64>();

            // Ensure the quote token has been deployed (token_id < counter)
            if new_token_id >= factory_token_id_counter {
                return Err(TIP20Error::invalid_quote_token().into());
            }
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

    pub fn complete_quote_token_update(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::completeQuoteTokenUpdateCall,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self.next_quote_token()?;

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (PathUSD)
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

    /// Sets a new fee recipient
    pub fn set_fee_recipient(&mut self, msg_sender: Address, new_recipient: Address) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.fee_recipient.write(new_recipient)?;

        self.emit_event(TIP20Event::FeeRecipientUpdated(
            ITIP20::FeeRecipientUpdated {
                updater: msg_sender,
                newRecipient: new_recipient,
            },
        ))?;

        Ok(())
    }

    /// Gets the current fee recipient
    pub fn get_fee_recipient(&self, _msg_sender: Address) -> Result<Address> {
        self.fee_recipient.read()
    }

    // Token operations
    /// Mints new tokens to specified address
    pub fn mint(&mut self, msg_sender: Address, call: ITIP20::mintCall) -> Result<()> {
        self._mint(msg_sender, call.to, call.amount)?;
        if self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Mint(ITIP20::Mint {
                to: call.to,
                amount: call.amount,
            }))?;
        }
        Ok(())
    }

    /// Mints new tokens to specified address with memo attached
    pub fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<()> {
        self._mint(msg_sender, call.to, call.amount)?;

        // Post-Moderato: emit events where sender is Address::ZERO for mint operations
        let from = if self.storage.spec().is_moderato() {
            Address::ZERO
        } else {
            msg_sender
        };

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;
        if self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Mint(ITIP20::Mint {
                to: call.to,
                amount: call.amount,
            }))?;
        }
        Ok(())
    }

    /// Internal helper to mint new tokens and update balances
    fn _mint(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

        // Check if the `to` address is authorized to receive tokens
        if self.storage.spec().is_allegretto() {
            let transfer_policy_id = self.transfer_policy_id()?;
            let registry = TIP403Registry::new();
            if !registry.is_authorized(ITIP403Registry::isAuthorizedCall {
                policyId: transfer_policy_id,
                user: to,
            })? {
                return Err(TIP20Error::policy_forbids().into());
            }
        }

        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let supply_cap = self.supply_cap()?;
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        self.handle_rewards_on_mint(to, amount)?;

        self.set_total_supply(new_supply)?;
        let to_balance = self.get_balance(to)?;
        let new_to_balance: alloy::primitives::Uint<256, 4> = to_balance
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_balance(to, new_to_balance)?;

        self.emit_event(TIP20Event::Transfer(ITIP20::Transfer {
            from: Address::ZERO,
            to,
            amount,
        }))?;

        // Pre-Allegro Moderato: emit Mint event here
        if !self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Mint(ITIP20::Mint { to, amount }))?;
        }
        Ok(())
    }

    /// Burns tokens from sender's balance and reduces total supply
    pub fn burn(&mut self, msg_sender: Address, call: ITIP20::burnCall) -> Result<()> {
        self._burn(msg_sender, call.amount)?;
        if self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Burn(ITIP20::Burn {
                from: msg_sender,
                amount: call.amount,
            }))?;
        }
        Ok(())
    }

    /// Burns tokens from sender's balance with memo attached
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
        if self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Burn(ITIP20::Burn {
                from: msg_sender,
                amount: call.amount,
            }))?;
        }
        Ok(())
    }

    /// Burns tokens from blocked addresses that cannot transfer
    pub fn burn_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<()> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Prevent burning from `FeeManager` and `StablecoinExchange` to protect accounting invariants
        if self.storage.spec().is_allegretto()
            && matches!(
                call.from,
                TIP_FEE_MANAGER_ADDRESS | STABLECOIN_EXCHANGE_ADDRESS
            )
        {
            return Err(TIP20Error::protected_address().into());
        }

        // Check if the address is blocked from transferring
        let transfer_policy_id = self.transfer_policy_id()?;
        let registry = TIP403Registry::new();
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: call.from,
        })? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        self._transfer(call.from, Address::ZERO, call.amount)?;

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
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, Address::ZERO, amount)?;

        let total_supply = self.total_supply()?;
        let new_supply =
            total_supply
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_balance(
                    total_supply,
                    amount,
                    self.address,
                ))?;
        self.set_total_supply(new_supply)?;

        // Pre-Allegro Moderato: emit Burn event here
        if !self.storage.spec().is_allegro_moderato() {
            self.emit_event(TIP20Event::Burn(ITIP20::Burn {
                from: msg_sender,
                amount,
            }))?;
        }
        Ok(())
    }

    // Standard token functions
    pub fn approve(&mut self, msg_sender: Address, call: ITIP20::approveCall) -> Result<bool> {
        // Only check access keys after Allegretto hardfork
        if self.storage.spec().is_allegretto() {
            // Get the old allowance
            let old_allowance = self.get_allowance(msg_sender, call.spender)?;

            // Check and update spending limits for access keys
            let mut keychain = AccountKeychain::new();
            keychain.authorize_approve(msg_sender, self.address, old_allowance, call.amount)?;
        }

        // Set the new allowance
        self.set_allowance(msg_sender, call.spender, call.amount)?;

        self.emit_event(TIP20Event::Approval(ITIP20::Approval {
            owner: msg_sender,
            spender: call.spender,
            amount: call.amount,
        }))?;

        Ok(true)
    }

    pub fn transfer(&mut self, msg_sender: Address, call: ITIP20::transferCall) -> Result<bool> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        self.check_not_paused()?;
        self.check_not_token_address(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;

        // Only check access keys after Allegretto hardfork
        if self.storage.spec().is_allegretto() {
            // Check and update spending limits for access keys
            let mut keychain = AccountKeychain::new();
            keychain.authorize_transfer(msg_sender, self.address, call.amount)?;
        }

        self._transfer(msg_sender, call.to, call.amount)?;
        Ok(true)
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)
    }

    /// Transfer from `from` to `to` address with memo attached
    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)?;

        // Post-Moderato: call.from address in events, pre-Moderato uses msg_sender
        let from = if self.storage.spec().is_moderato() {
            call.from
        } else {
            msg_sender
        };

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;

        Ok(true)
    }

    /// Transfer from `from` to `to` address without approval requirement
    /// This function is not exposed via the public interface and should only be invoked by precompiles
    pub fn system_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        self.check_not_paused()?;
        self.check_not_token_address(to)?;
        self.ensure_transfer_authorized(from, to)?;

        self._transfer(from, to, amount)?;

        Ok(true)
    }

    fn _transfer_from(
        &mut self,
        msg_sender: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        self.check_not_paused()?;
        self.check_not_token_address(to)?;
        self.ensure_transfer_authorized(from, to)?;

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

    // TIP20 extension functions
    pub fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<()> {
        self.check_not_paused()?;
        self.check_not_token_address(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;

        self._transfer(msg_sender, call.to, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: msg_sender,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))
    }
}

// Utility functions
impl TIP20Token {
    pub fn new(token_id: u64) -> Self {
        let token_address = token_id_to_address(token_id);
        Self::__new(token_address)
    }

    /// Create a TIP20Token from an address.
    /// Returns an error if the address is not a valid TIP20 token (post-AllegroModerato).
    pub fn from_address(address: Address) -> Result<Self> {
        if StorageCtx.spec().is_allegro_moderato() && !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }
        let token_id = address_to_token_id_unchecked(address);
        Ok(Self::new(token_id))
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
    pub fn initialize(
        &mut self,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: Address,
        fee_recipient: Address,
    ) -> Result<()> {
        trace!(%name, address=%self.address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.__initialize()?;

        self.name.write(name.to_string())?;
        self.symbol.write(symbol.to_string())?;
        self.currency.write(currency.to_string())?;

        // If the currency is USD, the quote token must also be USD.
        // Skip this check in AllegroModerato+ when quote_token is Address::ZERO (first token case).
        if currency == USD_CURRENCY {
            let skip_check = self.storage.spec().is_allegro_moderato() && quote_token.is_zero();
            if !skip_check {
                let quote_token_currency = Self::from_address(quote_token)?.currency()?;
                if quote_token_currency != USD_CURRENCY {
                    return Err(TIP20Error::invalid_quote_token().into());
                }
            }
        }

        self.quote_token.write(quote_token)?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.next_quote_token.write(quote_token)?;

        // Set default values
        if self.storage.spec().is_moderato() {
            self.supply_cap.write(U256::from(u128::MAX))?;
        } else {
            self.supply_cap.write(U256::MAX)?;
        }
        self.transfer_policy_id.write(1)?;

        // Gate to avoid consensus-breaking gas usage
        if self.storage.spec().is_allegretto() {
            self.fee_recipient.write(fee_recipient)?;
        }

        // Initialize roles system and grant admin role
        self.initialize_roles()?;
        self.grant_default_admin(admin)
    }

    fn get_balance(&self, account: Address) -> Result<U256> {
        self.balances.at(account).read()
    }

    fn set_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances.at(account).write(amount)
    }

    fn get_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        self.allowances.at(owner).at(spender).read()
    }

    fn set_allowance(&mut self, owner: Address, spender: Address, amount: U256) -> Result<()> {
        self.allowances.at(owner).at(spender).write(amount)
    }

    fn set_total_supply(&mut self, amount: U256) -> Result<()> {
        self.total_supply.write(amount)
    }

    fn check_not_paused(&self) -> Result<()> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: Address) -> Result<()> {
        // Don't allow sending to other precompiled tokens
        if is_tip20_prefix(to) {
            return Err(TIP20Error::invalid_recipient().into());
        }
        Ok(())
    }

    /// Checks if the transfer is authorized.
    pub fn is_transfer_authorized(&self, from: Address, to: Address) -> Result<bool> {
        let transfer_policy_id = self.transfer_policy_id()?;
        let registry = TIP403Registry::new();

        // Check if 'from' address is authorized
        let from_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: from,
        })?;

        // Check if 'to' address is authorized
        let to_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: to,
        })?;

        Ok(from_authorized && to_authorized)
    }

    /// Ensures the transfer is authorized.
    pub fn ensure_transfer_authorized(&self, from: Address, to: Address) -> Result<()> {
        if !self.is_transfer_authorized(from, to)? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    fn _transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
            );
        }

        // Accrue before balance changes
        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        self.handle_rewards_on_transfer(from, to, amount)?;

        // Adjust balances
        let from_balance = self.get_balance(from)?;
        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        self.set_balance(from, new_from_balance)?;

        if to != Address::ZERO {
            let to_balance = self.get_balance(to)?;
            let new_to_balance = to_balance
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.set_balance(to, new_to_balance)?;
        }

        self.emit_event(TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }))
    }

    /// Transfers fee tokens from user to fee manager before transaction execution
    pub fn transfer_fee_pre_tx(&mut self, from: Address, amount: U256) -> Result<()> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
            );
        }

        // Handle rewards (only after Moderato hardfork)
        if self.storage.spec().is_moderato() {
            // Accrue rewards up to current timestamp
            let current_timestamp = self.storage.timestamp();
            self.accrue(current_timestamp)?;

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
        self.set_balance(TIP_FEE_MANAGER_ADDRESS, new_to_balance)?;

        Ok(())
    }

    /// Refunds unused fee tokens to user and emits transfer event for gas amount used
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

        // Handle rewards (only after Moderato hardfork)
        if self.storage.spec().is_moderato() {
            // Note: We assume that transferFeePreTx is always called first, so _accrue has already been called
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
        }

        let from_balance = self.get_balance(TIP_FEE_MANAGER_ADDRESS)?;
        if refund > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, refund, self.address).into(),
            );
        }

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

#[cfg(test)]
pub(crate) mod tests {
    use alloy::primitives::{Address, FixedBytes, IntoLogData, U256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, ITIP20Factory};

    use super::*;
    use crate::{
        PATH_USD_ADDRESS, error::TempoPrecompileError, storage::hashmap::HashMapStorageProvider,
        test_util::setup_storage,
    };
    use rand::{Rng, distributions::Alphanumeric, random, thread_rng};

    /// Initialize PathUSD token. For AllegroModerato+, uses the factory flow.
    /// For older specs, initializes directly.
    pub(crate) fn initialize_path_usd(admin: Address) -> Result<()> {
        if !StorageCtx.spec().is_allegretto() {
            let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            path_usd.initialize(
                "PathUSD",
                "PUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
        } else {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;
            deploy_path_usd(&mut factory, admin)?;

            Ok(())
        }
    }

    /// Deploy PathUSD via the factory. Requires AllegroModerato+ spec and no tokens deployed yet.
    pub(crate) fn deploy_path_usd(factory: &mut TIP20Factory, admin: Address) -> Result<Address> {
        let token_id = factory.token_id_counter()?;

        if !token_id.is_zero() {
            return Err(TempoPrecompileError::Fatal(
                "PathUSD is not the first deployed token".to_string(),
            ));
        }

        factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: "PathUSD".to_string(),
                symbol: "PUSD".to_string(),
                currency: "USD".to_string(),
                quoteToken: Address::ZERO,
                admin,
            },
        )
    }

    /// Helper to setup a token with rewards for testing fee transfer functions
    /// Returns (token_id, initial_opted_in_supply)
    fn setup_token_with_rewards(
        admin: Address,
        user: Address,
        mint_amount: U256,
        reward_amount: U256,
    ) -> Result<(u64, u128)> {
        initialize_path_usd(admin)?;
        let token_id = setup_factory_with_token(admin, "Test", "TST")?;

        let mut token = TIP20Token::new(token_id);
        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens to admin (for reward stream)
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Mint tokens to user
        token.mint(
            admin,
            ITIP20::mintCall {
                to: user,
                amount: mint_amount,
            },
        )?;

        // User opts into rewards
        token.set_reward_recipient(user, ITIP20::setRewardRecipientCall { recipient: user })?;

        // Verify initial opted-in supply
        let initial_opted_in = token.get_opted_in_supply()?;
        assert_eq!(initial_opted_in, mint_amount.to::<u128>());

        // Start a reward stream
        token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 100,
            },
        )?;

        // Advance time to accrue rewards
        let initial_time = StorageCtx.timestamp();
        StorageCtx.set_timestamp(initial_time + U256::from(50));

        Ok((token_id, initial_opted_in))
    }

    /// Initialize a factory and create a single token
    fn setup_factory_with_token(admin: Address, name: &str, symbol: &str) -> Result<u64> {
        initialize_path_usd(admin)?;

        let mut factory = TIP20Factory::new();
        let token_address = factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: name.to_string(),
                symbol: symbol.to_string(),
                currency: "USD".to_string(),
                quoteToken: PATH_USD_ADDRESS,
                admin,
            },
        )?;

        Ok(address_to_token_id_unchecked(token_address))
    }

    /// Create a token via an already-initialized factory
    fn create_token_via_factory(
        factory: &mut TIP20Factory,
        admin: Address,
        name: &str,
        symbol: &str,
        quote_token: Address,
    ) -> Result<u64> {
        let token_address = factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: name.to_string(),
                symbol: symbol.to_string(),
                currency: "USD".to_string(),
                quoteToken: quote_token,
                admin,
            },
        )?;

        Ok(address_to_token_id_unchecked(token_address))
    }

    /// Setup factory and create a token with a separate quote token (both linking to LINKING_USD)
    fn setup_token_with_custom_quote_token(admin: Address) -> Result<(u64, u64)> {
        initialize_path_usd(admin)?;
        let mut factory = TIP20Factory::new();
        factory.initialize()?;

        let token_id =
            create_token_via_factory(&mut factory, admin, "Test", "TST", PATH_USD_ADDRESS)?;
        let quote_token_id =
            create_token_via_factory(&mut factory, admin, "Quote", "QUOTE", PATH_USD_ADDRESS)?;

        Ok((token_id, quote_token_id))
    }

    #[test]
    fn test_mint_increases_balance_and_supply() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let addr = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            // Initialize with admin
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            // Grant issuer role to admin
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let amount = U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?;
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
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let amount = U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?;
            token.mint(admin, ITIP20::mintCall { to: from, amount })?;
            token.transfer(from, ITIP20::transferCall { to, amount })?;

            assert_eq!(token.get_balance(from)?, U256::ZERO);
            assert_eq!(token.get_balance(to)?, amount);
            assert_eq!(token.total_supply()?, amount); // Supply unchanged

            token.assert_emitted_events(vec![
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: Address::ZERO,
                    to: from,
                    amount,
                }),
                TIP20Event::Mint(ITIP20::Mint { to: from, amount }),
                TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let from = Address::random();
        let to = Address::random();

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(1);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            let amount =
                U256::random().min(U256::from(u128::MAX)) % token.supply_cap()? + U256::ONE;
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
    fn test_mint_with_memo_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let to = Address::random();
            let amount = U256::random() % token.supply_cap()?;
            let memo = FixedBytes::random();

            token.mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo })?;

            // TransferWithMemo event should have Address::ZERO as from for post-Moderato
            assert_eq!(
                token.emitted_events()[2],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: Address::ZERO,
                    to,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_mint_with_memo_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let to = Address::random();
            let amount = U256::random();
            let memo = FixedBytes::random();

            token.mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo })?;

            // TransferWithMemo event should have msg_sender as from for pre-Moderato
            assert_eq!(
                token.emitted_events()[2],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: admin,
                    to,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let amount = U256::from(random::<u128>());
            let memo = FixedBytes::random();

            token.mint(admin, ITIP20::mintCall { to: admin, amount })?;
            token.burn_with_memo(admin, ITIP20::burnWithMemoCall { amount, memo })?;

            assert_eq!(
                token.emitted_events()[2],
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: admin,
                    to: Address::ZERO,
                    amount
                })
                .into_log_data()
            );

            assert_eq!(
                token.emitted_events()[3],
                TIP20Event::Burn(ITIP20::Burn {
                    from: admin,
                    amount
                })
                .into_log_data()
            );

            assert_eq!(
                token.emitted_events()[4],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: admin,
                    to: Address::ZERO,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let owner = Address::random();
            let spender = Address::random();
            let to = Address::random();
            let amount = U256::random();
            let memo = FixedBytes::random();

            token.mint(admin, ITIP20::mintCall { to: owner, amount })?;
            token.approve(owner, ITIP20::approveCall { spender, amount })?;
            assert!(token.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to,
                    amount,
                    memo,
                },
            )?);

            assert_eq!(
                token.emitted_events()[3],
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: owner,
                    to,
                    amount
                })
                .into_log_data()
            );

            assert_eq!(
                token.emitted_events()[4],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: spender,
                    to,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_from_address_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let owner = Address::random();
            let spender = Address::random();
            let to = Address::random();
            let amount = U256::random() % token.supply_cap()?;
            let memo = FixedBytes::random();

            token.mint(admin, ITIP20::mintCall { to: owner, amount })?;
            token.approve(owner, ITIP20::approveCall { spender, amount })?;
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
            assert_eq!(
                token.emitted_events()[4],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: owner,
                    to,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_from_address_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let owner = Address::random();
            let spender = Address::random();
            let to = Address::random();
            let amount = U256::random();
            let memo = FixedBytes::random();

            token.mint(admin, ITIP20::mintCall { to: owner, amount })?;
            token.approve(owner, ITIP20::approveCall { spender, amount })?;
            token.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to,
                    amount,
                    memo,
                },
            )?;

            // TransferWithMemo event should user msg_sender in transfer event
            assert_eq!(
                token.emitted_events()[4],
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: spender,
                    to,
                    amount,
                    memo
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let amount = U256::from(100);
            token.mint(admin, ITIP20::mintCall { to: user, amount })?;

            let fee_amount = U256::from(50);
            token
                .transfer_fee_pre_tx(user, fee_amount)
                .expect("transfer failed");

            assert_eq!(token.get_balance(user)?, U256::from(50));
            assert_eq!(token.get_balance(TIP_FEE_MANAGER_ADDRESS)?, fee_amount);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            let fee_amount = U256::from(50);
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
    fn test_transfer_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            let initial_fee = U256::from(100);
            token.set_balance(TIP_FEE_MANAGER_ADDRESS, initial_fee)?;

            let refund_amount = U256::from(30);
            let gas_used = U256::from(10);
            token.transfer_fee_post_tx(user, refund_amount, gas_used)?;

            assert_eq!(token.get_balance(user)?, refund_amount);
            assert_eq!(token.get_balance(TIP_FEE_MANAGER_ADDRESS)?, U256::from(70));

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
    fn test_transfer_from_insufficient_allowance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::from(100);
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;
            token.mint(admin, ITIP20::mintCall { to: from, amount })?;

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
        let amount = U256::from(100);
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            token.mint(admin, ITIP20::mintCall { to: from, amount })?;

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
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let token = TIP20Token::new(token_id);

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
            let (token_id, quote_token_id) = setup_token_with_custom_quote_token(admin)?;
            let quote_token_address = token_id_to_address(quote_token_id);

            let mut token = TIP20Token::new(token_id);

            // Set next quote token
            token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )?;

            // Verify next quote token was set
            assert_eq!(token.next_quote_token()?, quote_token_address);

            // Verify event was emitted
            assert_eq!(
                token.emitted_events().last().unwrap(),
                &TIP20Event::NextQuoteTokenSet(ITIP20::NextQuoteTokenSet {
                    updater: admin,
                    nextQuoteToken: quote_token_address,
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
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            let quote_token_address = token_id_to_address(2);

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
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let mut token = TIP20Token::new(token_id);

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
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let mut token = TIP20Token::new(token_id);

            // Try to set a TIP20 address that hasn't been deployed yet (token_id = 999)
            // This has the correct TIP20 address pattern but hasn't been created
            let undeployed_token_address = token_id_to_address(999);
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
            let (token_id, quote_token_id) = setup_token_with_custom_quote_token(admin)?;
            let quote_token_address = token_id_to_address(quote_token_id);

            let mut token = TIP20Token::new(token_id);

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
            initialize_path_usd(admin)?;
            let mut factory = TIP20Factory::new();

            // Create token_b first (links to LINKING_USD)
            let token_b_id =
                create_token_via_factory(&mut factory, admin, "Token B", "TKB", PATH_USD_ADDRESS)?;
            let token_b_address = token_id_to_address(token_b_id);

            // Create token_a (links to token_b)
            let token_a_id =
                create_token_via_factory(&mut factory, admin, "Token A", "TKA", token_b_address)?;
            let token_a_address = token_id_to_address(token_a_id);

            // Now try to set token_a as the next quote token for token_b (would create A -> B -> A loop)
            let mut token_b = TIP20Token::new(token_b_id);
            token_b.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: token_a_address,
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
            let (token_id, quote_token_id) = setup_token_with_custom_quote_token(admin)?;
            let quote_token_address = token_id_to_address(quote_token_id);

            let mut token = TIP20Token::new(token_id);

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
        assert_eq!(
            &DEFAULT_FEE_TOKEN_POST_ALLEGRETTO.as_slice()[..12],
            &TIP20_TOKEN_PREFIX
        );
    }

    #[test]
    fn test_arbitrary_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            for _ in 0..50 {
                let mut token = TIP20Token::new(1);

                let currency: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(31)
                    .map(char::from)
                    .collect();

                // Initialize token with the random currency
                token.initialize(
                    "Test",
                    "TST",
                    &currency,
                    PATH_USD_ADDRESS,
                    admin,
                    Address::ZERO,
                )?;

                // Verify the currency was stored and can be retrieved correctly
                let stored_currency = token.currency()?;
                assert_eq!(stored_currency, currency,);
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "NOTE(rusowsky): this doesn't panic anymore, as storage primitives can handle long strings now"]
    fn test_invalid_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            for _ in 0..10 {
                let mut token = TIP20Token::new(1);

                let currency: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect();

                let result = token.initialize(
                    "Test",
                    "TST",
                    &currency,
                    PATH_USD_ADDRESS,
                    admin,
                    Address::ZERO,
                );
                assert!(matches!(
                    result,
                    Err(TempoPrecompileError::TIP20(TIP20Error::StringTooLong(_)))
                ),);
            }

            Ok(())
        })
    }

    #[test]
    fn test_from_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create a token to get a valid address
            let token_id = setup_factory_with_token(admin, "TEST", "TST")?;
            let token_address = token_id_to_address(token_id);

            // Test from_address creates same instance as new()
            let token = TIP20Token::new(token_id);
            let addr_via_new = token.address;

            let token = TIP20Token::from_address(token_address)?;
            let addr_via_from_address = token.address;

            assert_eq!(
                addr_via_new, addr_via_from_address,
                "Both methods should create token with same address"
            );
            assert_eq!(
                addr_via_from_address, token_address,
                "from_address should use the provided address"
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

            let mut token = TIP20Token::new(1);
            token.initialize(
                "Token",
                "T",
                &currency,
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;

            // Try to create a new USD token with the arbitrary token as the quote token, this should fail
            let token_address = token.address;
            let mut usd_token = TIP20Token::new(2);
            let result = usd_token.initialize(
                "USD Token",
                "USDT",
                USD_CURRENCY,
                token_address,
                admin,
                Address::ZERO,
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
    fn test_new_valid_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut usd_token1 = TIP20Token::new(1);
            usd_token1.initialize(
                "USD Token",
                "USDT",
                USD_CURRENCY,
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;

            // USD token with USD token as quote
            let usd_token1_address = token_id_to_address(1);
            let mut usd_token2 = TIP20Token::new(2);
            let result = usd_token2.initialize(
                "USD Token 2",
                "USD2",
                USD_CURRENCY,
                usd_token1_address,
                admin,
                Address::ZERO,
            );
            assert!(result.is_ok());

            // Create non USD token
            let currency_1: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let mut token_1 = TIP20Token::new(3);
            token_1.initialize(
                "Token 1",
                "TK1",
                &currency_1,
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;

            // Create a non USD token with non USD quote token
            let currency_2: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let token_1_address = token_id_to_address(3);
            let mut token_2 = TIP20Token::new(4);
            let result = token_2.initialize(
                "Token 2",
                "TK2",
                &currency_2,
                token_1_address,
                admin,
                Address::ZERO,
            );
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_update_quote_token_invalid_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let currency: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(31)
                .map(char::from)
                .collect();

            let mut token_1 = TIP20Token::new(1);
            token_1.initialize(
                "Token 1",
                "TK1",
                &currency,
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;

            // Create a new USD token
            let mut usd_token = TIP20Token::new(2);
            usd_token.initialize(
                "USD Token",
                "USDT",
                USD_CURRENCY,
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;

            // Try to update the USD token's quote token to the arbitrary currency token, this should fail
            let token_1_address = token_id_to_address(1);
            let result = usd_token.set_next_quote_token(
                admin,
                ITIP20::setNextQuoteTokenCall {
                    newQuoteToken: token_1_address,
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
    fn test_is_tip20_prefix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(sender)?;

            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            let created_tip20 = factory.create_token(
                sender,
                ITIP20Factory::createTokenCall {
                    name: "Test Token".to_string(),
                    symbol: "TEST".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: crate::PATH_USD_ADDRESS,
                    admin: sender,
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
    fn test_transfer_fee_pre_tx_handles_rewards_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (rewards should be handled)
        // Note that we initially create storage at the Adagio hardfork so that scheduled rewards
        // are enabled for the test setup
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            // Setup token with rewards enabled
            let (token_id, initial_opted_in) =
                setup_token_with_rewards(admin, user, mint_amount, reward_amount)?;

            // Update the hardfork to Moderato to ensure rewards are handled post hardfork
            StorageCtx.set_spec(TempoHardfork::Moderato);

            // Transfer fee from user
            let fee_amount = U256::from(100e18);
            let mut token = TIP20Token::new(token_id);
            token.transfer_fee_pre_tx(user, fee_amount)?;

            // After transfer_fee_pre_tx, the opted-in supply should be decreased
            let final_opted_in = token.get_opted_in_supply()?;
            assert_eq!(
                final_opted_in,
                initial_opted_in - fee_amount.to::<u128>(),
                "opted-in supply should decrease by fee amount"
            );

            // User should have accumulated rewards (verify rewards were updated)
            let user_info = token.get_user_reward_info(user)?;
            assert!(
                user_info.reward_balance > U256::ZERO,
                "user should have accumulated rewards"
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_pre_tx_no_rewards_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - rewards should NOT be handled
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            // Setup token with rewards enabled
            let (token_id, initial_opted_in) =
                setup_token_with_rewards(admin, user, mint_amount, reward_amount)?;

            // Transfer fee from user
            let fee_amount = U256::from(100e18);
            let mut token = TIP20Token::new(token_id);
            token.transfer_fee_pre_tx(user, fee_amount)?;

            // Pre-Moderato: opted-in supply should NOT be decreased (rewards not handled)
            let final_opted_in = token.get_opted_in_supply()?;
            assert_eq!(
                final_opted_in, initial_opted_in,
                "opted-in supply should NOT change pre-Moderato"
            );

            // User should NOT have accumulated rewards (rewards not handled)
            let user_info = token.get_user_reward_info(user)?;
            assert_eq!(
                user_info.reward_balance,
                U256::ZERO,
                "user should NOT have accumulated rewards pre-Moderato"
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_post_tx_handles_rewards_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (rewards should be handled)
        // Note that we initially create storage at the Adagio hardfork so that scheduled rewards
        // are enabled for the test setup
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            // Setup token with rewards enabled
            let (token_id, _initial_opted_in) =
                setup_token_with_rewards(admin, user, mint_amount, reward_amount)?;

            // Update the hardfork to Moderato to ensure rewards are handled post hardfork
            StorageCtx.set_spec(TempoHardfork::Moderato);
            // Simulate fee transfer: first take fee from user
            let fee_amount = U256::from(100e18);
            let mut token = TIP20Token::new(token_id);
            token.transfer_fee_pre_tx(user, fee_amount)?;

            // Get opted-in supply after pre_tx
            let opted_in_after_pre = token.get_opted_in_supply()?;

            // Now refund part of it back
            let refund_amount = U256::from(40e18);
            let actual_used = U256::from(60e18);
            token.transfer_fee_post_tx(user, refund_amount, actual_used)?;

            // After transfer_fee_post_tx, the opted-in supply should increase by refund amount
            let final_opted_in = token.get_opted_in_supply()?;

            assert_eq!(
                final_opted_in,
                opted_in_after_pre + refund_amount.to::<u128>(),
                "opted-in supply should increase by refund amount"
            );

            // User should have accumulated rewards
            let user_info = token.get_user_reward_info(user)?;
            assert!(
                user_info.reward_balance > U256::ZERO,
                "user should have accumulated rewards"
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_fee_post_tx_no_rewards_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - rewards should NOT be handled
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Adagio);
        let user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            // Setup token with rewards enabled
            let (token_id, initial_opted_in) =
                setup_token_with_rewards(admin, user, mint_amount, reward_amount)?;

            // Simulate fee transfer: first take fee from user
            let fee_amount = U256::from(100e18);
            let mut token = TIP20Token::new(token_id);
            token.transfer_fee_pre_tx(user, fee_amount)?;

            // Get opted-in supply after pre_tx (should be unchanged pre-Moderato)
            let opted_in_after_pre = token.get_opted_in_supply()?;
            assert_eq!(
                opted_in_after_pre, initial_opted_in,
                "opted-in supply should be unchanged in pre_tx pre-Moderato"
            );

            // Now refund part of it back
            let refund_amount = U256::from(40e18);
            let actual_used = U256::from(60e18);
            token.transfer_fee_post_tx(user, refund_amount, actual_used)?;

            // After transfer_fee_post_tx, the opted-in supply should still be unchanged (rewards not handled)
            let final_opted_in = token.get_opted_in_supply()?;

            assert_eq!(
                final_opted_in, initial_opted_in,
                "opted-in supply should remain unchanged pre-Moderato"
            );

            // User should NOT have accumulated rewards
            let user_info = token.get_user_reward_info(user)?;
            assert_eq!(
                user_info.reward_balance,
                U256::ZERO,
                "user should NOT have accumulated rewards pre-Moderato"
            );

            Ok(())
        })
    }

    #[test]
    fn test_initialize_supply_cap_post_moderato() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let token = TIP20Token::new(token_id);

            let supply_cap = token.supply_cap()?;
            assert_eq!(supply_cap, U256::from(u128::MAX));

            Ok(())
        })
    }

    #[test]
    fn test_initialize_supply_cap_pre_moderato() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        storage.set_spec(TempoHardfork::Adagio);

        StorageCtx::enter(&mut storage, || {
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let token = TIP20Token::new(token_id);

            let supply_cap = token.supply_cap()?;
            assert_eq!(supply_cap, U256::MAX);

            Ok(())
        })
    }

    #[test]
    fn test_unable_to_burn_blocked_from_protected_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let admin = Address::random();
        let burner = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Initialize token
            initialize_path_usd(admin)?;
            let token_id = 1;
            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            // Grant BURN_BLOCKED_ROLE to burner
            token.grant_role_internal(burner, *BURN_BLOCKED_ROLE)?;

            // Simulate collected fees
            token.grant_role_internal(admin, *ISSUER_ROLE)?;
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::from(1000),
                },
            )?;

            // Attempt to burn from FeeManager
            let result = token.burn_blocked(
                burner,
                ITIP20::burnBlockedCall {
                    from: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::from(500),
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
            assert_eq!(balance, U256::from(1000));

            // Mint tokens to StablecoinExchange
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: STABLECOIN_EXCHANGE_ADDRESS,
                    amount: U256::from(1000),
                },
            )?;

            // Attempt to burn from StablecoinExchange
            let result = token.burn_blocked(
                burner,
                ITIP20::burnBlockedCall {
                    from: STABLECOIN_EXCHANGE_ADDRESS,
                    amount: U256::from(500),
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ProtectedAddress(_)))
            ));

            // Verify StablecoinExchange balance is unchanged
            let balance = token.balance_of(ITIP20::balanceOfCall {
                account: STABLECOIN_EXCHANGE_ADDRESS,
            })?;
            assert_eq!(balance, U256::from(1000));

            Ok(())
        })
    }

    #[test]
    fn test_set_fee_recipient() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        storage.set_spec(TempoHardfork::Adagio);

        StorageCtx::enter(&mut storage, || {
            let token_id = setup_factory_with_token(admin, "Test", "TST")?;
            let mut token = TIP20Token::new(token_id);

            let fee_recipient = token.get_fee_recipient(admin)?;
            assert_eq!(fee_recipient, Address::ZERO);

            let expected_recipient = Address::random();
            token.set_fee_recipient(admin, expected_recipient)?;

            let fee_recipient = token.get_fee_recipient(admin)?;
            assert_eq!(fee_recipient, expected_recipient);

            let result = token.set_fee_recipient(Address::random(), expected_recipient);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_initialize_usd_token_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // USD token with zero quote token should succeed
            let mut token = TIP20Token::new(1);
            assert!(
                token
                    .initialize(
                        "TestToken",
                        "TEST",
                        "USD",
                        Address::ZERO,
                        admin,
                        Address::ZERO
                    )
                    .is_ok()
            );

            // Non-USD token with zero quote token should succeed
            let mut eur_token = TIP20Token::new(2);
            assert!(
                eur_token
                    .initialize(
                        "EuroToken",
                        "EUR",
                        "EUR",
                        Address::ZERO,
                        admin,
                        Address::ZERO
                    )
                    .is_ok()
            );

            // USD token with non-USD quote token should fail
            let mut usd_token = TIP20Token::new(3);
            let eur_token_address = token_id_to_address(2);
            assert!(
                usd_token
                    .initialize(
                        "USDToken",
                        "USD",
                        "USD",
                        eur_token_address,
                        admin,
                        Address::ZERO
                    )
                    .is_err()
            );

            Ok(())
        })
    }

    #[test]
    fn test_initialize_usd_token_pre_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // USD token with zero quote token should fail (no skip for zero quote token pre-AllegroModerato)
            let mut token = TIP20Token::new(1);
            assert!(
                token
                    .initialize(
                        "TestToken",
                        "TEST",
                        "USD",
                        Address::ZERO,
                        admin,
                        Address::ZERO
                    )
                    .is_err()
            );

            // Non-USD token with zero quote token should succeed
            let mut eur_token = TIP20Token::new(1);
            assert!(
                eur_token
                    .initialize(
                        "EuroToken",
                        "EUR",
                        "EUR",
                        Address::ZERO,
                        admin,
                        Address::ZERO,
                    )
                    .is_ok()
            );

            Ok(())
        })
    }

    #[test]
    fn test_deploy_path_usd_via_factory_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            let path_usd_address = deploy_path_usd(&mut factory, admin)?;
            assert_eq!(path_usd_address, PATH_USD_ADDRESS);

            let path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            assert_eq!(path_usd.currency()?, "USD");
            assert_eq!(path_usd.quote_token()?, Address::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_deploy_path_usd_fails_if_token_already_deployed_post_allegro_moderato()
    -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            deploy_path_usd(&mut factory, admin)?;

            let result = deploy_path_usd(&mut factory, admin);
            assert!(
                result.is_err(),
                "deploy_path_usd should fail if a token has already been deployed"
            );
            Ok(())
        })
    }

    #[test]
    fn test_change_transfer_policy_id_invalid_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            // Deploy PathUSD token
            deploy_path_usd(&mut factory, admin)?;
            let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;

            // Initialize the TIP403 registry
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            // Try to change to a non-existent policy ID (should fail with Allegretto hardfork)
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
}
