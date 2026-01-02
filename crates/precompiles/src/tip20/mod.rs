pub mod dispatch;
pub mod rewards;
pub mod roles;

use tempo_contracts::precompiles::STABLECOIN_EXCHANGE_ADDRESS;
pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event,
};

use crate::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{rewards::UserRewardInfo, roles::DEFAULT_ADMIN_ROLE},
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
/// NOTE: This only checks the prefix, not whether the token was actually created.
/// Use `TIP20Factory::is_tip20()` for full validation.
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

/// Validates that a token has USD currency
pub fn validate_usd_currency(token: Address) -> Result<()> {
    if TIP20Token::from_address(token)?.currency()? != USD_CURRENCY {
        return Err(TIP20Error::invalid_currency().into());
    }
    Ok(())
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
    opted_in_supply: u128,
    user_reward_info: Mapping<Address, UserRewardInfo>,
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

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

    // Token operations
    /// Mints new tokens to specified address
    pub fn mint(&mut self, msg_sender: Address, call: ITIP20::mintCall) -> Result<()> {
        self._mint(msg_sender, call.to, call.amount)?;
        self.emit_event(TIP20Event::Mint(ITIP20::Mint {
            to: call.to,
            amount: call.amount,
        }))?;
        Ok(())
    }

    /// Mints new tokens to specified address with memo attached
    pub fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<()> {
        self._mint(msg_sender, call.to, call.amount)?;

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: Address::ZERO,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
        }))?;
        self.emit_event(TIP20Event::Mint(ITIP20::Mint {
            to: call.to,
            amount: call.amount,
        }))
    }

    /// Internal helper to mint new tokens and update balances
    fn _mint(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

        // Check if the `to` address is authorized to receive tokens
        if !TIP403Registry::new().is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: self.transfer_policy_id()?,
            user: to,
        })? {
            return Err(TIP20Error::policy_forbids().into());
        }

        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let supply_cap = self.supply_cap()?;
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

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
        }))
    }

    /// Burns tokens from sender's balance and reduces total supply
    pub fn burn(&mut self, msg_sender: Address, call: ITIP20::burnCall) -> Result<()> {
        self._burn(msg_sender, call.amount)?;
        self.emit_event(TIP20Event::Burn(ITIP20::Burn {
            from: msg_sender,
            amount: call.amount,
        }))
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
        self.emit_event(TIP20Event::Burn(ITIP20::Burn {
            from: msg_sender,
            amount: call.amount,
        }))
    }

    /// Burns tokens from blocked addresses that cannot transfer
    pub fn burn_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<()> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Prevent burning from `FeeManager` and `StablecoinExchange` to protect accounting invariants
        if matches!(
            call.from,
            TIP_FEE_MANAGER_ADDRESS | STABLECOIN_EXCHANGE_ADDRESS
        ) {
            return Err(TIP20Error::protected_address().into());
        }

        // Check if the address is blocked from transferring
        if TIP403Registry::new().is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: self.transfer_policy_id()?,
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
        self.set_total_supply(new_supply)
    }

    // Standard token functions
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

    pub fn transfer(&mut self, msg_sender: Address, call: ITIP20::transferCall) -> Result<bool> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        self.check_not_paused()?;
        self.check_recipient(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;

        // Check and update spending limits for access keys
        AccountKeychain::new().authorize_transfer(msg_sender, self.address, call.amount)?;

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

        self.emit_event(TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
            from: call.from,
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
        self.check_recipient(to)?;
        self.ensure_transfer_authorized(from, to)?;
        self.check_and_update_spending_limit(from, amount)?;

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
        self.check_recipient(to)?;
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
        self.check_recipient(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;
        self.check_and_update_spending_limit(msg_sender, call.amount)?;

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
    /// Returns an error if the address is not a valid TIP20 token.
    pub fn from_address(address: Address) -> Result<Self> {
        if !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }
        let token_id = address_to_token_id_unchecked(address);
        Ok(Self::new(token_id))
    }

    /// Returns true if the token has been initialized (has bytecode deployed).
    pub fn is_initialized(&self) -> Result<bool> {
        self.storage
            .with_account_info(self.address, |info| Ok(!info.is_empty_code_hash()))
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
    pub fn initialize(
        &mut self,
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

        // If the currency is USD, the quote token must also be USD.
        // Skip this check when quote_token is Address::ZERO (first token case).
        if currency == USD_CURRENCY && !quote_token.is_zero() {
            let quote_token_currency = Self::from_address(quote_token)?.currency()?;
            if quote_token_currency != USD_CURRENCY {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        self.quote_token.write(quote_token)?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.next_quote_token.write(quote_token)?;

        // Set default values
        self.supply_cap.write(U256::from(u128::MAX))?;
        self.transfer_policy_id.write(1)?;

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

    /// Validates that the recipient is not:
    /// - the zero address (preventing accidental burns)
    /// - another TIP20 token
    fn check_recipient(&self, to: Address) -> Result<()> {
        if to.is_zero() || is_tip20_prefix(to) {
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

    /// Checks and updates spending limits for access keys.
    pub fn check_and_update_spending_limit(&mut self, from: Address, amount: U256) -> Result<()> {
        AccountKeychain::new().authorize_transfer(from, self.address, amount)
    }

    fn _transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(
                TIP20Error::insufficient_balance(from_balance, amount, self.address).into(),
            );
        }

        self.handle_rewards_on_transfer(from, to, amount)?;

        // Adjust balances
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

#[cfg(test)]
pub(crate) mod tests {
    use alloy::primitives::{Address, FixedBytes, IntoLogData, U256};
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20Factory};

    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, setup_storage},
    };
    use rand::{Rng, distributions::Alphanumeric, thread_rng};

    #[test]
    fn test_mint_increases_balance_and_supply() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let addr = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
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
            let quote_token_address = token.quote_token()?;

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

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

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
            let (token_id, token) = TIP20Setup::create("Test", "TST", admin).apply_with_id()?;

            // Test `from_address()` creates same instance as `new()`
            let via_new = TIP20Token::new(token_id).address;
            let via_from_address = TIP20Token::from_address(token.address)?.address;

            assert_eq!(
                via_new, via_from_address,
                "Both methods should create token with same address"
            );
            assert_eq!(
                via_from_address, token.address,
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
                // Mint tokens to StablecoinExchange
                .with_mint(STABLECOIN_EXCHANGE_ADDRESS, amount)
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

            // Attempt to burn from StablecoinExchange
            let result = token.burn_blocked(
                burner,
                ITIP20::burnBlockedCall {
                    from: STABLECOIN_EXCHANGE_ADDRESS,
                    amount: amount / U256::from(2),
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
    fn test_deploy_path_usd_via_factory() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            let token_id = factory.token_id_counter()?;
            assert!(
                token_id.is_zero(),
                "PathUSD is not the first deployed token"
            );

            let path_usd_address = factory.create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: "PathUSD".to_string(),
                    symbol: "PUSD".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: Address::ZERO,
                    admin,
                },
            )?;
            assert_eq!(path_usd_address, PATH_USD_ADDRESS);

            let path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            assert_eq!(path_usd.currency()?, "USD");
            assert_eq!(path_usd.quote_token()?, Address::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_deploy_path_usd_fails_if_token_already_deployed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;

            let result = TIP20Factory::new().create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: "PathUSD".to_string(),
                    symbol: "PUSD".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: Address::ZERO,
                    admin,
                },
            );
            assert!(
                result.is_err(),
                "deploying pathUSD should fail if a token has already been deployed"
            );
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
            let mut rng = rand::thread_rng();
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
}
