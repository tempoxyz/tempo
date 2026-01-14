use super::{
    BURN_BLOCKED_ROLE, DEFAULT_ADMIN_ROLE, ISSUER_ROLE, PAUSE_ROLE, TIP20Error, TIP20Event,
    TIP20Token, UNPAUSE_ROLE, abi,
};
use crate::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20_factory::TIP20Factory,
    tip403_registry::{ITIP403Registry, TIP403Registry},
};
use alloy::primitives::{Address, B256, U256, hex, uint};
use tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
use tracing::trace;

use abi::IRewards as _;

pub const U128_MAX: U256 = uint!(0xffffffffffffffffffffffffffffffff_U256);
pub(crate) const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

/// Decimal precision for TIP-20 tokens
pub(crate) const TIP20_DECIMALS: u8 = 6;

/// USD currency string constant
pub(crate) const USD_CURRENCY: &str = "USD";

/// TIP20 token address prefix (12 bytes)
/// The full address is: TIP20_TOKEN_PREFIX (12 bytes) || derived_bytes (8 bytes)
pub(crate) const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Returns true if the address has the TIP20 prefix.
///
/// NOTE: This only checks the prefix, not whether the token was actually created.
/// Use `TIP20Factory::is_tip20()` for full validation.
pub fn is_tip20_prefix(token: Address) -> bool {
    token.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// Validates that a token has USD currency
pub fn validate_usd_currency(token: Address) -> Result<()> {
    if TIP20Token::from_address(token)?.currency()? != USD_CURRENCY {
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

        self.emit_event(TIP20Event::transfer(Address::ZERO, to, amount))
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
}

impl abi::IToken for TIP20Token {
    fn name(&self) -> Result<String> {
        self.name.read()
    }

    fn symbol(&self) -> Result<String> {
        self.symbol.read()
    }

    fn decimals(&self) -> Result<u8> {
        Ok(TIP20_DECIMALS)
    }

    fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    fn quote_token(&self) -> Result<Address> {
        self.quote_token.read()
    }

    fn next_quote_token(&self) -> Result<Address> {
        self.next_quote_token.read()
    }

    fn balance_of(&self, account: Address) -> Result<U256> {
        self.balances[account].read()
    }

    fn allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        self.allowances[owner][spender].read()
    }

    fn currency(&self) -> Result<String> {
        self.currency.read()
    }

    fn supply_cap(&self) -> Result<U256> {
        self.supply_cap.read()
    }

    fn paused(&self) -> Result<bool> {
        self.paused.read()
    }

    fn transfer_policy_id(&self) -> Result<u64> {
        self.transfer_policy_id.read()
    }

    fn PAUSE_ROLE(&self) -> Result<B256> {
        Ok(Self::pause_role())
    }

    fn UNPAUSE_ROLE(&self) -> Result<B256> {
        Ok(Self::unpause_role())
    }

    fn ISSUER_ROLE(&self) -> Result<B256> {
        Ok(Self::issuer_role())
    }

    fn BURN_BLOCKED_ROLE(&self) -> Result<B256> {
        Ok(Self::burn_blocked_role())
    }

    fn transfer(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<bool> {
        trace!(%msg_sender, %to, %amount, "transferring TIP20");
        self.check_not_paused()?;
        self.check_recipient(to)?;
        self.ensure_transfer_authorized(msg_sender, to)?;

        // Check and update spending limits for access keys
        AccountKeychain::new().authorize_transfer(msg_sender, self.address, amount)?;

        self._transfer(msg_sender, to, amount)?;
        Ok(true)
    }

    fn approve(&mut self, msg_sender: Address, spender: Address, amount: U256) -> Result<bool> {
        // Check and update spending limits for access keys
        AccountKeychain::new().authorize_approve(
            msg_sender,
            self.address,
            self.get_allowance(msg_sender, spender)?,
            amount,
        )?;

        // Set the new allowance
        self.set_allowance(msg_sender, spender, amount)?;

        self.emit_event(TIP20Event::approval(msg_sender, spender, amount))?;

        Ok(true)
    }

    fn transfer_from(
        &mut self,
        msg_sender: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        self._transfer_from(msg_sender, from, to, amount)
    }

    fn mint(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<()> {
        self._mint(msg_sender, to, amount)?;
        self.emit_event(TIP20Event::mint(to, amount))?;
        Ok(())
    }

    fn burn(&mut self, msg_sender: Address, amount: U256) -> Result<()> {
        self._burn(msg_sender, amount)?;
        self.emit_event(TIP20Event::burn(msg_sender, amount))
    }

    fn burn_blocked(&mut self, msg_sender: Address, from: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Prevent burning from `FeeManager` and `StablecoinDEX` to protect accounting invariants
        if matches!(from, TIP_FEE_MANAGER_ADDRESS | STABLECOIN_DEX_ADDRESS) {
            return Err(TIP20Error::protected_address().into());
        }

        // Check if the address is blocked from transferring
        if TIP403Registry::new().is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: self.transfer_policy_id()?,
            user: from,
        })? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        self._transfer(from, Address::ZERO, amount)?;

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

        self.emit_event(TIP20Event::burn_blocked(from, amount))
    }

    fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self._mint(msg_sender, to, amount)?;

        self.emit_event(TIP20Event::transfer_with_memo(
            Address::ZERO,
            to,
            amount,
            memo,
        ))?;
        self.emit_event(TIP20Event::mint(to, amount))
    }

    fn burn_with_memo(&mut self, msg_sender: Address, amount: U256, memo: B256) -> Result<()> {
        self._burn(msg_sender, amount)?;

        self.emit_event(TIP20Event::transfer_with_memo(
            msg_sender,
            Address::ZERO,
            amount,
            memo,
        ))?;
        self.emit_event(TIP20Event::burn(msg_sender, amount))
    }

    fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.check_not_paused()?;
        self.check_recipient(to)?;
        self.ensure_transfer_authorized(msg_sender, to)?;
        self.check_and_update_spending_limit(msg_sender, amount)?;

        self._transfer(msg_sender, to, amount)?;

        self.emit_event(TIP20Event::transfer_with_memo(msg_sender, to, amount, memo))
    }

    fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<bool> {
        self._transfer_from(msg_sender, from, to, amount)?;

        self.emit_event(TIP20Event::transfer_with_memo(from, to, amount, memo))?;

        Ok(true)
    }

    fn change_transfer_policy_id(&mut self, msg_sender: Address, new_policy_id: u64) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Validate that the policy exists
        if !TIP403Registry::new().policy_exists(ITIP403Registry::policyExistsCall {
            policyId: new_policy_id,
        })? {
            return Err(TIP20Error::invalid_transfer_policy_id().into());
        }

        self.transfer_policy_id.write(new_policy_id)?;

        self.emit_event(TIP20Event::transfer_policy_update(
            msg_sender,
            new_policy_id,
        ))
    }

    fn set_supply_cap(&mut self, msg_sender: Address, new_supply_cap: U256) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if new_supply_cap < self.total_supply()? {
            return Err(TIP20Error::invalid_supply_cap().into());
        }

        if new_supply_cap > super::U128_MAX {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.supply_cap.write(new_supply_cap)?;

        self.emit_event(TIP20Event::supply_cap_update(msg_sender, new_supply_cap))
    }

    fn pause(&mut self, msg_sender: Address) -> Result<()> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.paused.write(true)?;

        self.emit_event(TIP20Event::pause_state_update(msg_sender, true))
    }

    fn unpause(&mut self, msg_sender: Address) -> Result<()> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.paused.write(false)?;

        self.emit_event(TIP20Event::pause_state_update(msg_sender, false))
    }

    fn set_next_quote_token(
        &mut self,
        msg_sender: Address,
        new_quote_token: Address,
    ) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Verify the new quote token is a valid TIP20 token that has been deployed
        // use factory's `is_tip20()` which checks both prefix and counter
        if !TIP20Factory::new().is_tip20(new_quote_token)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Check if the currency is USD, if so then the quote token's currency MUST also be USD
        let currency = self.currency()?;
        if currency == USD_CURRENCY {
            let quote_token_currency = Self::from_address(new_quote_token)?.currency()?;
            if quote_token_currency != USD_CURRENCY {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        self.next_quote_token.write(new_quote_token)?;

        self.emit_event(TIP20Event::next_quote_token_set(
            msg_sender,
            new_quote_token,
        ))
    }

    fn complete_quote_token_update(&mut self, msg_sender: Address) -> Result<()> {
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

        self.emit_event(TIP20Event::quote_token_update(msg_sender, next_quote_token))
    }
}

// Utility functions
impl TIP20Token {
    /// Create a TIP20Token from an address.
    /// Returns an error if the address is not a valid TIP20 token.
    pub fn from_address(address: Address) -> Result<Self> {
        if !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }
        Ok(Self::__new(address))
    }

    /// Returns true if the token has been initialized (has bytecode deployed).
    pub fn is_initialized(&self) -> Result<bool> {
        self.storage
            .with_account_info(self.address, |info| Ok(!info.is_empty_code_hash()))
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
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
        self.supply_cap.write(U256::from(u128::MAX))?;
        self.transfer_policy_id.write(1)?;

        // Initialize roles system and grant admin role
        self.initialize_roles()?;
        self.grant_default_admin(msg_sender, admin)
    }

    pub fn get_balance(&self, account: Address) -> Result<U256> {
        self.balances[account].read()
    }

    pub fn set_balance(&mut self, account: Address, amount: U256) -> Result<()> {
        self.balances[account].write(amount)
    }

    pub fn get_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        self.allowances[owner][spender].read()
    }

    pub fn set_allowance(&mut self, owner: Address, spender: Address, amount: U256) -> Result<()> {
        self.allowances[owner][spender].write(amount)
    }

    pub fn set_total_supply(&mut self, amount: U256) -> Result<()> {
        self.total_supply.write(amount)
    }

    pub fn check_not_paused(&self) -> Result<()> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    /// Validates that the recipient is not:
    /// - the zero address (preventing accidental burns)
    /// - another TIP20 token
    pub fn check_recipient(&self, to: Address) -> Result<()> {
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

    pub fn _transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
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

        self.emit_event(TIP20Event::transfer(from, to, amount))
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
            let opted_in_supply = U256::from(self.opted_in_supply()?)
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
        self.emit_event(TIP20Event::transfer(
            to,
            TIP_FEE_MANAGER_ADDRESS,
            actual_spending,
        ))?;

        // Exit early if there is no refund
        if refund.is_zero() {
            return Ok(());
        }

        // Update rewards for the recipient and get their reward recipient
        let to_reward_recipient = self.update_rewards(to)?;

        // If user is opted into rewards, increase opted-in supply by refund amount
        if to_reward_recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.opted_in_supply()?)
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
    use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIP20Factory, STABLECOIN_DEX_ADDRESS};

    use super::*;
    use crate::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, setup_storage},
        tip20::{RolesAuthError, abi},
        tip20_factory::TIP20Factory,
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };
    use abi::{IRewards as _, IRolesAuth as _, IToken as _};
    use rand::Rng;

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

            token.mint(admin, addr, amount)?;

            assert_eq!(token.get_balance(addr)?, amount);
            assert_eq!(token.total_supply()?, amount);

            token.assert_emitted_events(vec![
                TIP20Event::transfer(Address::ZERO, addr, amount),
                TIP20Event::mint(addr, amount),
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

            token.transfer(from, to, amount)?;

            assert_eq!(token.get_balance(from)?, U256::ZERO);
            assert_eq!(token.get_balance(to)?, amount);
            assert_eq!(token.total_supply()?, amount); // Supply unchanged

            token.assert_emitted_events(vec![TIP20Event::transfer(from, to, amount)]);

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

            let result = token.transfer(from, to, amount);
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

            token.mint_with_memo(admin, to, amount, memo)?;

            // TransferWithMemo event should have Address::ZERO as from for mint
            token.assert_emitted_events(vec![
                TIP20Event::transfer(Address::ZERO, to, amount),
                TIP20Event::transfer_with_memo(Address::ZERO, to, amount, memo),
                TIP20Event::mint(to, amount),
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

            token.burn_with_memo(admin, amount, memo)?;
            token.assert_emitted_events(vec![
                TIP20Event::transfer(admin, Address::ZERO, amount),
                TIP20Event::transfer_with_memo(admin, Address::ZERO, amount, memo),
                TIP20Event::burn(admin, amount),
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

            token.transfer_from_with_memo(spender, owner, to, amount, memo)?;

            // TransferWithMemo event should have use call.from in transfer event
            token.assert_emitted_events(vec![
                TIP20Event::transfer(owner, to, amount),
                TIP20Event::transfer_with_memo(owner, to, amount, memo),
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
    fn test_transfer_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let amount = U256::from(100);
        let fee_amount = amount / U256::from(2);
        let refund = fee_amount / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(user, amount)
                .apply()?;

            // Simulate pre-tx fee transfer
            token.transfer_fee_pre_tx(user, fee_amount)?;

            // Simulate post-tx refund
            token.transfer_fee_post_tx(user, refund, fee_amount - refund)?;

            assert_eq!(
                token.get_balance(user)?,
                amount - fee_amount + refund,
                "User should have initial balance minus fee plus refund"
            );
            assert_eq!(
                token.get_balance(TIP_FEE_MANAGER_ADDRESS)?,
                fee_amount - refund,
                "Fee manager should have fee minus refund"
            );

            Ok(())
        })
    }

    #[test]
    fn test_approve_and_transfer_from() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(owner, amount)
                .clear_events()
                .apply()?;

            // Approve spender
            token.approve(owner, spender, amount)?;
            assert_eq!(token.allowance(owner, spender)?, amount);

            // Transfer from owner to recipient via spender
            token.transfer_from(spender, owner, recipient, amount)?;

            assert_eq!(token.get_balance(owner)?, U256::ZERO);
            assert_eq!(token.get_balance(recipient)?, amount);
            assert_eq!(token.allowance(owner, spender)?, U256::ZERO);

            token.assert_emitted_events(vec![
                TIP20Event::approval(owner, spender, amount),
                TIP20Event::transfer(owner, recipient, amount),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_unlimited_allowance() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let initial_balance = U256::from(1000);
        let transfer_amount = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(owner, initial_balance)
                .apply()?;

            // Set unlimited allowance
            token.approve(owner, spender, U256::MAX)?;
            assert_eq!(token.allowance(owner, spender)?, U256::MAX);

            // Transfer some tokens
            token.transfer_from(spender, owner, recipient, transfer_amount)?;

            // Allowance should remain unchanged
            assert_eq!(token.allowance(owner, spender)?, U256::MAX);
            assert_eq!(token.get_balance(owner)?, initial_balance - transfer_amount);

            Ok(())
        })
    }

    #[test]
    fn test_burn_decreases_supply() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let user = Address::random();
        let mint_amount = U256::random() % U256::from(u128::MAX);
        let burn_amount = mint_amount / U256::from(2);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .clear_events()
                .apply()?;

            // Burn some tokens
            token.burn(admin, burn_amount)?;

            assert_eq!(token.total_supply()?, mint_amount - burn_amount);
            assert_eq!(token.get_balance(admin)?, mint_amount - burn_amount);

            token.assert_emitted_events(vec![
                TIP20Event::transfer(admin, Address::ZERO, burn_amount),
                TIP20Event::burn(admin, burn_amount),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_pause_unpause() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_role(admin, *PAUSE_ROLE)
                .with_role(admin, *UNPAUSE_ROLE)
                .clear_events()
                .apply()?;

            // Pause
            token.pause(admin)?;
            assert!(token.paused()?);

            // Unpause
            token.unpause(admin)?;
            assert!(!token.paused()?);

            token.assert_emitted_events(vec![
                TIP20Event::pause_state_update(admin, true),
                TIP20Event::pause_state_update(admin, false),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_blocked_when_paused() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(from, amount)
                .with_role(admin, *PAUSE_ROLE)
                .apply()?;

            token.pause(admin)?;

            let result = token.transfer(from, to, amount);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ContractPaused(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_create_and_initialize_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("TestToken", "TT", admin).apply()?;

            assert_eq!(token.name()?, "TestToken");
            assert_eq!(token.symbol()?, "TT");
            assert_eq!(token.decimals()?, 6);
            assert_eq!(token.total_supply()?, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_mint_without_issuer_fails() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let non_issuer = Address::random();
        let recipient = Address::random();
        let amount = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            let result = token.mint(non_issuer, recipient, amount);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(abi::Error::Unauthorized(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_grant_issuer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let new_issuer = Address::random();
        let recipient = Address::random();
        let amount = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;

            // Grant issuer role
            token.grant_role(admin, *ISSUER_ROLE, new_issuer)?;

            // Now the new issuer can mint
            token.mint(new_issuer, recipient, amount)?;
            assert_eq!(token.get_balance(recipient)?, amount);

            Ok(())
        })
    }

    #[test]
    fn test_revoke_issuer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let issuer = Address::random();
        let recipient = Address::random();
        let amount = U256::from(100);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(issuer)
                .apply()?;

            // Issuer can mint
            token.mint(issuer, recipient, amount)?;

            // Revoke issuer role
            token.revoke_role(admin, *ISSUER_ROLE, issuer)?;

            // Now the issuer cannot mint
            let result = token.mint(issuer, recipient, amount);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(abi::Error::Unauthorized(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_insufficient_allowance() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let balance = U256::from(1000);
        let allowance = U256::from(500);
        let transfer_amount = U256::from(600);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(owner, balance)
                .with_approval(owner, spender, allowance)
                .apply()?;

            let result = token.transfer_from(spender, owner, recipient, transfer_amount);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(
                    TIP20Error::InsufficientAllowance(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_supply_cap() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let cap = U256::from(1_000_000);
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;

            // Set supply cap
            token.set_supply_cap(admin, cap)?;
            assert_eq!(token.supply_cap()?, cap);

            // Mint up to cap succeeds
            token.mint(admin, recipient, cap)?;

            // Mint beyond cap fails
            let result = token.mint(admin, recipient, U256::from(1));
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::SupplyCapExceeded(
                    _
                )))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_set_supply_cap_below_total_supply_fails() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let initial_mint = U256::from(1000);
        let new_cap = U256::from(500);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, initial_mint)
                .apply()?;

            let result = token.set_supply_cap(admin, new_cap);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidSupplyCap(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_quote_token_lifecycle() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create pathUSD first
            let path_usd = TIP20Setup::path_usd(admin).apply()?;

            // Create a USD token using pathUSD as quote
            let mut token_1 = TIP20Setup::create("Token1", "TK1", admin)
                .quote_token(PATH_USD_ADDRESS)
                .apply()?;

            // Create a second USD token
            let token_2 = TIP20Setup::create("Token2", "TK2", admin)
                .quote_token(PATH_USD_ADDRESS)
                .apply()?;

            // Set next quote token
            token_1.set_next_quote_token(admin, token_2.address)?;
            assert_eq!(token_1.next_quote_token()?, token_2.address);

            // Complete the update
            token_1.complete_quote_token_update(admin)?;
            assert_eq!(token_1.quote_token()?, token_2.address);

            Ok(())
        })
    }

    #[test]
    fn test_quote_token_cycle_detection() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create pathUSD first
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;

            // Create two tokens
            let mut token_1 = TIP20Setup::create("Token1", "TK1", admin)
                .quote_token(PATH_USD_ADDRESS)
                .apply()?;

            let mut token_2 = TIP20Setup::create("Token2", "TK2", admin)
                .quote_token(token_1.address)
                .apply()?;

            // Try to create a cycle: token_1 -> token_2 -> token_1
            token_1.set_next_quote_token(admin, token_2.address)?;

            // This should fail due to cycle detection
            let result = token_1.complete_quote_token_update(admin);
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
    fn test_set_next_quote_token_to_arbitrary_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create pathUSD first
            let path_usd = TIP20Setup::path_usd(admin).apply()?;

            // Create an arbitrary currency token (e.g., EUR)
            let token_1 = TIP20Setup::create("Euro Token", "EUR", admin)
                .currency("EUR")
                .apply()?;

            // Create a USD token using pathUSD as quote
            let mut usd_token = TIP20Setup::create("USD Token", "USDT", admin).apply()?;

            // Try to update the USD token's quote token to the arbitrary currency token, this should fail
            let result = usd_token.set_next_quote_token(admin, token_1.address);

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
                    salt: alloy::primitives::B256::random(),
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
            let result =
                token.burn_blocked(burner, TIP_FEE_MANAGER_ADDRESS, amount / U256::from(2));

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ProtectedAddress(_)))
            ));

            // Verify FeeManager balance is unchanged
            let balance = token.balance_of(TIP_FEE_MANAGER_ADDRESS)?;
            assert_eq!(balance, amount);

            // Attempt to burn from StablecoinDEX
            let result = token.burn_blocked(burner, STABLECOIN_DEX_ADDRESS, amount / U256::from(2));

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::ProtectedAddress(_)))
            ));

            // Verify StablecoinDEX balance is unchanged
            let balance = token.balance_of(STABLECOIN_DEX_ADDRESS)?;
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
    fn test_deploy_path_usd_directly() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // pathUSD is at a reserved address, so we initialize it directly (not via factory)
            let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            path_usd.initialize(admin, "pathUSD", "pathUSD", "USD", PATH_USD_ADDRESS, admin)?;

            assert_eq!(path_usd.currency()?, "USD");
            // pathUSD uses itself as quote token
            assert_eq!(path_usd.quote_token()?, PATH_USD_ADDRESS);
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
            let result = token.change_transfer_policy_id(admin, invalid_policy_id);

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

            let result = token.transfer(admin, Address::ZERO, amount);
            assert!(result.is_err_and(|err| err.to_string().contains("InvalidRecipient")));

            let result = token.transfer_from(bob, admin, Address::ZERO, amount);
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
            token.change_transfer_policy_id(admin, 0)?;
            assert_eq!(token.transfer_policy_id()?, 0);

            token.change_transfer_policy_id(admin, 1)?;
            assert_eq!(token.transfer_policy_id()?, 1);

            // Test random invalid policy IDs should fail
            let mut rng = rand::thread_rng();
            for _ in 0..20 {
                let invalid_policy_id = rng.gen_range(2..u64::MAX);
                let result = token.change_transfer_policy_id(admin, invalid_policy_id);
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
                let result = token.change_transfer_policy_id(admin, policy_id);
                assert!(result.is_ok());
                assert_eq!(token.transfer_policy_id()?, policy_id);
            }

            Ok(())
        })
    }
}
