mod rewards;
mod roles;

use tempo_contracts::precompiles::{
    IRolesAuth::{self, IRolesAuthEvents},
    ITIP20::{self, ITIP20Events},
    ITIP20Rewards::{self, ITIP20RewardsEvents},
    RolesAuthError, TIP20Error,
};

use crate::{
    LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, PrecompileStorageProvider},
    tip20_factory::TIP20Factory,
    tip20_migrated::rewards::RewardStream,
    tip403_registry::{ITIP403Registry, TIP403Registry},
    tip4217_registry::{ITIP4217Registry, TIP4217Registry},
    utils::MathUtils,
};
use alloy::{
    hex,
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use revm::state::Bytecode;
use std::sync::LazyLock;
use tempo_precompiles_macros::contract;
use tracing::trace;

/// TIP20 token address prefix (12 bytes for token ID encoding)
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// TIP20 payment address prefix (14 bytes for payment classification)
/// Same as TIP20_TOKEN_PREFIX but extended to 14 bytes for payment classification
pub const TIP20_PAYMENT_PREFIX: [u8; 14] = hex!("20C0000000000000000000000000");

pub fn is_tip20(token: Address) -> bool {
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

#[contract(ITIP20, ITIP20Rewards, IRolesAuth)]
pub struct TIP20Token {
    // RolesAuth
    #[map = "has_role"]
    roles: Mapping<Address, Mapping<B256, bool>>, // slot 0
    #[map = "get_role_admin"]
    role_admins: Mapping<B256, B256>, // slot 1

    // TIP20 Metadata
    name: String,              // slot 2
    symbol: String,            // slot 3
    currency: String,          // slot 4
    domain_separator: B256,    // slot 5
    quote_token: Address,      // slot 6
    next_quote_token: Address, // slot 7
    transfer_policy_id: u64,   // slot 8

    // TIP20 Token
    total_supply: U256, // slot 9
    #[map = "balance_of"]
    balances: Mapping<Address, U256>, // slot 10
    #[map = "allowance"]
    allowances: Mapping<Address, Mapping<Address, U256>>, // slot 11
    nonces: Mapping<Address, U256>, // slot 12
    paused: bool,       // slot 13
    supply_cap: U256,   // slot 14
    salts: Mapping<B256, bool>, // slot 15

    // TIP20 Rewards
    last_update_time: u64, // slot 16
    opted_in_supply: U256, // slot 17
    #[map = "get_stream_id"]
    next_stream_id: u64, // slot 18
    #[map = "get_stream"]
    streams: Mapping<u64, RewardStream>, // slot 19
    scheduled_rate_decrease: Mapping<u128, U256>, // slot 20
    reward_recipient_of: Mapping<Address, Address>, // slot 21
    user_reward_per_token_paid: Mapping<Address, U256>, // slot 22
    delegated_balance: Mapping<Address, U256>, // slot 23
    reward_per_token_stored: U256, // slot 24
    total_reward_per_second: U256, // slot 25
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

// Re-export role constants from roles module for convenience
pub use roles::DEFAULT_ADMIN_ROLE;

impl<'a, S: PrecompileStorageProvider> TIP20Token_ITIP20 for TIP20Token<'a, S> {
    // Metadata functions
    fn decimals(&mut self) -> Result<u8> {
        let currency = self.currency()?;
        Ok(TIP4217Registry::default()
            .get_currency_decimals(ITIP4217Registry::getCurrencyDecimalsCall { currency }))
    }

    // Admin functions
    fn change_transfer_policy_id(&mut self, msg_sender: Address, new_policy_id: u64) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.sstore_transfer_policy_id(new_policy_id)?;
        self.emit_transfer_policy_update(msg_sender, new_policy_id)
    }

    fn set_supply_cap(&mut self, msg_sender: Address, new_supply_cap: U256) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if new_supply_cap < self.total_supply()? {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        self.sstore_supply_cap(new_supply_cap)?;
        self.emit_supply_cap_update(msg_sender, new_supply_cap)
    }

    fn pause(&mut self, msg_sender: Address) -> Result<()> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.sstore_paused(true)?;
        self.emit_pause_state_update(msg_sender, true)
    }
    fn unpause(&mut self, msg_sender: Address) -> Result<()> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.sstore_paused(false)?;
        self.emit_pause_state_update(msg_sender, false)
    }
    fn update_quote_token(&mut self, msg_sender: Address, new_quote_token: Address) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Verify the new quote token is a valid TIP20 token that has been deployed
        if !is_tip20(new_quote_token) {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        let new_token_id = address_to_token_id_unchecked(new_quote_token);
        let factory_token_id_counter = TIP20Factory::new(self.storage)
            .token_id_counter()?
            .to::<u64>();

        // Ensure the quote token has been deployed (token_id < counter)
        if new_token_id >= factory_token_id_counter {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        self.sstore_next_quote_token(new_quote_token)?;
        self.emit_update_quote_token(msg_sender, new_quote_token)
    }

    fn finalize_quote_token_update(&mut self, msg_sender: Address) -> Result<()> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self.next_quote_token()?;

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (LinkingUSD)
        let mut current = next_quote_token;
        while current != LINKING_USD_ADDRESS {
            if current == self.address {
                return Err(TIP20Error::invalid_quote_token().into());
            }

            current = TIP20Token::from_address(current, self.storage).quote_token()?;
        }

        // Update the quote token
        self.sstore_quote_token(next_quote_token)?;
        self.emit_quote_token_update_finalized(msg_sender, next_quote_token)
    }

    // Token operations
    /// Mints new tokens to specified address
    fn mint(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

        let new_supply = total_supply.add_checked(amount)?;

        let supply_cap = self.supply_cap()?;
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        self.handle_rewards_on_mint(to, amount)?;

        self.sstore_total_supply(new_supply)?;
        let to_balance = self.sload_balances(to)?;
        let new_to_balance: U256 = to_balance.add_checked(amount)?;
        self.sstore_balances(to, new_to_balance)?;

        self.emit_transfer(Address::ZERO, to, amount)?;
        self.emit_mint(to, amount)
    }

    /// Mints new tokens to specified address with memo attached
    fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.mint(msg_sender, to, amount)?;
        self.emit_transfer_with_memo(msg_sender, to, amount, memo)
    }

    /// Burns tokens from sender's balance and reduces total supply
    fn burn(&mut self, msg_sender: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, Address::ZERO, amount)?;

        let total_supply = self.total_supply()?;
        let new_supply = total_supply.sub_checked(amount)?;
        self.sstore_total_supply(new_supply)?;

        self.emit_burn(msg_sender, amount)
    }

    /// Burns tokens from sender's balance with memo attached
    fn burn_with_memo(&mut self, msg_sender: Address, amount: U256, memo: B256) -> Result<()> {
        self.burn(msg_sender, amount)?;
        self.emit_transfer_with_memo(msg_sender, Address::ZERO, amount, memo)
    }

    /// Burns tokens from blocked addresses that cannot transfer
    fn burn_blocked(&mut self, msg_sender: Address, from: Address, amount: U256) -> Result<()> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Check if the address is blocked from transferring
        let transfer_policy_id = self.transfer_policy_id()?;
        let mut registry = TIP403Registry::new(self.storage);
        // TODO(rusowsky): use flattened version once migrated
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: from,
        })? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        self._transfer(from, Address::ZERO, amount)?;

        let total_supply = self.total_supply()?;
        let new_supply = total_supply.sub_checked(amount)?;
        self.sstore_total_supply(new_supply)?;

        self.emit_burn_blocked(from, amount)
    }

    // Standard token functions
    fn approve(&mut self, msg_sender: Address, spender: Address, amount: U256) -> Result<bool> {
        self.sstore_allowances(msg_sender, spender, amount)?;
        self.emit_approval(msg_sender, spender, amount)?;
        Ok(true)
    }

    fn transfer(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<bool> {
        trace!(%msg_sender, ?to, ?amount, "transferring TIP20");
        self.check_not_paused()?;
        self.check_not_token_address(to)?;
        self.ensure_transfer_authorized(msg_sender, to)?;
        self._transfer(msg_sender, to, amount)?;
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

    // TIP20 extension functions
    fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.check_not_paused()?;
        self.check_not_token_address(to)?;
        self.ensure_transfer_authorized(msg_sender, to)?;

        self._transfer(msg_sender, to, amount)?;
        self.emit_transfer_with_memo(msg_sender, to, amount, memo)
    }

    /// Transfer from `from` to `to` address with memo attached
    fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<bool> {
        self._transfer_from(msg_sender, from, to, amount)?;
        self.emit_transfer_with_memo(msg_sender, to, amount, memo)?;
        Ok(true)
    }
}

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
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

        let allowed = self.sload_allowances(from, msg_sender)?;
        if amount > allowed {
            return Err(TIP20Error::insufficient_allowance().into());
        }

        if allowed != U256::MAX {
            let new_allowance = allowed
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_allowance())?;
            self.sstore_allowances(from, msg_sender, new_allowance)?;
        }

        self._transfer(from, to, amount)?;

        Ok(true)
    }
}

// Utility functions
impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    pub fn new(token_id: u64, storage: &'a mut S) -> Self {
        let token_address = token_id_to_address(token_id);
        Self::_new(token_address, storage)
    }

    /// Create a TIP20Token from an address
    pub fn from_address(address: Address, storage: &'a mut S) -> Self {
        let token_id = address_to_token_id_unchecked(address);
        Self::new(token_id, storage)
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
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        self.sstore_name(name.to_string())?;
        self.sstore_symbol(symbol.to_string())?;
        self.sstore_currency(currency.to_string())?;
        self.sstore_quote_token(quote_token)?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.sstore_next_quote_token(quote_token)?;

        // Validate currency via TIP4217 registry
        if self.decimals()? == 0 {
            return Err(TIP20Error::invalid_currency().into());
        }

        // Set default values
        self.sstore_supply_cap(U256::MAX)?;
        self.sstore_transfer_policy_id(1)?;

        // Initialize roles system and grant admin role
        self.roles_initialize()?;
        self.roles_grant_default_admin(admin)
    }

    fn check_not_paused(&mut self) -> Result<()> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: Address) -> Result<()> {
        // Don't allow sending to other precompiled tokens
        if is_tip20(to) {
            return Err(TIP20Error::invalid_recipient().into());
        }
        Ok(())
    }

    /// Checks if the transfer is authorized.
    pub fn is_transfer_authorized(&mut self, from: Address, to: Address) -> Result<bool> {
        let transfer_policy_id = self.transfer_policy_id()?;
        let mut registry = TIP403Registry::new(self.storage);

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
    pub fn ensure_transfer_authorized(&mut self, from: Address, to: Address) -> Result<()> {
        if !self.is_transfer_authorized(from, to)? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    fn _transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        // Accrue before balance changes
        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;
        self.handle_rewards_on_transfer(from, to, amount)?;

        let from_balance = self.sload_balances(from)?;
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
        }

        // Adjust balances
        let from_balance = self.sload_balances(from)?;
        let new_from_balance = from_balance.sub_checked(amount)?;

        self.sstore_balances(from, new_from_balance)?;

        if to != Address::ZERO {
            let to_balance = self.sload_balances(to)?;
            let new_to_balance = to_balance.add_checked(amount)?;

            self.sstore_balances(to, new_to_balance)?;
        }

        self.emit_transfer(from, to, amount)
    }

    /// Transfers fee tokens from user to fee manager before transaction execution
    pub fn transfer_fee_pre_tx(&mut self, from: Address, amount: U256) -> Result<()> {
        let from_balance = self.sload_balances(from)?;
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;

        self.sstore_balances(from, new_from_balance)?;

        let to_balance = self.sload_balances(TIP_FEE_MANAGER_ADDRESS)?;
        let new_to_balance = to_balance.add_checked(amount)?;
        self.sstore_balances(TIP_FEE_MANAGER_ADDRESS, new_to_balance)?;

        Ok(())
    }

    /// Refunds unused fee tokens to user and emits transfer event for gas amount used
    pub fn transfer_fee_post_tx(
        &mut self,
        to: Address,
        refund: U256,
        actual_used: U256,
    ) -> Result<()> {
        let from_balance = self.sload_balances(TIP_FEE_MANAGER_ADDRESS)?;
        if refund > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
        }

        let new_from_balance = from_balance.sub_checked(refund)?;
        self.sstore_balances(TIP_FEE_MANAGER_ADDRESS, new_from_balance)?;

        let to_balance = self.sload_balances(to)?;
        let new_to_balance = to_balance.add_checked(refund)?;
        self.sstore_balances(to, new_to_balance)?;

        self.emit_transfer(to, TIP_FEE_MANAGER_ADDRESS, actual_used)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, FixedBytes, U256},
        sol_types::SolEvent,
    };

    use super::*;
    use crate::{
        DEFAULT_FEE_TOKEN, LINKING_USD_ADDRESS,
        storage::hashmap::HashMapStorageProvider,
        tip20_factory::{ITIP20Factory, TIP20Factory},
    };

    /// Initialize a factory and create a single token
    fn setup_factory_with_token(
        storage: &mut HashMapStorageProvider,
        admin: Address,
        name: &str,
        symbol: &str,
    ) -> u64 {
        let mut factory = TIP20Factory::new(storage);
        factory.initialize().unwrap();

        factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    currency: "USD".to_string(),
                    quoteToken: LINKING_USD_ADDRESS,
                    admin,
                },
            )
            .unwrap()
            .to::<u64>()
    }

    /// Create a token via an already-initialized factory
    fn create_token_via_factory(
        factory: &mut TIP20Factory<'_, HashMapStorageProvider>,
        admin: Address,
        name: &str,
        symbol: &str,
        quote_token: Address,
    ) -> u64 {
        factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    currency: "USD".to_string(),
                    quoteToken: quote_token,
                    admin,
                },
            )
            .unwrap()
            .to::<u64>()
    }

    /// Setup factory and create a token with a separate quote token (both linking to LINKING_USD)
    fn setup_token_with_custom_quote_token(
        storage: &mut HashMapStorageProvider,
        admin: Address,
    ) -> (u64, u64) {
        let mut factory = TIP20Factory::new(storage);
        factory.initialize().unwrap();

        let token_id =
            create_token_via_factory(&mut factory, admin, "Test", "TST", LINKING_USD_ADDRESS);
        let quote_token_id =
            create_token_via_factory(&mut factory, admin, "Quote", "QUOTE", LINKING_USD_ADDRESS);

        (token_id, quote_token_id)
    }

    #[test]
    fn test_mint_increases_balance_and_supply() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let addr = Address::from([1u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            // Initialize with admin
            token
                .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
                .unwrap();

            // Grant issuer role to admin
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            token.mint(admin, addr, amount).unwrap();

            assert_eq!(token.sload_balances(addr)?, amount);
            assert_eq!(token.total_supply()?, amount);
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 2);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            ITIP20::Transfer {
                from: Address::ZERO,
                to: addr,
                amount
            }
            .encode_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            ITIP20::Mint { to: addr, amount }.encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_transfer_moves_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            token
                .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
                .unwrap();
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            token.mint(admin, from, amount).unwrap();
            token.transfer(from, to, amount).unwrap();

            assert_eq!(token.sload_balances(from)?, U256::ZERO);
            assert_eq!(token.sload_balances(to)?, amount);
            assert_eq!(token.total_supply()?, amount); // Supply unchanged
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 3);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            ITIP20::Transfer {
                from: Address::ZERO,
                to: from,
                amount
            }
            .encode_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            ITIP20::Mint { to: from, amount }.encode_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][2],
            ITIP20::Transfer { from, to, amount }.encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);

        let result = token.transfer(from, to, amount);
        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(
                TIP20Error::InsufficientBalance(_)
            ))
        ));

        Ok(())
    }

    #[test]
    fn test_mint_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token.mint_with_memo(admin, to, amount, memo).unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[0],
            ITIP20::Transfer {
                from: Address::ZERO,
                to,
                amount
            }
            .encode_log_data()
        );

        assert_eq!(events[1], ITIP20::Mint { to, amount }.encode_log_data());

        assert_eq!(
            events[2],
            ITIP20::TransferWithMemo {
                from: admin,
                to,
                amount,
                memo
            }
            .encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_burn_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::random();
        let memo = FixedBytes::random();

        token.mint(admin, admin, amount).unwrap();

        token.burn_with_memo(admin, amount, memo).unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[2],
            ITIP20::Transfer {
                from: admin,
                to: Address::ZERO,
                amount
            }
            .encode_log_data()
        );

        assert_eq!(
            events[3],
            ITIP20::Burn {
                from: admin,
                amount
            }
            .encode_log_data()
        );

        assert_eq!(
            events[4],
            ITIP20::TransferWithMemo {
                from: admin,
                to: Address::ZERO,
                amount,
                memo
            }
            .encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_transfer_from_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let owner = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token.mint(admin, owner, amount).unwrap();

        token.approve(owner, spender, amount).unwrap();

        let result = token
            .transfer_from_with_memo(spender, owner, to, amount, memo)
            .unwrap();

        assert!(result);

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[3],
            ITIP20::Transfer {
                from: owner,
                to,
                amount
            }
            .encode_log_data()
        );

        assert_eq!(
            events[4],
            ITIP20::TransferWithMemo {
                from: spender,
                to,
                amount,
                memo
            }
            .encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_transfer_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::from(100);
        token.mint(admin, user, amount).unwrap();

        let fee_amount = U256::from(50);
        token
            .transfer_fee_pre_tx(user, fee_amount)
            .expect("transfer failed");

        assert_eq!(token.sload_balances(user)?, U256::from(50));
        assert_eq!(token.sload_balances(TIP_FEE_MANAGER_ADDRESS)?, fee_amount);

        Ok(())
    }

    #[test]
    fn test_transfer_fee_pre_tx_insufficient_balance() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        let fee_amount = U256::from(50);
        let result = token.transfer_fee_pre_tx(user, fee_amount);
        assert_eq!(
            result,
            Err(TempoPrecompileError::TIP20(
                TIP20Error::insufficient_balance()
            ))
        );
    }

    #[test]
    fn test_transfer_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        let initial_fee = U256::from(100);
        token.sstore_balances(TIP_FEE_MANAGER_ADDRESS, initial_fee)?;

        let refund_amount = U256::from(30);
        let gas_used = U256::from(10);
        token
            .transfer_fee_post_tx(user, refund_amount, gas_used)
            .expect("transfer failed");

        assert_eq!(token.sload_balances(user)?, refund_amount);
        assert_eq!(
            token.sload_balances(TIP_FEE_MANAGER_ADDRESS)?,
            U256::from(70)
        );

        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &ITIP20::Transfer {
                from: user,
                to: TIP_FEE_MANAGER_ADDRESS,
                amount: gas_used
            }
            .encode_log_data()
        );

        Ok(())
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
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        token.mint(admin, from, amount).unwrap();

        let result = token.transfer_from(spender, from, to, amount);
        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(
                TIP20Error::InsufficientAllowance(_)
            ))
        ));

        Ok(())
    }

    #[test]
    fn test_system_transfer_from() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(100);
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        token.mint(admin, from, amount).unwrap();

        let result = token.system_transfer_from(from, to, amount);
        assert!(result.is_ok());

        assert_eq!(
            storage.events[&token_id_to_address(token_id)].last(),
            Some(&ITIP20::Transfer { from, to, amount }.encode_log_data())
        );

        Ok(())
    }

    #[test]
    fn test_initialize_sets_next_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Verify both quoteToken and nextQuoteToken are set to the same value
        assert_eq!(token.quote_token()?, LINKING_USD_ADDRESS);
        assert_eq!(token.next_quote_token()?, LINKING_USD_ADDRESS);

        Ok(())
    }

    #[test]
    fn test_update_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token
        token
            .update_quote_token(admin, quote_token_address)
            .unwrap();

        // Verify next quote token was set
        assert_eq!(token.next_quote_token()?, quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &ITIP20::UpdateQuoteToken {
                updater: admin,
                newQuoteToken: quote_token_address,
            }
            .encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_update_quote_token_requires_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        let quote_token_address = token_id_to_address(2);

        // Try to set next quote token as non-admin
        let result = token.update_quote_token(non_admin, quote_token_address);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::RolesAuthError(
                RolesAuthError::Unauthorized(_)
            ))
        ));

        Ok(())
    }

    #[test]
    fn test_update_quote_token_rejects_non_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Try to set a non-TIP20 address (random address that doesn't match TIP20 pattern)
        let non_tip20_address = Address::random();
        let result = token.update_quote_token(admin, non_tip20_address);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                _
            )))
        ));

        Ok(())
    }

    #[test]
    fn test_update_quote_token_rejects_undeployed_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Try to set a TIP20 address that hasn't been deployed yet (token_id = 999)
        // This has the correct TIP20 address pattern but hasn't been created
        let undeployed_token_address = token_id_to_address(999);
        let result = token.update_quote_token(admin, undeployed_token_address);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                _
            )))
        ));

        Ok(())
    }

    #[test]
    fn test_finalize_quote_token_update() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token
        token
            .update_quote_token(admin, quote_token_address)
            .unwrap();

        // Complete the update
        token.finalize_quote_token_update(admin).unwrap();

        // Verify quote token was updated
        assert_eq!(token.quote_token()?, quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &ITIP20::QuoteTokenUpdateFinalized {
                updater: admin,
                newQuoteToken: quote_token_address,
            }
            .encode_log_data()
        );

        Ok(())
    }

    #[test]
    fn test_finalize_quote_token_update_detects_loop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize().unwrap();

        // Create token_b first (links to LINKING_USD)
        let token_b_id =
            create_token_via_factory(&mut factory, admin, "Token B", "TKB", LINKING_USD_ADDRESS);
        let token_b_address = token_id_to_address(token_b_id);

        // Create token_a (links to token_b)
        let token_a_id =
            create_token_via_factory(&mut factory, admin, "Token A", "TKA", token_b_address);
        let token_a_address = token_id_to_address(token_a_id);

        // Now try to set token_a as the next quote token for token_b (would create A -> B -> A loop)
        let mut token_b = TIP20Token::new(token_b_id, &mut storage);
        token_b.update_quote_token(admin, token_a_address).unwrap();

        // Try to complete the update - should fail due to loop detection
        let result = token_b.finalize_quote_token_update(admin);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                _
            )))
        ));

        Ok(())
    }

    #[test]
    fn test_finalize_quote_token_update_requires_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token as admin
        token.update_quote_token(admin, quote_token_address)?;

        // Try to complete update as non-admin
        let result = token.finalize_quote_token_update(non_admin);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::RolesAuthError(
                RolesAuthError::Unauthorized(_)
            ))
        ));

        Ok(())
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
    fn test_tip20_payment_prefix() {
        assert_eq!(
            TIP20_PAYMENT_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Payment prefix should start with token prefix
        assert_eq!(&TIP20_PAYMENT_PREFIX[..12], &TIP20_TOKEN_PREFIX);
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..14], &TIP20_PAYMENT_PREFIX);
    }

    #[test]
    fn test_from_address() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        // Create a token to get a valid address
        let token_id = setup_factory_with_token(&mut storage, admin, "TEST", "TST");
        let token_address = token_id_to_address(token_id);

        // Test from_address creates same instance as new()
        let addr_via_new = {
            let token = TIP20Token::new(token_id, &mut storage);
            token.address
        };

        let addr_via_from_address = {
            let token = TIP20Token::from_address(token_address, &mut storage);
            token.address
        };

        assert_eq!(
            addr_via_new, addr_via_from_address,
            "Both methods should create token with same address"
        );
        assert_eq!(
            addr_via_from_address, token_address,
            "from_address should use the provided address"
        );
    }
}
