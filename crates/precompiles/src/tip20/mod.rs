pub mod dispatch;
pub mod rewards;
pub mod roles;

pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event,
};

use crate::{
    LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    error::TempoPrecompileError,
    storage::{
        PrecompileStorageProvider,
        slots::{double_mapping_slot, mapping_slot},
    },
    tip20::roles::{DEFAULT_ADMIN_ROLE, RolesAuthContract},
    tip20_factory::TIP20Factory,
    tip403_registry::{ITIP403Registry, TIP403Registry},
    tip4217_registry::{ITIP4217Registry, TIP4217Registry},
};
use alloy::{
    hex,
    primitives::{Address, B256, Bytes, IntoLogData, U256, keccak256},
};
use revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};
use std::sync::LazyLock;
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

pub mod slots {
    use alloy::primitives::{U256, uint};

    // Roles Auth slots
    pub const ROLES_BASE_SLOT: U256 = uint!(0_U256);
    pub const ROLE_ADMIN_BASE_SLOT: U256 = uint!(1_U256);

    // TIP20 variables
    pub const NAME: U256 = uint!(2_U256);
    pub const SYMBOL: U256 = uint!(3_U256);
    pub const CURRENCY: U256 = uint!(4_U256);
    pub const DOMAIN_SEPARATOR: U256 = uint!(5_U256);
    pub const QUOTE_TOKEN: U256 = uint!(6_U256);
    pub const NEXT_QUOTE_TOKEN: U256 = uint!(7_U256);
    pub const TRANSFER_POLICY_ID: U256 = uint!(8_U256);
    pub const TOTAL_SUPPLY: U256 = uint!(9_U256);
    pub const BALANCES: U256 = uint!(10_U256);
    pub const ALLOWANCES: U256 = uint!(11_U256);
    pub const NONCES: U256 = uint!(12_U256);
    pub const PAUSED: U256 = uint!(13_U256);
    pub const SUPPLY_CAP: U256 = uint!(14_U256);
    pub const SALTS: U256 = uint!(15_U256);
}

#[derive(Debug)]
pub struct TIP20Token<'a, S: PrecompileStorageProvider> {
    pub token_address: Address,
    pub storage: &'a mut S,
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    pub fn name(&mut self) -> Result<String, TempoPrecompileError> {
        self.read_string(slots::NAME)
    }

    pub fn symbol(&mut self) -> Result<String, TempoPrecompileError> {
        self.read_string(slots::SYMBOL)
    }

    pub fn decimals(&mut self) -> Result<u8, TempoPrecompileError> {
        let currency = self.currency()?;
        Ok(TIP4217Registry::default()
            .get_currency_decimals(ITIP4217Registry::getCurrencyDecimalsCall { currency }))
    }

    pub fn currency(&mut self) -> Result<String, TempoPrecompileError> {
        self.read_string(slots::CURRENCY)
    }

    pub fn total_supply(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage.sload(self.token_address, slots::TOTAL_SUPPLY)
    }

    pub fn quote_token(&mut self) -> Result<Address, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.token_address, slots::QUOTE_TOKEN)?
            .into_address())
    }

    pub fn next_quote_token(&mut self) -> Result<Address, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.token_address, slots::NEXT_QUOTE_TOKEN)?
            .into_address())
    }

    pub fn supply_cap(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage.sload(self.token_address, slots::SUPPLY_CAP)
    }

    pub fn paused(&mut self) -> Result<bool, TempoPrecompileError> {
        Ok(self.storage.sload(self.token_address, slots::PAUSED)? != U256::ZERO)
    }

    pub fn transfer_policy_id(&mut self) -> Result<u64, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.token_address, slots::TRANSFER_POLICY_ID)?
            .to::<u64>())
    }

    // View functions
    pub fn balance_of(
        &mut self,
        call: ITIP20::balanceOfCall,
    ) -> Result<U256, TempoPrecompileError> {
        self.get_balance(call.account)
    }

    pub fn allowance(&mut self, call: ITIP20::allowanceCall) -> Result<U256, TempoPrecompileError> {
        self.get_allowance(call.owner, call.spender)
    }

    // Admin functions
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.storage.sstore(
            self.token_address,
            slots::TRANSFER_POLICY_ID,
            U256::from(call.newPolicyId),
        )?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferPolicyUpdate(ITIP20::TransferPolicyUpdate {
                updater: msg_sender,
                newPolicyId: call.newPolicyId,
            })
            .into_log_data(),
        )
    }

    pub fn set_supply_cap(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self.total_supply()? {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, call.newSupplyCap)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::SupplyCapUpdate(ITIP20::SupplyCapUpdate {
                updater: msg_sender,
                newSupplyCap: call.newSupplyCap,
            })
            .into_log_data(),
        )
    }

    pub fn pause(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::pauseCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::ONE)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                updater: msg_sender,
                isPaused: true,
            })
            .into_log_data(),
        )
    }

    pub fn unpause(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::unpauseCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::ZERO)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                updater: msg_sender,
                isPaused: false,
            })
            .into_log_data(),
        )
    }

    pub fn update_quote_token(
        &mut self,
        msg_sender: Address,
        call: ITIP20::updateQuoteTokenCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Verify the new quote token is a valid TIP20 token that has been deployed
        if !is_tip20(call.newQuoteToken) {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        let new_token_id = address_to_token_id_unchecked(call.newQuoteToken);
        let factory_token_id_counter = TIP20Factory::new(self.storage)
            .token_id_counter()?
            .to::<u64>();

        // Ensure the quote token has been deployed (token_id < counter)
        if new_token_id >= factory_token_id_counter {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        self.storage.sstore(
            self.token_address,
            slots::NEXT_QUOTE_TOKEN,
            call.newQuoteToken.into_u256(),
        )?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::UpdateQuoteToken(ITIP20::UpdateQuoteToken {
                updater: msg_sender,
                newQuoteToken: call.newQuoteToken,
            })
            .into_log_data(),
        )
    }

    pub fn finalize_quote_token_update(
        &mut self,
        msg_sender: Address,
        _call: ITIP20::finalizeQuoteTokenUpdateCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self.next_quote_token()?;

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (LinkingUSD)
        let mut current = next_quote_token;
        while current != LINKING_USD_ADDRESS {
            if current == self.token_address {
                return Err(TIP20Error::invalid_quote_token().into());
            }

            current = TIP20Token::from_address(current, self.storage).quote_token()?;
        }

        // Update the quote token
        self.storage.sstore(
            self.token_address,
            slots::QUOTE_TOKEN,
            next_quote_token.into_u256(),
        )?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::QuoteTokenUpdateFinalized(ITIP20::QuoteTokenUpdateFinalized {
                updater: msg_sender,
                newQuoteToken: next_quote_token,
            })
            .into_log_data(),
        )
    }

    // Token operations
    /// Mints new tokens to specified address
    pub fn mint(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintCall,
    ) -> Result<(), TempoPrecompileError> {
        self._mint(msg_sender, call.to, call.amount)
    }

    /// Mints new tokens to specified address with memo attached
    pub fn mint_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<(), TempoPrecompileError> {
        self._mint(msg_sender, call.to, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: msg_sender,
                to: call.to,
                amount: call.amount,
                memo: call.memo,
            })
            .into_log_data(),
        )
    }

    /// Internal helper to mint new tokens and update balances
    fn _mint(
        &mut self,
        msg_sender: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply()?;

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

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to,
                amount,
            })
            .into_log_data(),
        )?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Mint(ITIP20::Mint { to, amount }).into_log_data(),
        )
    }

    /// Burns tokens from sender's balance and reduces total supply
    pub fn burn(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnCall,
    ) -> Result<(), TempoPrecompileError> {
        self._burn(msg_sender, call.amount)
    }

    /// Burns tokens from sender's balance with memo attached
    pub fn burn_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnWithMemoCall,
    ) -> Result<(), TempoPrecompileError> {
        self._burn(msg_sender, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: msg_sender,
                to: Address::ZERO,
                amount: call.amount,
                memo: call.memo,
            })
            .into_log_data(),
        )
    }

    /// Burns tokens from blocked addresses that cannot transfer
    pub fn burn_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Check if the address is blocked from transferring
        let transfer_policy_id = self.transfer_policy_id()?;
        let mut registry = TIP403Registry::new(self.storage);
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: call.from,
        })? {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids().into());
        }

        self._transfer(call.from, Address::ZERO, call.amount)?;

        let total_supply = self.total_supply()?;
        let new_supply = total_supply
            .checked_sub(call.amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self.set_total_supply(new_supply)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::BurnBlocked(ITIP20::BurnBlocked {
                from: call.from,
                amount: call.amount,
            })
            .into_log_data(),
        )
    }

    fn _burn(&mut self, msg_sender: Address, amount: U256) -> Result<(), TempoPrecompileError> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, Address::ZERO, amount)?;

        let total_supply = self.total_supply()?;
        let new_supply = total_supply
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self.set_total_supply(new_supply)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Burn(ITIP20::Burn {
                from: msg_sender,
                amount,
            })
            .into_log_data(),
        )
    }

    // Standard token functions
    pub fn approve(
        &mut self,
        msg_sender: Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TempoPrecompileError> {
        self.set_allowance(msg_sender, call.spender, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Approval(ITIP20::Approval {
                owner: msg_sender,
                spender: call.spender,
                amount: call.amount,
            })
            .into_log_data(),
        )?;

        Ok(true)
    }

    pub fn transfer(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TempoPrecompileError> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        self.check_not_paused()?;
        self.check_not_token_address(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;
        self._transfer(msg_sender, call.to, call.amount)?;
        Ok(true)
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TempoPrecompileError> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)
    }

    /// Transfer from `from` to `to` address with memo attached
    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool, TempoPrecompileError> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: msg_sender,
                to: call.to,
                amount: call.amount,
                memo: call.memo,
            })
            .into_log_data(),
        )?;

        Ok(true)
    }

    /// Transfer from `from` to `to` address without approval requirement
    /// This function is not exposed via the public interface and should only be invoked by precompiles
    pub fn system_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool, TempoPrecompileError> {
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
    ) -> Result<bool, TempoPrecompileError> {
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
    ) -> Result<(), TempoPrecompileError> {
        self.check_not_paused()?;
        self.check_not_token_address(call.to)?;
        self.ensure_transfer_authorized(msg_sender, call.to)?;

        self._transfer(msg_sender, call.to, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: msg_sender,
                to: call.to,
                amount: call.amount,
                memo: call.memo,
            })
            .into_log_data(),
        )
    }
}

// Utility functions
impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    pub fn new(token_id: u64, storage: &'a mut S) -> Self {
        let token_address = token_id_to_address(token_id);

        Self {
            token_address,
            storage,
        }
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
    ) -> Result<(), TempoPrecompileError> {
        trace!(%name, address=%self.token_address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.token_address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        self.write_string(slots::NAME, name.to_string())?;
        self.write_string(slots::SYMBOL, symbol.to_string())?;
        self.write_string(slots::CURRENCY, currency.to_string())?;
        self.storage.sstore(
            self.token_address,
            slots::QUOTE_TOKEN,
            quote_token.into_u256(),
        )?;
        // Initialize nextQuoteToken to the same value as quoteToken
        self.storage.sstore(
            self.token_address,
            slots::NEXT_QUOTE_TOKEN,
            quote_token.into_u256(),
        )?;

        // Validate currency via TIP4217 registry
        if self.decimals()? == 0 {
            return Err(TIP20Error::invalid_currency().into());
        }

        // Set default values
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, U256::MAX)?;
        self.storage
            .sstore(self.token_address, slots::TRANSFER_POLICY_ID, U256::ONE)?;

        // Initialize roles system and grant admin role
        let mut roles = self.get_roles_contract();
        roles.initialize()?;
        roles.grant_default_admin(admin)
    }

    // Helper to get a RolesAuthContract instance
    pub fn get_roles_contract(&mut self) -> RolesAuthContract<'_, S> {
        RolesAuthContract::new(
            self.storage,
            self.token_address,
            slots::ROLES_BASE_SLOT,
            slots::ROLE_ADMIN_BASE_SLOT,
        )
    }

    fn get_balance(&mut self, account: Address) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage.sload(self.token_address, slot)
    }

    fn set_balance(&mut self, account: Address, amount: U256) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage.sstore(self.token_address, slot, amount)
    }

    fn get_allowance(
        &mut self,
        owner: Address,
        spender: Address,
    ) -> Result<U256, TempoPrecompileError> {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage.sload(self.token_address, slot)
    }

    fn set_allowance(
        &mut self,
        owner: Address,
        spender: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage.sstore(self.token_address, slot, amount)
    }

    fn set_total_supply(&mut self, amount: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::TOTAL_SUPPLY, amount)
    }

    pub fn check_role(&mut self, account: Address, role: B256) -> Result<(), TempoPrecompileError> {
        let mut roles = self.get_roles_contract();
        roles.check_role(account, role)
    }

    pub fn has_role(&mut self, account: Address, role: B256) -> Result<bool, TempoPrecompileError> {
        let mut roles = self.get_roles_contract();
        roles.has_role_internal(account, role)
    }

    fn check_not_paused(&mut self) -> Result<(), TempoPrecompileError> {
        if self.paused()? {
            return Err(TIP20Error::contract_paused().into());
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: Address) -> Result<(), TIP20Error> {
        // Don't allow sending to other precompiled tokens
        if is_tip20(to) {
            return Err(TIP20Error::invalid_recipient());
        }
        Ok(())
    }

    /// Checks if the transfer is authorized.
    pub fn is_transfer_authorized(
        &mut self,
        from: Address,
        to: Address,
    ) -> Result<bool, TempoPrecompileError> {
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
    pub fn ensure_transfer_authorized(
        &mut self,
        from: Address,
        to: Address,
    ) -> Result<(), TempoPrecompileError> {
        if !self.is_transfer_authorized(from, to)? {
            return Err(TIP20Error::policy_forbids().into());
        }

        Ok(())
    }

    fn _transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
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

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data(),
        )
    }

    /// Transfers fee tokens from user to fee manager before transaction execution
    pub fn transfer_fee_pre_tx(
        &mut self,
        from: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let from_balance = self.get_balance(from)?;
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;

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
        actual_used: U256,
    ) -> Result<(), TempoPrecompileError> {
        let from_balance = self.get_balance(TIP_FEE_MANAGER_ADDRESS)?;
        if refund > from_balance {
            return Err(TIP20Error::insufficient_balance().into());
        }

        let new_from_balance = from_balance
            .checked_sub(refund)
            .ok_or(TIP20Error::insufficient_balance())?;

        self.set_balance(TIP_FEE_MANAGER_ADDRESS, new_from_balance)?;

        let to_balance = self.get_balance(to)?;
        let new_to_balance = to_balance
            .checked_add(refund)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self.set_balance(to, new_to_balance)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Transfer(ITIP20::Transfer {
                from: to,
                to: TIP_FEE_MANAGER_ADDRESS,
                amount: actual_used,
            })
            .into_log_data(),
        )
    }

    fn read_string(&mut self, slot: U256) -> Result<String, TempoPrecompileError> {
        let value = self.storage.sload(self.token_address, slot)?;
        let bytes = value.to_be_bytes::<32>();
        let len = bytes[31] as usize / 2; // Last byte stores length * 2 for short strings
        if len > 31 {
            panic!("String too long, we shouldn't have stored this in the first place.");
        } else {
            Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
        }
    }

    /// Write string to storage (simplified - assumes string fits in one slot)
    fn write_string(&mut self, slot: U256, value: String) -> Result<(), TempoPrecompileError> {
        let bytes = value.as_bytes();
        if bytes.len() > 31 {
            return Err(TIP20Error::string_too_long().into());
        }
        let mut storage_bytes = [0u8; 32];
        storage_bytes[..bytes.len()].copy_from_slice(bytes);
        storage_bytes[31] = (bytes.len() * 2) as u8; // Store length * 2 in last byte

        self.storage
            .sstore(self.token_address, slot, U256::from_be_bytes(storage_bytes))
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, FixedBytes, U256};

    use super::*;
    use crate::{
        DEFAULT_FEE_TOKEN, LINKING_USD_ADDRESS, storage::hashmap::HashMapStorageProvider,
        tip20_factory::ITIP20Factory,
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
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(admin, *ISSUER_ROLE)?;

            token
                .mint(admin, ITIP20::mintCall { to: addr, amount })
                .unwrap();

            assert_eq!(token.get_balance(addr)?, amount);
            assert_eq!(token.total_supply()?, amount);
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 2);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to: addr,
                amount
            })
            .into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            TIP20Event::Mint(ITIP20::Mint { to: addr, amount }).into_log_data()
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
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(admin, *ISSUER_ROLE)?;

            token
                .mint(admin, ITIP20::mintCall { to: from, amount })
                .unwrap();
            token
                .transfer(from, ITIP20::transferCall { to, amount })
                .unwrap();

            assert_eq!(token.get_balance(from)?, U256::ZERO);
            assert_eq!(token.get_balance(to)?, amount);
            assert_eq!(token.total_supply()?, amount); // Supply unchanged
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 3);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to: from,
                amount
            })
            .into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            TIP20Event::Mint(ITIP20::Mint { to: from, amount }).into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][2],
            TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data()
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

        let result = token.transfer(from, ITIP20::transferCall { to, amount });
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint_with_memo(admin, ITIP20::mintWithMemoCall { to, amount, memo })
            .unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[1],
            TIP20Event::Mint(ITIP20::Mint { to, amount }).into_log_data()
        );

        assert_eq!(
            events[2],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: admin,
                to,
                amount,
                memo
            })
            .into_log_data()
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint(admin, ITIP20::mintCall { to: admin, amount })
            .unwrap();

        token
            .burn_with_memo(admin, ITIP20::burnWithMemoCall { amount, memo })
            .unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[2],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: admin,
                to: Address::ZERO,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[3],
            TIP20Event::Burn(ITIP20::Burn {
                from: admin,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[4],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: admin,
                to: Address::ZERO,
                amount,
                memo
            })
            .into_log_data()
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let owner = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint(admin, ITIP20::mintCall { to: owner, amount })
            .unwrap();

        token
            .approve(owner, ITIP20::approveCall { spender, amount })
            .unwrap();

        let result = token
            .transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to,
                    amount,
                    memo,
                },
            )
            .unwrap();

        assert!(result);

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[3],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: owner,
                to,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[4],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: spender,
                to,
                amount,
                memo
            })
            .into_log_data()
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::from(100);
        token
            .mint(admin, ITIP20::mintCall { to: user, amount })
            .unwrap();

        let fee_amount = U256::from(50);
        token
            .transfer_fee_pre_tx(user, fee_amount)
            .expect("transfer failed");

        assert_eq!(token.get_balance(user)?, U256::from(50));
        assert_eq!(token.get_balance(TIP_FEE_MANAGER_ADDRESS)?, fee_amount);

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
        token.set_balance(TIP_FEE_MANAGER_ADDRESS, initial_fee)?;

        let refund_amount = U256::from(30);
        let gas_used = U256::from(10);
        token
            .transfer_fee_post_tx(user, refund_amount, gas_used)
            .expect("transfer failed");

        assert_eq!(token.get_balance(user)?, refund_amount);
        assert_eq!(token.get_balance(TIP_FEE_MANAGER_ADDRESS)?, U256::from(70));

        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::Transfer(ITIP20::Transfer {
                from: user,
                to: TIP_FEE_MANAGER_ADDRESS,
                amount: gas_used
            })
            .into_log_data()
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        token
            .mint(admin, ITIP20::mintCall { to: from, amount })
            .unwrap();

        let result = token.transfer_from(spender, ITIP20::transferFromCall { from, to, amount });
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

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        token
            .mint(admin, ITIP20::mintCall { to: from, amount })
            .unwrap();

        let result = token.system_transfer_from(from, to, amount);
        assert!(result.is_ok());

        assert_eq!(
            storage.events[&token_id_to_address(token_id)].last(),
            Some(&TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data())
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
            .update_quote_token(
                admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )
            .unwrap();

        // Verify next quote token was set
        assert_eq!(token.next_quote_token()?, quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::UpdateQuoteToken(ITIP20::UpdateQuoteToken {
                updater: admin,
                newQuoteToken: quote_token_address,
            })
            .into_log_data()
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
        let result = token.update_quote_token(
            non_admin,
            ITIP20::updateQuoteTokenCall {
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
    }

    #[test]
    fn test_update_quote_token_rejects_non_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Try to set a non-TIP20 address (random address that doesn't match TIP20 pattern)
        let non_tip20_address = Address::random();
        let result = token.update_quote_token(
            admin,
            ITIP20::updateQuoteTokenCall {
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
        let result = token.update_quote_token(
            admin,
            ITIP20::updateQuoteTokenCall {
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
            .update_quote_token(
                admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )
            .unwrap();

        // Complete the update
        token
            .finalize_quote_token_update(admin, ITIP20::finalizeQuoteTokenUpdateCall {})
            .unwrap();

        // Verify quote token was updated
        assert_eq!(token.quote_token()?, quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::QuoteTokenUpdateFinalized(ITIP20::QuoteTokenUpdateFinalized {
                updater: admin,
                newQuoteToken: quote_token_address,
            })
            .into_log_data()
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
        token_b
            .update_quote_token(
                admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: token_a_address,
                },
            )
            .unwrap();

        // Try to complete the update - should fail due to loop detection
        let result =
            token_b.finalize_quote_token_update(admin, ITIP20::finalizeQuoteTokenUpdateCall {});

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
        token.update_quote_token(
            admin,
            ITIP20::updateQuoteTokenCall {
                newQuoteToken: quote_token_address,
            },
        )?;

        // Try to complete update as non-admin
        let result =
            token.finalize_quote_token_update(non_admin, ITIP20::finalizeQuoteTokenUpdateCall {});

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
            token.token_address
        };

        let addr_via_from_address = {
            let token = TIP20Token::from_address(token_address, &mut storage);
            token.token_address
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
