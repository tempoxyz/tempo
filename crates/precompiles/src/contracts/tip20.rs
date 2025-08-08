use std::sync::LazyLock;

use alloy::primitives::{Address, B256, IntoLogData, U256, keccak256};

use crate::{
    contracts::{
        ITIP20, ITIP403Registry, ITIP4217Registry, StorageProvider, TIP403Registry,
        TIP4217Registry, address_is_token_address,
        roles::{DEFAULT_ADMIN_ROLE, RolesAuthContract},
        storage::slots::{double_mapping_slot, mapping_slot},
        token_id_to_address,
        types::{TIP20Error, TIP20Event},
    },
    tip20_err,
};

mod slots {
    use crate::contracts::storage::slots::to_u256;
    use alloy::primitives::U256;

    // Variables
    pub const NAME: U256 = to_u256(0);
    pub const SYMBOL: U256 = to_u256(1);
    pub const TOTAL_SUPPLY: U256 = to_u256(3);
    pub const CURRENCY: U256 = to_u256(4);
    pub const DOMAIN_SEPARATOR: U256 = to_u256(5);
    pub const TRANSFER_POLICY_ID: U256 = to_u256(6);
    pub const SUPPLY_CAP: U256 = to_u256(7);
    pub const PAUSED: U256 = to_u256(8);
    // Mappings
    pub const BALANCES: U256 = to_u256(10);
    pub const ALLOWANCES: U256 = to_u256(11);
    pub const NONCES: U256 = to_u256(12);
    pub const SALTS: U256 = to_u256(13);
    pub const ROLES_BASE_SLOT: U256 = to_u256(14); // via RolesAuthContract
    pub const ROLE_ADMIN_BASE_SLOT: U256 = to_u256(15); // via RolesAuthContract
}

#[derive(Debug)]
pub struct TIP20Token<'a, S: StorageProvider> {
    token_address: Address,
    storage: &'a mut S,
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"PAUSE_ROLE")));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"UNPAUSE_ROLE")));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"ISSUER_ROLE")));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> =
    LazyLock::new(|| B256::from(keccak256(b"BURN_BLOCKED_ROLE")));

impl<'a, S: StorageProvider> TIP20Token<'a, S> {
    pub fn name(&mut self) -> String {
        self.read_string(slots::NAME)
    }

    pub fn symbol(&mut self) -> String {
        self.read_string(slots::SYMBOL)
    }

    pub fn decimals(&mut self) -> u8 {
        TIP4217Registry::default().get_currency_decimals(
            ITIP4217Registry::getCurrencyDecimalsCall {
                currency: self.currency(),
            },
        )
    }

    pub fn currency(&mut self) -> String {
        self.read_string(slots::CURRENCY)
    }

    pub fn total_supply(&mut self) -> U256 {
        self.storage.sload(self.token_address, slots::TOTAL_SUPPLY)
    }

    pub fn supply_cap(&mut self) -> U256 {
        self.storage.sload(self.token_address, slots::SUPPLY_CAP)
    }

    pub fn paused(&mut self) -> bool {
        self.storage.sload(self.token_address, slots::PAUSED) != U256::ZERO
    }

    pub fn transfer_policy_id(&mut self) -> u64 {
        self.storage
            .sload(self.token_address, slots::TRANSFER_POLICY_ID)
            .to::<u64>()
    }

    pub fn domain_separator(&mut self) -> B256 {
        B256::from(
            self.storage
                .sload(self.token_address, slots::DOMAIN_SEPARATOR),
        )
    }

    // View functions
    pub fn balance_of(&mut self, call: ITIP20::balanceOfCall) -> U256 {
        self.get_balance(&call.account)
    }

    pub fn allowance(&mut self, call: ITIP20::allowanceCall) -> U256 {
        self.get_allowance(&call.owner, &call.spender)
    }

    pub fn nonces(&mut self, call: ITIP20::noncesCall) -> U256 {
        let slot = mapping_slot(call.owner, slots::NONCES);
        self.storage.sload(self.token_address, slot)
    }

    pub fn salts(&mut self, call: ITIP20::saltsCall) -> bool {
        let slot = double_mapping_slot(call.owner, call.salt, slots::SALTS);
        self.storage.sload(self.token_address, slot) != U256::ZERO
    }

    // Admin functions
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.storage.sstore(
            self.token_address,
            slots::TRANSFER_POLICY_ID,
            U256::from(call.newPolicyId),
        );

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferPolicyUpdate(ITIP20::TransferPolicyUpdate {
                updater: *msg_sender,
                newPolicyId: call.newPolicyId,
            })
            .into_log_data(),
        );
        Ok(())
    }

    pub fn set_supply_cap(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self.total_supply() {
            return Err(tip20_err!(SupplyCapExceeded));
        }
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, call.newSupplyCap);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::SupplyCapUpdate(ITIP20::SupplyCapUpdate {
                updater: *msg_sender,
                newSupplyCap: call.newSupplyCap,
            })
            .into_log_data(),
        );
        Ok(())
    }

    pub fn pause(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::pauseCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::from(1));

        self.storage.emit_event(
            self.token_address,
            TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                updater: *msg_sender,
                isPaused: true,
            })
            .into_log_data(),
        );
        Ok(())
    }

    pub fn unpause(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::unpauseCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::ZERO);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                updater: *msg_sender,
                isPaused: false,
            })
            .into_log_data(),
        );
        Ok(())
    }

    // Token operations
    pub fn mint(&mut self, msg_sender: &Address, call: ITIP20::mintCall) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply();

        let new_supply = total_supply
            .checked_add(call.amount)
            .ok_or(tip20_err!(SupplyCapExceeded))?;

        let supply_cap = self.supply_cap();
        if new_supply > supply_cap {
            return Err(tip20_err!(SupplyCapExceeded));
        }

        self.set_total_supply(new_supply);

        let to_balance = self.get_balance(&call.to);
        let new_to_balance: alloy::primitives::Uint<256, 4> =
            to_balance
                .checked_add(call.amount)
                .ok_or(tip20_err!(SupplyCapExceeded))?;
        self.set_balance(&call.to, new_to_balance);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to: call.to,
                amount: call.amount,
            })
            .into_log_data(),
        );

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Mint(ITIP20::Mint {
                to: call.to,
                amount: call.amount,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn burn(&mut self, msg_sender: &Address, call: ITIP20::burnCall) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, &Address::ZERO, call.amount)?;

        let total_supply = self.total_supply();
        let new_supply = total_supply
            .checked_sub(call.amount)
            .ok_or(tip20_err!(InsufficientBalance))?;
        self.set_total_supply(new_supply);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Burn(ITIP20::Burn {
                from: *msg_sender,
                amount: call.amount,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn burn_blocked(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Check if the address is blocked from transferring
        let transfer_policy_id = self.transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: call.from,
        }) {
            // Only allow burning from addresses that are blocked from transferring
            return Err(tip20_err!(PolicyForbids));
        }

        self._transfer(&call.from, &Address::ZERO, call.amount)?;

        let total_supply = self.total_supply();
        let new_supply = total_supply
            .checked_sub(call.amount)
            .ok_or(tip20_err!(InsufficientBalance))?;
        self.set_total_supply(new_supply);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::BurnBlocked(ITIP20::BurnBlocked {
                from: call.from,
                amount: call.amount,
            })
            .into_log_data(),
        );

        Ok(())
    }

    // Standard token functions
    pub fn approve(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TIP20Error> {
        self.set_allowance(msg_sender, &call.spender, call.amount);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Approval(ITIP20::Approval {
                owner: *msg_sender,
                spender: call.spender,
                amount: call.amount,
            })
            .into_log_data(),
        );

        Ok(true)
    }

    pub fn transfer(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.check_transfer_authorized(msg_sender, &call.to)?;
        self._transfer(msg_sender, &call.to, call.amount)?;
        Ok(true)
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.check_transfer_authorized(&call.from, &call.to)?;

        // Check and update allowance
        let allowed = self.get_allowance(&call.from, msg_sender);
        if call.amount > allowed {
            return Err(tip20_err!(InsufficientAllowance));
        }

        if allowed != U256::MAX {
            let new_allowance = allowed
                .checked_sub(call.amount)
                .ok_or(tip20_err!(InsufficientAllowance))?;
            self.set_allowance(&call.from, msg_sender, new_allowance);
        }

        self._transfer(&call.from, &call.to, call.amount)?;
        Ok(true)
    }

    pub fn permit(
        &mut self,
        _msg_sender: &Address,
        call: ITIP20::permitCall,
    ) -> Result<(), TIP20Error> {
        if U256::from(call.deadline)
            < U256::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        {
            return Err(tip20_err!(Expired));
        }

        // Get and increment nonce
        let nonce_slot = mapping_slot(call.owner, slots::NONCES);
        let nonce = self.storage.sload(self.token_address, nonce_slot);
        self.storage
            .sstore(self.token_address, nonce_slot, nonce + U256::from(1));

        // Verify signature
        let domain_separator = self.domain_separator();

        // Manually encode the struct hash for Permit
        let mut struct_data = Vec::new();
        struct_data.extend_from_slice(
            keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)").as_slice(),
        );
        struct_data.extend_from_slice(call.owner.as_slice());
        struct_data.extend_from_slice(call.spender.as_slice());
        struct_data.extend_from_slice(&call.value.to_be_bytes::<32>());
        struct_data.extend_from_slice(&nonce.to_be_bytes::<32>());
        struct_data.extend_from_slice(&U256::from(call.deadline).to_be_bytes::<32>());
        let struct_hash = keccak256(&struct_data);

        let mut digest_data = Vec::new();
        digest_data.push(0x19);
        digest_data.push(0x01);
        digest_data.extend_from_slice(domain_separator.as_slice());
        digest_data.extend_from_slice(struct_hash.as_slice());
        let _digest = keccak256(&digest_data);

        // TODO: Implement ecrecover verification
        // For now, we'll skip signature verification

        self.set_allowance(&call.owner, &call.spender, call.value);

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Approval(ITIP20::Approval {
                owner: call.owner,
                spender: call.spender,
                amount: call.value,
            })
            .into_log_data(),
        );

        Ok(())
    }

    // TIP20 extension functions
    pub fn transfer_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.check_transfer_authorized(msg_sender, &call.to)?;

        self._transfer(msg_sender, &call.to, call.amount)?;

        self.storage.emit_event(
            self.token_address,
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: *msg_sender,
                to: call.to,
                amount: call.amount,
                memo: call.memo,
            })
            .into_log_data(),
        );

        Ok(())
    }
}

// Utility functions
impl<'a, S: StorageProvider> TIP20Token<'a, S> {
    pub fn new(token_id: u64, storage: &'a mut S) -> Self {
        Self {
            token_address: token_id_to_address(token_id),
            storage,
        }
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
    pub fn initialize(
        &mut self,
        name: &str,
        symbol: &str,
        currency: &str,
        admin: &Address,
    ) -> Result<(), TIP20Error> {
        // EVM invariant that empty accounts do nothing, so must give some code.
        self.storage.set_code(self.token_address, vec![0xef]);

        self.write_string(slots::NAME, name.to_string())?;
        self.write_string(slots::SYMBOL, symbol.to_string())?;
        self.write_string(slots::CURRENCY, currency.to_string())?;

        // Validate currency via TIP4217 registry
        if self.decimals() == 0 {
            return Err(tip20_err!(InvalidCurrency));
        }

        // Set default values
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, U256::MAX);
        self.storage
            .sstore(self.token_address, slots::TRANSFER_POLICY_ID, U256::ONE); // Default "always-allow" policy

        // Initialize roles system and grant admin role
        let mut roles = self.get_roles_contract();
        roles.initialize();
        roles.grant_default_admin(admin);

        // Calculate DOMAIN_SEPARATOR
        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").as_slice(),
        );
        domain_data.extend_from_slice(keccak256(name.as_bytes()).as_slice());
        domain_data.extend_from_slice(keccak256(b"1").as_slice());
        domain_data.extend_from_slice(&U256::from(self.storage.chain_id()).to_be_bytes::<32>());
        domain_data.extend_from_slice(self.token_address.as_slice());
        let domain_separator = keccak256(&domain_data);
        self.storage.sstore(
            self.token_address,
            slots::DOMAIN_SEPARATOR,
            U256::from_be_bytes(domain_separator.0),
        );

        Ok(())
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

    #[inline]
    fn get_balance(&mut self, account: &Address) -> U256 {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage.sload(self.token_address, slot)
    }

    #[inline]
    fn set_balance(&mut self, account: &Address, amount: U256) {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage.sstore(self.token_address, slot, amount);
    }

    #[inline]
    fn get_allowance(&mut self, owner: &Address, spender: &Address) -> U256 {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage.sload(self.token_address, slot)
    }

    #[inline]
    fn set_allowance(&mut self, owner: &Address, spender: &Address, amount: U256) {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage.sstore(self.token_address, slot, amount);
    }

    #[inline]
    fn set_total_supply(&mut self, amount: U256) {
        self.storage
            .sstore(self.token_address, slots::TOTAL_SUPPLY, amount);
    }

    fn check_role(&mut self, account: &Address, role: B256) -> Result<(), TIP20Error> {
        let mut roles = self.get_roles_contract();
        roles
            .check_role(account, role)
            .map_err(|_| tip20_err!(PolicyForbids))
    }

    fn check_not_paused(&mut self) -> Result<(), TIP20Error> {
        if self.paused() {
            return Err(tip20_err!(ContractPaused));
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: &Address) -> Result<(), TIP20Error> {
        // Don't allow sending to other precompiled tokens
        if address_is_token_address(to) {
            return Err(tip20_err!(InvalidRecipient));
        }
        Ok(())
    }

    fn check_transfer_authorized(
        &mut self,
        from: &Address,
        to: &Address,
    ) -> Result<(), TIP20Error> {
        let transfer_policy_id = self.transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);

        // Check if 'from' address is authorized
        let from_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *from,
        });

        // Check if 'to' address is authorized
        let to_authorized_call = ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *to,
        };
        let to_authorized = registry.is_authorized(to_authorized_call);

        if !from_authorized || !to_authorized {
            return Err(tip20_err!(PolicyForbids));
        }

        Ok(())
    }

    fn _transfer(&mut self, from: &Address, to: &Address, amount: U256) -> Result<(), TIP20Error> {
        let from_balance = self.get_balance(from);
        if amount > from_balance {
            return Err(tip20_err!(InsufficientBalance));
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(tip20_err!(InsufficientBalance))?;
        self.set_balance(from, new_from_balance);

        if *to != Address::ZERO {
            let to_balance = self.get_balance(to);
            let new_to_balance = to_balance
                .checked_add(amount)
                .ok_or(tip20_err!(SupplyCapExceeded))?;
            self.set_balance(to, new_to_balance);
        }

        self.storage.emit_event(
            self.token_address,
            TIP20Event::Transfer(ITIP20::Transfer {
                from: *from,
                to: *to,
                amount,
            })
            .into_log_data(),
        );

        Ok(())
    }

    #[inline]
    fn read_string(&mut self, slot: U256) -> String {
        let value = self.storage.sload(self.token_address, slot);
        let bytes = value.to_be_bytes::<32>();
        let len = bytes[31] as usize / 2; // Last byte stores length * 2 for short strings
        if len > 31 {
            panic!("String too long, we shouldn't have stored this in the first place.");
        } else {
            String::from_utf8_lossy(&bytes[..len]).to_string()
        }
    }

    #[inline]
    /// Write string to storage (simplified - assumes string fits in one slot)
    fn write_string(&mut self, slot: U256, value: String) -> Result<(), TIP20Error> {
        let bytes = value.as_bytes();
        if bytes.len() > 31 {
            return Err(tip20_err!(StringTooLong));
        }
        let mut storage_bytes = [0u8; 32];
        storage_bytes[..bytes.len()].copy_from_slice(bytes);
        storage_bytes[31] = (bytes.len() * 2) as u8; // Store length * 2 in last byte

        self.storage
            .sstore(self.token_address, slot, U256::from_be_bytes(storage_bytes));
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use alloy::primitives::Address;

    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_mint_increases_balance_and_supply() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let addr = Address::from([1u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            // Initialize with admin
            token.initialize("Test", "TST", "USD", &admin).unwrap();

            // Grant issuer role to admin
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: addr, amount })
                .unwrap();

            assert_eq!(token.get_balance(&addr), amount);
            assert_eq!(token.total_supply(), amount);
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
    }

    #[test]
    fn test_transfer_moves_balance() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            token.initialize("Test", "TST", "USD", &admin).unwrap();
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: from, amount })
                .unwrap();
            token
                .transfer(&from, ITIP20::transferCall { to, amount })
                .unwrap();

            assert_eq!(token.get_balance(&from), U256::ZERO);
            assert_eq!(token.get_balance(&to), amount);
            assert_eq!(token.total_supply(), amount); // Supply unchanged
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
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", &admin).unwrap();
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);

        let result = token.transfer(&from, ITIP20::transferCall { to, amount });
        assert!(matches!(result, Err(TIP20Error::InsufficientBalance(_))));
    }
}
