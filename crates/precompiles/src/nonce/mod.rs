pub mod bindings;
pub mod dispatch;

use self::bindings::INonce;
use crate::{
    DelegateCallNotAllowed,
    storage::{PrecompileStorageProvider, evm::EvmPrecompileStorageProvider},
};
use alloy::primitives::{Address, U256};
use alloy_evm::precompiles::DynPrecompile;
use revm::precompile::PrecompileOutput;

/// Storage slots for Nonce precompile data
pub mod slots {
    use alloy::primitives::{Address, U256};

    use crate::storage::slots::{double_mapping_slot, mapping_slot};

    /// Base slot for nonces mapping: nonces\[account\]\[nonce_key\]
    pub const NONCES: U256 = U256::ZERO;
    /// Base slot for active key count mapping: activeKeyCount\[account\]
    pub const ACTIVE_KEY_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);

    /// Compute storage slot for nonces\[account\]\[nonce_key\]
    pub fn nonce_slot(account: &Address, nonce_key: u64) -> U256 {
        double_mapping_slot(account, nonce_key.to_be_bytes(), NONCES)
    }

    /// Compute storage slot for activeKeyCount\[account\]
    pub fn active_key_count_slot(account: &Address) -> U256 {
        mapping_slot(account, ACTIVE_KEY_COUNT)
    }
}

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint64 => uint64)) public nonces;      // slot 0
///     mapping(address => uint256) public activeKeyCount;                  // slot 1
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Active key count - keccak256(abi.encode(account, 1))
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
#[derive(Debug)]
pub struct NonceManager<'a, S: PrecompileStorageProvider> {
    pub storage: &'a mut S,
}

impl<'a, S: PrecompileStorageProvider> NonceManager<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    /// Get the nonce for a specific account and nonce key
    pub fn get_nonce(&mut self, call: INonce::getNonceCall) -> Result<u64, String> {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if call.nonceKey == 0 {
            return Err("Protocol nonce not supported".to_string());
        }

        // For user nonce keys, read from precompile storage
        let slot = slots::nonce_slot(&call.account, call.nonceKey);
        let nonce = self
            .storage
            .sload(crate::NONCE_PRECOMPILE_ADDRESS, slot)
            .map_err(|e| format!("Failed to read nonce from storage: {e:?}"))?;

        Ok(nonce.to::<u64>())
    }

    /// Get the number of active user nonce keys for an account
    pub fn get_active_nonce_key_count(&mut self, call: INonce::getActiveNonceKeyCountCall) -> U256 {
        let slot = slots::active_key_count_slot(&call.account);
        self.storage
            .sload(crate::NONCE_PRECOMPILE_ADDRESS, slot)
            .expect("TODO: handle error")
    }

    /// Internal: Set nonce for a specific account and nonce key
    /// This is called by the transaction validation logic
    pub fn set_nonce(&mut self, account: &Address, nonce_key: u64, nonce: u64) {
        if nonce_key == 0 {
            // Protocol nonce is managed by account state, not this precompile
            return;
        }

        let slot = slots::nonce_slot(account, nonce_key);

        // If this is a new nonce key (sequence was 0), increment active key count
        let current = self
            .storage
            .sload(crate::NONCE_PRECOMPILE_ADDRESS, slot)
            .expect("TODO: handle error");

        if current == U256::ZERO && nonce > 0 {
            self.increment_active_key_count(account);
        }

        self.storage
            .sstore(crate::NONCE_PRECOMPILE_ADDRESS, slot, U256::from(nonce))
            .expect("TODO: handle error");
    }

    /// Internal: Increment nonce for a specific account and nonce key
    pub fn increment_nonce(&mut self, account: &Address, nonce_key: u64) -> u64 {
        if nonce_key == 0 {
            // Protocol nonce is managed by account state, not this precompile
            panic!("Protocol nonce should not be managed by nonce precompile");
        }

        let slot = slots::nonce_slot(account, nonce_key);
        let current = self
            .storage
            .sload(crate::NONCE_PRECOMPILE_ADDRESS, slot)
            .expect("TODO: handle error");

        // If transitioning from 0 to 1, increment active key count
        if current == U256::ZERO {
            self.increment_active_key_count(account);
        }

        let new_nonce = current.checked_add(U256::from(1)).expect("Nonce overflow");

        self.storage
            .sstore(crate::NONCE_PRECOMPILE_ADDRESS, slot, new_nonce)
            .expect("TODO: handle error");

        new_nonce.to::<u64>()
    }

    /// Increment the active key count for an account
    fn increment_active_key_count(&mut self, account: &Address) {
        let slot = slots::active_key_count_slot(account);
        let current = self
            .storage
            .sload(crate::NONCE_PRECOMPILE_ADDRESS, slot)
            .expect("TODO: handle error");

        let new_count = current
            .checked_add(U256::from(1))
            .expect("Active key count overflow");

        self.storage
            .sstore(crate::NONCE_PRECOMPILE_ADDRESS, slot, new_count)
            .expect("TODO: handle error");
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::hashmap::HashMapStorageProvider;

    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_get_nonce_returns_zero_for_new_key() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce = nonce_mgr
            .get_nonce(INonce::getNonceCall {
                account,
                nonceKey: 5,
            })
            .unwrap();

        assert_eq!(nonce, 0);
    }

    #[test]
    fn test_get_nonce_rejects_protocol_nonce() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");
        let result = nonce_mgr.get_nonce(INonce::getNonceCall {
            account,
            nonceKey: 0,
        });

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Protocol nonce not supported");
    }

    #[test]
    fn test_set_and_get_nonce() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce_key = 5;

        nonce_mgr.set_nonce(&account, nonce_key, 42);

        let nonce = nonce_mgr
            .get_nonce(INonce::getNonceCall {
                account,
                nonceKey: nonce_key,
            })
            .unwrap();

        assert_eq!(nonce, 42);
    }

    #[test]
    fn test_increment_nonce() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce_key = 5;

        let new_nonce = nonce_mgr.increment_nonce(&account, nonce_key);
        assert_eq!(new_nonce, 1);

        let new_nonce = nonce_mgr.increment_nonce(&account, nonce_key);
        assert_eq!(new_nonce, 2);
    }

    #[test]
    fn test_active_key_count() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");

        // Initially, no active keys
        let count =
            nonce_mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account });
        assert_eq!(count, U256::ZERO);

        // Increment a nonce key - should increase active count
        nonce_mgr.increment_nonce(&account, 1);
        let count =
            nonce_mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account });
        assert_eq!(count, U256::from(1));

        // Increment same key again - count should stay the same
        nonce_mgr.increment_nonce(&account, 1);
        let count =
            nonce_mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account });
        assert_eq!(count, U256::from(1));

        // Increment a different key - count should increase
        nonce_mgr.increment_nonce(&account, 2);
        let count =
            nonce_mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account });
        assert_eq!(count, U256::from(2));
    }

    #[test]
    fn test_different_accounts_independent() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account1 = address!("0x1111111111111111111111111111111111111111");
        let account2 = address!("0x2222222222222222222222222222222222222222");
        let nonce_key = 5;

        nonce_mgr.set_nonce(&account1, nonce_key, 10);
        nonce_mgr.set_nonce(&account2, nonce_key, 20);

        let nonce1 = nonce_mgr
            .get_nonce(INonce::getNonceCall {
                account: account1,
                nonceKey: nonce_key,
            })
            .unwrap();
        let nonce2 = nonce_mgr
            .get_nonce(INonce::getNonceCall {
                account: account2,
                nonceKey: nonce_key,
            })
            .unwrap();

        assert_eq!(nonce1, 10);
        assert_eq!(nonce2, 20);
    }
}
