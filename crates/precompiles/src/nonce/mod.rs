pub mod dispatch;

use alloy::primitives::Bytes;
use revm::state::Bytecode;
pub use tempo_contracts::precompiles::INonce;
use tempo_contracts::precompiles::{NonceError, NonceEvent};
use tempo_precompiles_macros::contract;

use crate::{NONCE_PRECOMPILE_ADDRESS, error::Result, storage::PrecompileStorageProvider};
use alloy::primitives::{Address, IntoLogData, U256};

/// NonceManager contract for managing 2D nonces as per the AA spec
///
/// Storage Layout (similar to Solidity contract):
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///     mapping(address => uint256) public activeKeyCount;                  // slot 1
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Active key count - keccak256(abi.encode(account, 1))
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
#[contract]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
    active_key_count: Mapping<Address, U256>,
}

impl<'a, S: PrecompileStorageProvider> NonceManager<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(NONCE_PRECOMPILE_ADDRESS, storage)
    }

    /// Initializes the nonce manager contract.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            NONCE_PRECOMPILE_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Get the nonce for a specific account and nonce key
    pub fn get_nonce(&mut self, call: INonce::getNonceCall) -> Result<u64> {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if call.nonceKey == 0 {
            return Err(NonceError::protocol_nonce_not_supported().into());
        }

        // For user nonce keys, read from precompile storage
        self.sload_nonces(call.account, call.nonceKey)
    }

    /// Get the number of active user nonce keys for an account
    pub fn get_active_nonce_key_count(
        &mut self,
        call: INonce::getActiveNonceKeyCountCall,
    ) -> Result<U256> {
        self.sload_active_key_count(call.account)
    }

    /// Internal: Increment nonce for a specific account and nonce key
    pub fn increment_nonce(&mut self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key == 0 {
            // TODO: Should this be a different error?
            return Err(NonceError::invalid_nonce_key().into());
        }

        let current = self.sload_nonces(account, nonce_key)?;

        // If transitioning from 0 to 1, increment active key count
        if current == 0 {
            self.increment_active_key_count(account)?;
        }

        let new_nonce = current
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.sstore_nonces(account, nonce_key, new_nonce)?;

        Ok(new_nonce)
    }

    /// Increment the active key count for an account
    fn increment_active_key_count(&mut self, account: Address) -> Result<()> {
        let current = self.sload_active_key_count(account)?;

        let new_count = current
            .checked_add(U256::ONE)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.sstore_active_key_count(account, new_count)?;

        // Emit ActiveKeyCountChanged event (only after Moderato hardfork)
        if self.storage.spec().is_moderato() {
            self.storage.emit_event(
                self.address,
                NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
                    account,
                    newCount: new_count,
                })
                .into_log_data(),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::TempoPrecompileError, storage::hashmap::HashMapStorageProvider};
    use tempo_chainspec::hardfork::TempoHardfork;

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
                nonceKey: U256::from(5),
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
            nonceKey: U256::ZERO,
        });

        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::NonceError(NonceError::protocol_nonce_not_supported())
        );
    }

    #[test]
    fn test_increment_nonce() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce_key = U256::from(5);

        let new_nonce = nonce_mgr.increment_nonce(account, nonce_key).unwrap();
        assert_eq!(new_nonce, 1);

        let new_nonce = nonce_mgr.increment_nonce(account, nonce_key).unwrap();
        assert_eq!(new_nonce, 2);
    }

    #[test]
    fn test_active_key_count() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account = address!("0x1111111111111111111111111111111111111111");

        // Initially, no active keys
        let count = nonce_mgr
            .get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })
            .unwrap();
        assert_eq!(count, U256::ZERO);

        // Increment a nonce key - should increase active count
        nonce_mgr.increment_nonce(account, U256::ONE).unwrap();
        let count = nonce_mgr
            .get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })
            .unwrap();
        assert_eq!(count, U256::ONE);

        // Increment same key again - count should stay the same
        nonce_mgr.increment_nonce(account, U256::ONE).unwrap();
        let count = nonce_mgr
            .get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })
            .unwrap();
        assert_eq!(count, U256::ONE);

        // Increment a different key - count should increase
        nonce_mgr.increment_nonce(account, U256::from(2)).unwrap();
        let count = nonce_mgr
            .get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })
            .unwrap();
        assert_eq!(count, U256::from(2));
    }

    #[test]
    fn test_different_accounts_independent() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_mgr = NonceManager::new(&mut storage);

        let account1 = address!("0x1111111111111111111111111111111111111111");
        let account2 = address!("0x2222222222222222222222222222222222222222");
        let nonce_key = U256::from(5);

        for _ in 0..10 {
            nonce_mgr.increment_nonce(account1, nonce_key).unwrap();
        }
        for _ in 0..20 {
            nonce_mgr.increment_nonce(account2, nonce_key).unwrap();
        }

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

    #[test]
    fn test_active_key_count_event_emitted_post_moderato() {
        // Test with Moderato hardfork (event should be emitted)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce_key = U256::from(5);

        // First increment should emit ActiveKeyCountChanged event
        {
            let mut nonce_mgr = NonceManager::new(&mut storage);
            nonce_mgr.increment_nonce(account, nonce_key).unwrap();
        }

        // Check that ActiveKeyCountChanged event was emitted
        let events = storage.events.get(&NONCE_PRECOMPILE_ADDRESS);
        assert!(events.is_some(), "No events emitted");
        let events = events.unwrap();
        assert_eq!(events.len(), 1, "Should emit ActiveKeyCountChanged");

        // Check the ActiveKeyCountChanged event
        let expected_event = NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
            account,
            newCount: U256::ONE,
        });
        assert_eq!(events[0], expected_event.into_log_data());

        // Second increment on same key should NOT emit ActiveKeyCountChanged
        {
            let mut nonce_mgr = NonceManager::new(&mut storage);
            nonce_mgr.increment_nonce(account, nonce_key).unwrap();
        }
        let events = storage.events.get(&NONCE_PRECOMPILE_ADDRESS).unwrap();
        assert_eq!(events.len(), 1); // Still only one event

        // Increment on different key SHOULD emit ActiveKeyCountChanged again
        let nonce_key2 = U256::from(10);
        {
            let mut nonce_mgr = NonceManager::new(&mut storage);
            nonce_mgr.increment_nonce(account, nonce_key2).unwrap();
        }
        let events = storage.events.get(&NONCE_PRECOMPILE_ADDRESS).unwrap();
        assert_eq!(events.len(), 2); // Second ActiveKeyCountChanged

        let expected_event2 = NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
            account,
            newCount: U256::from(2),
        });
        assert_eq!(events[1], expected_event2.into_log_data());
    }

    #[test]
    fn test_active_key_count_event_not_emitted_pre_moderato() {
        // Test with Adagio (pre-Moderato) - event should NOT be emitted
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let account = address!("0x1111111111111111111111111111111111111111");
        let nonce_key = U256::from(5);

        // First increment should NOT emit ActiveKeyCountChanged event pre-Moderato
        {
            let mut nonce_mgr = NonceManager::new(&mut storage);
            nonce_mgr.increment_nonce(account, nonce_key).unwrap();
        }

        // Check that NO events were emitted
        let events = storage.events.get(&NONCE_PRECOMPILE_ADDRESS);
        assert!(
            events.is_none() || events.unwrap().is_empty(),
            "No events should be emitted pre-Moderato"
        );

        // Increment on different key should also NOT emit event
        let nonce_key2 = U256::from(10);
        {
            let mut nonce_mgr = NonceManager::new(&mut storage);
            nonce_mgr.increment_nonce(account, nonce_key2).unwrap();
        }

        // Still no events
        let events = storage.events.get(&NONCE_PRECOMPILE_ADDRESS);
        assert!(
            events.is_none() || events.unwrap().is_empty(),
            "No events should be emitted pre-Moderato"
        );
    }
}
