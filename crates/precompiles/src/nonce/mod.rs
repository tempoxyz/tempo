pub mod dispatch;

pub use tempo_contracts::precompiles::INonce;
use tempo_contracts::precompiles::{NonceError, NonceEvent};
use tempo_precompiles_macros::contract;

use crate::{
    NONCE_PRECOMPILE_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};

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

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceManager {
    pub fn new() -> Self {
        Self::__new(NONCE_PRECOMPILE_ADDRESS)
    }

    /// Initializes the nonce manager contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Get the nonce for a specific account and nonce key
    pub fn get_nonce(&self, call: INonce::getNonceCall) -> Result<u64> {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if call.nonceKey == 0 {
            return Err(NonceError::protocol_nonce_not_supported().into());
        }

        // For user nonce keys, read from precompile storage
        self.nonces.at(call.account).at(call.nonceKey).read()
    }

    /// Get the number of active user nonce keys for an account
    pub fn get_active_nonce_key_count(
        &self,
        call: INonce::getActiveNonceKeyCountCall,
    ) -> Result<U256> {
        self.active_key_count.at(call.account).read()
    }

    /// Internal: Increment nonce for a specific account and nonce key
    pub fn increment_nonce(&mut self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key == 0 {
            return Err(NonceError::invalid_nonce_key().into());
        }

        let current = self.nonces.at(account).at(nonce_key).read()?;

        // If transitioning from 0 to 1, increment active key count
        if current == 0 {
            self.increment_active_key_count(account)?;
        }

        let new_nonce = current
            .checked_add(1)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.nonces.at(account).at(nonce_key).write(new_nonce)?;

        if self.storage.spec().is_allegretto() {
            self.emit_event(NonceEvent::NonceIncremented(INonce::NonceIncremented {
                account,
                nonceKey: nonce_key,
                newNonce: new_nonce,
            }))?;
        }

        Ok(new_nonce)
    }

    /// Increment the active key count for an account
    fn increment_active_key_count(&mut self, account: Address) -> Result<()> {
        let current = self.active_key_count.at(account).read()?;

        let new_count = current
            .checked_add(U256::ONE)
            .ok_or_else(NonceError::nonce_overflow)?;

        self.active_key_count.at(account).write(new_count)?;

        // Emit ActiveKeyCountChanged event (only after Moderato hardfork)
        if self.storage.spec().is_moderato() {
            self.emit_event(NonceEvent::ActiveKeyCountChanged(
                INonce::ActiveKeyCountChanged {
                    account,
                    newCount: new_count,
                },
            ))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_get_nonce_returns_zero_for_new_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce = mgr.get_nonce(INonce::getNonceCall {
                account,
                nonceKey: U256::from(5),
            })?;

            assert_eq!(nonce, 0);
            Ok(())
        })
    }

    #[test]
    fn test_get_nonce_rejects_protocol_nonce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let result = mgr.get_nonce(INonce::getNonceCall {
                account,
                nonceKey: U256::ZERO,
            });

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::NonceError(NonceError::protocol_nonce_not_supported())
            );
            Ok(())
        })
    }

    #[test]
    fn test_increment_nonce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce_key = U256::from(5);

            let new_nonce = mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(new_nonce, 1);

            let new_nonce = mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(new_nonce, 2);
            Ok(())
        })
    }

    #[test]
    fn test_active_key_count() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");

            // Initially, no active keys
            let count =
                mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })?;
            assert_eq!(count, U256::ZERO);

            // Increment a nonce key - should increase active count
            mgr.increment_nonce(account, U256::ONE)?;
            let count =
                mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })?;
            assert_eq!(count, U256::ONE);

            // Increment same key again - count should stay the same
            mgr.increment_nonce(account, U256::ONE)?;
            let count =
                mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })?;
            assert_eq!(count, U256::ONE);

            // Increment a different key - count should increase
            mgr.increment_nonce(account, U256::from(2))?;
            let count =
                mgr.get_active_nonce_key_count(INonce::getActiveNonceKeyCountCall { account })?;
            assert_eq!(count, U256::from(2));
            Ok(())
        })
    }

    #[test]
    fn test_different_accounts_independent() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut mgr = NonceManager::new();

            let account1 = address!("0x1111111111111111111111111111111111111111");
            let account2 = address!("0x2222222222222222222222222222222222222222");
            let nonce_key = U256::from(5);

            for _ in 0..10 {
                mgr.increment_nonce(account1, nonce_key)?;
            }
            for _ in 0..20 {
                mgr.increment_nonce(account2, nonce_key)?;
            }

            let nonce1 = mgr.get_nonce(INonce::getNonceCall {
                account: account1,
                nonceKey: nonce_key,
            })?;
            let nonce2 = mgr.get_nonce(INonce::getNonceCall {
                account: account2,
                nonceKey: nonce_key,
            })?;

            assert_eq!(nonce1, 10);
            assert_eq!(nonce2, 20);
            Ok(())
        })
    }

    #[test]
    fn test_active_key_count_event_emitted_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        StorageCtx::enter(&mut storage, || {
            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce_key = U256::from(5);

            // First increment should emit ActiveKeyCountChanged event
            let mut mgr = NonceManager::new();
            mgr.increment_nonce(account, nonce_key)?;

            // Check the ActiveKeyCountChanged event
            mgr.assert_emitted_events(vec![NonceEvent::ActiveKeyCountChanged(
                INonce::ActiveKeyCountChanged {
                    account,
                    newCount: U256::ONE,
                },
            )]);

            // Second increment on same key should NOT emit ActiveKeyCountChanged
            mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(mgr.emitted_events().len(), 1);

            // Increment on different key SHOULD emit ActiveKeyCountChanged again
            let nonce_key2 = U256::from(10);
            mgr.increment_nonce(account, nonce_key2)?;
            mgr.assert_emitted_events(vec![
                NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
                    account,
                    newCount: U256::ONE,
                }),
                NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
                    account,
                    newCount: U256::from(2),
                }),
            ]);

            // Second increment on same key should NOT emit ActiveKeyCountChanged
            mgr.increment_nonce(account, nonce_key2)?;
            assert_eq!(mgr.emitted_events().len(), 2);

            Ok(())
        })
    }

    #[test]
    fn test_active_key_count_event_not_emitted_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        StorageCtx::enter(&mut storage, || {
            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce_key = U256::from(5);

            let mut mgr = NonceManager::new();
            mgr.increment_nonce(account, nonce_key)?;

            assert!(
                mgr.emitted_events().is_empty(),
                "No events should be emitted pre-Moderato"
            );

            let nonce_key2 = U256::from(10);
            mgr.increment_nonce(account, nonce_key2)?;

            assert!(
                mgr.emitted_events().is_empty(),
                "No events should be emitted pre-Moderato"
            );
            Ok(())
        })
    }

    #[test]
    fn test_increment_nonce_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        StorageCtx::enter(&mut storage, || {
            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce_key = U256::from(5);

            // First increment emits ActiveKeyCountChanged + NonceIncremented
            let mut mgr = NonceManager::new();
            mgr.increment_nonce(account, nonce_key)?;

            mgr.assert_emitted_events(vec![
                NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
                    account,
                    newCount: U256::ONE,
                }),
                NonceEvent::NonceIncremented(INonce::NonceIncremented {
                    account,
                    nonceKey: nonce_key,
                    newNonce: 1,
                }),
            ]);

            // Second increment on same key only emits NonceIncremented (no new key)
            mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(mgr.emitted_events().len(), 3);

            mgr.assert_emitted_events(vec![
                NonceEvent::ActiveKeyCountChanged(INonce::ActiveKeyCountChanged {
                    account,
                    newCount: U256::ONE,
                }),
                NonceEvent::NonceIncremented(INonce::NonceIncremented {
                    account,
                    nonceKey: nonce_key,
                    newNonce: 1,
                }),
                NonceEvent::NonceIncremented(INonce::NonceIncremented {
                    account,
                    nonceKey: nonce_key,
                    newNonce: 2,
                }),
            ]);

            Ok(())
        })
    }
}
