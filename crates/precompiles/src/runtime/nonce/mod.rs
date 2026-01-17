pub use crate::abi::{INonce::prelude::*, NONCE_PRECOMPILE_ADDRESS};
use tempo_precompiles_macros::contract;

use crate::{
    abi::nonce::abi,
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
///     mapping(address => uint256) public activeKeyCount;                  // slot 1 (deprecated)
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Active key count - keccak256(abi.encode(account, 1)) (deprecated)
///
/// Note: Protocol nonce (key 0) is stored directly in account state, not here.
/// Only user nonce keys (1-N) are managed by this precompile.
#[contract(addr = NONCE_PRECOMPILE_ADDRESS, abi, dispatch)]
pub struct NonceManager {
    nonces: Mapping<Address, Mapping<U256, u64>>,
}

impl abi::INonce for NonceManager {
    /// Get the nonce for a specific account and nonce key.
    ///
    /// Protocol nonce (key 0) is stored in account state, not in this precompile.
    /// Users should query account nonce directly, not through this precompile.
    fn get_nonce(&self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key.is_zero() {
            return Err(abi::Error::protocol_nonce_not_supported().into());
        }

        self.nonces[account][nonce_key].read()
    }
}

impl NonceManager {
    /// Initializes the nonce manager contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Internal: Increment nonce for a specific account and nonce key
    pub fn increment_nonce(&mut self, account: Address, nonce_key: U256) -> Result<u64> {
        if nonce_key.is_zero() {
            return Err(abi::Error::invalid_nonce_key().into());
        }

        let current = self.nonces[account][nonce_key].read()?;

        let new_nonce = current
            .checked_add(1)
            .ok_or_else(abi::Error::nonce_overflow)?;

        self.nonces[account][nonce_key].write(new_nonce)?;

        self.emit_event(abi::Event::NonceIncremented(abi::NonceIncremented {
            account,
            nonce_key,
            new_nonce,
        }))?;

        Ok(new_nonce)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };

    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_get_nonce_returns_zero_for_new_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mgr = NonceManager::new();

            let account = address!("0x1111111111111111111111111111111111111111");
            let nonce = abi::INonce::get_nonce(&mgr, account, U256::from(5))?;

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
            let result = abi::INonce::get_nonce(&mgr, account, U256::ZERO);

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::Nonce(abi::Error::protocol_nonce_not_supported())
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
            assert_eq!(mgr.emitted_events().len(), 1);

            let new_nonce = mgr.increment_nonce(account, nonce_key)?;
            assert_eq!(new_nonce, 2);
            mgr.assert_emitted_events(vec![
                abi::NonceIncremented {
                    account,
                    nonce_key,
                    new_nonce: 1,
                },
                abi::NonceIncremented {
                    account,
                    nonce_key,
                    new_nonce: 2,
                },
            ]);

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

            let nonce1 = abi::INonce::get_nonce(&mgr, account1, nonce_key)?;
            let nonce2 = abi::INonce::get_nonce(&mgr, account2, nonce_key)?;

            assert_eq!(nonce1, 10);
            assert_eq!(nonce2, 20);
            Ok(())
        })
    }
}
