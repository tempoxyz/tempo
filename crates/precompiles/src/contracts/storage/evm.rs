use alloy::primitives::{Address, Log, LogData, U256};
use alloy_evm::{EvmInternals, EvmInternalsError};
use reth_evm::revm::state::Bytecode;

use crate::contracts::storage::{AccountInfo, StorageProvider};

pub struct EvmStorageProvider<'a> {
    internals: EvmInternals<'a>,
    chain_id: u64,
}

impl<'a> EvmStorageProvider<'a> {
    pub fn new(internals: EvmInternals<'a>, chain_id: u64) -> Self {
        Self {
            internals,
            chain_id,
        }
    }

    pub fn ensure_loaded_account(&mut self, account: Address) -> Result<(), EvmInternalsError> {
        self.internals.load_account(account)?;
        self.internals.touch_account(account);
        Ok(())
    }
}

impl<'a> StorageProvider for EvmStorageProvider<'a> {
    type Error = EvmInternalsError;

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error> {
        self.ensure_loaded_account(address)?;
        self.internals.set_code(address, code);
        Ok(())
    }

    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        self.ensure_loaded_account(address)?;
        let account = self.internals.load_account_code(address)?;
        Ok(account.data.info.clone())
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.ensure_loaded_account(address)?;
        self.internals.sstore(address, key, value)?;
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error> {
        self.internals.log(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.ensure_loaded_account(address)?;
        Ok(self
            .internals
            .sload(address, key)
            .map_or(U256::ZERO, |value| value.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::{
        EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
        revm::context::{ContextTr, Host},
    };
    use reth_evm::revm::{
        database::{CacheDB, EmptyDB},
        interpreter::StateLoad,
    };

    #[test]
    fn test_sstore_sload() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut provider = EvmStorageProvider::new(evm_internals, 1);

        let addr = Address::random();
        let key = U256::random();
        let value = U256::random();

        provider.sstore(addr, key, value)?;
        let sload_val = provider.sload(addr, key)?;

        assert_eq!(sload_val, value);
        Ok(())
    }

    #[test]
    fn test_set_code() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut provider = EvmStorageProvider::new(evm_internals, 1);

        let addr = Address::random();
        let code = Bytecode::new_raw(vec![0xff].into());
        provider.set_code(addr, code.clone())?;
        drop(provider);

        let Some(StateLoad { data, is_cold: _ }) = evm.load_account_code(addr) else {
            panic!("Failed to load account code")
        };

        assert_eq!(data, *code.original_bytes());
        Ok(())
    }
}
