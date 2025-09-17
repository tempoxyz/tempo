use alloy_primitives::{Address, LogData, U256};
use reth_evm::revm::{
    context::JournalTr,
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::contracts::storage::StorageProvider;

/// Wraps a journal to implement StorageProvider for calling precompiles from handlers
pub struct JournalStorageProvider<'a, J: JournalTr> {
    journal: &'a mut J,
    chain_id: u64,
}

impl<'a, J: JournalTr> JournalStorageProvider<'a, J> {
    pub fn new(journal: &'a mut J, chain_id: u64) -> Self {
        Self { journal, chain_id }
    }
    pub fn ensure_loaded_account(
        &mut self,
        account: Address,
    ) -> Result<(), <J::Database as reth_evm::revm::database::Database>::Error> {
        self.journal.load_account(account)?;
        self.journal.touch_account(account);
        Ok(())
    }
}

impl<'a, J: JournalTr> StorageProvider for JournalStorageProvider<'a, J> {
    type Error = <J::Database as reth_evm::revm::database::Database>::Error;

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error> {
        self.journal.load_account(address)?;
        let account = self.journal.load_account_code(address)?;
        let code_hash = code.hash_slow();
        account.data.info.set_code_and_hash(code, code_hash);
        Ok(())
    }

    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        self.journal.load_account(address)?;
        let account = self.journal.load_account_code(address)?;
        Ok(account.info.clone())
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.journal.load_account(address)?;
        self.journal.touch_account(address);
        self.journal.sstore(address, key, value)?;
        Ok(())
    }

    fn emit_event(&mut self, _address: Address, _event: LogData) -> Result<(), Self::Error> {
        // Events can't be emitted from handlers, only during execution
        // This is OK since our fee collection functions don't emit events
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.journal.load_account(address)?;
        let value = self.journal.sload(address, key)?;
        Ok(value.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address, b256, bytes};
    use reth_evm::revm::{
        Journal,
        database::{CacheDB, EmptyDB},
    };

    fn create_test_journal() -> Journal<CacheDB<EmptyDB>> {
        let db = CacheDB::new(EmptyDB::default());
        Journal::new(db)
    }

    #[test]
    fn test_chain_id() {
        let mut journal = create_test_journal();
        let chain_id = 42u64;
        let provider = JournalStorageProvider::new(&mut journal, chain_id);

        assert_eq!(provider.chain_id(), chain_id);
    }

    #[test]
    fn test_sstore_and_sload() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("1000000000000000000000000000000000000001");
        let key = U256::from(42);
        let value = U256::from(123456789);

        // Store a value
        provider.sstore(address, key, value)?;

        // Load the value back
        let loaded_value = provider.sload(address, key)?;
        assert_eq!(loaded_value, value);

        Ok(())
    }

    #[test]
    fn test_set_code() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("2000000000000000000000000000000000000002");
        let code_bytes = bytes!(
            "608060405260008060006101000a81548160ff0219169083151502179055506000600190556000600290556102c5806100396000396000f3fe"
        );
        let code = Bytecode::new_raw(code_bytes);

        // Set the code
        provider.set_code(address, code.clone())?;

        // Verify the code was set by checking the account
        let account_info = provider.get_account_info(address)?;
        assert_eq!(account_info.code_hash, code.hash_slow());

        Ok(())
    }

    #[test]
    fn test_get_account_info() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("3000000000000000000000000000000000000003");

        // Get account info for a new account
        let account_info = provider.get_account_info(address)?;

        // Should be an empty account
        assert!(account_info.balance.is_zero());
        assert_eq!(account_info.nonce, 0);
        // Note: load_account_code may return empty bytecode as Some(empty) for new accounts
        if let Some(ref code) = account_info.code {
            assert!(code.is_empty(), "New account should have empty code");
        }

        Ok(())
    }

    #[test]
    fn test_emit_event() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("4000000000000000000000000000000000000004");
        let topic = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let data = bytes!(
            "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001"
        );

        let log_data = LogData::new_unchecked(vec![topic], data);

        // Should not error even though events can't be emitted from handlers
        provider.emit_event(address, log_data)?;

        Ok(())
    }

    #[test]
    fn test_multiple_storage_operations() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("5000000000000000000000000000000000000005");

        // Store multiple values
        for i in 0..10 {
            let key = U256::from(i);
            let value = U256::from(i * 100);
            provider.sstore(address, key, value)?;
        }

        // Verify all values
        for i in 0..10 {
            let key = U256::from(i);
            let expected_value = U256::from(i * 100);
            let loaded_value = provider.sload(address, key)?;
            assert_eq!(loaded_value, expected_value);
        }

        Ok(())
    }

    #[test]
    fn test_overwrite_storage() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address = address!("6000000000000000000000000000000000000006");
        let key = U256::from(99);

        // Store initial value
        let initial_value = U256::from(111);
        provider.sstore(address, key, initial_value)?;
        assert_eq!(provider.sload(address, key)?, initial_value);

        // Overwrite with new value
        let new_value = U256::from(999);
        provider.sstore(address, key, new_value)?;
        assert_eq!(provider.sload(address, key)?, new_value);

        Ok(())
    }

    #[test]
    fn test_different_addresses() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let chain_id = 1u64;
        let mut provider = JournalStorageProvider::new(&mut journal, chain_id);

        let address1 = address!("7000000000000000000000000000000000000001");
        let address2 = address!("7000000000000000000000000000000000000002");
        let key = U256::from(42);

        // Store different values at the same key for different addresses
        let value1 = U256::from(100);
        let value2 = U256::from(200);

        provider.sstore(address1, key, value1)?;
        provider.sstore(address2, key, value2)?;

        // Verify values are independent
        assert_eq!(provider.sload(address1, key)?, value1);
        assert_eq!(provider.sload(address2, key)?, value2);

        Ok(())
    }
}
