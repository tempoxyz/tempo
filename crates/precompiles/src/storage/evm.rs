use alloy::primitives::{Address, Log, LogData, U256};
use alloy_evm::{EvmInternals, EvmInternalsError};
use revm::{
    context::{Block, CfgEnv},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};

pub struct EvmPrecompileStorageProvider<'a> {
    internals: EvmInternals<'a>,
    chain_id: u64,
    gas_remaining: u64,
    gas_refunded: i64,
    gas_limit: u64,
    spec: TempoHardfork,
}

impl<'a> EvmPrecompileStorageProvider<'a> {
    /// Create a new storage provider with a specific gas limit.
    pub fn new(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        chain_id: u64,
        spec: TempoHardfork,
    ) -> Self {
        Self {
            internals,
            chain_id,
            gas_remaining: gas_limit,
            gas_refunded: 0,
            gas_limit,
            spec,
        }
    }

    /// Create a new storage provider with maximum gas limit.
    pub fn new_max_gas(internals: EvmInternals<'a>, cfg: &CfgEnv<TempoHardfork>) -> Self {
        Self::new(internals, u64::MAX, cfg.chain_id, cfg.spec)
    }

    pub fn ensure_loaded_account(&mut self, account: Address) -> Result<(), EvmInternalsError> {
        self.internals.load_account(account)?;
        self.internals.touch_account(account);
        Ok(())
    }
}

impl<'a> PrecompileStorageProvider for EvmPrecompileStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn timestamp(&self) -> U256 {
        self.internals.block_timestamp()
    }

    fn beneficiary(&self) -> Address {
        self.internals.block_env().beneficiary()
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        self.deduct_gas(code.len() as u64 * revm::interpreter::gas::CODEDEPOSIT)?;

        self.internals.set_code(address, code);

        Ok(())
    }

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        let account = self.internals.load_account_code(address)?.map(|a| &a.info);
        let is_cold = account.is_cold;

        // deduct gas
        self.gas_remaining = self
            .gas_remaining
            .checked_sub(revm::interpreter::gas::warm_cold_cost(is_cold))
            .ok_or(TempoPrecompileError::OutOfGas)?;

        f(account.data);
        Ok(())
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        let result = self.internals.sstore(address, key, value)?;

        self.deduct_gas(revm::interpreter::gas::sstore_cost(
            SpecId::AMSTERDAM,
            &result.data,
            result.is_cold,
        ))?;

        // refund gas.
        self.refund_gas(revm::interpreter::gas::sstore_refund(
            SpecId::AMSTERDAM,
            &result.data,
        ));

        Ok(())
    }

    #[inline]
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        self.deduct_gas(revm::interpreter::gas::WARM_STORAGE_READ_COST)?;

        self.internals.tstore(address, key, value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(
            revm::interpreter::gas::log_cost(event.topics().len() as u8, event.data.len() as u64)
                .unwrap_or(u64::MAX),
        )?;

        self.internals.log(Log {
            address,
            data: event,
        });

        Ok(())
    }

    #[inline]
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        let val = self.internals.sload(address, key)?;

        self.deduct_gas(revm::interpreter::gas::sload_cost(
            SpecId::AMSTERDAM,
            val.is_cold,
        ))?;

        Ok(val.data)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.ensure_loaded_account(address)?;
        self.deduct_gas(revm::interpreter::gas::WARM_STORAGE_READ_COST)?;

        Ok(self.internals.tload(address, key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas_remaining = self
            .gas_remaining
            .checked_sub(gas)
            .ok_or(TempoPrecompileError::OutOfGas)?;
        Ok(())
    }

    #[inline]
    fn refund_gas(&mut self, gas: i64) {
        self.gas_refunded = self.gas_refunded.saturating_add(gas);
    }

    #[inline]
    fn gas_used(&self) -> u64 {
        self.gas_limit - self.gas_remaining
    }

    #[inline]
    fn gas_refunded(&self) -> i64 {
        self.gas_refunded
    }

    #[inline]
    fn spec(&self) -> TempoHardfork {
        self.spec
    }
}

impl From<EvmInternalsError> for TempoPrecompileError {
    fn from(value: EvmInternalsError) -> Self {
        Self::Fatal(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, bytes};
    use alloy_evm::{EvmEnv, EvmFactory, EvmInternals, revm::context::Host};
    use revm::{
        database::{CacheDB, EmptyDB},
        interpreter::StateLoad,
    };
    use tempo_evm::TempoEvmFactory;

    #[test]
    fn test_sstore_sload() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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

    #[test]
    fn test_get_account_info() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

        let address = address!("3000000000000000000000000000000000000003");

        // Get account info for a new account
        provider.with_account_info(address, &mut |info| {
            // Should be an empty account
            assert!(info.balance.is_zero());
            assert_eq!(info.nonce, 0);
            // Note: load_account_code may return empty bytecode as Some(empty) for new accounts
            if let Some(ref code) = info.code {
                assert!(code.is_empty(), "New account should have empty code");
            }
        })?;

        Ok(())
    }

    #[test]
    fn test_emit_event() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

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

    #[test]
    fn test_multiple_transient_storage_operations() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

        let address = address!("8000000000000000000000000000000000000001");

        // Store multiple values
        for i in 0..10 {
            let key = U256::from(i);
            let value = U256::from(i * 100);
            provider.tstore(address, key, value)?;
        }

        // Verify all values
        for i in 0..10 {
            let key = U256::from(i);
            let expected_value = U256::from(i * 100);
            let loaded_value = provider.tload(address, key)?;
            assert_eq!(loaded_value, expected_value);
        }

        Ok(())
    }

    #[test]
    fn test_overwrite_transient_storage() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

        let address = address!("9000000000000000000000000000000000000001");
        let key = U256::from(99);

        // Store initial value
        let initial_value = U256::from(111);
        provider.tstore(address, key, initial_value)?;
        assert_eq!(provider.tload(address, key)?, initial_value);

        // Overwrite with new value
        let new_value = U256::from(999);
        provider.tstore(address, key, new_value)?;
        assert_eq!(provider.tload(address, key)?, new_value);

        Ok(())
    }

    #[test]
    fn test_transient_storage_different_addresses() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

        let address1 = address!("a000000000000000000000000000000000000001");
        let address2 = address!("a000000000000000000000000000000000000002");
        let key = U256::from(42);

        // Store different values at the same key for different addresses
        let value1 = U256::from(100);
        let value2 = U256::from(200);

        provider.tstore(address1, key, value1)?;
        provider.tstore(address2, key, value2)?;

        // Verify values are independent
        assert_eq!(provider.tload(address1, key)?, value1);
        assert_eq!(provider.tload(address2, key)?, value2);

        Ok(())
    }

    #[test]
    fn test_transient_storage_isolation_from_persistent() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

        let address = address!("b000000000000000000000000000000000000001");
        let key = U256::from(123);
        let persistent_value = U256::from(456);
        let transient_value = U256::from(789);

        // Store in persistent storage
        provider.sstore(address, key, persistent_value)?;

        // Store in transient storage with same key
        provider.tstore(address, key, transient_value)?;

        // Verify they are independent
        assert_eq!(provider.sload(address, key)?, persistent_value);
        assert_eq!(provider.tload(address, key)?, transient_value);

        Ok(())
    }
}
