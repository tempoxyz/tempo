use alloy::primitives::{Address, Log, LogData, U256};
use alloy_evm::EvmInternals;
use revm::{
    context::{Block, CfgEnv, journaled_state::JournalCheckpoint},
    context_interface::cfg::{GasParams, gas},
    interpreter::gas::GasTracker,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};

/// Production [`PrecompileStorageProvider`] backed by the live EVM journal.
///
/// Wraps `EvmInternals` and tracks gas consumption for storage operations.
pub struct EvmPrecompileStorageProvider<'a> {
    internals: EvmInternals<'a>,
    gas_tracker: GasTracker,
    spec: TempoHardfork,
    is_static: bool,
    gas_params: GasParams,
    /// Debug-only LIFO checkpoint validator. See [`Self::assert_lifo`].
    #[cfg(debug_assertions)]
    checkpoint_stack: Vec<(usize, usize)>,
}

impl<'a> EvmPrecompileStorageProvider<'a> {
    /// Creates a new storage provider with the given gas limit, hardfork, and static flag.
    pub fn new(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        reservoir: u64,
        spec: TempoHardfork,
        is_static: bool,
        gas_params: GasParams,
    ) -> Self {
        Self {
            internals,
            gas_tracker: GasTracker::new(gas_limit, gas_limit, reservoir),
            spec,
            is_static,
            gas_params,
            #[cfg(debug_assertions)]
            checkpoint_stack: Vec::new(),
        }
    }

    /// Creates a new storage provider with maximum gas limit and non-static context.
    pub fn new_max_gas(internals: EvmInternals<'a>, cfg: &CfgEnv<TempoHardfork>) -> Self {
        Self::new(
            internals,
            u64::MAX,
            0,
            cfg.spec,
            false,
            cfg.gas_params.clone(),
        )
    }

    /// Creates a new storage provider with the given gas limit, deriving spec from `cfg`.
    pub fn new_with_gas_limit(
        internals: EvmInternals<'a>,
        cfg: &CfgEnv<TempoHardfork>,
        gas_limit: u64,
        reservoir: u64,
    ) -> Self {
        Self::new(
            internals,
            gas_limit,
            reservoir,
            cfg.spec,
            false,
            cfg.gas_params.clone(),
        )
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if !self.gas_tracker.record_state_cost(gas) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }
}

impl<'a> PrecompileStorageProvider for EvmPrecompileStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.internals.chain_id()
    }

    fn timestamp(&self) -> U256 {
        self.internals.block_timestamp()
    }

    fn beneficiary(&self) -> Address {
        self.internals.block_env().beneficiary()
    }

    fn block_number(&self) -> u64 {
        self.internals.block_env().number().to::<u64>()
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        let code_len = code.len();
        self.deduct_gas(self.gas_params.code_deposit_cost(code_len))?;

        // Track state gas for code deposit
        self.deduct_state_gas(self.gas_params.code_deposit_state_gas(code_len))?;

        let was_empty = {
            let mut account = self.internals.load_account_mut(address)?;
            let was_empty = account.data.account().info.is_empty();
            account.set_code_and_hash_slow(code);
            was_empty
        };

        // T4: charge TIP20 creations as CREATE
        if self.spec.is_t4() && was_empty {
            self.deduct_gas(self.gas_params.create_cost())?;
            self.deduct_state_gas(self.gas_params.create_state_gas())?;
        }

        Ok(())
    }

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_account_additional_cost();

        let mut account = self
            .internals
            .load_account_mut_skip_cold_load(address, false)?;

        // TODO(rakita) can be moved to the beginning of the function. Requires fork.
        deduct_gas(
            &mut self.gas_tracker,
            self.gas_params.warm_storage_read_cost(),
        )?;

        // dynamic gas
        if account.is_cold {
            deduct_gas(&mut self.gas_tracker, additional_cost)?;
        }

        account.load_code()?;

        f(&account.data.account().info);
        Ok(())
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let result = self
            .internals
            .load_account_mut(address)?
            .sstore(key, value, false)?;

        // TODO(rakita) can be moved to the beginning of the function. Requires fork.
        self.deduct_gas(self.gas_params.sstore_static_gas())?;

        // dynamic gas
        self.deduct_gas(
            self.gas_params
                .sstore_dynamic_gas(true, &result.data, result.is_cold),
        )?;

        // Track state gas (cold SSTORE zero->non-zero only)
        self.deduct_state_gas(self.gas_params.sstore_state_gas(&result.data))?;

        // refund gas.
        self.refund_gas(self.gas_params.sstore_refund(true, &result.data));

        Ok(())
    }

    #[inline]
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        self.internals.tstore(address, key, value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(
            gas::LOG
                + self
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len() as u64),
        )?;

        self.internals.log(Log {
            address,
            data: event,
        });

        Ok(())
    }

    #[inline]
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_storage_additional_cost();

        let value;
        let is_cold;
        {
            let mut account = self.internals.load_account_mut(address)?;
            let val = account.sload(key, false)?;

            value = val.present_value;
            is_cold = val.is_cold;
        };

        // TODO(rakita) can be moved to the beginning of the function. Requires fork.
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;

        if is_cold {
            self.deduct_gas(additional_cost)?;
        }

        Ok(value)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;

        Ok(self.internals.tload(address, key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        deduct_gas(&mut self.gas_tracker, gas)
    }

    #[inline]
    fn refund_gas(&mut self, gas: i64) {
        self.gas_tracker.record_refund(gas);
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_tracker.limit()
    }

    #[inline]
    fn gas_used(&self) -> u64 {
        self.gas_tracker.limit() - self.gas_tracker.remaining()
    }

    #[inline]
    fn state_gas_used(&self) -> u64 {
        self.gas_tracker.state_gas_spent()
    }

    #[inline]
    fn gas_refunded(&self) -> i64 {
        self.gas_tracker.refunded()
    }

    #[inline]
    fn reservoir(&self) -> u64 {
        self.gas_tracker.reservoir()
    }

    #[inline]
    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    #[inline]
    fn is_static(&self) -> bool {
        self.is_static
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        let cp = self.internals.checkpoint();
        #[cfg(debug_assertions)]
        self.track_checkpoint(&cp);
        cp
    }

    #[inline]
    fn checkpoint_commit(&mut self, _checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&_checkpoint, "commit");
        self.internals.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&checkpoint, "revert");
        self.internals.checkpoint_revert(checkpoint)
    }
}

/// LIFO checkpoint validation (debug builds only).
///
/// Since `EvmInternals` doesn't expose revm's journal depth, we mirror it by
/// recording each checkpoint's (`journal_i`, `log_i`) on creation and asserting
/// that commits/reverts always resolve the most recent checkpoint first.
#[cfg(debug_assertions)]
impl EvmPrecompileStorageProvider<'_> {
    /// Records a newly created checkpoint for later LIFO validation.
    fn track_checkpoint(&mut self, cp: &JournalCheckpoint) {
        self.checkpoint_stack.push((cp.journal_i, cp.log_i));
    }

    /// Panics if `cp` is not the most recently created checkpoint.
    fn assert_lifo(&mut self, cp: &JournalCheckpoint, op: &str) {
        let top = self
            .checkpoint_stack
            .pop()
            .unwrap_or_else(|| panic!("checkpoint_{op}: no active checkpoint"));

        assert_eq!(
            (cp.journal_i, cp.log_i),
            top,
            "out-of-order checkpoint {op} (expected top of stack)"
        );
    }
}

/// Deducts gas from the remaining gas and returns an error if insufficient.
#[inline]
pub fn deduct_gas(
    gas_tracker: &mut GasTracker,
    additional_cost: u64,
) -> Result<(), TempoPrecompileError> {
    if !gas_tracker.record_regular_cost(additional_cost) {
        return Err(TempoPrecompileError::OutOfGas);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, b256, bytes, keccak256};
    use alloy_evm::{EvmEnv, EvmFactory, EvmInternals, revm::context::Host};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use revm::{
        database::{CacheDB, EmptyDB},
        interpreter::StateLoad,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_evm::{TempoEvmFactory, evm::TempoEvm};
    use tempo_revm::gas_params::tempo_gas_params;

    struct TestEvm(TempoEvm<CacheDB<EmptyDB>>);

    impl TestEvm {
        fn new(spec: TempoHardfork) -> Self {
            let db = CacheDB::new(EmptyDB::new());
            let mut cfg = revm::context::CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = tempo_gas_params(spec);

            Self(TempoEvmFactory::default().create_evm(
                db,
                EvmEnv {
                    cfg_env: cfg,
                    ..Default::default()
                },
            ))
        }

        fn provider_with_gas_limit(
            &mut self,
            gas_limit: u64,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_> {
            let ctx = self.0.ctx_mut();
            let spec = ctx.cfg.spec;
            let gas_params = ctx.cfg.gas_params.clone();
            let evm_internals =
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);

            EvmPrecompileStorageProvider::new(
                evm_internals,
                gas_limit,
                reservoir,
                spec,
                false,
                gas_params,
            )
        }

        fn provider_with_reservoir(&mut self, reservoir: u64) -> EvmPrecompileStorageProvider<'_> {
            self.provider_with_gas_limit(u64::MAX, reservoir)
        }

        fn provider_max_gas(&mut self) -> EvmPrecompileStorageProvider<'_> {
            let ctx = self.0.ctx_mut();
            let evm_internals =
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);
            EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg)
        }
    }

    impl Default for TestEvm {
        fn default() -> Self {
            Self::new(TempoHardfork::default())
        }
    }

    impl std::ops::Deref for TestEvm {
        type Target = TempoEvm<CacheDB<EmptyDB>>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for TestEvm {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[test]
    fn test_sstore_sload() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let addr = Address::random();
        let code = Bytecode::new_raw(vec![0xff].into());

        provider.set_code(addr, code.clone())?;
        std::mem::drop(provider);

        let Some(StateLoad { data, is_cold: _ }) = evm.load_account_code(addr) else {
            panic!("Failed to load account code")
        };

        assert_eq!(data, *code.original_bytes());
        Ok(())
    }

    #[test]
    fn test_get_account_info() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        // Get account info for a new account
        provider.with_account_info(Address::random(), &mut |info| {
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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let topic = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let data = bytes!(
            "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001"
        );

        let log_data = LogData::new_unchecked(vec![topic], data);

        // Should not error even though events can't be emitted from handlers
        provider.emit_event(Address::random(), log_data)?;

        Ok(())
    }

    #[test]
    fn test_multiple_storage_operations() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();

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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let (address1, address2) = (Address::random(), Address::random());
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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();

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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let (address1, address2) = (Address::random(), Address::random());
        let key = U256::ONE;

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
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
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

    #[test]
    fn test_keccak256_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        // 1 word: KECCAK256(30) + KECCAK256WORD(6) * ceil(11/32) = 36
        assert_eq!(
            provider.keccak256(b"hello world")?,
            keccak256(b"hello world")
        );
        assert_eq!(provider.gas_used(), 36);
        // 2 words: 30 + 6*2 = 42, cumulative = 78
        provider.keccak256(&[0u8; 64])?;
        assert_eq!(provider.gas_used(), 78);
        std::mem::drop(provider);

        // OOG: 30 gas is not enough (needs 36 for 1 word)
        let mut provider = evm.provider_with_gas_limit(30, 0);
        assert!(matches!(
            provider.keccak256(b"hello"),
            Err(TempoPrecompileError::OutOfGas)
        ));

        Ok(())
    }

    #[test]
    fn test_recover_signer_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let signer = PrivateKeySigner::random();
        let digest = keccak256(b"test message");
        let sig = signer.sign_hash_sync(&digest).unwrap();
        let v = sig.v() as u8 + 27;
        let r: B256 = sig.r().into();
        let s: B256 = sig.s().into();

        // Invalid v → None, gas still charged
        assert!(
            provider
                .recover_signer(B256::ZERO, 0, B256::ZERO, B256::ZERO)?
                .is_none()
        );
        assert_eq!(provider.gas_used(), crate::ECRECOVER_GAS);

        // Valid signature → correct recovery
        assert_eq!(
            provider.recover_signer(digest, v, r, s)?,
            Some(signer.address())
        );
        assert_eq!(provider.gas_used(), crate::ECRECOVER_GAS * 2);
        std::mem::drop(provider);

        // OOG: 100 gas is not enough (needs 3000)
        let mut provider = evm.provider_with_gas_limit(100, 0);
        assert!(matches!(
            provider.recover_signer(digest, v, r, s),
            Err(TempoPrecompileError::OutOfGas)
        ));

        Ok(())
    }

    #[test]
    fn test_state_gas_used_only_counts_state_creating_ops() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let gas_params = evm.ctx().cfg.gas_params.clone();
        let mut provider = evm.provider_with_reservoir(0);

        let (address, code_address, slot) = (Address::random(), Address::random(), U256::ONE);

        // SLOADs should not add state gas
        provider.sload(address, slot)?;
        assert_eq!(
            provider.state_gas_used(),
            0,
            "SLOAD should not add state gas"
        );
        assert!(provider.gas_used() > 0, "SLOAD should consume regular gas");

        // SSTORE zero->non-zero should add state gas
        let gas_before = provider.gas_used();
        provider.sstore(address, slot, U256::from(1))?;
        let state_gas_after_set = provider.state_gas_used();
        assert_eq!(
            state_gas_after_set, 230_000,
            "SSTORE zero->non-zero should add 230k state gas"
        );
        assert!(
            provider.gas_used() > gas_before,
            "SSTORE should consume gas"
        );

        // SSTORE non-zero->non-zero should NOT add more state gas
        provider.sstore(address, slot, U256::from(2))?;
        assert_eq!(
            provider.state_gas_used(),
            state_gas_after_set,
            "SSTORE non-zero->non-zero should not add state gas"
        );

        // Code deposit should add state gas (2,300 per byte)
        let state_gas_before_code = provider.state_gas_used();
        provider.set_code(
            code_address,
            revm::state::Bytecode::new_raw(vec![0xef].into()),
        )?;
        assert_eq!(
            provider.state_gas_used(),
            state_gas_before_code
                + gas_params.create_state_gas()
                + gas_params.code_deposit_state_gas(1),
            "set_code(new account, 1 byte) should add CREATE state gas plus 2,300 code deposit state gas"
        );

        Ok(())
    }

    /// Tests that state gas (EIP-8037) is deducted from the reservoir first and
    /// spills into regular gas once the reservoir is exhausted.
    #[test]
    fn test_state_gas_spills_from_reservoir_to_regular_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);

        // Reservoir = 500k: enough for 2 full SSTOREs (2 × 230k = 460k)
        // but the 3rd SSTORE (230k) must spill 190k into regular gas.
        let gas_limit = 1_000_000u64;
        let reservoir = 500_000u64;
        let state_gas_per_sstore = 230_000u64;
        let mut provider = evm.provider_with_gas_limit(gas_limit, reservoir);
        let address = Address::random();

        // --- First SSTORE (zero→non-zero): fully covered by reservoir ---
        provider.sstore(address, U256::from(1), U256::from(42))?;

        let regular_gas_per_sstore = provider.gas_used(); // static + dynamic (regular)
        assert_eq!(
            provider.state_gas_used(),
            state_gas_per_sstore,
            "first SSTORE should consume 230k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - state_gas_per_sstore,
            "reservoir should decrease by state gas cost"
        );

        // --- Second SSTORE: still fits in remaining reservoir (270k left, need 230k) ---
        provider.sstore(address, U256::from(2), U256::from(43))?;

        assert_eq!(
            provider.state_gas_used(),
            2 * state_gas_per_sstore,
            "two SSTOREs should consume 460k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - 2 * state_gas_per_sstore,
            "reservoir should have 40k left after 2 SSTOREs"
        );
        let remaining_reservoir = provider.reservoir(); // 40k
        let regular_gas_before_spill = provider.gas_used();

        // --- Third SSTORE: reservoir insufficient, 190k spills to regular gas ---
        provider.sstore(address, U256::from(3), U256::from(44))?;

        assert_eq!(
            provider.state_gas_used(),
            3 * state_gas_per_sstore,
            "three SSTOREs should consume 690k state gas total"
        );
        assert_eq!(
            provider.reservoir(),
            0,
            "reservoir should be fully exhausted"
        );

        // Regular gas increase = normal sstore cost + spill from reservoir
        let spill = state_gas_per_sstore - remaining_reservoir; // 230k - 40k = 190k
        let expected_regular_after = regular_gas_before_spill + regular_gas_per_sstore + spill;
        assert_eq!(
            provider.gas_used(),
            expected_regular_after,
            "regular gas should include spill of {spill} from exhausted reservoir"
        );

        Ok(())
    }

    #[test]
    fn test_t4_cold_sstore_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_with_reservoir(460_000);

        let (address, cold_slot, warm_slot) = (Address::random(), U256::ONE, U256::from(2));

        provider.sstore(address, cold_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used(),
            22_200,
            "TIP-1016 cold SSTORE should consume 22,200 regular gas including the retained Berlin cold-slot access charge"
        );
        assert_eq!(
            provider.state_gas_used(),
            230_000,
            "TIP-1016 cold SSTORE should consume 230,000 state gas"
        );

        provider.sload(address, warm_slot)?;
        let gas_before_warm_sstore = provider.gas_used();
        let state_gas_before_warm_sstore = provider.state_gas_used();

        provider.sstore(address, warm_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used() - gas_before_warm_sstore,
            20_100,
            "TIP-1016 warm zero-to-non-zero SSTORE should consume 20,100 regular gas after the slot is warmed by SLOAD"
        );
        assert_eq!(
            provider.state_gas_used() - state_gas_before_warm_sstore,
            230_000,
            "TIP-1016 warm zero-to-non-zero SSTORE should still consume 230,000 state gas"
        );

        Ok(())
    }

    #[test]
    fn test_t4_set_code_new_account_matches_tip1016_success_path() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let gas_params = evm.ctx().cfg.gas_params.clone();

        let code = Bytecode::new_raw(vec![0xef].into());
        let expected_state_gas =
            gas_params.create_state_gas() + gas_params.code_deposit_state_gas(code.len());
        let expected_regular_gas =
            gas_params.create_cost() + gas_params.code_deposit_cost(code.len());
        let mut provider = evm.provider_with_reservoir(expected_state_gas);

        provider.set_code(Address::random(), code)?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas,
            "TIP-1016 CREATE success path should charge CREATE + code deposit"
        );
        assert_eq!(
            provider.state_gas_used(),
            expected_state_gas,
            "set_code on a new account should charge CREATE state gas plus code deposit state gas"
        );

        Ok(())
    }

    #[test]
    #[ignore = "TIP-1016 mismatch: 0->X->0 refund math does not net to GAS_WARM_ACCESS (100 gas) yet"]
    fn test_t4_sstore_restore_refund_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_with_reservoir(230_000);

        let (address, slot) = (Address::random(), U256::ONE);
        provider.sstore(address, slot, U256::ONE)?;
        provider.sstore(address, slot, U256::ZERO)?;
        assert_eq!(provider.gas_refunded(), 247_800);
        let net_gas_after_refund =
            provider.gas_used() + provider.state_gas_used() - provider.gas_refunded() as u64;
        assert_eq!(
            net_gas_after_refund, 100,
            "TIP-1016 says 0->X->0 should net to GAS_WARM_ACCESS (100)"
        );

        Ok(())
    }
}
