use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory,
    precompiles::PrecompilesMap,
    revm::{
        Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
        context::result::{EVMError, ResultAndState},
        inspector::NoOpInspector,
    },
};
use alloy_primitives::{Address, Bytes, Log, TxKind};
use reth_revm::{InspectSystemCallEvm, MainContext, context::result::ExecutionResult};
use std::ops::{Deref, DerefMut};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_revm::{TempoHaltReason, TempoInvalidTransaction, TempoTxEnv, evm::TempoContext};

use crate::TempoBlockEnv;

/// TIP-1000 sets transaction gas limit cap to 30 million gas.
///
/// Increase of tx gas limit cap to 30M gas is to allow for maximum-sized
/// contract deployments under TIP-1000 state creation costs.
pub const TIP1000_TX_GAS_LIMIT_CAP: u64 = 30_000_000;

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEvmFactory;

impl EvmFactory for TempoEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = TempoEvm<DB, I>;
    type Context<DB: Database> = TempoContext<DB>;
    type Tx = TempoTxEnv;
    type Error<DBError: std::error::Error + Send + Sync + 'static> =
        EVMError<DBError, TempoInvalidTransaction>;
    type HaltReason = TempoHaltReason;
    type Spec = TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        TempoEvm::new(db, input)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        TempoEvm::new(db, input).with_inspector(inspector)
    }
}

/// Tempo EVM implementation.
///
/// This is a wrapper type around the `revm` ethereum evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// `RevmEvm` type.
#[expect(missing_debug_implementations)]
pub struct TempoEvm<DB: Database, I = NoOpInspector> {
    inner: tempo_revm::TempoEvm<DB, I>,
    inspect: bool,
}

impl<DB: Database> TempoEvm<DB> {
    /// Create a new [`TempoEvm`] instance.
    pub fn new(db: DB, input: EvmEnv<TempoHardfork, TempoBlockEnv>) -> Self {
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .with_tx(Default::default());

        Self {
            inner: tempo_revm::TempoEvm::new(ctx, NoOpInspector {}),
            inspect: false,
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &TempoContext<DB> {
        &self.inner.inner.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoContext<DB> {
        &mut self.inner.inner.ctx
    }

    /// Sets the inspector for the EVM.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm {
            inner: self.inner.with_inspector(inspector),
            inspect: true,
        }
    }

    /// Takes the inner EVM's revert logs.
    ///
    /// This is used as a work around to allow logs to be
    /// included for reverting transactions.
    ///
    /// TODO: remove once revm supports emitting logs for reverted transactions
    ///
    /// <https://github.com/tempoxyz/tempo/pull/729>
    pub fn take_revert_logs(&mut self) -> Vec<Log> {
        std::mem::take(&mut self.inner.logs)
    }
}

impl<DB: Database, I> Deref for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Target = TempoContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I> DerefMut for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I> Evm for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type DB = DB;
    type Tx = TempoTxEnv;
    type Error = EVMError<DB::Error, TempoInvalidTransaction>;
    type HaltReason = TempoHaltReason;
    type Spec = TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &Self::BlockEnv {
        &self.block
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if tx.is_system_tx {
            let TxKind::Call(to) = tx.inner.kind else {
                return Err(TempoInvalidTransaction::SystemTransactionMustBeCall.into());
            };

            let mut result = if self.inspect {
                self.inner
                    .inspect_system_call_with_caller(tx.inner.caller, to, tx.inner.data)?
            } else {
                self.inner
                    .system_call_with_caller(tx.inner.caller, to, tx.inner.data)?
            };

            // system transactions should not consume any gas
            let ExecutionResult::Success {
                gas_used,
                gas_refunded,
                ..
            } = &mut result.result
            else {
                return Err(TempoInvalidTransaction::SystemTransactionFailed(result.result).into());
            };

            *gas_used = 0;
            *gas_refunded = 0;

            Ok(result)
        } else if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        let Context {
            block: block_env,
            cfg: cfg_env,
            journaled_state,
            ..
        } = self.inner.inner.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.inner.ctx.journaled_state.database,
            &self.inner.inner.inspector,
            &self.inner.inner.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.inner.ctx.journaled_state.database,
            &mut self.inner.inner.inspector,
            &mut self.inner.inner.precompiles,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{test_evm, test_evm_with_basefee};
    use revm::{
        context::{CfgEnv, TxEnv},
        database::{EmptyDB, in_memory_db::CacheDB},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_revm::gas_params::tempo_gas_params;

    use super::*;

    #[test]
    fn can_execute_system_tx() {
        let mut evm = test_evm(EmptyDB::default());
        let result = evm
            .transact(TempoTxEnv {
                inner: TxEnv {
                    caller: Address::ZERO,
                    gas_price: 0,
                    gas_limit: 21000,
                    ..Default::default()
                },
                is_system_tx: true,
                ..Default::default()
            })
            .unwrap();

        assert!(result.result.is_success());
    }

    #[test]
    fn test_transact_raw() {
        let mut evm = test_evm_with_basefee(EmptyDB::default(), 0);

        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::repeat_byte(0x01),
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Call(Address::repeat_byte(0x02)),
                ..Default::default()
            },
            is_system_tx: false,
            fee_token: None,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
        assert_eq!(result.result.gas_used(), 21000);
    }

    #[test]
    fn test_transact_raw_system_tx() {
        let mut evm = test_evm(EmptyDB::default());

        // System transaction
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Call(Address::repeat_byte(0x01)),
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
        // System transactions should not consume gas
        assert_eq!(result.result.gas_used(), 0);
    }

    #[test]
    fn test_transact_raw_system_tx_must_be_call() {
        let mut evm = test_evm(EmptyDB::default());

        // System transaction with Create kind
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Create,
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            EVMError::Transaction(TempoInvalidTransaction::SystemTransactionMustBeCall)
        ));
    }

    #[test]
    fn test_transact_raw_system_tx_failed() {
        let mut cache_db = CacheDB::new(EmptyDB::default());
        // Deploy a contract that always reverts: PUSH1 0x00 PUSH1 0x00 REVERT (0x60006000fd)
        let revert_code = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
        let contract_addr = Address::repeat_byte(0xaa);

        cache_db.insert_account_info(
            contract_addr,
            revm::state::AccountInfo {
                code_hash: alloy_primitives::keccak256(&revert_code),
                code: Some(revm::bytecode::Bytecode::new_raw(revert_code)),
                ..Default::default()
            },
        );

        let mut evm = test_evm(cache_db);

        // System transaction that will fail with call to contract that reverts
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 1_000_000,
                kind: TxKind::Call(contract_addr),
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            EVMError::Transaction(TempoInvalidTransaction::SystemTransactionFailed(_))
        ));
    }

    #[test]
    fn test_transact_system_call() {
        let mut evm = test_evm(EmptyDB::default());

        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x02);
        let data = Bytes::from_static(&[0x01, 0x02, 0x03]);

        let result = evm.transact_system_call(caller, contract, data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
    }

    #[test]
    fn test_take_revert_logs() {
        let mut evm = test_evm(EmptyDB::default());

        assert!(evm.take_revert_logs().is_empty());

        let log1 = Log::new_unchecked(
            Address::repeat_byte(0x01),
            vec![alloy_primitives::B256::repeat_byte(0xaa)],
            Bytes::from_static(&[0x01, 0x02]),
        );
        let log2 = Log::new_unchecked(
            Address::repeat_byte(0x02),
            vec![],
            Bytes::from_static(&[0x03, 0x04]),
        );
        evm.inner.logs.push(log1);
        evm.inner.logs.push(log2);

        let logs = evm.take_revert_logs();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].address, Address::repeat_byte(0x01));
        assert_eq!(logs[1].address, Address::repeat_byte(0x02));

        assert!(evm.take_revert_logs().is_empty());
    }

    // ==================== TIP-1000 EVM Configuration Tests ====================

    /// Helper to create EvmEnv with a specific hardfork spec.
    fn evm_env_with_spec(
        spec: tempo_chainspec::hardfork::TempoHardfork,
    ) -> EvmEnv<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv> {
        EvmEnv::<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv>::new(
            CfgEnv::new_with_spec_and_gas_params(spec, tempo_gas_params(spec)),
            TempoBlockEnv::default(),
        )
    }

    /// Test that TempoEvm applies custom gas params via `tempo_gas_params()`.
    /// This verifies the TIP-1000 gas parameter override mechanism.
    #[test]
    fn test_tempo_evm_applies_gas_params() {
        // Create EVM with T1 hardfork to get TIP-1000 gas params
        let evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));

        // Verify gas params were applied (check a known T1 override)
        // T1 has tx_eip7702_per_empty_account_cost = 12,500
        let gas_params = &evm.ctx().cfg.gas_params;
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost(),
            12_500,
            "T1 should have EIP-7702 per empty account cost of 12,500"
        );
    }

    /// Test that TempoEvm respects the gas limit cap passed in via EvmEnv.
    /// Note: The 30M TIP-1000 gas cap is set in ConfigureEvm::evm_env(), not here.
    /// This test verifies that TempoEvm::new() preserves the cap from the input.
    #[test]
    fn test_tempo_evm_respects_gas_cap() {
        let mut env = evm_env_with_spec(TempoHardfork::T1);
        env.cfg_env.tx_gas_limit_cap = Some(TIP1000_TX_GAS_LIMIT_CAP);

        let evm = TempoEvm::new(EmptyDB::default(), env);

        // Verify gas limit cap is preserved
        assert_eq!(
            evm.ctx().cfg.tx_gas_limit_cap,
            Some(TIP1000_TX_GAS_LIMIT_CAP),
            "TempoEvm should preserve the gas limit cap from input"
        );
    }

    /// Test that gas params differ between T0 and T1 hardforks.
    #[test]
    fn test_tempo_evm_gas_params_differ_t0_vs_t1() {
        // Create T0 and T1 EVMs
        let t0_evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T0));
        let t1_evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));

        // T0 should have default EIP-7702 cost (25,000)
        // T1 should have reduced cost (12,500)
        let t0_eip7702_cost = t0_evm
            .ctx()
            .cfg
            .gas_params
            .tx_eip7702_per_empty_account_cost();
        let t1_eip7702_cost = t1_evm
            .ctx()
            .cfg
            .gas_params
            .tx_eip7702_per_empty_account_cost();

        assert_eq!(t0_eip7702_cost, 25_000, "T0 should have default 25,000");
        assert_eq!(t1_eip7702_cost, 12_500, "T1 should have reduced 12,500");
        assert_ne!(
            t0_eip7702_cost, t1_eip7702_cost,
            "Gas params should differ between T0 and T1"
        );
    }

    /// Test that T1 has significantly higher state creation costs.
    #[test]
    fn test_tempo_evm_t1_state_creation_costs() {
        use revm::context_interface::cfg::GasId;

        let evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));
        let gas_params = &evm.ctx().cfg.gas_params;

        // Verify TIP-1000 state creation cost increases
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            250_000,
            "T1 SSTORE set cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::tx_create_cost()),
            500_000,
            "T1 TX create cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::create()),
            500_000,
            "T1 CREATE opcode cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost()),
            250_000,
            "T1 new account cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::code_deposit_cost()),
            1_000,
            "T1 code deposit cost should be 1,000 per byte"
        );
    }
}
