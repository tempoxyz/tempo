use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, IntoTxEnv,
    precompiles::PrecompilesMap,
    revm::{
        Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
        context::result::{EVMError, ResultAndState, ResultGas},
        inspector::NoOpInspector,
    },
};
use alloy_primitives::{Address, Bytes, TxKind};
use reth_revm::{InspectSystemCallEvm, MainContext, context::result::ExecutionResult};
use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_revm::{
    TempoHaltReason, TempoInvalidTransaction, TempoTxEnv, ValidationContext, evm::TempoContext,
    handler::TempoEvmHandler,
};

use crate::TempoBlockEnv;
use crate::parallel::{ExecutionStats, SpeculativeExecutor, SpeculativeResult};

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
    speculative: Option<SpeculativeExecutor>,
    prepared: VecDeque<SpeculativeResult<DB::Error>>,
    execution_stats: ExecutionStats,
    last_sample: ExecutionStats,
    backoff_remaining: usize,
    worker_cfg: reth_revm::context::CfgEnv<TempoHardfork>,
}

impl<DB: Database> TempoEvm<DB> {
    /// Create a new [`TempoEvm`] instance.
    pub fn new(db: DB, input: EvmEnv<TempoHardfork, TempoBlockEnv>) -> Self {
        let worker_cfg = input.cfg_env.clone();
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .with_tx(Default::default());

        Self {
            inner: tempo_revm::TempoEvm::new(ctx, NoOpInspector {}),
            inspect: false,
            speculative: None,
            prepared: VecDeque::new(),
            execution_stats: ExecutionStats::default(),
            last_sample: ExecutionStats::default(),
            backoff_remaining: 0,
            worker_cfg,
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Enables bounded speculative execution using the standard Tempo EVM configuration.
    pub fn set_speculative_executor(&mut self, executor: Option<SpeculativeExecutor>) {
        self.prepared.clear();
        self.speculative = executor;
        self.last_sample = self.execution_stats;
        self.backoff_remaining = 0;
    }

    /// Maximum lookahead, or zero when speculative execution is disabled.
    pub fn speculative_batch_size(&self) -> usize {
        if self.inspect {
            return 0;
        }
        self.speculative
            .as_ref()
            .map_or(0, SpeculativeExecutor::batch_size)
    }

    /// Returns execution counters for this EVM instance.
    pub const fn execution_stats(&self) -> ExecutionStats {
        self.execution_stats
    }

    pub(crate) fn has_prepared_transactions(&self) -> bool {
        !self.prepared.is_empty() || self.backoff_remaining > 0
    }

    /// Speculates on a bounded set of transactions with their respective fee recipients.
    /// No writes are committed. Candidates are checked against the actual transaction,
    /// configuration, block environment and database reads before reuse.
    pub fn prepare_transactions(
        &mut self,
        transactions: impl IntoIterator<Item = (TempoTxEnv, Address)>,
    ) {
        self.prepared.clear();
        if self.inspect
            // Instructions and precompiles were constructed with this configuration.
            // Mutating ctx.cfg alone does not reconstruct those components.
            || self.inner.ctx.cfg != self.worker_cfg
            || self.inner.ctx.cfg.disable_fee_charge
            || self.inner.skip_valid_after_check
            || self.inner.skip_liquidity_check
            || !self.inner.ctx.journaled_state.state.is_empty()
            || !self.inner.ctx.journaled_state.transient_storage.is_empty()
            || !self.inner.ctx.journaled_state.logs.is_empty()
        {
            return;
        }
        let Some(executor) = &self.speculative else {
            return;
        };
        let sampled = self.execution_stats.speculated - self.last_sample.speculated;
        let reused = self.execution_stats.reused - self.last_sample.reused
            + self.execution_stats.bodies_reused
            - self.last_sample.bodies_reused;
        if executor.adaptive_backoff() && sampled >= 32 && reused * 8 < sampled {
            // This is only a scheduling choice. No result bypasses read validation.
            // Retry periodically so a later independent workload can use the pool.
            self.backoff_remaining = executor.batch_size().saturating_mul(8);
        }
        self.last_sample = self.execution_stats;
        if self.backoff_remaining > 0 {
            // Advance a payload builder's preview iterator by the same window even
            // when workers are idle, preserving its lookahead alignment.
            transactions
                .into_iter()
                .take(executor.batch_size())
                .for_each(drop);
            return;
        }
        // Limit speculative gas as well as transaction count. A malformed block
        // or a pool of high-limit transactions must not multiply a whole block's
        // maximum execution work by the lookahead window.
        let mut remaining_gas = self.inner.ctx.block.gas_limit;
        let inputs = transactions
            .into_iter()
            .take(executor.batch_size())
            .filter_map(|(mut tx, beneficiary)| {
                if tx.is_system_tx {
                    return None;
                }
                remaining_gas = remaining_gas.checked_sub(tx.inner.gas_limit)?;
                if let Some(aa) = tx.tempo_tx_env.as_mut() {
                    aa.expiring_nonce_idx = None;
                }
                let mut block_env = self.inner.ctx.block.clone();
                block_env.beneficiary = beneficiary;
                Some((
                    tx,
                    EvmEnv {
                        block_env,
                        cfg_env: self.inner.ctx.cfg.clone(),
                    },
                ))
            })
            .collect::<Vec<_>>();
        self.execution_stats.speculated += inputs.len() as u64;
        self.prepared = executor
            .speculate(&mut self.inner.ctx.journaled_state.database, inputs)
            .into();
    }

    /// Consumes this EVM wrapper and returns the inner [`tempo_revm::TempoEvm`].
    pub fn into_inner(self) -> tempo_revm::TempoEvm<DB, I> {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &TempoContext<DB> {
        &self.inner.inner.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoContext<DB> {
        &mut self.inner.inner.ctx
    }

    /// Provides a mutable reference to the inner [`tempo_revm::TempoEvm`].
    pub fn inner_mut(&mut self) -> &mut tempo_revm::TempoEvm<DB, I> {
        // Custom instructions or precompiles must execute on this EVM.
        self.set_speculative_executor(None);
        &mut self.inner
    }

    /// Sets the inspector for the EVM.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm {
            inner: self.inner.with_inspector(inspector),
            inspect: true,
            speculative: self.speculative,
            prepared: VecDeque::new(),
            execution_stats: self.execution_stats,
            last_sample: self.last_sample,
            backoff_remaining: self.backoff_remaining,
            worker_cfg: self.worker_cfg,
        }
    }

    /// Runs the full transaction validation pipeline without executing the transaction.
    ///
    /// Returns a [`ValidationContext`] with context relevant for the transaction pool.
    pub fn validate_transaction(
        &mut self,
        tx: impl IntoTxEnv<TempoTxEnv>,
    ) -> Result<ValidationContext, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.inner.inner.ctx.tx = tx.into_tx_env();
        let mut handler = TempoEvmHandler::new();
        handler.validate_transaction(&mut self.inner)
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
        self.inner.set_body_replay(None);
        if self.backoff_remaining > 0 && !tx.is_system_tx {
            self.backoff_remaining -= 1;
            self.execution_stats.backoff += 1;
        }
        if !self.inspect
            && !self.inner.skip_valid_after_check
            && !self.inner.skip_liquidity_check
            && self.inner.ctx.journaled_state.state.is_empty()
            && self.inner.ctx.journaled_state.transient_storage.is_empty()
            && self.inner.ctx.journaled_state.logs.is_empty()
            && let Some(index) = self.prepared.iter().position(|candidate| {
                candidate.tx == tx
                    && candidate
                        .tx
                        .tempo_tx_env
                        .as_ref()
                        .zip(tx.tempo_tx_env.as_ref())
                        .is_none_or(|(a, b)| {
                            a.tempo_authorization_list
                                .iter()
                                .zip(&b.tempo_authorization_list)
                                .all(|(a, b)| a.authority_status() == b.authority_status())
                        })
            })
        {
            self.prepared.drain(..index);
            let candidate = self.prepared.pop_front().expect("located candidate");
            if candidate.env.cfg_env == self.inner.ctx.cfg
                && candidate.env.block_env == self.inner.ctx.block
            {
                if candidate.result.is_err() {
                    self.execution_stats.retries += 1;
                } else if candidate
                    .validate(&mut self.inner.ctx.journaled_state.database)
                    .unwrap_or(false)
                {
                    self.execution_stats.reused += 1;
                    self.inner.ctx.tx = tx;
                    return candidate.result;
                } else {
                    self.execution_stats.conflicts += 1;
                    self.inner.set_body_replay(candidate.body);
                }
            }
        }
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
            let ExecutionResult::Success { gas, .. } = &mut result.result else {
                return Err(
                    TempoInvalidTransaction::SystemTransactionFailed(result.result.into()).into(),
                );
            };

            *gas = ResultGas::default();

            Ok(result)
        } else if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            let result = self.inner.transact(tx);
            if self.inner.body_was_reused() {
                self.execution_stats.bodies_reused += 1;
            }
            result
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
        if enabled {
            self.prepared.clear();
        }
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.inner.ctx.journaled_state.database,
            &self.inner.inner.inspector,
            &self.inner.inner.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        // Access to the instruction/precompile or inspector configuration invalidates
        // the assumption that workers run the same standard Tempo EVM.
        self.set_speculative_executor(None);
        (
            &mut self.inner.inner.ctx.journaled_state.database,
            &mut self.inner.inner.inspector,
            &mut self.inner.inner.precompiles,
        )
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        // Database mutations are covered by read validation and do not require
        // disabling the pool (this is also the ordinary ordered commit path).
        &mut self.inner.inner.ctx.journaled_state.database
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
        assert_eq!(result.result.tx_gas_used(), 21000);
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
        assert_eq!(result.result.tx_gas_used(), 0);
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
    /// This verifies the [TIP-1000] gas parameter override mechanism.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
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
    /// Note: The 30M [TIP-1000] gas cap is set in ConfigureEvm::evm_env(), not here.
    /// This test verifies that TempoEvm::new() preserves the cap from the input.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    #[test]
    fn test_tempo_evm_respects_gas_cap() {
        let mut env = evm_env_with_spec(TempoHardfork::T1);
        env.cfg_env.tx_gas_limit_cap = TempoHardfork::T1.tx_gas_limit_cap();

        let evm = TempoEvm::new(EmptyDB::default(), env);

        // Verify gas limit cap is preserved
        assert_eq!(
            evm.ctx().cfg.tx_gas_limit_cap,
            TempoHardfork::T1.tx_gas_limit_cap(),
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
