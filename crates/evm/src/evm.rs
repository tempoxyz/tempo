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
    use reth_revm::context::BlockEnv;
    use revm::{
        context::TxEnv,
        database::{EmptyDB, in_memory_db::CacheDB},
    };

    use super::*;

    #[test]
    fn can_execute_system_tx() {
        let mut evm = TempoEvm::new(
            EmptyDB::default(),
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
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
        let mut evm = TempoEvm::new(
            EmptyDB::default(),
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 0,
                        gas_limit: 30_000_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

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
        let mut evm = TempoEvm::new(
            EmptyDB::default(),
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

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
        let mut evm = TempoEvm::new(
            EmptyDB::default(),
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

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

        let mut evm = TempoEvm::new(
            cache_db,
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // System transaction that will fail with call to contract that reverts
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 100000,
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
        let mut evm = TempoEvm::new(
            EmptyDB::default(),
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        basefee: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x02);
        let data = Bytes::from_static(&[0x01, 0x02, 0x03]);

        let result = evm.transact_system_call(caller, contract, data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
    }
}
