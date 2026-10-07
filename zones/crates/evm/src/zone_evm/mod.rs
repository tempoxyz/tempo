//! Zone runtime EVM and its private execution policies.

pub(crate) mod contract_creation;
mod validation;

pub use validation::validate_transaction;

use crate::{
    TempoCtx,
    database::{L1OverlayDB, ZoneDbError},
};
use alloy_evm::{Database, Evm, EvmEnv, precompiles::PrecompilesMap, revm::Inspector};
use alloy_primitives::{Address, B256, Bytes};
use revm::context::{
    DBErrorMarker,
    result::{EVMError, HaltReason, ResultAndState},
};
use tempo_evm::{TempoBlockEnv, TempoPoolValidationEvm, TempoPoolValidationResult, evm::TempoEvm};
use tempo_revm::{ExecutionContext, TempoInvalidTransaction, TempoTxEnv};
use zone_l1::state::L1StateProvider;
use zone_precompiles::{L1StorageReader, tx_context};
use zone_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

type TempoResult = ResultAndState<HaltReason>;
type AdaptedEvmError<E> = EVMError<ZoneDbError<E>, TempoInvalidTransaction>;
type ZoneEvmError<E> = EVMError<E, TempoInvalidTransaction>;

/// Zone runtime EVM.
///
/// Execution uses an anchored database adapter internally while the public [`Evm::DB`] remains the
/// exact database supplied by the caller. All completed results are validated and sanitized before
/// their state transitions can be committed through that public database.
pub struct ZoneEvm<DB: Database, I, L1: L1StorageReader = L1StateProvider> {
    inner: TempoEvm<L1OverlayDB<DB, L1>, I>,
}

impl<DB: Database, I, L1: L1StorageReader> ZoneEvm<DB, I, L1> {
    /// Creates a new `ZoneEvm` with guarded `CREATE` and `CREATE2` opcodes.
    pub(super) fn new(mut evm: TempoEvm<L1OverlayDB<DB, L1>, I>) -> Self {
        contract_creation::configure_runtime(&mut evm);
        Self { inner: evm }
    }

    /// Provides a reference to the EVM context.
    pub fn ctx(&self) -> &TempoCtx<L1OverlayDB<DB, L1>> {
        self.inner.ctx()
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoCtx<L1OverlayDB<DB, L1>> {
        self.inner.ctx_mut()
    }

    /// Clears the L1 overlay bookkeeping left by the current transaction attempt.
    pub(crate) fn clear_l1_overlay_state(&mut self) {
        self.inner
            .ctx_mut()
            .journaled_state
            .database
            .reset_transaction_state();
    }
}

impl<DB, I, L1> ZoneEvm<DB, I, L1>
where
    DB: Database,
    L1: L1StorageReader,
    I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>,
{
    /// Executes a transaction through Tempo, strips mirrored L1 fields from its state transition,
    /// and clears transaction-local overlay bookkeeping before returning.
    fn execute_and_sanitize(
        &mut self,
        execute: impl FnOnce(
            &mut TempoEvm<L1OverlayDB<DB, L1>, I>,
        ) -> Result<TempoResult, AdaptedEvmError<DB::Error>>,
    ) -> Result<TempoResult, ZoneEvmError<DB::Error>> {
        let result = match execute(&mut self.inner) {
            Ok(mut result) => {
                if let Err(error) = self.inner.db_mut().sanitize_state(&mut result.state) {
                    Err(error.into_evm_error())
                } else {
                    Ok(result)
                }
            }
            Err(error) => Err(map_adapter_error(error)),
        };

        self.clear_l1_overlay_state();
        result
    }
}

impl<DB, I, L1> TempoPoolValidationEvm for ZoneEvm<DB, I, L1>
where
    DB: Database,
    L1: L1StorageReader,
    I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>,
{
    fn configure_for_pool(&mut self) {
        self.inner.configure_for_pool();
    }

    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> (TempoPoolValidationResult<DB::Error>, TempoTxEnv) {
        if let Err(err) = validate_transaction(&tx, CONTRACT_DEPLOYER_ALLOWLIST) {
            return (Err(EVMError::Transaction(err)), tx);
        }
        let (result, tx) = self.inner.validate_pool_transaction(tx);
        let result = result.map_err(map_adapter_error);
        self.clear_l1_overlay_state();
        (result, tx)
    }
}

impl<DB, I, L1> Evm for ZoneEvm<DB, I, L1>
where
    DB: Database,
    L1: L1StorageReader,
    I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>,
{
    type DB = DB;
    type Tx = TempoTxEnv;
    type Error = ZoneEvmError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = tempo_chainspec::hardfork::TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &Self::BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &revm::context::CfgEnv<Self::Spec> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        validate_transaction(&tx, CONTRACT_DEPLOYER_ALLOWLIST)?;
        let tx_hash = match tx.execution_context() {
            ExecutionContext::Transaction { tx_hash } => tx_hash,
            ExecutionContext::Simulation => B256::repeat_byte(0xff),
        };
        let _tx_context_guard =
            tx_context::set_current_transaction(tx_hash, tx.fee_payer().unwrap_or(tx.caller));
        self.execute_and_sanitize(|evm| evm.transact_raw(tx))
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.execute_and_sanitize(|evm| evm.transact_system_call(caller, contract, data))
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        let (db, env) = self.inner.finish();
        (db.into_inner(), env)
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        let (db, inspector, precompiles) = self.inner.components();
        (db.inner(), inspector, precompiles)
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        let (db, inspector, precompiles) = self.inner.components_mut();
        (db.inner_mut(), inspector, precompiles)
    }
}

fn map_adapter_error<E: core::error::Error + DBErrorMarker>(
    error: AdaptedEvmError<E>,
) -> ZoneEvmError<E> {
    match error {
        EVMError::Transaction(error) => EVMError::Transaction(error),
        EVMError::Header(error) => EVMError::Header(error),
        EVMError::Database(error) => error.into_evm_error(),
        EVMError::Custom(error) => EVMError::Custom(error),
        EVMError::CustomAny(error) => EVMError::CustomAny(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::EvmEnv;
    use alloy_primitives::U256;
    use revm::{
        context::{
            TxEnv,
            result::{ExecutionResult, HaltReason, Output, ResultGas, SuccessReason},
            transaction::{Authorization, SignedAuthorization},
        },
        context_interface::either::Either,
        database::EmptyDB,
        inspector::NoOpInspector,
        primitives::AddressMap,
        state::{Account, EvmStorageSlot},
    };
    use tempo_precompiles::TIP403_REGISTRY_ADDRESS;
    use tempo_primitives::transaction::{
        RecoveredTempoAuthorization, TempoSignature, TempoSignedAuthorization,
    };
    use tempo_revm::TempoBatchCallEnv;
    use zone_precompiles::test_utils::MockL1Reader;

    fn test_evm() -> ZoneEvm<EmptyDB, NoOpInspector, MockL1Reader> {
        let db = L1OverlayDB::new(EmptyDB::default(), MockL1Reader::default(), Address::ZERO);
        ZoneEvm::new(TempoEvm::new(db, EvmEnv::default()))
    }

    fn registry_write() -> AddressMap<Account> {
        let mut account = Account::default();
        account.storage.insert(
            U256::ZERO,
            EvmStorageSlot {
                original_value: U256::ZERO,
                present_value: U256::ONE,
                ..Default::default()
            },
        );
        AddressMap::from_iter([(TIP403_REGISTRY_ADDRESS, account)])
    }

    fn transactions_with_authorization_lists() -> [TempoTxEnv; 2] {
        let authorization = Authorization {
            chain_id: U256::ZERO,
            address: Address::ZERO,
            nonce: 0,
        };

        let eip7702 = TempoTxEnv {
            inner: TxEnv {
                authorization_list: vec![Either::Left(SignedAuthorization::new_unchecked(
                    authorization.clone(),
                    0,
                    U256::ONE,
                    U256::ONE,
                ))],
                ..Default::default()
            },
            ..Default::default()
        };
        let tempo = TempoTxEnv {
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                tempo_authorization_list: vec![RecoveredTempoAuthorization::new(
                    TempoSignedAuthorization::new_unchecked(
                        authorization,
                        TempoSignature::default(),
                    ),
                )],
                ..Default::default()
            })),
            ..Default::default()
        };

        [eip7702, tempo]
    }

    #[test]
    fn pool_validation_rejects_authorization_lists() {
        for tx in transactions_with_authorization_lists() {
            let (result, _) = test_evm().validate_pool_transaction(tx);

            assert!(matches!(
                result,
                Err(EVMError::Transaction(
                    TempoInvalidTransaction::CallsValidation(
                        "authorization lists are not supported"
                    )
                ))
            ));
        }
    }

    #[test]
    fn block_execution_rejects_authorization_lists() {
        for tx in transactions_with_authorization_lists() {
            let err = test_evm()
                .transact_raw(tx)
                .expect_err("authorization list must be rejected before execution");

            assert!(matches!(
                err,
                EVMError::Transaction(TempoInvalidTransaction::CallsValidation(
                    "authorization lists are not supported"
                ))
            ));
        }
    }

    #[test]
    fn sanitizes_all_completed_execution_results() {
        let gas = ResultGas::default();
        let results = [
            ExecutionResult::Success {
                reason: SuccessReason::Stop,
                gas,
                logs: Vec::new(),
                output: Output::Call(Bytes::new()),
            },
            ExecutionResult::Revert {
                gas,
                logs: Vec::new(),
                output: Bytes::new(),
            },
            ExecutionResult::Halt {
                reason: HaltReason::NotActivated,
                gas,
                logs: Vec::new(),
            },
        ];

        for execution_result in results {
            let mut evm = test_evm();
            let result = evm.execute_and_sanitize(move |_| {
                Ok(ResultAndState::new(execution_result, registry_write()))
            });

            assert!(matches!(result, Err(EVMError::CustomAny(_))));
        }
    }
}
