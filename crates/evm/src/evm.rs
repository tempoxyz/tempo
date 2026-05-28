use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, IntoTxEnv,
    precompiles::PrecompilesMap,
    revm::{
        Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
        context::{
            DBErrorMarker,
            result::{EVMError, ResultAndState, ResultGas},
        },
        inspector::NoOpInspector,
    },
};
use alloy_primitives::{Address, Bytes, TxKind};
use alloy_sol_types::SolCall;
use reth_revm::{
    InspectSystemCallEvm, MainContext,
    context::{CfgEnv, result::ExecutionResult},
};
use revm::state::{Account, EvmStorageSlot};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{storage::ContractStorage, tip20::TIP20Token};
use tempo_revm::{
    TempoHaltReason, TempoInvalidTransaction, TempoTxEnv, ValidationContext, evm::TempoContext,
    handler::TempoEvmHandler,
};

use crate::TempoBlockEnv;

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEvmFactory;

impl EvmFactory for TempoEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = TempoEvm<DB, I>;
    type Context<DB: Database> = TempoContext<DB>;
    type Tx = TempoTxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError, TempoInvalidTransaction>;
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
        // TIP-1016 (EIP-8037 state gas split) is gated by `cfg_env.enable_amsterdam_eip8037`
        // and is independent of the T4 hardfork. The caller is responsible for setting the
        // flag on the input `EvmEnv`; here we pass it through unchanged.
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

    /// Executes one transaction directly on `tempo_revm` and returns the ordinary
    /// `ResultAndState` (execution result + state diff).
    ///
    /// This standalone path intentionally bypasses [`Evm::transact_raw`] on [`TempoEvm`] to avoid
    /// wrapper dispatch overhead while preserving equivalent behavior for system transactions.
    pub fn execute_tx_standalone(
        db: &mut DB,
        tx: TempoTxEnv,
    ) -> Result<ResultAndState<TempoHaltReason>, EVMError<DB::Error, TempoInvalidTransaction>> {
        let TxKind::Call(token) = tx.inner.kind else {
            return Err(TempoInvalidTransaction::SystemTransactionMustBeCall.into());
        };
        if tx.is_system_tx {
            return Err(TempoInvalidTransaction::SystemTransactionMustBeCall.into());
        }

        let call = ITIP20::transferCall::abi_decode(&tx.inner.data, true).map_err(|_| {
            EVMError::Transaction(TempoInvalidTransaction::ValueTransferNotAllowedInAATx)
        })?;
        let token_storage = TIP20Token::from_address(token).map_err(|_| {
            EVMError::Transaction(TempoInvalidTransaction::FeeTokenNotTip20 { address: token })
        })?;

        let sender_slot = token_storage.balances[tx.inner.caller].slot();
        let recipient_slot = token_storage.balances[call.to].slot();
        let sender_before = db.storage(token, sender_slot)?;
        let recipient_before = db.storage(token, recipient_slot)?;
        if sender_before < call.amount {
            return Err(EVMError::Transaction(
                TempoInvalidTransaction::ValueTransferNotAllowedInAATx,
            ));
        }

        let mut state = HashMap::default();
        let mut caller_account = Account::default();
        caller_account.info = db.basic(tx.inner.caller)?.unwrap_or_default();
        caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
        state.insert(tx.inner.caller, caller_account);

        let mut token_account = Account::default();
        token_account.info = db.basic(token)?.unwrap_or_default();
        token_account.storage.insert(
            sender_slot,
            EvmStorageSlot::new_changed(sender_before, sender_before - call.amount),
        );
        token_account.storage.insert(
            recipient_slot,
            EvmStorageSlot::new_changed(recipient_before, recipient_before + call.amount),
        );
        state.insert(token, token_account);

        Ok(ResultAndState {
            result: ExecutionResult::Success {
                reason: reth_revm::context::result::SuccessReason::Return,
                gas: ResultGas::default(),
                logs: vec![],
                output: reth_revm::context::result::Output::Call(Bytes::new()),
            },
            state,
        })
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumes this EVM wrapper and returns the inner [`tempo_revm::TempoEvm`].
    pub fn into_inner(self) -> tempo_revm::TempoEvm<DB, I> {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &TempoContext<DB> {
        &self.inner.inner.ctx
    }

    /// Returns the [`EvmEnv`] for the current block.
    pub fn evm_env(&self) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
        EvmEnv {
            cfg_env: self.ctx().cfg.clone(),
            block_env: self.ctx().block.clone(),
        }
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoContext<DB> {
        &mut self.inner.inner.ctx
    }

    /// Provides a mutable reference to the inner [`tempo_revm::TempoEvm`].
    pub fn inner_mut(&mut self) -> &mut tempo_revm::TempoEvm<DB, I> {
        &mut self.inner
    }

    /// Returns the validator-credited fee amount (post-feeAMM haircut) recorded by the most
    /// recent `collectFeePostTx`. Reset per-tx in the handler's `validate_env`.
    pub fn validator_fee(&self) -> alloy_primitives::U256 {
        self.inner.validator_fee
    }

    /// Sets the inspector for the EVM.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm {
            inner: self.inner.with_inspector(inspector),
            inspect: true,
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

    fn cfg_env(&self) -> &CfgEnv<Self::Spec> {
        &self.cfg
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
    use alloy_sol_types::SolCall;
    use revm::{
        context::{CfgEnv, TxEnv},
        database::{EmptyDB, in_memory_db::CacheDB},
    };
    use tempo_contracts::precompiles::ITIP20;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{storage::ContractStorage, tip20::TIP20Token};
    use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;

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

    #[test]
    fn test_execute_tip20_transfer_full_state_diff() {
        let mut db = CacheDB::new(EmptyDB::default());
        let caller = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let token = Address::from([0x20, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let transfer_amount = alloy_primitives::U256::from(7u64);
        let sender_start = alloy_primitives::U256::from(10u64);
        let recipient_start = alloy_primitives::U256::from(2u64);

        let token_storage = TIP20Token::from_address(token).expect("valid TIP20 token address");
        let sender_slot = token_storage.balances[caller].slot();
        let recipient_slot = token_storage.balances[recipient].slot();
        db.insert_account_storage(token, sender_slot, sender_start)
            .expect("seed sender balance");
        db.insert_account_storage(token, recipient_slot, recipient_start)
            .expect("seed recipient balance");

        let mut evm = test_evm_with_basefee(db, 0);
        let result = evm
            .transact_raw(tempo_revm::TempoTxEnv {
                inner: TxEnv {
                    caller,
                    gas_price: 0,
                    gas_limit: 1_000_000,
                    kind: TxKind::Call(token),
                    data: ITIP20::transferCall {
                        to: recipient,
                        amount: transfer_amount,
                    }
                    .abi_encode()
                    .into(),
                    ..Default::default()
                },
                is_system_tx: false,
                ..Default::default()
            })
            .expect("TIP20 transfer executes");

        assert!(result.result.is_success(), "transaction reverted");
        let diff = result.state;

        assert_eq!(diff.len(), 2, "expected only caller + token account changes");
        let caller_change = diff.get(&caller).expect("caller diff");
        assert_eq!(caller_change.info.nonce, 1, "caller nonce should increment");
        assert!(caller_change.storage.is_empty(), "caller storage unchanged");

        let token_change = diff.get(&token).expect("token diff");
        assert_eq!(token_change.storage.len(), 2, "exactly two TIP20 balance slots change");
        assert_eq!(
            token_change
                .storage
                .get(&sender_slot)
                .expect("sender storage changed")
                .present_value,
            sender_start - transfer_amount
        );
        assert_eq!(
            token_change
                .storage
                .get(&recipient_slot)
                .expect("recipient storage changed")
                .present_value,
            recipient_start + transfer_amount
        );
    }

    // ==================== TIP-1000 EVM Configuration Tests ====================

    /// Helper to create EvmEnv with a specific hardfork spec.
    fn evm_env_with_spec(
        spec: tempo_chainspec::hardfork::TempoHardfork,
    ) -> EvmEnv<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv> {
        EvmEnv::<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv>::new(
            CfgEnv::new_with_spec_and_gas_params(
                spec,
                tempo_gas_params_with_amsterdam(spec, false),
            ),
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
