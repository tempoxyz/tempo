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
use reth_revm::{
    InspectSystemCallEvm, MainContext,
    context::{CfgEnv, result::ExecutionResult},
};
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    rc::Rc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{storage::StorageAction, storage_credits::NonCreditableSlots};
use tempo_revm::{
    ProtocolFeeManager, TempoHaltReason, TempoInvalidTransaction, TempoTxEnv, ValidationContext,
    evm::TempoContext, handler::TempoEvmHandler,
};

use crate::TempoBlockEnv;

/// Factory for creating Tempo EVM instances.
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

    /// Consumes this EVM wrapper and returns the EVM context.
    pub fn into_ctx(self) -> TempoContext<DB> {
        self.inner.inner.ctx
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

    /// Returns the transaction-local protocol slots whose clears must not mint storage credits.
    pub fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
        self.inner.non_creditable_slots()
    }

    /// Sets the inspector for the EVM.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm {
            inner: self.inner.with_inspector(inspector),
            inspect: true,
        }
    }

    /// Updates the protocol fee manager used by the EVM.
    pub fn with_fee_manager<F>(self, fee_manager: F) -> Self
    where
        F: ProtocolFeeManager<DB> + 'static,
    {
        Self {
            inner: self.inner.with_fee_manager(fee_manager),
            inspect: self.inspect,
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
        let mut handler = TempoEvmHandler::<DB, I>::new();
        handler.validate_transaction(&mut self.inner)
    }

    /// Enables recording of storage actions.
    pub fn with_actions(mut self) -> Self {
        let mut actions = self.inner.actions().clone();
        actions.enable();
        self.inner = self.inner.with_actions(actions);
        self
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take_actions(&mut self) -> Option<Vec<StorageAction>> {
        self.inner.actions().take()
    }

    /// Clears the recorded storage actions without releasing the backing allocation.
    pub fn clear_actions(&mut self) {
        self.inner.actions().clear();
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace_actions(&mut self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        self.inner.actions().replace(actions)
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
    use alloy_primitives::{B256, U256};
    use alloy_sol_types::SolCall;
    use indexmap::IndexMap;
    use revm::{
        DatabaseCommit, DatabaseRef,
        context::{BlockEnv, CfgEnv, JournalTr, TxEnv},
        database::{EmptyDB, in_memory_db::CacheDB},
        state::EvmState,
    };
    use std::{assert_matches, collections::BTreeMap};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
        TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
        storage::{ContractStorage, StorageAction, StorageActions, StorageCtx, StorageKey},
        storage_credits::StorageCredits,
        test_util::TIP20Setup,
        tip_fee_manager::{
            IFeeManager, TipFeeManager,
            amm::{Pool, PoolKey, compute_amount_out},
            slots as fee_manager_slots,
        },
        tip20::{
            ITIP20, rewards::__packing_user_reward_info as user_reward_info_slots,
            slots as tip20_slots,
        },
        tip403_registry::slots as tip403_registry_slots,
    };
    use tempo_primitives::transaction::Call;
    use tempo_revm::{TempoBatchCallEnv, gas_params::tempo_gas_params_with_amsterdam};

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

    #[derive(Default)]
    struct StorageState {
        reconstructed: BTreeMap<(Address, U256), U256>,
        original_values: BTreeMap<(Address, U256), U256>,
        first_loads: BTreeMap<(Address, U256), U256>,
    }

    impl StorageState {
        fn get_or_init_storage(&mut self, key: (Address, U256)) -> U256 {
            match self.reconstructed.get(&key) {
                Some(current) => *current,
                None => {
                    let (address, slot) = key;

                    let original = *self
                        .original_values
                        .get(&key)
                        .unwrap_or_else(|| panic!("No prior SLOAD for {address:?}:{slot:?}",));

                    self.first_loads.insert(key, original);
                    self.reconstructed.insert(key, original);

                    original
                }
            }
        }
    }

    fn assert_storage_actions_reconstruct_evm_state(
        actions: &[StorageAction],
        state: &EvmState,
        hardfork: TempoHardfork,
    ) {
        let mut storage_state = StorageState::default();
        for (address, account) in state {
            for (slot, storage_slot) in &account.storage {
                storage_state
                    .original_values
                    .insert((*address, *slot), storage_slot.original_value());
            }
        }

        for action in actions {
            match *action {
                StorageAction::Sload(address, slot, value) => {
                    let key = (address, slot);
                    match storage_state.reconstructed.get(&key) {
                        Some(previous) => assert_eq!(
                            *previous, value,
                            "SLOAD must match reconstructed current value for {address:?}:{slot:?} on {hardfork:?}",
                        ),
                        None => {
                            storage_state.first_loads.insert(key, value);
                            storage_state.reconstructed.insert(key, value);
                        }
                    }
                }
                StorageAction::Sstore(address, slot, value) => {
                    let key = (address, slot);
                    assert!(
                        storage_state.reconstructed.contains_key(&key),
                        "SSTORE without prior SLOAD for {address:?}:{slot:?} on {hardfork:?}",
                    );
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sinc(address, slot, delta) => {
                    let key = (address, slot);
                    let current = storage_state.get_or_init_storage(key);
                    let value = current.checked_add(delta).unwrap_or_else(|| {
                        panic!("SINC overflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sdec(address, slot, delta) => {
                    let key = (address, slot);
                    let current = storage_state.get_or_init_storage(key);
                    let value = current.checked_sub(delta).unwrap_or_else(|| {
                        panic!("SDEC underflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::FeeAmmSwap(address, slot, amount_in) => {
                    let key = (address, slot);
                    let current = storage_state.get_or_init_storage(key);
                    let mut pool = Pool::decode_from_slot(current);
                    pool.apply_swap(
                        amount_in,
                        compute_amount_out(amount_in).expect("compute_amount_out should not fail"),
                    )
                    .unwrap_or_else(|err| {
                        panic!("FeeAmmSwap invalid for {address:?}:{slot:?} on {hardfork:?}: {err}")
                    });
                    storage_state
                        .reconstructed
                        .insert(key, pool.encode_to_slot().unwrap());
                }
            }
        }

        for (address, account) in state {
            for (slot, storage_slot) in &account.storage {
                let key = (*address, *slot);
                let original_value = storage_state.first_loads.get(&key).unwrap_or_else(|| {
                    panic!(
                        "EVM output storage cell {address:?}:{slot:?} was not loaded in StorageActions on {hardfork:?}",
                    )
                });
                assert_eq!(
                    *original_value,
                    storage_slot.original_value(),
                    "reconstructed original value mismatch for {address:?}:{slot:?} on {hardfork:?}",
                );

                let reconstructed_value = storage_state.reconstructed.get(&key).unwrap_or_else(|| {
                    panic!(
                        "EVM output storage cell {address:?}:{slot:?} was not reconstructed from StorageActions on {hardfork:?}",
                    )
                });
                assert_eq!(
                    *reconstructed_value,
                    storage_slot.present_value(),
                    "reconstructed present value mismatch for {address:?}:{slot:?} on {hardfork:?}",
                );
            }
        }
    }

    struct StorageActionSnapshotLabels {
        addresses: BTreeMap<Address, &'static str>,
        slots: BTreeMap<(Address, U256), &'static str>,
    }

    fn snapshot_storage_actions(
        actions: &[StorageAction],
        labels: &StorageActionSnapshotLabels,
    ) -> Vec<String> {
        actions
            .iter()
            .map(|action| match *action {
                StorageAction::Sload(address, slot, value) => {
                    format!(
                        "Sload({}, {}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sstore(address, slot, value) => {
                    format!(
                        "Sstore({}, {}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sinc(address, slot, delta) => {
                    format!(
                        "Sinc({}, {}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sdec(address, slot, delta) => {
                    format!(
                        "Sdec({}, {}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::FeeAmmSwap(address, slot, amount_in) => {
                    format!(
                        "FeeAmmSwap({}, {}, {amount_in})",
                        labels.address(address),
                        labels.slot(address, slot),
                    )
                }
            })
            .collect()
    }

    impl StorageActionSnapshotLabels {
        fn address(&self, address: Address) -> String {
            self.addresses
                .get(&address)
                .copied()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{address:?}"))
        }

        fn slot(&self, address: Address, slot: U256) -> String {
            self.slots
                .get(&(address, slot))
                .copied()
                .map(str::to_string)
                .unwrap_or_else(|| slot.to_string())
        }
    }

    #[test]
    fn test_tip20_full_evm_storage_actions() {
        for hardfork in TempoHardfork::VARIANTS {
            // skip pre-T5 hardforks to avoid clutter
            if !hardfork.is_t5() {
                continue;
            }

            let sender = Address::repeat_byte(0x01);
            let recipient = Address::repeat_byte(0x02);
            let beneficiary = Address::repeat_byte(0x03);
            let starting_balance = U256::from(1_000_000);
            let transfer_amount = U256::from(100);
            let gas_limit = 1_000_000;
            let gas_price = 1_000_000_000u64;

            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(*hardfork);

            let mut evm = TempoEvm::new(
                CacheDB::new(EmptyDB::default()),
                EvmEnv {
                    cfg_env: cfg,
                    block_env: TempoBlockEnv {
                        inner: BlockEnv {
                            beneficiary,
                            basefee: gas_price,
                            gas_limit: 30_000_000,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                },
            );

            let fee_token =
                StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                    TIP20Setup::path_usd(sender)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .apply()?;
                    let fee_token = TIP20Setup::create("FeeToken", "FEE", sender)
                        .with_salt(B256::ZERO)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .with_mint(recipient, starting_balance)
                        .apply()?;

                    let mut fee_manager = TipFeeManager::new();
                    fee_manager.set_user_token(
                        sender,
                        IFeeManager::setUserTokenCall {
                            token: fee_token.address(),
                        },
                    )?;
                    fee_manager.mint(
                        sender,
                        fee_token.address(),
                        PATH_USD_ADDRESS,
                        U256::from(500_000),
                        sender,
                    )?;

                    Ok::<Address, tempo_precompiles::error::TempoPrecompileError>(
                        fee_token.address(),
                    )
                })
                .expect("TIP20 setup should succeed");
            let setup_state = evm.ctx_mut().journaled_state.finalize();
            evm.db_mut().commit(setup_state);

            let mut evm = evm.with_actions();
            assert_eq!(evm.take_actions(), Some(vec![]));

            let sender_balance_slot = sender.mapping_slot(tip20_slots::BALANCES);
            let sender_fee_token_balance_slot = sender.mapping_slot(tip20_slots::BALANCES);
            let fee_manager_balance_slot =
                TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES);
            let fee_manager_fee_token_balance_slot =
                TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES);
            let recipient_balance_slot = recipient.mapping_slot(tip20_slots::BALANCES);
            let sender_reward_info_slot = sender.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let sender_fee_token_reward_info_slot =
                sender.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let recipient_reward_info_slot = recipient.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let validator_token_slot =
                beneficiary.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS);
            let user_token_slot = sender.mapping_slot(fee_manager_slots::USER_TOKENS);
            let collected_fees_slot = PATH_USD_ADDRESS
                .mapping_slot(beneficiary.mapping_slot(fee_manager_slots::COLLECTED_FEES));
            let pool_id = PoolKey::new(fee_token, PATH_USD_ADDRESS).get_id();
            let pool_slot =
                U256::from_be_bytes::<32>(pool_id.into()).mapping_slot(fee_manager_slots::POOLS);
            let pending_pool_reservation_slot = U256::from_be_bytes::<32>(pool_id.into())
                .mapping_slot(fee_manager_slots::PENDING_FEE_SWAP_RESERVATION);
            let receive_policy_config_slot =
                recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);
            let nonce_key = U256::from(42);
            let sender_nonce_key_slot = nonce_key
                .mapping_slot(sender.mapping_slot(tempo_precompiles::nonce::slots::NONCES));

            #[rustfmt::skip]
            let labels = StorageActionSnapshotLabels {
                addresses: BTreeMap::from([
                    (PATH_USD_ADDRESS, "PATH_USD"),
                    (fee_token, "FEE_TOKEN"),
                    (TIP_FEE_MANAGER_ADDRESS, "TIP_FEE_MANAGER"),
                    (TIP403_REGISTRY_ADDRESS, "TIP403_REGISTRY"),
                    (STORAGE_CREDITS_ADDRESS, "STORAGE_CREDITS"),
                    (NONCE_PRECOMPILE_ADDRESS, "NONCE_MANAGER"),
                ]),
                slots: BTreeMap::from([
                    ((PATH_USD_ADDRESS, tip20_slots::CURRENCY), "currency"),
                    ((PATH_USD_ADDRESS, tip20_slots::TRANSFER_POLICY_ID), "transferPolicyId"),
                    ((PATH_USD_ADDRESS, tip20_slots::PAUSED), "paused"),
                    ((PATH_USD_ADDRESS, tip20_slots::GLOBAL_REWARD_PER_TOKEN), "globalRewardPerToken"),
                    ((PATH_USD_ADDRESS, sender_balance_slot), "balances[sender]"),
                    ((PATH_USD_ADDRESS, fee_manager_balance_slot), "balances[FeeManager]"),
                    ((PATH_USD_ADDRESS, recipient_balance_slot), "balances[recipient]"),
                    ((PATH_USD_ADDRESS, sender_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT), "userRewardInfo[sender].rewardRecipient"),
                    ((PATH_USD_ADDRESS, sender_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN), "userRewardInfo[sender].rewardPerToken"),
                    ((PATH_USD_ADDRESS, sender_reward_info_slot + user_reward_info_slots::REWARD_BALANCE), "userRewardInfo[sender].rewardBalance"),
                    ((PATH_USD_ADDRESS, recipient_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT), "userRewardInfo[recipient].rewardRecipient"),
                    ((PATH_USD_ADDRESS, recipient_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN), "userRewardInfo[recipient].rewardPerToken"),
                    ((PATH_USD_ADDRESS, recipient_reward_info_slot + user_reward_info_slots::REWARD_BALANCE), "userRewardInfo[recipient].rewardBalance"),
                    ((fee_token, tip20_slots::CURRENCY), "currency"),
                    ((fee_token, tip20_slots::TRANSFER_POLICY_ID), "transferPolicyId"),
                    ((fee_token, tip20_slots::PAUSED), "paused"),
                    ((fee_token, tip20_slots::GLOBAL_REWARD_PER_TOKEN), "globalRewardPerToken"),
                    ((fee_token, sender_fee_token_balance_slot), "balances[sender]"),
                    ((fee_token, fee_manager_fee_token_balance_slot), "balances[FeeManager]"),
                    ((fee_token, sender_fee_token_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT), "userRewardInfo[sender].rewardRecipient"),
                    ((fee_token, sender_fee_token_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN), "userRewardInfo[sender].rewardPerToken"),
                    ((fee_token, sender_fee_token_reward_info_slot + user_reward_info_slots::REWARD_BALANCE), "userRewardInfo[sender].rewardBalance"),
                    ((TIP_FEE_MANAGER_ADDRESS, validator_token_slot), "validatorTokens[beneficiary]"),
                    ((TIP_FEE_MANAGER_ADDRESS, user_token_slot), "userTokens[sender]"),
                    ((TIP_FEE_MANAGER_ADDRESS, collected_fees_slot), "collectedFees[beneficiary][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pool_slot), "pools[FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pending_pool_reservation_slot), "pendingFeeSwapReservation[FEE_TOKEN][PATH_USD]"),
                    ((TIP403_REGISTRY_ADDRESS, receive_policy_config_slot), "receivePolicies[recipient]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(PATH_USD_ADDRESS)), "storageCredits[PATH_USD]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(fee_token)), "storageCredits[FEE_TOKEN]"),
                    ((NONCE_PRECOMPILE_ADDRESS, sender_nonce_key_slot), "nonces[sender][42]"),
                ]),
            };

            let run_transfer = |evm: &mut TempoEvm<CacheDB<EmptyDB>>,
                                caller: Address,
                                to: Address,
                                amount: U256,
                                nonce: u64,
                                nonce_key: U256|
             -> eyre::Result<Vec<String>> {
                let calldata: Bytes = ITIP20::transferCall { to, amount }.abi_encode().into();
                let tx = TempoTxEnv {
                    inner: TxEnv {
                        caller,
                        gas_price: u128::from(gas_price),
                        gas_limit,
                        kind: TxKind::Call(PATH_USD_ADDRESS),
                        data: calldata.clone(),
                        nonce,
                        ..Default::default()
                    },
                    fee_token: Some(fee_token),
                    tempo_tx_env: (!nonce_key.is_zero()).then(|| {
                        Box::new(TempoBatchCallEnv {
                            aa_calls: vec![Call {
                                to: TxKind::Call(PATH_USD_ADDRESS),
                                value: U256::ZERO,
                                input: calldata.clone(),
                            }],
                            nonce_key,
                            ..Default::default()
                        })
                    }),
                    ..Default::default()
                };
                let result = evm.transact_raw(tx)?;
                assert_matches!(
                    result.result,
                    ExecutionResult::Success { .. },
                    "hardfork: {hardfork:?}"
                );
                let actions = evm
                    .take_actions()
                    .expect("storage action recording should be enabled");
                assert_storage_actions_reconstruct_evm_state(&actions, &result.state, *hardfork);
                evm.db_mut().commit(result.state);
                Ok(snapshot_storage_actions(&actions, &labels))
            };

            let snapshot = IndexMap::from([
                // TIP-20 transfer with sequential protocol nonce and a fee token that requires going through feeAMM to pay fees.
                (
                    "first_transfer",
                    run_transfer(&mut evm, sender, recipient, transfer_amount, 0, U256::ZERO)
                        .unwrap(),
                ),
                // Same as first transfer. Now we expect a lot of storage actions to change from SLOAD+SSTORE into SINC/SDEC, because recipient
                // and fee balances are no longer zero.
                (
                    "second_transfer",
                    run_transfer(&mut evm, sender, recipient, transfer_amount, 1, U256::ZERO)
                        .unwrap(),
                ),
                // TIP-20 transfer with a 2D nonce and a fee token that requires going through feeAMM to pay fees.
                (
                    "2d_nonce_transfer",
                    run_transfer(&mut evm, sender, recipient, transfer_amount, 0, nonce_key)
                        .unwrap(),
                ),
                // Clear sender balance, minting a storage credit for PATH_USD.
                ("clear_balance", {
                    let sender_balance = evm
                        .db()
                        .storage_ref(PATH_USD_ADDRESS, sender_balance_slot)
                        .expect("sender balance slot should be available");
                    run_transfer(&mut evm, sender, recipient, sender_balance, 2, U256::ZERO)
                        .unwrap()
                }),
                // Recreate sender balance, consuming the PATH_USD storage credit through an SSTORE.
                (
                    "recreate_balance",
                    run_transfer(&mut evm, recipient, sender, transfer_amount, 0, U256::ZERO)
                        .unwrap(),
                ),
            ]);
            insta::assert_yaml_snapshot!(
                format!("tip20_full_evm_storage_actions_{}", hardfork.name()),
                snapshot
            );
        }
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
