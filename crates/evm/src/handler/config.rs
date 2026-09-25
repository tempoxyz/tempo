//! EVM2 transaction handler plumbing.

use crate::{
    FeePaymentError, ProtocolFeeContext, ProtocolFeeManager, SYSTEM_CALL_GAS_LIMIT, TempoEvmTx,
    TempoFeeManager, TempoInvalidTransaction, TempoStateAccess, TempoTxEnv,
};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, TxKind, U256};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, TxResult,
    ethereum::{LazyTxEip7702, PreparedTx, eip1559, eip2930, eip7702, finalize_gas, legacy},
    evm::{DynDatabase, SystemTx, precompile::PrecompileProvider},
    handler::{GasSettlement, TxHandlerHooks},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest, handler},
    version::GasId,
};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_contracts::precompiles::TIPFeeAMMError;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    account_keychain::AccountKeychain,
    error::TempoPrecompileError,
    storage::{FromWord, StorageActions, StorageCtx},
    storage_credits::{NonCreditableSlots, TransientState},
    tip20::TIP20Error,
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{TempoAddressExt, transaction::calc_gas_balance_spending};
pub use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

/// EVM2 type family used by Tempo execution.
#[derive(Clone, Copy, Debug)]
pub struct TempoEvmTypes;

impl EvmTypesHost for TempoEvmTypes {
    type ConfigSelector = TempoConfigSelector;
    type SpecId = TempoHardfork;
    type Tx = TempoTxEnv;
    type EvmExt = TempoEvmExt;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = TempoTxResultExt;
    type BlockEnvExt = TempoBlockExt;
    type Host<'a> = Evm<'a, Self>;
}

/// Tempo opcode configuration over an inherited Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct TempoConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<TempoEvmTypes> for TempoConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Tempo base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<TempoEvmTypes> =
        &tempo_opcode_config::<BASE_SPEC_ID>();
}

/// Returns Tempo's opcode configuration over an inherited Ethereum specification.
pub const fn tempo_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<TempoEvmTypes> {
    let mut config = OpcodeConfig::base::<TempoConfig<BASE_SPEC_ID>>();
    config.set_instruction::<crate::instructions::millis_timestamp>(0x4f, 0);
    config.set_instruction::<crate::instructions::sstore>(evm2::interpreter::op::SSTORE, 0);
    config
}

/// Selects Tempo's opcode table for the active Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct TempoConfigSelector;

impl EvmConfigSelector<TempoEvmTypes> for TempoConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = TempoConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: TempoHardfork) -> ExecutionConfig<TempoEvmTypes> {
        let spec_id = SpecId::from(spec_id);
        evm2::spec_to_generic!(spec_id, |SPEC_ID| ExecutionConfig::for_config::<
            TempoConfig<SPEC_ID>,
        >())
    }
}

/// Tempo-specific transaction result fields produced by EVM2 settlement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempoTxResultExt {
    /// Fee credited to the block beneficiary after fee-AMM settlement.
    pub validator_fee: U256,
}

/// Tempo-specific state owned by an EVM2 instance.
#[derive(Clone, Debug)]
pub struct TempoEvmExt {
    /// Protocol fee implementation used by transaction hooks.
    pub fee_manager: Arc<dyn ProtocolFeeManager>,
    /// Recorder for protocol storage accesses.
    pub actions: StorageActions,
    /// Transaction-local slots whose clears must not create storage credits.
    pub non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Whether transaction-pool execution may skip the lower validity bound.
    pub skip_valid_after_check: bool,
    /// Whether transaction-pool execution may skip the fee AMM liquidity check.
    pub skip_liquidity_check: bool,
    /// Fee token resolved for the most recently handled transaction.
    pub resolved_fee_token: Option<Address>,
    /// Access-key expiry resolved for the most recently handled transaction.
    pub key_expiry: Option<u64>,
}

impl Default for TempoEvmExt {
    fn default() -> Self {
        Self {
            fee_manager: Arc::new(TempoFeeManager::new()),
            actions: StorageActions::disabled(),
            non_creditable_slots: Rc::new(RefCell::new(NonCreditableSlots::empty())),
            skip_valid_after_check: false,
            skip_liquidity_check: false,
            resolved_fee_token: None,
            key_expiry: None,
        }
    }
}

impl TempoEvmExt {
    /// Replaces the protocol fee implementation used by transaction hooks.
    pub fn with_fee_manager(mut self, fee_manager: impl ProtocolFeeManager + 'static) -> Self {
        self.fee_manager = Arc::new(fee_manager);
        self
    }
}

impl tempo_precompiles::storage::evm::EvmStorageExt for TempoEvmExt {
    fn storage_actions(&self) -> StorageActions {
        self.actions.clone()
    }

    fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
        self.non_creditable_slots.clone()
    }
}

/// Builds an EVM2 execution config for Tempo's ERC-20 fee model.
pub fn tempo_execution_config(
    tempo_spec: TempoHardfork,
    chain_id: u64,
) -> ExecutionConfig<TempoEvmTypes> {
    let spec_id = SpecId::from(tempo_spec);
    let mut version = tempo_chainspec::gas_params::version(spec_id, tempo_spec, false);
    version.chain_id = chain_id;
    version.features.remove(EvmFeatures::BALANCE_CHECK);
    version.features.remove(EvmFeatures::BALANCE_TOP_UP);
    ExecutionConfig::for_spec_and_version(tempo_spec, version)
}

/// Builds a Tempo-configured EVM2 instance.
pub fn build_tempo_evm<'a>(
    tempo_spec: TempoHardfork,
    chain_id: u64,
    block: TempoBlockEnv,
    database: impl DynDatabase + 'a,
    precompiles: impl PrecompileProvider<TempoEvmTypes> + 'a,
    ext: TempoEvmExt,
) -> Evm<'a, TempoEvmTypes> {
    let spec_id = SpecId::from(tempo_spec);
    let execution_config = tempo_execution_config(tempo_spec, chain_id);
    Evm::new_with_execution_config_and_ext(
        execution_config,
        tempo_spec,
        block,
        tempo_tx_registry(spec_id),
        database,
        precompiles,
        ext,
    )
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TempoFeeContext {
    pub(super) fee_payer: alloy_primitives::Address,
    pub(super) fee_token: alloy_primitives::Address,
    pub(super) collected: U256,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TempoHandlerHooks;

impl TxHandlerHooks<TempoEvmTypes> for TempoHandlerHooks {
    fn adjust_intrinsic_gas(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        intrinsic: &mut u64,
        initial_state_gas: &mut u64,
        _floor_gas: &mut u64,
    ) -> HandlerResult<()> {
        if !host.config_spec_id().is_t1() {
            return Ok(());
        }

        let (nonce, zero_nonce_authorizations) = match envelope.evm_tx() {
            TempoEvmTx::Legacy { transaction, .. } => (transaction.nonce, 0),
            TempoEvmTx::Eip2930(transaction) => (transaction.nonce, 0),
            TempoEvmTx::Eip1559(transaction) => (transaction.nonce, 0),
            TempoEvmTx::Eip7702(transaction) => (
                transaction.nonce,
                transaction
                    .authorization_list
                    .iter()
                    .filter(|authorization| authorization.nonce() == 0)
                    .count() as u64,
            ),
            TempoEvmTx::AA(_) => return Ok(()),
        };
        let new_accounts = zero_nonce_authorizations.saturating_add(u64::from(nonce == 0));
        *intrinsic = intrinsic.saturating_add(new_accounts.saturating_mul(u64::from(
            host.version().gas_params.get(GasId::NewAccountCost),
        )));
        *initial_state_gas = initial_state_gas.saturating_add(
            new_accounts.saturating_mul(host.version().gas_params.new_account_state_gas()),
        );
        Ok(())
    }

    fn before_execution(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        _caller: Address,
        _upfront_fee: U256,
    ) -> HandlerResult<()> {
        let context = Self::resolve_fee_context(host, envelope)?;
        if host.feature(EvmFeatures::FEE_CHARGE) {
            Self::collect_fee(host, context, None)?;
        }
        Ok(())
    }

    fn settle_transaction(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        mut gas: GasSettlement<TempoEvmTypes>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        settle_storage_credit_refunds(host, &mut gas.result)?;
        let gas_price = u128::try_from(gas.gas_price)
            .map_err(|_| HandlerError::Fatal("effective gas price does not fit u128".into()))?;
        let gas_limit = gas.gas_limit;
        let mut result = finalize_gas(host, gas)?;
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            return Ok(result);
        }
        let actual_spending = calc_gas_balance_spending(result.tx_gas_used(), gas_price);
        let collected = calc_gas_balance_spending(gas_limit, gas_price);
        let refund = collected
            .checked_sub(actual_spending)
            .ok_or_else(|| HandlerError::Fatal("actual fee exceeds upfront fee".into()))?;

        if collected.is_zero() && !actual_spending.is_zero() {
            return Ok(result);
        }

        let fee_payer = envelope
            .fee_payer()
            .map_err(|_| invalid(TempoInvalidTransaction::InvalidFeePayerSignature))?;
        let fee_token = host.ext().resolved_fee_token.ok_or_else(|| {
            HandlerError::Fatal("fee token was not resolved before settlement".into())
        })?;
        let fee_manager = host.ext().fee_manager.clone();
        let beneficiary = host.block().beneficiary;
        let validator_fee = if actual_spending.is_zero() && refund.is_zero() {
            U256::ZERO
        } else {
            fee_manager.collect_fee_post_tx(
                ProtocolFeeContext { host },
                fee_payer,
                actual_spending,
                refund,
                fee_token,
                beneficiary,
            )?
        };
        result.ext.validator_fee = validator_fee;
        Ok(result)
    }
}

impl TempoHandlerHooks {
    pub(super) fn resolve_fee_context(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
    ) -> HandlerResult<TempoFeeContext> {
        host.ext_mut().resolved_fee_token = None;
        host.ext_mut().key_expiry = None;
        host.ext().non_creditable_slots.borrow_mut().clear();
        let fee_payer = envelope
            .fee_payer()
            .map_err(|_| invalid(TempoInvalidTransaction::InvalidFeePayerSignature))?;
        let base_fee = u64::try_from(host.block().basefee)
            .map_err(|_| HandlerError::Fatal("block base fee does not fit u64".into()))?;
        let gas_price = envelope.evm_tx().effective_gas_price(Some(base_fee));
        let collected = if host.feature(EvmFeatures::FEE_CHARGE) {
            calc_gas_balance_spending(envelope.evm_tx().gas_limit(), gas_price)
        } else {
            U256::ZERO
        };
        let max_fee =
            calc_gas_balance_spending(envelope.evm_tx().gas_limit(), envelope.max_fee_per_gas());
        let spec = host.config_spec_id();

        StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            AccountKeychain::new().set_tx_origin(envelope.evm_tx().signer())?;
            TIP20ChannelReserve::new()
                .set_channel_open_context_hash(envelope.channel_open_context_hash())
        })?;

        let fee_manager = host.ext().fee_manager.clone();
        let fee_token = fee_manager.get_fee_token(host, envelope, fee_payer, spec)?;
        host.ext_mut().resolved_fee_token = Some(fee_token);
        if !fee_token.is_tip20() {
            return Err(invalid(TempoInvalidTransaction::FeeTokenNotTip20 {
                address: fee_token,
            }));
        }
        if !max_fee.is_zero() {
            fee_manager.validate_fee_token(host, fee_token, spec)?;
        }
        let balance =
            host.get_token_balance(fee_token, fee_payer, spec, StorageActions::disabled())?;
        if balance < max_fee {
            return Err(invalid(FeePaymentError::InsufficientFeeTokenBalance {
                fee: max_fee,
                balance,
            }));
        }

        Ok(TempoFeeContext {
            fee_payer,
            fee_token,
            collected,
        })
    }

    pub(super) fn collect_fee(
        host: &mut Evm<'_, TempoEvmTypes>,
        context: TempoFeeContext,
        key_id: Option<Address>,
    ) -> HandlerResult<()> {
        let checkpoint = host.state().checkpoint();
        let features = host.version().features;
        let beneficiary = host.block().beneficiary;
        let skip_liquidity_check = host.ext().skip_liquidity_check;
        let fee_manager = host.ext().fee_manager.clone();
        if !context.collected.is_zero()
            && let Err(error) = fee_manager.collect_fee_pre_tx(
                ProtocolFeeContext { host },
                context.fee_payer,
                context.fee_token,
                context.collected,
                beneficiary,
                skip_liquidity_check,
            )
        {
            host.state_mut().rollback(checkpoint, features);
            return Err(match error {
                TempoPrecompileError::TIPFeeAMMError(TIPFeeAMMError::InsufficientLiquidity(_)) => {
                    let validator_token = fee_manager.get_validator_token(host, beneficiary).ok();
                    invalid(FeePaymentError::InsufficientAmmLiquidity {
                        user_token: validator_token.map(|_| context.fee_token),
                        validator_token,
                        fee: context.collected,
                    })
                }
                TempoPrecompileError::TIP20(TIP20Error::InsufficientBalance(error)) => {
                    invalid(FeePaymentError::InsufficientFeeTokenBalance {
                        fee: context.collected,
                        balance: error.available,
                    })
                }
                TempoPrecompileError::TIP20(TIP20Error::ContractPaused(_)) => {
                    invalid(TempoInvalidTransaction::FeeTokenPaused {
                        address: context.fee_token,
                    })
                }
                TempoPrecompileError::Database(error) => HandlerError::Database(error),
                TempoPrecompileError::Fatal(error) => HandlerError::Fatal(error.into()),
                error => invalid(FeePaymentError::Other(error.to_string())),
            });
        }

        if host.config_spec_id().is_t7() && !context.collected.is_zero() {
            host.ext().non_creditable_slots.borrow_mut().initialize(
                context.fee_payer,
                context.fee_token,
                key_id,
            );
        }

        Ok(())
    }
}

pub(super) fn invalid(error: impl Into<TempoInvalidTransaction>) -> HandlerError {
    HandlerError::external(error.into())
}

fn settle_storage_credit_refunds(
    host: &mut Evm<'_, TempoEvmTypes>,
    result: &mut evm2::interpreter::MessageResult<TempoEvmTypes>,
) -> HandlerResult<()> {
    if !host.config_spec_id().is_t7() || !result.is_success() {
        return Ok(());
    }

    let slots = host
        .state_mut()
        .take_transient_storage(&STORAGE_CREDITS_ADDRESS);
    if slots.is_empty() {
        return Ok(());
    }

    let settled = StorageCtx::enter_evm_without_tip1060_accounting(host, || {
        let mut storage = StorageCtx;
        let mut settled = 0i64;
        for (key, word) in slots {
            let state = TransientState::try_from(word)?;
            if state.pending_refunds == 0 {
                continue;
            }

            let old_word = storage.sload(STORAGE_CREDITS_ADDRESS, key)?;
            let mut balance = u64::from_word(old_word)?;
            let credits = state.pending_refunds.min(balance);
            if credits == 0 {
                continue;
            }

            balance -= credits;
            settled = settled.saturating_add(credits as i64);
            let new_word = U256::from(balance);
            debug_assert_ne!(new_word, old_word);
            storage.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
        }
        Ok::<_, TempoPrecompileError>(settled)
    })?;
    result
        .gas
        .record_refund(settled.saturating_mul(STORAGE_CREDIT_VALUE as i64));
    Ok(())
}

enum PreparedLegacy {
    System,
    Transaction(PreparedTx),
}

fn prepare_legacy(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxLegacy>,
) -> HandlerResult<PreparedLegacy> {
    validate_no_native_value(request.envelope)?;
    if request.envelope.evm_tx().is_system_tx() {
        if !matches!(request.tx.to, TxKind::Call(_)) {
            return Err(invalid(
                TempoInvalidTransaction::SystemTransactionMustBeCall,
            ));
        }
        return Ok(PreparedLegacy::System);
    }
    legacy::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
        .map(PreparedLegacy::Transaction)
}

fn execute_legacy(
    request: TxRequest<'_, '_, TempoEvmTypes, TxLegacy>,
    prepared: PreparedLegacy,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    match prepared {
        PreparedLegacy::Transaction(prepared) => {
            legacy::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>(request, prepared)
        }
        PreparedLegacy::System => {
            let tx = request.tx.inner();
            let TxKind::Call(to) = tx.to else {
                unreachable!("system transaction kind was validated during preparation");
            };
            let mut result = request.host.execute_system_call(
                SystemTx::new(to, tx.input.clone())
                    .with_caller(request.tx.signer())
                    .with_gas_limit(SYSTEM_CALL_GAS_LIMIT),
            )?;
            if !result.status {
                return Err(invalid(TempoInvalidTransaction::SystemTransactionFailed(
                    format!("{:?}", result.stop),
                )));
            }
            result.total_gas_spent = 0;
            result.state_gas_spent = 0;
            result.refunded = 0;
            Ok(result)
        }
    }
}

fn prepare_eip2930(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxEip2930>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip2930::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn prepare_eip1559(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxEip1559>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip1559::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn prepare_eip7702(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, LazyTxEip7702>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip7702::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn validate_no_native_value(envelope: &TempoTxEnv) -> HandlerResult<()> {
    if envelope.transaction().value().is_zero() {
        Ok(())
    } else {
        Err(invalid(TempoInvalidTransaction::ValueTransferNotAllowed))
    }
}

/// Returns the Tempo transaction registry for `spec_id`.
pub fn tempo_tx_registry(spec_id: SpecId) -> TxRegistry<TempoEvmTypes, TxResult<TempoEvmTypes>> {
    let mut registry = TxRegistry::new().with_handler(
        0,
        TempoTxEnv::as_legacy,
        handler(prepare_legacy, execute_legacy),
    );

    if spec_id.enables(SpecId::BERLIN) {
        registry.register(
            1,
            TempoTxEnv::as_eip2930,
            handler(
                prepare_eip2930,
                eip2930::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::LONDON) {
        registry.register(
            2,
            TempoTxEnv::as_eip1559,
            handler(
                prepare_eip1559,
                eip1559::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TempoTxEnv::as_eip7702,
            handler(
                prepare_eip7702,
                eip7702::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    registry.register(
        0x76,
        TempoTxEnv::as_aa,
        handler(super::prepare_aa, super::execute_aa),
    );

    registry
}
