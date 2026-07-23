//! EVM2 transaction handler plumbing.

use crate::{
    FeePaymentError, TempoEvmTx, TempoInvalidTransaction, TempoStateAccess, TempoTx, TempoTxEnv,
    common::is_tip20_fee_inference_call,
};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, TxKind, U256};
use alloy_sol_types::SolCall;
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, TxResult,
    ethereum::{LazyTxEip7702, eip1559, eip2930, eip7702, finalize_gas, legacy},
    evm::{DynDatabase, SystemTx, precompile::PrecompileProvider},
    handler::{GasSettlement, TxHandlerHooks, UpfrontFee},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest},
    version::GasId,
};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS, TIPFeeAMMError,
};
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{FromWord, Handler, StorageActions, StorageCtx},
    storage_credits::{NonCreditableSlots, TransientState},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Error,
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{TempoAddressExt, transaction::calc_gas_balance_spending};
pub use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

/// Resolves a transaction's fee token for state consumers outside the EVM handler.
pub trait FeeTokenResolver {
    /// Resolves the fee token that should pay for `tx`.
    fn resolve_fee_token<S, M>(
        &self,
        state: &mut S,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
    where
        S: TempoStateAccess<M>;
}

/// Internal protocol fee policy used by Tempo transaction handlers.
pub trait ProtocolFeeManager: core::fmt::Debug + Send + Sync {
    /// Resolves the fee token that should pay for `tx`.
    fn get_fee_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
    ) -> TempoResult<Address> {
        let actions = host.ext().actions.clone();
        TempoFeeManager.resolve_fee_token(host, tx, fee_payer, spec, actions)
    }

    /// Validates whether a TIP-20 can be used to pay fees.
    ///
    /// The handler checks the TIP-20 prefix first. Implementations define which tokens are valid.
    /// `host` is mutable because validation reads can warm accounts and storage, but
    /// implementations must not stage state changes here.
    ///
    /// This hook runs before nonce and replay state are consumed. Do not return
    /// `CollectFeePreTx`, `FeeTokenPaused`, or `LackOfFundForMaxFee`; subblock handling treats
    /// those as post-nonce fee collection failures.
    ///
    /// Implementations charging non-zero fees in non-USD tokens must normalize them to the fee
    /// unit used by admission, ordering, charging, and settlement.
    fn validate_fee_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_token: Address,
        spec: TempoHardfork,
    ) -> HandlerResult<()> {
        let actions = host.ext().actions.clone();
        host.ensure_tip20_usd(spec, fee_token, actions)
    }

    /// Resolves the validator token used to receive protocol fees.
    fn get_validator_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        beneficiary: Address,
    ) -> TempoResult<Address> {
        let spec = host.config_spec_id();
        let actions = host.ext().actions.clone();
        host.with_read_only_storage_ctx(spec, actions, || {
            TipFeeManager::new().get_validator_token(beneficiary)
        })
    }

    /// Collects the maximum possible fee before transaction execution.
    fn collect_fee_pre_tx(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address>;

    /// Settles the final fee after transaction execution.
    fn collect_fee_post_tx(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256>;
}

/// Default Tempo protocol fee policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct TempoFeeManager;

impl TempoFeeManager {
    /// Creates the default Tempo protocol fee policy.
    pub const fn new() -> Self {
        Self
    }
}

impl FeeTokenResolver for TempoFeeManager {
    fn resolve_fee_token<S, M>(
        &self,
        state: &mut S,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
    where
        S: TempoStateAccess<M>,
    {
        // If there is a fee token explicitly set on the tx type, use that.
        if let Some(fee_token) = tx.fee_token() {
            return Ok(fee_token);
        }

        // If the fee payer is also the msg.sender and the transaction is calling FeeManager to set a
        // new preference, the newly set preference should be used immediately instead of the
        // previously stored one
        if !tx.is_aa()
            && fee_payer == tx.caller()
            && let Some((kind, input)) = tx.calls().next()
            && kind.to() == Some(&TIP_FEE_MANAGER_ADDRESS)
            && let Ok(call) = IFeeManager::setUserTokenCall::abi_decode(input)
        {
            return Ok(call.token);
        }

        // Check stored user token preference
        let user_token = state.with_read_only_storage_ctx(spec, actions.clone(), || {
            // ensure TIP_FEE_MANAGER_ADDRESS is loaded
            TipFeeManager::new().user_tokens[fee_payer].read()
        })?;

        if !user_token.is_zero() {
            return Ok(user_token);
        }

        // Check if the fee can be inferred from the TIP20 token being called
        if let Some(to) = tx.calls().next().and_then(|(kind, _)| kind.to().copied()) {
            let can_infer_tip20 =
                // AA txs only when fee_payer == tx.origin.
                if tx.is_aa() && fee_payer != tx.caller() {
                    false
                }
                // Otherwise, restricted to TIP-20 calls that move the called token.
                else {
                    tx.calls().all(|(kind, input)| {
                        kind.to() == Some(&to) && is_tip20_fee_inference_call(spec, input)
                    })
                };

            if can_infer_tip20 && state.is_valid_fee_token(spec, to, actions.clone())? {
                return Ok(to);
            }
        }

        // If calling swapExactAmountOut() or swapExactAmountIn() on the Stablecoin DEX,
        // use the input token as the fee token (the token that will be pulled from the user).
        // For AA transactions, this only applies if there's exactly one call.
        let mut calls = tx.calls();
        if let Some((kind, input)) = calls.next()
            && kind.to() == Some(&STABLECOIN_DEX_ADDRESS)
            && (!tx.is_aa() || calls.next().is_none())
        {
            if let Ok(call) = IStablecoinDEX::swapExactAmountInCall::abi_decode(input)
                && state.is_valid_fee_token(spec, call.tokenIn, actions.clone())?
            {
                return Ok(call.tokenIn);
            } else if let Ok(call) = IStablecoinDEX::swapExactAmountOutCall::abi_decode(input)
                && state.is_valid_fee_token(spec, call.tokenIn, actions)?
            {
                return Ok(call.tokenIn);
            }
        }

        // If no fee token is found, default to the first deployed TIP20
        Ok(DEFAULT_FEE_TOKEN)
    }
}

impl ProtocolFeeManager for TempoFeeManager {
    fn collect_fee_pre_tx(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address> {
        StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            TipFeeManager::new().collect_fee_pre_tx(
                fee_payer,
                user_token,
                max_amount,
                beneficiary,
                skip_liquidity_check,
            )
        })
    }

    fn collect_fee_post_tx(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            TipFeeManager::new().collect_fee_post_tx(
                fee_payer,
                actual_spending,
                refund_amount,
                fee_token,
                beneficiary,
            )
        })
    }
}

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

const fn tempo_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<TempoEvmTypes> {
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

pub(super) fn invalid(error: impl Into<TempoInvalidTransaction>) -> HandlerError {
    HandlerError::external(error.into())
}

fn map_protocol_result<R>(result: TempoResult<R>) -> HandlerResult<R> {
    match result {
        Ok(value) => Ok(value),
        Err(TempoPrecompileError::EvmError(code)) => Err(HandlerError::Fatal(code)),
        Err(error) => Err(HandlerError::Custom(error.to_string())),
    }
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

    let settled = map_protocol_result(StorageCtx::enter_evm_without_tip1060_accounting(
        host,
        || {
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
                storage.sstore(STORAGE_CREDITS_ADDRESS, key, U256::from(balance))?;
            }
            Ok(settled)
        },
    ))?;
    result
        .gas
        .record_refund(settled.saturating_mul(STORAGE_CREDIT_VALUE as i64));
    Ok(())
}

impl TxHandlerHooks<TempoEvmTypes> for TempoHandlerHooks {
    fn adjust_intrinsic_gas(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        intrinsic: &mut u64,
        initial_state_gas: &mut u64,
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
        _fee: UpfrontFee,
        disable_fee_charge: bool,
    ) -> HandlerResult<()> {
        let context = Self::resolve_fee_context(host, envelope)?;
        if !disable_fee_charge {
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
            .map_err(|_| HandlerError::Custom("effective gas price does not fit u128".into()))?;
        let gas_limit = gas.gas_limit;
        let mut result = finalize_gas(host, gas)?;
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            return Ok(result);
        }
        let actual_spending = calc_gas_balance_spending(result.tx_gas_used(), gas_price);
        let collected = calc_gas_balance_spending(gas_limit, gas_price);
        let refund = collected
            .checked_sub(actual_spending)
            .ok_or_else(|| HandlerError::Custom("actual fee exceeds upfront fee".into()))?;

        if collected.is_zero() && !actual_spending.is_zero() {
            return Ok(result);
        }

        let fee_payer = envelope
            .fee_payer()
            .map_err(|_| invalid(TempoInvalidTransaction::InvalidFeePayerSignature))?;
        let fee_token = host.ext().resolved_fee_token.ok_or_else(|| {
            HandlerError::Custom("fee token was not resolved before settlement".into())
        })?;
        let fee_manager = host.ext().fee_manager.clone();
        let beneficiary = host.block().beneficiary;
        let validator_fee = if actual_spending.is_zero() && refund.is_zero() {
            U256::ZERO
        } else {
            map_protocol_result(fee_manager.collect_fee_post_tx(
                host,
                fee_payer,
                actual_spending,
                refund,
                fee_token,
                beneficiary,
            ))?
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
            .map_err(|_| HandlerError::Custom("block base fee does not fit u64".into()))?;
        let gas_price = envelope.evm_tx().effective_gas_price(Some(base_fee));
        let collected = if host.feature(EvmFeatures::FEE_CHARGE) {
            calc_gas_balance_spending(envelope.evm_tx().gas_limit(), gas_price)
        } else {
            U256::ZERO
        };
        let spec = host.config_spec_id();

        map_protocol_result(StorageCtx::enter_evm_without_tip1060_accounting(
            host,
            || {
                AccountKeychain::new().set_tx_origin(envelope.evm_tx().signer())?;
                TIP20ChannelReserve::new()
                    .set_channel_open_context_hash(envelope.channel_open_context_hash())
            },
        ))?;

        let fee_manager = host.ext().fee_manager.clone();
        let fee_token =
            map_protocol_result(fee_manager.get_fee_token(host, envelope, fee_payer, spec))?;
        host.ext_mut().resolved_fee_token = Some(fee_token);
        if !fee_token.is_tip20() {
            return Err(invalid(TempoInvalidTransaction::FeeTokenNotTip20 {
                address: fee_token,
            }));
        }
        if !collected.is_zero()
            || envelope
                .evm_tx()
                .as_aa()
                .is_some_and(|tx| tx.inner().tx().subblock_proposer().is_some())
        {
            fee_manager.validate_fee_token(host, fee_token, spec)?;
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
                host,
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
                TempoPrecompileError::EvmError(code) => HandlerError::Fatal(code),
                TempoPrecompileError::Fatal(error) => HandlerError::Custom(error),
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

fn handle_legacy(
    request: TxRequest<'_, '_, TempoEvmTypes, TxLegacy>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    if request.envelope.evm_tx().is_system_tx() {
        let tx = request.tx.inner();
        let TxKind::Call(to) = tx.to else {
            return Err(invalid(
                TempoInvalidTransaction::SystemTransactionMustBeCall,
            ));
        };
        let mut result = request.host.execute_system_call(
            SystemTx::new(to, tx.input.clone()).with_caller(request.tx.signer()),
        )?;
        if !result.status {
            return Err(invalid(TempoInvalidTransaction::SystemTransactionFailed(
                format!("{:?}", result.stop),
            )));
        }
        result.total_gas_spent = 0;
        result.state_gas_spent = 0;
        result.refunded = 0;
        return Ok(result);
    }
    legacy::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip2930(
    request: TxRequest<'_, '_, TempoEvmTypes, TxEip2930>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    eip2930::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip1559(
    request: TxRequest<'_, '_, TempoEvmTypes, TxEip1559>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    eip1559::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip7702(
    request: TxRequest<'_, '_, TempoEvmTypes, LazyTxEip7702>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    eip7702::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
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
    let mut registry = TxRegistry::new().with_handler(0, TempoTxEnv::as_legacy, handle_legacy);

    if spec_id.enables(SpecId::BERLIN) {
        registry.register(1, TempoTxEnv::as_eip2930, handle_eip2930);
    }
    if spec_id.enables(SpecId::LONDON) {
        registry.register(2, TempoTxEnv::as_eip1559, handle_eip1559);
    }
    if spec_id.enables(SpecId::PRAGUE) {
        registry.register(4, TempoTxEnv::as_eip7702, handle_eip7702);
    }
    registry.register(0x76, TempoTxEnv::as_aa, super::handle);

    registry
}
