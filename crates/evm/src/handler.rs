//! EVM2 transaction handlers.

mod aa;

use crate::{FeePaymentError, TempoInvalidTransaction, TempoStateAccess, TempoTxEnv};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, U256};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, TxResult,
    ethereum::{LazyTxEip7702, default_settle_gas, eip1559, eip2930, eip7702, legacy},
    evm::{DynDatabase, precompile::PrecompileProvider},
    handler::{SettlementRequest, TxHandlerHooks},
    interpreter::InstrStop,
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest},
};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
#[cfg(test)]
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_contracts::precompiles::TIPFeeAMMError;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{FromWord, StorageActions, StorageCtx},
    storage_credits::{NonCreditableSlots, TransientState},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Error,
    tip20_channel_reserve::TIP20ChannelReserve,
};
#[cfg(test)]
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, tip20::TIP20Token};
use tempo_primitives::{TempoAddressExt, transaction::calc_gas_balance_spending};
pub use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

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
        host.get_fee_token(tx, fee_payer, spec, actions)
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
    version.features.remove(EvmFeatures::FEE_CHARGE);
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
struct TempoFeeContext {
    fee_payer: alloy_primitives::Address,
    fee_token: alloy_primitives::Address,
    collected: U256,
}

#[derive(Clone, Copy, Debug, Default)]
struct TempoHandlerHooks;

fn invalid(error: impl Into<TempoInvalidTransaction>) -> HandlerError {
    HandlerError::external(error.into())
}

fn map_protocol_result<R>(result: TempoResult<R>) -> HandlerResult<R> {
    match result {
        Ok(value) => Ok(value),
        Err(TempoPrecompileError::EvmError(code)) => Err(HandlerError::Fatal(code)),
        Err(error) => Err(HandlerError::Custom(error.to_string())),
    }
}

/// Ensures the given TIP20 token uses USD currency.
///
/// IMPORTANT: Caller must ensure `fee_token` has a valid TIP20 prefix.
fn ensure_fee_token_usd(
    host: &mut Evm<'_, TempoEvmTypes>,
    fee_token: Address,
) -> HandlerResult<()> {
    let spec = host.config_spec_id();
    let actions = host.ext().actions.clone();
    host.ensure_tip20_usd(spec, fee_token, actions)
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
    type Context = TempoFeeContext;

    fn before_execution(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
    ) -> HandlerResult<Self::Context> {
        let context = Self::prepare_fee(host, envelope)?;
        Self::collect_fee(host, context, None)?;
        Ok(context)
    }

    fn settle_transaction(
        request: SettlementRequest<'_, '_, TempoEvmTypes, Self::Context>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        let SettlementRequest {
            host,
            envelope: _,
            context,
            mut gas,
        } = request;
        settle_storage_credit_refunds(host, &mut gas.result)?;
        let gas_price = u128::try_from(gas.gas_price)
            .map_err(|_| HandlerError::Custom("effective gas price does not fit u128".into()))?;
        let gas_limit = gas.gas_limit;
        let mut result = default_settle_gas(host, gas)?;
        let actual_spending = calc_gas_balance_spending(result.tx_gas_used(), gas_price);
        let refund = calc_gas_balance_spending(gas_limit, gas_price)
            .checked_sub(actual_spending)
            .ok_or_else(|| HandlerError::Custom("actual fee exceeds upfront fee".into()))?;

        if context.collected.is_zero() && !actual_spending.is_zero() {
            return Ok(result);
        }

        let fee_manager = host.ext().fee_manager.clone();
        let beneficiary = host.block().beneficiary;
        let validator_fee = if actual_spending.is_zero() && refund.is_zero() {
            U256::ZERO
        } else {
            map_protocol_result(fee_manager.collect_fee_post_tx(
                host,
                context.fee_payer,
                actual_spending,
                refund,
                context.fee_token,
                beneficiary,
            ))?
        };
        result.ext.validator_fee = validator_fee;
        Ok(result)
    }
}

impl TempoHandlerHooks {
    fn prepare_fee(
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
        let collected = calc_gas_balance_spending(envelope.evm_tx().gas_limit(), gas_price);
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
            ensure_fee_token_usd(host, fee_token)?;
        }

        Ok(TempoFeeContext {
            fee_payer,
            fee_token,
            collected,
        })
    }

    fn collect_fee(
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
    request: TxRequest<'_, '_, TempoEvmTypes, Recovered<TxLegacy>>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    if request.envelope.evm_tx().is_system_tx() {
        return Ok(TxResult {
            status: true,
            stop: InstrStop::Stop,
            ..TxResult::default()
        });
    }
    legacy::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip2930(
    request: TxRequest<'_, '_, TempoEvmTypes, Recovered<TxEip2930>>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    eip2930::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip1559(
    request: TxRequest<'_, '_, TempoEvmTypes, Recovered<TxEip1559>>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    validate_no_native_value(request.envelope)?;
    eip1559::handle_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn handle_eip7702(
    request: TxRequest<'_, '_, TempoEvmTypes, Recovered<LazyTxEip7702>>,
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
    registry.register(0x76, TempoTxEnv::as_aa, aa::handle);

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::{Bytes, Signature, TxKind};
    use evm2::{
        evm::{AccountInfo, InMemoryDB, precompile::NoPrecompiles},
        version::GasId,
    };
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        storage::{ContractStorage, Handler},
        test_util::TIP20Setup,
    };
    use tempo_primitives::{
        AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
        transaction::tt_signature::PrimitiveSignature,
    };

    const SIGNER: Address = Address::new([0x11; 20]);

    fn legacy_env(to: TxKind, input: Bytes) -> TempoTxEnv {
        Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(1),
                    gas_limit: 21_000,
                    to,
                    input,
                    ..Default::default()
                },
                Signature::test_signature(),
            )),
            SIGNER,
        )
        .into()
    }

    fn aa_env(transaction: TempoTransaction) -> TempoTxEnv {
        aa_env_for(SIGNER, transaction)
    }

    fn aa_env_for(signer: Address, transaction: TempoTransaction) -> TempoTxEnv {
        Recovered::new_unchecked(
            TempoTxEnvelope::AA(AASigned::new_unhashed(
                transaction,
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            )),
            signer,
        )
        .into()
    }

    fn fee_tx_env(
        caller: Address,
        fee_token: Address,
        gas_limit: u64,
        gas_price: u128,
    ) -> TempoTxEnv {
        aa_env_for(
            caller,
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(fee_token),
                max_priority_fee_per_gas: gas_price,
                max_fee_per_gas: gas_price,
                gas_limit,
                calls: Vec::new(),
                ..Default::default()
            },
        )
    }

    fn storage_evm(spec: TempoHardfork) -> crate::TempoEvm<'static> {
        build_tempo_evm(
            spec,
            1,
            TempoBlockEnv::default(),
            InMemoryDB::default(),
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        )
    }

    fn insert_storage(evm: &mut crate::TempoEvm<'_>, address: Address, slot: U256, value: U256) {
        evm.overlay_db_mut()
            .insert_account_info(&address, AccountInfo::default());
        evm.overlay_db_mut()
            .insert_account_storage(&address, &slot, &value);
    }

    fn resolve(
        evm: &mut crate::TempoEvm<'_>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
    ) -> TempoResult<Address> {
        evm.get_fee_token(tx, fee_payer, spec, StorageActions::disabled())
    }

    fn validate_against_state_and_deduct_caller(
        evm: &mut crate::TempoEvm<'_>,
        tx: &TempoTxEnv,
    ) -> HandlerResult<()> {
        let context = TempoHandlerHooks::prepare_fee(evm, tx)?;
        TempoHandlerHooks::collect_fee(evm, context, None)
    }

    #[derive(Debug)]
    struct ValidatorTokenLookupFailsFeeManager;

    impl ProtocolFeeManager for ValidatorTokenLookupFailsFeeManager {
        fn get_fee_token(
            &self,
            _host: &mut Evm<'_, TempoEvmTypes>,
            tx: &TempoTxEnv,
            _fee_payer: Address,
            _spec: TempoHardfork,
        ) -> tempo_precompiles::error::Result<Address> {
            Ok(tx.evm_tx().fee_token().unwrap_or(DEFAULT_FEE_TOKEN))
        }

        fn get_validator_token(
            &self,
            _host: &mut Evm<'_, TempoEvmTypes>,
            _beneficiary: Address,
        ) -> tempo_precompiles::error::Result<Address> {
            Err(TempoPrecompileError::Fatal(
                "injected validator token lookup failure".to_string(),
            ))
        }

        fn collect_fee_pre_tx(
            &self,
            _host: &mut Evm<'_, TempoEvmTypes>,
            _fee_payer: Address,
            _user_token: Address,
            _max_amount: U256,
            _beneficiary: Address,
            _skip_liquidity_check: bool,
        ) -> tempo_precompiles::error::Result<Address> {
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::InsufficientLiquidity(
                    tempo_contracts::precompiles::ITIPFeeAMM::InsufficientLiquidity {},
                ),
            ))
        }

        fn collect_fee_post_tx(
            &self,
            _host: &mut Evm<'_, TempoEvmTypes>,
            _fee_payer: Address,
            _actual_spending: U256,
            _refund_amount: U256,
            _fee_token: Address,
            _beneficiary: Address,
        ) -> tempo_precompiles::error::Result<U256> {
            Ok(U256::ZERO)
        }
    }

    #[test]
    fn registers_transaction_types_by_fork() {
        let frontier = tempo_tx_registry(SpecId::FRONTIER);
        assert!(frontier.contains(0));
        assert!(!frontier.contains(1));
        assert!(!frontier.contains(2));
        assert!(!frontier.contains(4));
        assert!(frontier.contains(0x76));

        let prague = tempo_tx_registry(SpecId::PRAGUE);
        assert!(prague.contains(0));
        assert!(prague.contains(1));
        assert!(prague.contains(2));
        assert!(prague.contains(4));
        assert!(prague.contains(0x76));
    }

    #[test]
    fn builds_evm_with_matching_tempo_spec_and_fee_rules() {
        let evm = build_tempo_evm(
            TempoHardfork::T7,
            4242,
            TempoBlockEnv::default(),
            InMemoryDB::default(),
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        );

        assert_eq!(evm.version().chain_id, 4242);
        assert_eq!(evm.config_spec_id(), TempoHardfork::T7);
        assert!(!evm.version().features.contains(EvmFeatures::BALANCE_CHECK));
        assert!(!evm.version().features.contains(EvmFeatures::BALANCE_TOP_UP));
        assert!(!evm.version().features.contains(EvmFeatures::FEE_CHARGE));
        assert_eq!(evm.version().gas_params[GasId::MaxRefundQuotient], 1);
    }

    #[test]
    fn test_invalid_fee_token_rejected() {
        // Test that an invalid fee token (non-TIP20 address) is rejected with a typed error
        // rather than panicking. This validates the check in validate_against_state_and_deduct_caller that
        // guards against invalid tokens reaching get_token_balance.
        let invalid_token = Address::random(); // Random address won't have TIP20 prefix
        assert!(
            !invalid_token.is_tip20(),
            "Test requires a non-TIP20 address"
        );

        let mut test = storage_evm(TempoHardfork::default());
        let tx = fee_tx_env(SIGNER, invalid_token, 100_000, 1_000_000_000);

        let result = validate_against_state_and_deduct_caller(&mut test, &tx);

        assert!(
            matches!(
                result,
                Err(ref error)
                    if matches!(
                        error.external_ref::<TempoInvalidTransaction>(),
                        Some(TempoInvalidTransaction::FeeTokenNotTip20 { address })
                            if *address == invalid_token
                    )
            ),
            "Should reject non-TIP20 fee token with FeeTokenNotTip20 error"
        );
    }

    #[test]
    fn test_non_usd_fee_token_rejected() {
        let admin = Address::random();
        let mut test = storage_evm(TempoHardfork::default());

        let fee_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
            TIP20Setup::create("Euro", "EUR", admin)
                .currency("EUR")
                .apply()
                .map(|token| token.address())
        })
        .expect("EUR token setup succeeds");

        let tx = fee_tx_env(SIGNER, fee_token, 100_000, 1_000_000_000);

        let result = validate_against_state_and_deduct_caller(&mut test, &tx);

        assert!(
            matches!(
                result,
                Err(ref error)
                    if matches!(
                        error.external_ref::<TempoInvalidTransaction>(),
                        Some(TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                            address,
                            currency,
                        }) if *address == fee_token && currency == "EUR"
                    )
            ),
            "Should reject non-USD fee token with FeeTokenNotUsdCurrency error"
        );
    }

    #[test]
    fn test_paused_fee_token_rejected() {
        let admin = Address::random();
        let fee_payer = Address::random();
        let fee = U256::from(100_000_000_000_000_u64);
        let mut test = storage_evm(TempoHardfork::default());

        let fee_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
            let mut token = TIP20Setup::create("Paused USD", "PUSD", admin)
                .with_issuer(admin)
                .with_role(admin, *tempo_precompiles::tip20::PAUSE_ROLE)
                .with_mint(fee_payer, fee)
                .apply()?;
            token.pause(admin, tempo_precompiles::tip20::ITIP20::pauseCall {})?;
            Ok::<_, TempoPrecompileError>(token.address())
        })
        .expect("paused USD token setup succeeds");

        let tx = fee_tx_env(fee_payer, fee_token, 100_000, 1_000_000_000);

        let result = validate_against_state_and_deduct_caller(&mut test, &tx);

        assert!(
            matches!(
                result,
                Err(ref error)
                    if matches!(
                        error.external_ref::<TempoInvalidTransaction>(),
                        Some(TempoInvalidTransaction::FeeTokenPaused { address })
                            if *address == fee_token
                    )
            ),
            "Should reject paused fee token with FeeTokenPaused error"
        );
    }

    #[test]
    fn test_collect_fee_pre_tx_insufficient_liquidity_reports_pair_from_handler() -> eyre::Result<()>
    {
        use tempo_contracts::precompiles::IFeeManager;

        let admin = Address::random();
        let fee_payer = Address::random();
        let validator = Address::random();
        let gas_limit = 1_000;
        let gas_price = 1_000_000_000_000_u128;
        let fee = calc_gas_balance_spending(gas_limit, gas_price);

        let mut test = storage_evm(TempoHardfork::T5);
        let mut block = *test.block();
        block.beneficiary = validator;
        test.set_block(block);

        let (user_token, validator_token) =
            StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
                let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                    .with_issuer(admin)
                    .with_mint(fee_payer, fee)
                    .with_approval(fee_payer, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                    .apply()?;

                let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                    .with_issuer(admin)
                    .apply()?;

                TipFeeManager::new().set_validator_token(
                    validator,
                    IFeeManager::setValidatorTokenCall {
                        token: validator_token.address(),
                    },
                    Address::random(),
                )?;

                Ok::<_, TempoPrecompileError>((user_token.address(), validator_token.address()))
            })?;

        let tx = fee_tx_env(fee_payer, user_token, gas_limit, gas_price);

        let result = validate_against_state_and_deduct_caller(&mut test, &tx);

        assert!(
            matches!(
                result,
                Err(ref error)
                    if matches!(
                        error.external_ref::<TempoInvalidTransaction>(),
                        Some(TempoInvalidTransaction::CollectFeePreTx(err))
                            if *err == FeePaymentError::InsufficientAmmLiquidity {
                                user_token: Some(user_token),
                                validator_token: Some(validator_token),
                                fee,
                            }
                    )
            ),
            "expected pair-aware insufficient liquidity error, got: {result:?}"
        );

        Ok(())
    }

    #[test]
    fn test_collect_fee_pre_tx_insufficient_liquidity_falls_back_when_pair_lookup_fails()
    -> eyre::Result<()> {
        let admin = Address::random();
        let fee_payer = Address::random();
        let gas_limit = 1_000;
        let gas_price = 1_000_000_000_000_u128;
        let fee = calc_gas_balance_spending(gas_limit, gas_price);

        let mut test = storage_evm(TempoHardfork::T5);
        test.ext_mut().fee_manager = Arc::new(ValidatorTokenLookupFailsFeeManager);

        let user_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
            TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(fee_payer, fee)
                .apply()
                .map(|token| token.address())
        })?;

        let tx = fee_tx_env(fee_payer, user_token, gas_limit, gas_price);

        let result = validate_against_state_and_deduct_caller(&mut test, &tx);

        assert!(
            matches!(
                result,
                Err(ref error)
                    if matches!(
                        error.external_ref::<TempoInvalidTransaction>(),
                        Some(TempoInvalidTransaction::CollectFeePreTx(err))
                            if *err == FeePaymentError::InsufficientAmmLiquidity {
                                user_token: None,
                                validator_token: None,
                                fee,
                            }
                    )
            ),
            "expected generic insufficient liquidity error when pair lookup fails, got: {result:?}"
        );

        Ok(())
    }

    #[test]
    fn test_get_token_balance() {
        let mut evm = storage_evm(TempoHardfork::Genesis);
        // Use PATH_USD_ADDRESS which has the TIP20 prefix
        let token = PATH_USD_ADDRESS;
        let account = Address::random();
        let expected_balance = U256::random();

        // Set up initial balance
        let balance_slot = TIP20Token::from_address(token).unwrap().balances[account].slot();
        insert_storage(&mut evm, token, balance_slot, expected_balance);

        let balance = StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Token::from_address(token).unwrap().balances[account].read()
        })
        .unwrap();
        assert_eq!(balance, expected_balance);
    }

    #[test]
    fn test_get_fee_token() {
        let mut evm = storage_evm(TempoHardfork::Genesis);
        let user = Address::random();
        let validator = Address::random();
        let user_fee_token = Address::random();
        let validator_fee_token = Address::random();
        let tx_fee_token = Address::random();

        // Set validator token
        let validator_slot = TipFeeManager::new().validator_tokens[validator].slot();
        insert_storage(
            &mut evm,
            TIP_FEE_MANAGER_ADDRESS,
            validator_slot,
            U256::from_be_bytes(validator_fee_token.into_word().0),
        );

        {
            let tx = legacy_env(TxKind::Call(Address::ZERO), Bytes::new());
            let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
            assert_eq!(DEFAULT_FEE_TOKEN, fee_token);
        }

        // Set user token
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TipFeeManager::new().user_tokens[user].write(user_fee_token)
        })
        .unwrap();

        {
            let tx = legacy_env(TxKind::Call(Address::ZERO), Bytes::new());
            let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
            assert_eq!(user_fee_token, fee_token);
        }

        // Set tx fee token
        let tx = aa_env(TempoTransaction {
            fee_token: Some(tx_fee_token),
            ..Default::default()
        });
        let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
        assert_eq!(tx_fee_token, fee_token);
    }

    #[test]
    fn test_tempo_evm_applies_gas_params() {
        let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
        assert_eq!(
            version.gas_params[GasId::TxEip7702PerEmptyAccountCost],
            12_500
        );
    }

    #[test]
    fn test_tempo_evm_respects_gas_cap() {
        let mut version =
            tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
        version.tx_gas_limit_cap = TempoHardfork::T1.tx_gas_limit_cap().unwrap();
        let evm = Evm::new_with_execution_config_and_ext(
            ExecutionConfig::for_spec_and_version(TempoHardfork::T1, version),
            TempoHardfork::T1,
            TempoBlockEnv::default(),
            tempo_tx_registry(SpecId::OSAKA),
            InMemoryDB::default(),
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        );
        assert_eq!(
            evm.version().tx_gas_limit_cap,
            TempoHardfork::T1.tx_gas_limit_cap().unwrap()
        );
    }

    #[test]
    fn test_tempo_evm_gas_params_differ_t0_vs_t1() {
        let t0 = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T0, false);
        let t1 = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
        assert_eq!(t0.gas_params[GasId::TxEip7702PerEmptyAccountCost], 25_000);
        assert_eq!(t1.gas_params[GasId::TxEip7702PerEmptyAccountCost], 12_500);
    }

    #[test]
    fn test_tempo_evm_t1_state_creation_costs() {
        let params = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false)
            .gas_params;
        assert_eq!(params[GasId::SstoreSetWithoutLoadCost], 250_000);
        assert_eq!(params[GasId::TxCreateCost], 500_000);
        assert_eq!(params[GasId::Create], 500_000);
        assert_eq!(params[GasId::NewAccountCost], 250_000);
        assert_eq!(params[GasId::CodeDepositCost], 1_000);
    }
}
