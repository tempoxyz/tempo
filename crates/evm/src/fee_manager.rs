use crate::{
    TempoEvmTypes, TempoStateAccess, TempoTx, TempoTxEnv, common::is_tip20_fee_inference_call,
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use core::fmt::Debug;
use evm2::{Evm, registry::HandlerResult};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::Result as TempoResult,
    storage::{StorageAction, StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Error,
};
use tempo_primitives::transaction::calc_gas_balance_spending;

/// EVM state needed to install storage for an internal protocol fee hook.
pub struct ProtocolFeeContext<'evm, 'db> {
    /// Active Tempo EVM.
    pub host: &'evm mut Evm<'db, TempoEvmTypes>,
}

impl ProtocolFeeContext<'_, '_> {
    /// Installs Tempo's ordinary protocol storage context and executes `f`.
    ///
    /// TIP-1060 accounting is disabled because protocol fee storage is charged externally.
    pub fn enter<R>(self, f: impl FnOnce() -> R) -> R {
        StorageCtx::enter_evm_without_tip1060_accounting(self.host, f)
    }
}

/// Fee token resolved for a transaction, and the step that chose it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedFeeToken {
    /// Chosen by the transaction or a fee-manager rule; fee-token balances cannot change it.
    Selected(Address),
    /// Chosen from the ordered fallback list because no earlier rule applied.
    ///
    /// Another fallback token may pay once the fee payer's fallback-token balances change.
    Fallback(Address),
}

impl ResolvedFeeToken {
    /// Returns the token that pays the fee.
    pub const fn address(self) -> Address {
        match self {
            Self::Selected(token) | Self::Fallback(token) => token,
        }
    }

    /// Returns whether the token came from the ordered fallback list.
    pub const fn is_fallback(self) -> bool {
        matches!(self, Self::Fallback(_))
    }
}

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

/// Internal protocol fee hooks, separate from the public FeeManager precompile.
pub trait ProtocolFeeManager: Debug + Send + Sync {
    /// Resolves the fee token that should pay for `tx`.
    /// `max_fee` is in TIP-20 base units.
    fn get_fee_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        max_fee: U256,
        spec: TempoHardfork,
    ) -> TempoResult<ResolvedFeeToken> {
        let actions = host.ext().actions.clone();
        resolve_fee_token(host, tx, fee_payer, max_fee, spec, actions)
    }

    /// Validates whether a TIP-20 can be used to pay fees.
    ///
    /// The handler checks the TIP-20 prefix first. Implementations define which tokens are valid.
    /// `host` is mutable because validation reads can warm accounts and storage, but
    /// implementations must not stage state changes here.
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

    /// Validates `fee_token` when `max_fee` is non-zero and loads `fee_payer_balance_slot`.
    fn validate_and_load_fee_balance(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_token: Address,
        fee_payer_balance_slot: U256,
        max_fee: U256,
        spec: TempoHardfork,
    ) -> HandlerResult<U256> {
        if !max_fee.is_zero() {
            self.validate_fee_token(host, fee_token, spec)?;
        }
        Ok(host.sload(fee_token, fee_payer_balance_slot)?)
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

    /// Installs protocol storage and collects the maximum possible fee before execution.
    ///
    /// Implementations must preserve the handler's externally charged storage and checkpoint
    /// semantics. [`ProtocolFeeContext::enter`] installs Tempo's ordinary storage provider;
    /// downstream EVMs may install a custom provider instead.
    #[allow(clippy::too_many_arguments)]
    fn collect_fee_pre_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address>;

    /// Installs protocol storage and settles the final fee after execution.
    ///
    /// Implementations must preserve the handler's externally charged storage semantics.
    /// [`ProtocolFeeContext::enter`] installs Tempo's ordinary storage provider;
    /// downstream EVMs may install a custom provider instead.
    #[allow(clippy::too_many_arguments)]
    fn collect_fee_post_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256>;
}

/// FeeManager for the default TempoEVM configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct TempoFeeManager;

impl TempoFeeManager {
    /// Creates the default Tempo protocol fee manager.
    pub const fn new() -> Self {
        Self
    }
}

impl ProtocolFeeManager for TempoFeeManager {
    fn validate_and_load_fee_balance(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_token: Address,
        fee_payer_balance_slot: U256,
        max_fee: U256,
        spec: TempoHardfork,
    ) -> HandlerResult<U256> {
        if max_fee.is_zero() {
            return Ok(host.sload(fee_token, fee_payer_balance_slot)?);
        }
        let (raw_currency, balance) = {
            let mut account = host.state_mut().account(&fee_token)?;
            account.warm();
            let raw_currency = {
                let mut slot = account
                    .storage()
                    .into_slot(tempo_precompiles::tip20::slots::CURRENCY)?;
                slot.warm();
                slot.current()
            };
            if !crate::common::is_usd_currency_word(raw_currency) {
                drop(account);
                self.validate_fee_token(host, fee_token, spec)?;
                return Ok(host.sload(fee_token, fee_payer_balance_slot)?);
            }
            let balance = {
                let mut slot = account.storage().into_slot(fee_payer_balance_slot)?;
                slot.warm();
                slot.current()
            };
            (raw_currency, balance)
        };
        host.ext()
            .actions
            .record(tempo_precompiles::storage::StorageAction::Sload(
                fee_token,
                tempo_precompiles::tip20::slots::CURRENCY,
                raw_currency,
            ));
        Ok(balance)
    }

    fn collect_fee_pre_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address> {
        let fee_payer_balance_slot = ctx.host.ext().resolved_fee_balance_slot;
        let validator_token_slot = ctx
            .host
            .ext_mut()
            .fee_slot_cache
            .validator_token_slot(beneficiary);
        let spec = ctx.host.config_spec_id();
        let mut gas = evm2::interpreter::GasTracker::new(u64::MAX);
        let mut storage =
            tempo_precompiles::storage::evm::EvmPrecompileStorageProvider::new_without_tip1060_accounting(
                ctx.host,
                &mut gas,
                spec,
            );
        let (token, used_two_hop) = TipFeeManager::collect_fee_pre_tx_on_provider(
            &mut storage,
            fee_payer,
            fee_payer_balance_slot,
            user_token,
            max_amount,
            validator_token_slot,
            skip_liquidity_check,
        )?;
        ctx.host.ext_mut().has_two_hop_intermediate = used_two_hop;
        Ok(token)
    }

    fn collect_fee_post_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        let fee_payer_balance_slot = ctx.host.ext().resolved_fee_balance_slot;
        let has_two_hop_intermediate = ctx.host.ext().has_two_hop_intermediate;
        let validator_token_slot = ctx
            .host
            .ext_mut()
            .fee_slot_cache
            .validator_token_slot(beneficiary);
        let spec = ctx.host.config_spec_id();
        let mut cache = core::mem::take(&mut ctx.host.ext_mut().fee_slot_cache);
        let mut gas = evm2::interpreter::GasTracker::new(u64::MAX);
        let res = {
            let mut storage =
                tempo_precompiles::storage::evm::EvmPrecompileStorageProvider::new_without_tip1060_accounting(
                    ctx.host,
                    &mut gas,
                    spec,
                );
            TipFeeManager::collect_fee_post_tx_on_provider(
                &mut storage,
                fee_payer,
                fee_payer_balance_slot,
                actual_spending,
                refund_amount,
                fee_token,
                validator_token_slot,
                |validator_token| cache.collected_fees_slot(beneficiary, validator_token),
                has_two_hop_intermediate,
            )
        };
        ctx.host.ext_mut().fee_slot_cache = cache;
        res
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
        resolve_fee_token(
            state,
            tx,
            fee_payer,
            calc_gas_balance_spending(tx.gas_limit(), tx.max_fee_per_gas()),
            spec,
            actions,
        )
        .map(ResolvedFeeToken::address)
    }
}

/// Returns the token a transaction without a fee token or preference pays with if it is a valid
/// fee token: the called TIP-20, or a Stablecoin DEX swap's `tokenIn`. `None` means no inference.
pub fn fee_token_inference_target(
    tx: &impl TempoTx,
    fee_payer: Address,
    spec: TempoHardfork,
) -> Option<Address> {
    let mut calls = tx.calls();
    let (kind, input) = calls.next()?;
    let to = *kind.to()?;

    // If calling swapExactAmountOut() or swapExactAmountIn() on the Stablecoin DEX,
    // use the input token as the fee token (the token that will be pulled from the user).
    // For AA transactions, this only applies if there's exactly one call.
    if to == STABLECOIN_DEX_ADDRESS {
        if tx.is_aa() && calls.next().is_some() {
            return None;
        }
        if let Ok(call) = IStablecoinDEX::swapExactAmountInCall::abi_decode(input) {
            return Some(call.tokenIn);
        }
        if let Ok(call) = IStablecoinDEX::swapExactAmountOutCall::abi_decode(input) {
            return Some(call.tokenIn);
        }
        return None;
    }

    // Infer from the called TIP-20 for AA txs only when fee_payer == tx.origin.
    if tx.is_aa() && fee_payer != tx.caller() {
        return None;
    }
    // Otherwise, restricted to TIP-20 calls that move the called token.
    tx.calls()
        .all(|(kind, input)| kind.to() == Some(&to) && is_tip20_fee_inference_call(spec, input))
        .then_some(to)
}

fn resolve_fee_token<S, M>(
    state: &mut S,
    tx: &TempoTxEnv,
    fee_payer: Address,
    max_fee: U256,
    spec: TempoHardfork,
    actions: StorageActions,
) -> TempoResult<ResolvedFeeToken>
where
    S: TempoStateAccess<M>,
{
    // If there is a fee token explicitly set on the tx type, use that.
    if let Some(fee_token) = tx.fee_token() {
        return Ok(ResolvedFeeToken::Selected(fee_token));
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
        return Ok(ResolvedFeeToken::Selected(call.token));
    }

    // Check stored user token preference
    let user_token = state.with_read_only_storage_ctx(spec, actions.clone(), || {
        // ensure TIP_FEE_MANAGER_ADDRESS is loaded
        TipFeeManager::get_user_token_direct(fee_payer)
    })?;

    if !user_token.is_zero() {
        return Ok(ResolvedFeeToken::Selected(user_token));
    }

    if let Some(token) = fee_token_inference_target(tx, fee_payer, spec)
        && state.is_valid_fee_token(spec, token, actions.clone())?
    {
        return Ok(ResolvedFeeToken::Selected(token));
    }

    if !spec.is_t13() || max_fee.is_zero() {
        return Ok(ResolvedFeeToken::Fallback(DEFAULT_FEE_TOKEN));
    }

    let candidates = spec.fallback_fee_tokens();
    let mut richest_token = DEFAULT_FEE_TOKEN;
    let mut highest_balance = U256::ZERO;
    let balance_slot = actions.is_enabled().then(|| {
        tempo_precompiles::storage::StorageKey::mapping_slot(
            &fee_payer,
            tempo_precompiles::tip20::slots::BALANCES,
        )
    });
    // Replay depends on affordability, not the exact balance.
    for &token in candidates {
        let balance = actions
            .unrecorded(|| state.get_token_balance(token, fee_payer, spec, actions.clone()))?;
        let sufficient = balance >= max_fee;
        if let Some(balance_slot) = balance_slot {
            actions.record(StorageAction::FeeTokenBalanceCheck(
                token,
                balance_slot,
                balance,
                max_fee,
                sufficient,
            ));
        }
        if sufficient {
            return Ok(ResolvedFeeToken::Fallback(token));
        }
        if balance > highest_balance {
            richest_token = token;
            highest_balance = balance;
        }
    }

    Err(TIP20Error::insufficient_balance(highest_balance, max_fee, richest_token).into())
}
