use crate::{
    TempoBlockEnv, TempoInvalidTransaction, TempoStateAccess, TempoTx, TempoTxEnv,
    common::is_tip20_fee_inference_call,
};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use core::fmt::Debug;
use revm::{
    Database,
    context::{CfgEnv, Journal, result::EVMError},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::Result as TempoResult,
    storage::{Handler, StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
};

/// EVM state needed to install storage for an internal protocol fee hook.
pub struct ProtocolFeeContext<'a, DB: Database> {
    /// Active transaction journal.
    pub journal: &'a mut Journal<DB>,
    /// Active block environment.
    pub block_env: &'a TempoBlockEnv,
    /// Active EVM configuration.
    pub cfg: &'a CfgEnv<TempoHardfork>,
    /// Active transaction environment.
    pub tx_env: &'a TempoTxEnv,
    /// Storage-action recorder shared with transaction execution.
    pub actions: StorageActions,
}

impl<DB: alloy_evm::Database> ProtocolFeeContext<'_, DB> {
    /// Installs Tempo's ordinary protocol storage context and executes `f`.
    ///
    /// TIP-1060 accounting is disabled because protocol fee storage is charged externally.
    pub fn enter<R>(self, f: impl FnOnce() -> R) -> R {
        StorageCtx::enter_evm_without_tip1060_accounting(
            self.journal,
            self.block_env,
            self.cfg,
            self.tx_env,
            self.actions,
            f,
        )
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
pub trait ProtocolFeeManager<DB: Database>: Debug {
    /// Resolves the fee token that should pay for `tx`.
    fn get_fee_token(
        &self,
        journal: &mut Journal<DB>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address> {
        TempoFeeManager::new().resolve_fee_token(journal, tx, fee_payer, spec, actions)
    }

    /// Validates whether a TIP-20 can be used to pay fees.
    ///
    /// The handler checks the TIP-20 prefix first. Implementations define which tokens are valid.
    /// `journal` is mutable because validation reads can warm accounts and storage, but
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
        journal: &mut Journal<DB>,
        fee_token: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
        journal.ensure_tip20_usd(spec, fee_token, actions)
    }

    /// Resolves the validator token used to receive protocol fees.
    fn get_validator_token(
        &self,
        journal: &mut Journal<DB>,
        beneficiary: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address> {
        journal.with_read_only_storage_ctx(spec, actions, || {
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
        ctx: ProtocolFeeContext<'_, DB>,
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
        ctx: ProtocolFeeContext<'_, DB>,
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

impl<DB: alloy_evm::Database> ProtocolFeeManager<DB> for TempoFeeManager {
    fn collect_fee_pre_tx(
        &self,
        ctx: ProtocolFeeContext<'_, DB>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address> {
        ctx.enter(|| {
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
        ctx: ProtocolFeeContext<'_, DB>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        ctx.enter(|| {
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
                        }
                    ;

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
