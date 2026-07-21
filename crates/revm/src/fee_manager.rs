use crate::{TempoBlockEnv, TempoStateAccess, TempoTxEnv};
use alloy_primitives::{Address, U256};
use core::fmt::Debug;
use revm::{
    Database,
    context::{CfgEnv, Journal},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::Result as TempoResult,
    storage::{StorageActions, StorageCtx},
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
        journal.get_fee_token(tx, fee_payer, spec, actions)
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
