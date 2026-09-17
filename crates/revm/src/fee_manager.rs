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
    DEFAULT_FEE_TOKEN, FALLBACK_FEE_TOKENS, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{Handler, StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
};
use tempo_primitives::transaction::calc_gas_balance_spending;

/// Failure while choosing a fee token, before nonce consumption or fee collection.
#[derive(Debug, thiserror::Error)]
pub enum FeeTokenResolutionError {
    /// A state read failed; do not advance to another token.
    #[error(transparent)]
    State(#[from] TempoPrecompileError),
    /// No fallback candidate covers the maximum fee.
    #[error("insufficient funds in fallback fee tokens: required {required}")]
    InsufficientFunds { required: U256 },
}

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
    ) -> Result<Address, FeeTokenResolutionError>
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
    ) -> Result<Address, FeeTokenResolutionError> {
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
    ) -> Result<Address, FeeTokenResolutionError>
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
                && state.is_valid_fee_token(spec, call.tokenIn, actions.clone())?
            {
                return Ok(call.tokenIn);
            }
        }

        if !spec.is_t12() {
            return Ok(DEFAULT_FEE_TOKEN);
        }

        select_fallback_fee_token(state, tx, fee_payer, spec, actions, FALLBACK_FEE_TOKENS)
    }
}

/// Only the final fallback is balance-dependent. Keep selection reads in the action trace so
/// replay also depends on candidates skipped for insufficient balance.
fn select_fallback_fee_token<S, M>(
    state: &mut S,
    tx: &TempoTxEnv,
    fee_payer: Address,
    spec: TempoHardfork,
    actions: StorageActions,
    candidates: &[Address],
) -> Result<Address, FeeTokenResolutionError>
where
    S: TempoStateAccess<M>,
{
    use revm::context::Transaction;
    let max_fee = calc_gas_balance_spending(tx.gas_limit(), tx.max_fee_per_gas());
    if max_fee.is_zero() {
        return Ok(DEFAULT_FEE_TOKEN);
    }

    for &token in candidates {
        if state.get_token_balance(token, fee_payer, spec, actions.clone())? >= max_fee {
            return Ok(token);
        }
    }

    // No token was selected. The handler maps this to a pre-nonce validation error, distinct
    // from fee-collection failures that subblock execution may commit.
    Err(FeeTokenResolutionError::InsufficientFunds { required: max_fee })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, address};
    use revm::{
        context::TxEnv,
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
    };
    use tempo_precompiles::{storage::StorageAction, tip20::TIP20Token};

    const TOKENS: [Address; 3] = [
        DEFAULT_FEE_TOKEN,
        address!("20c0000000000000000000000000000000000001"),
        address!("20c0000000000000000000000000000000000002"),
    ];
    const PAYER: Address = Address::repeat_byte(0x11);

    fn tx(gas_limit: u64, gas_price: u128) -> TempoTxEnv {
        TempoTxEnv {
            inner: TxEnv {
                caller: PAYER,
                kind: TxKind::Call(Address::repeat_byte(0x22)),
                gas_limit,
                gas_price,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn funded(balances: [u64; 3]) -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for (token, balance) in TOKENS.into_iter().zip(balances) {
            db.insert_account_storage(
                token,
                TIP20Token::from_address_unchecked(token).balances[PAYER].slot(),
                U256::from(balance),
            )
            .unwrap();
        }
        db
    }

    #[test]
    fn fallback_order_rounding_and_read_dependencies() {
        // 1001 * 10^9 attodollars rounds up to TWO microdollars.
        for (balances, expected, reads) in [
            ([2, 10, 10], Some(0), 1),
            ([1, 2, 10], Some(1), 2),
            ([1, 1, 2], Some(2), 3),
            ([1, 1, 1], None, 3), // combined funds must not qualify
            ([0, 0, 0], None, 3),
        ] {
            let mut db = funded(balances);
            let actions = StorageActions::enabled();
            let result = select_fallback_fee_token(
                &mut db,
                &tx(1001, 1_000_000_000),
                PAYER,
                TempoHardfork::T12,
                actions.clone(),
                &TOKENS,
            );
            if let Some(index) = expected {
                assert_eq!(result.unwrap(), TOKENS[index]);
            } else {
                assert!(
                    matches!(result, Err(FeeTokenResolutionError::InsufficientFunds { required }) if required == U256::from(2))
                );
            }
            let recorded = actions.take().unwrap();
            assert_eq!(recorded.len(), reads);
            for (index, action) in recorded.iter().enumerate() {
                assert!(matches!(action, StorageAction::Sload(token, _, balance)
                    if *token == TOKENS[index] && *balance == U256::from(balances[index])));
            }
        }
    }

    #[test]
    fn fallback_zero_fee_reads_no_balances() {
        let actions = StorageActions::enabled();
        assert_eq!(
            select_fallback_fee_token(
                &mut EmptyDB::default(),
                &tx(1001, 0),
                PAYER,
                TempoHardfork::T12,
                actions.clone(),
                &TOKENS
            )
            .unwrap(),
            DEFAULT_FEE_TOKEN
        );
        assert!(actions.take().unwrap().is_empty());
    }

    #[test]
    fn fallback_uses_recovered_payer_and_current_balances() {
        let mut db = funded([1, 2, 3]);
        let mut tx = tx(1001, 1_000_000_000);
        tx.inner.caller = Address::repeat_byte(0x33);
        let select = |db: &mut CacheDB<EmptyDB>| {
            select_fallback_fee_token(
                db,
                &tx,
                PAYER,
                TempoHardfork::T12,
                StorageActions::disabled(),
                &TOKENS,
            )
            .unwrap()
        };
        assert_eq!(select(&mut db), TOKENS[1]);
        db.insert_account_storage(
            TOKENS[0],
            TIP20Token::from_address_unchecked(TOKENS[0]).balances[PAYER].slot(),
            U256::from(2),
        )
        .unwrap();
        assert_eq!(select(&mut db), TOKENS[0]);
    }

    #[test]
    fn fallback_preserves_fork_boundary_and_explicit_precedence() {
        let mut db = funded([0, 10, 10]);
        let mut tx = tx(1001, 1_000_000_000);
        assert_eq!(
            TempoFeeManager
                .resolve_fee_token(
                    &mut db,
                    &tx,
                    PAYER,
                    TempoHardfork::T11,
                    StorageActions::disabled()
                )
                .unwrap(),
            DEFAULT_FEE_TOKEN
        );
        assert!(matches!(
            TempoFeeManager.resolve_fee_token(
                &mut db,
                &tx,
                PAYER,
                TempoHardfork::T12,
                StorageActions::disabled()
            ),
            Err(FeeTokenResolutionError::InsufficientFunds { .. })
        ));
        tx.fee_token = Some(TOKENS[0]);
        assert_eq!(
            TempoFeeManager
                .resolve_fee_token(
                    &mut db,
                    &tx,
                    PAYER,
                    TempoHardfork::T12,
                    StorageActions::disabled()
                )
                .unwrap(),
            TOKENS[0]
        );
    }

    #[test]
    fn fallback_maximum_fee_does_not_overflow() {
        let result = select_fallback_fee_token(
            &mut funded([u64::MAX; 3]),
            &tx(u64::MAX, u128::MAX),
            PAYER,
            TempoHardfork::T12,
            StorageActions::disabled(),
            &TOKENS,
        );
        // Independently written decimal result for ceil((2^64-1)*(2^128-1)/10^12).
        let expected =
            U256::from_str_radix("6277101735386680763495507056286727952620534093", 10).unwrap();
        assert!(
            matches!(result, Err(FeeTokenResolutionError::InsufficientFunds { required }) if required == expected)
        );
    }

    struct FailedRead {
        reads: usize,
    }

    impl TempoStateAccess for FailedRead {
        type Error = &'static str;
        fn basic(&mut self, _: Address) -> Result<AccountInfo, Self::Error> {
            Ok(AccountInfo::default())
        }
        fn sload(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
            self.reads += 1;
            if self.reads == 2 {
                Err("candidate read failed")
            } else {
                Ok(U256::ZERO)
            }
        }
    }

    #[test]
    fn fallback_storage_failure_does_not_try_later_candidates() {
        let mut state = FailedRead { reads: 0 };
        let result = select_fallback_fee_token(
            &mut state,
            &tx(1, 1),
            PAYER,
            TempoHardfork::T12,
            StorageActions::disabled(),
            &TOKENS,
        );
        assert!(
            matches!(result, Err(FeeTokenResolutionError::State(TempoPrecompileError::Fatal(message))) if message == "candidate read failed")
        );
        assert_eq!(state.reads, 2);
    }

    #[test]
    fn fallback_protocol_list_is_distinct_and_starts_with_pathusd() {
        assert_eq!(FALLBACK_FEE_TOKENS.first(), Some(&DEFAULT_FEE_TOKEN));
        for (i, token) in FALLBACK_FEE_TOKENS.iter().enumerate() {
            assert!(TIP20Token::from_address(*token).is_ok());
            assert!(!FALLBACK_FEE_TOKENS[..i].contains(token));
        }
    }
}
