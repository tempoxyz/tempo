//! [Fee manager] precompile for transaction fee collection, distribution, and token swaps.
//!
//! [Fee manager]: <https://docs.tempo.xyz/protocol/fees>

pub mod amm;
pub mod dispatch;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip_fee_manager::amm::{FeeRoute, Pool, compute_amount_out},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, U256, uint};
pub use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM,
    TIP_FEE_MANAGER_ADDRESS, TIPFeeAMMError, TIPFeeAMMEvent,
};
use tempo_precompiles_macros::contract;

/// Fee manager precompile that handles transaction fee collection and distribution.
///
/// Users and validators choose their preferred TIP-20 fee token. When they differ, fees are
/// swapped through the built-in AMM (`TIPFeeAMM`).
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = TIP_FEE_MANAGER_ADDRESS)]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, Mapping<Address, U256>>,
    pools: Mapping<B256, Pool>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,

    // WARNING(rusowsky): transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above this one.
    /// T1C+: Tracks liquidity reserved for a pending fee swap during `collect_fee_pre_tx`.
    /// Checked by `burn` and `rebalance_swap` to prevent withdrawals that would violate the reservation.
    pending_fee_swap_reservation: Mapping<B256, u128>,

    /// T2+: The fee token used for the current transaction ([TIP-1007]).
    /// Set by the handler before execution, read via `getFeeToken()`.
    ///
    /// [TIP-1007]: <https://docs.tempo.xyz/protocol/tips/tip-1007>
    tx_fee_token: Address,

    /// T5+: Intermediate token for two-hop fee swap routing ([TIP-1033]).
    /// Set by `collect_fee_pre_tx` when the direct `(userToken, validatorToken)` pool has
    /// insufficient liquidity and the swap falls back through `userToken.quoteToken()`.
    ///
    /// [TIP-1033]: <https://docs.tempo.xyz/protocol/tips/tip-1033>
    two_hop_intermediate: Address,
}

impl TipFeeManager {
    /// Swap fee in basis points (0.25%).
    pub const FEE_BPS: u64 = 25;
    /// Basis-point denominator (10 000 = 100%).
    pub const BASIS_POINTS: u64 = 10000;
    /// Minimum TIP-20 balance required for fee operations (1e9).
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256);

    /// Initializes the fee manager precompile.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the validator's preferred fee token, falling back to [`DEFAULT_FEE_TOKEN`].
    pub fn get_validator_token(&self, beneficiary: Address) -> Result<Address> {
        let token = self.validator_tokens[beneficiary].read()?;

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    /// Sets the caller's preferred fee token as a validator.
    ///
    /// Rejects the call if `sender` is the current block's beneficiary (prevents mid-block
    /// fee-token changes) or if the token is not a valid USD-denominated TIP-20 registered in
    /// [`TIP20Factory`].
    ///
    /// # Errors
    /// - `InvalidToken` — token is not a deployed TIP-20 in [`TIP20Factory`]
    /// - `CannotChangeWithinBlock` — `sender` equals the current block `beneficiary`
    /// - `InvalidCurrency` — token is not USD-denominated
    pub fn set_validator_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setValidatorTokenCall,
        beneficiary: Address,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Prevent changing within the validator's own block
        if sender == beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        self.validator_tokens[sender].write(call.token)?;

        // Emit ValidatorTokenSet event
        self.emit_event(FeeManagerEvent::ValidatorTokenSet(
            IFeeManager::ValidatorTokenSet {
                validator: sender,
                token: call.token,
            },
        ))
    }

    /// Sets the caller's preferred fee token as a user. Must be a valid USD-denominated TIP-20
    /// registered in [`TIP20Factory`].
    ///
    /// # Errors
    /// - `InvalidToken` — token is not a deployed TIP-20 in [`TIP20Factory`]
    /// - `InvalidCurrency` — token is not USD-denominated
    pub fn set_user_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        // T3+: skip write and event if the token is already set to the requested value.
        // Prevents permissionless callers from forcing redundant pool invalidation scans.
        if self.storage.spec().is_t3() {
            let current = self.user_tokens[sender].read()?;
            if current == call.token {
                return Ok(());
            }
        }

        self.user_tokens[sender].write(call.token)?;

        // Emit UserTokenSet event
        self.emit_event(FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
            user: sender,
            token: call.token,
        }))
    }

    /// Collects fees from `fee_payer` before transaction execution.
    ///
    /// Transfers `max_amount` of `user_token` to the fee manager via [`TIP20Token`] and, if the
    /// validator prefers a different token, verifies sufficient pool liquidity.
    /// Reserves liquidity on T1C+, with a two-hop fallback through `userToken.quoteToken()` on T5+.
    /// Returns the user's fee token.
    ///
    /// # Errors
    /// - `InvalidToken` — `user_token` does not have a valid TIP-20 prefix
    /// - `PolicyForbids` — TIP-403 policy rejects the fee token transfer
    /// - `InsufficientLiquidity` — AMM pool lacks liquidity for the fee swap (T5+: with two-hop fallback)
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        // Ensure that user and FeeManager are authorized to interact with the token
        tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        if !skip_liquidity_check {
            match self.get_fee_route(user_token, validator_token, max_amount)? {
                None => return Err(TIPFeeAMMError::insufficient_liquidity().into()),
                Some(FeeRoute::Direct) => {
                    if user_token != validator_token && self.storage.spec().is_t1c() {
                        let amount_out: u128 = compute_amount_out(max_amount)?
                            .try_into()
                            .map_err(|_| TempoPrecompileError::under_overflow())?;
                        self.reserve_pool_liquidity(
                            self.pool_id(user_token, validator_token),
                            amount_out,
                        )?;
                    }
                }
                Some(FeeRoute::TwoHop(intermediate)) => {
                    // T5+ implies T1C+, so reservation is always required here.
                    let out1: u128 = compute_amount_out(max_amount)?
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?;
                    let out2: u128 = compute_amount_out(U256::from(out1))?
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?;
                    self.reserve_pool_liquidity(self.pool_id(user_token, intermediate), out1)?;
                    self.reserve_pool_liquidity(
                        self.pool_id(intermediate, validator_token),
                        out2,
                    )?;
                    self.two_hop_intermediate.t_write(intermediate)?;
                }
            }
        }

        // Return the user's token preference
        Ok(user_token)
    }

    /// Finalizes fee collection after transaction execution.
    ///
    /// Refunds unused `user_token` to `fee_payer` via [`TIP20Token`], executes the fee swap
    /// through the AMM pool if tokens differ, and accumulates fees for the validator.
    ///
    /// # Errors
    /// - `InvalidToken` — `fee_token` does not have a valid TIP-20 prefix
    /// - `InsufficientLiquidity` — AMM pool lacks liquidity for the fee swap
    /// - `UnderOverflow` — collected-fee accumulator overflows
    pub fn collect_fee_post_tx(
        &mut self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> Result<()> {
        // Refund unused tokens to user
        let mut tip20_token = TIP20Token::from_address(fee_token)?;
        tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;

        // Execute fee swap and track collected fees
        let hop_token = self.two_hop_intermediate.t_read()?;
        let validator_token = self.get_validator_token(beneficiary)?;

        let amount = if fee_token == validator_token {
            actual_spending
        } else if hop_token.is_zero() {
            // Single-hop (direct) swap
            if !actual_spending.is_zero() {
                self.execute_fee_swap(fee_token, validator_token, actual_spending)?;
            }
            compute_amount_out(actual_spending)?
        } else {
            // Two-hop swap (only in T5+): each hop applies M = 9970/10000 sequentially
            if !actual_spending.is_zero() {
                let out1 = self.execute_fee_swap(fee_token, hop_token, actual_spending)?;
                self.execute_fee_swap(hop_token, validator_token, out1)?;
            }
            compute_amount_out(compute_amount_out(actual_spending)?)?
        };

        self.increment_collected_fees(beneficiary, validator_token, amount)?;

        Ok(())
    }

    /// Increment collected fees for a specific validator and token combination.
    fn increment_collected_fees(
        &mut self,
        validator: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let collected_fees = self.collected_fees[validator][token].read()?;
        self.collected_fees[validator][token].write(
            collected_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(())
    }

    /// Transfers a validator's accumulated fee balance to their address via [`TIP20Token`] and
    /// zeroes the ledger. No-ops when the balance is zero.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` does not have a valid TIP-20 prefix
    pub fn distribute_fees(&mut self, validator: Address, token: Address) -> Result<()> {
        let amount = self.collected_fees[validator][token].read()?;
        if amount.is_zero() {
            return Ok(());
        }
        self.collected_fees[validator][token].write(U256::ZERO)?;

        // Transfer fees to validator
        let mut tip20_token = TIP20Token::from_address(token)?;
        tip20_token.transfer(
            self.address,
            ITIP20::transferCall {
                to: validator,
                amount,
            },
        )?;

        // Emit FeesDistributed event
        self.emit_event(FeeManagerEvent::FeesDistributed(
            IFeeManager::FeesDistributed {
                validator,
                token,
                amount,
            },
        ))?;

        Ok(())
    }

    /// Reads the stored fee token preference for a user.
    pub fn user_tokens(&self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.user_tokens[call.user].read()
    }
}

#[cfg(test)]
mod tests {
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Token},
    };

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;

            // TODO: loop through and deploy and set user token for some range

            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setUserTokenCall {
                token: token.address(),
            };
            let result = fee_manager.set_user_token(user, call);
            assert!(result.is_ok());

            let call = IFeeManager::userTokensCall { user };
            assert_eq!(fee_manager.user_tokens(call)?, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_user_token_noop_when_unchanged_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setUserTokenCall {
                token: token.address(),
            };

            fee_manager.set_user_token(user, call.clone())?;
            fee_manager.set_user_token(user, call)?;
            let event_count = StorageCtx.get_events(TIP_FEE_MANAGER_ADDRESS).len();
            assert_eq!(
                event_count, 2,
                "pre-T3: event emitted even when token unchanged"
            );

            Ok(())
        })
    }

    #[test]
    fn test_set_user_token_noop_when_unchanged_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setUserTokenCall {
                token: token.address(),
            };

            fee_manager.set_user_token(user, call.clone())?;
            let event_count = StorageCtx.get_events(TIP_FEE_MANAGER_ADDRESS).len();
            assert_eq!(event_count, 1, "first set_user_token should emit event");

            fee_manager.set_user_token(user, call)?;
            let event_count = StorageCtx.get_events(TIP_FEE_MANAGER_ADDRESS).len();
            assert_eq!(
                event_count, 1,
                "T3+: repeated set_user_token with same token should not emit event"
            );

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            };

            // Should fail when validator == beneficiary (same block check)
            let result = fee_manager.set_validator_token(validator, call.clone(), validator);
            assert_eq!(
                result,
                Err(TempoPrecompileError::FeeManagerError(
                    FeeManagerError::cannot_change_within_block()
                ))
            );

            // Should succeed with different beneficiary
            let result = fee_manager.set_validator_token(validator, call, beneficiary);
            assert!(result.is_ok());

            let returned_token = fee_manager.get_validator_token(validator)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token_cannot_change_within_block() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let beneficiary = Address::random();
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            };

            // Setting validator token when not beneficiary should succeed
            let result = fee_manager.set_validator_token(validator, call.clone(), beneficiary);
            assert!(result.is_ok());

            // But if validator is the beneficiary, should fail with CannotChangeWithinBlock
            let result = fee_manager.set_validator_token(validator, call, validator);
            assert_eq!(
                result,
                Err(TempoPrecompileError::FeeManagerError(
                    FeeManagerError::cannot_change_within_block()
                ))
            );

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let max_amount = U256::from(10000);

            let token = TIP20Setup::create("Test", "TST", user)
                .with_issuer(user)
                .with_mint(user, U256::from(u64::MAX))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator token (use beneficiary to avoid CannotChangeWithinBlock)
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                beneficiary,
            )?;

            // Set user token
            fee_manager.set_user_token(
                user,
                IFeeManager::setUserTokenCall {
                    token: token.address(),
                },
            )?;

            // Call collect_fee_pre_tx directly
            let result =
                fee_manager.collect_fee_pre_tx(user, token.address(), max_amount, validator, false);
            assert!(result.is_ok());
            assert_eq!(result?, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let admin = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let actual_used = U256::from(6000);
            let refund_amount = U256::from(4000);

            // Mint to FeeManager (simulating collect_fee_pre_tx already happened)
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000000000000_u64))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator token (use beneficiary to avoid CannotChangeWithinBlock)
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                beneficiary,
            )?;

            // Set user token
            fee_manager.set_user_token(
                user,
                IFeeManager::setUserTokenCall {
                    token: token.address(),
                },
            )?;

            // Call collect_fee_post_tx directly
            let result = fee_manager.collect_fee_post_tx(
                user,
                actual_used,
                refund_amount,
                token.address(),
                validator,
            );
            assert!(result.is_ok());

            // Verify fees were tracked
            let tracked_amount = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(tracked_amount, actual_used);

            // Verify user got the refund
            let balance = token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(balance, refund_amount);

            Ok(())
        })
    }

    #[test]
    fn test_rejects_non_usd() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            // Create a non-USD token
            let non_usd_token = TIP20Setup::create("NonUSD", "EUR", admin)
                .currency("EUR")
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Try to set non-USD as user token - should fail
            let call = IFeeManager::setUserTokenCall {
                token: non_usd_token.address(),
            };
            let result = fee_manager.set_user_token(user, call);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            // Try to set non-USD as validator token - should also fail
            let call = IFeeManager::setValidatorTokenCall {
                token: non_usd_token.address(),
            };
            let result = fee_manager.set_validator_token(validator, call, beneficiary);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx with different tokens
    /// Verifies that liquidity is checked (not reserved) and no swap happens yet
    #[test]
    fn test_collect_fee_pre_tx_different_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create two different tokens
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Setup pool with liquidity
            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            // Set validator's preferred token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);

            // Call collect_fee_pre_tx
            fee_manager.collect_fee_pre_tx(
                user,
                user_token.address(),
                max_amount,
                validator,
                false,
            )?;

            // With different tokens:
            // - Liquidity is checked (not reserved)
            // - No swap happens yet (swap happens in collect_fee_post_tx)
            // - collected_fees should be zero
            let collected =
                fee_manager.collected_fees[validator][validator_token.address()].read()?;
            assert_eq!(
                collected,
                U256::ZERO,
                "Different tokens: no fees accumulated in pre_tx (swap happens in post_tx)"
            );

            // Pool reserves should NOT be updated yet
            let pool = fee_manager.pools[pool_id].read()?;
            assert_eq!(
                pool.reserve_user_token, 10000,
                "Reserves unchanged in pre_tx"
            );
            assert_eq!(
                pool.reserve_validator_token, 10000,
                "Reserves unchanged in pre_tx"
            );

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_post_tx_immediate_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);
            let actual_spending = U256::from(800);
            let refund_amount = U256::from(200);

            // First call collect_fee_pre_tx (checks liquidity)
            fee_manager.collect_fee_pre_tx(
                user,
                user_token.address(),
                max_amount,
                validator,
                false,
            )?;

            // Then call collect_fee_post_tx (executes swap immediately)
            fee_manager.collect_fee_post_tx(
                user,
                actual_spending,
                refund_amount,
                user_token.address(),
                validator,
            )?;

            // Expected output: 800 * 9970 / 10000 = 797
            let expected_fee_amount = (actual_spending * U256::from(9970)) / U256::from(10000);
            let collected =
                fee_manager.collected_fees[validator][validator_token.address()].read()?;
            assert_eq!(collected, expected_fee_amount);

            // Pool reserves should be updated
            let pool = fee_manager.pools[pool_id].read()?;
            assert_eq!(pool.reserve_user_token, 10000 + 800);
            assert_eq!(pool.reserve_validator_token, 10000 - 797);

            // User balance: started with 10000, paid 1000 in pre_tx, got 200 refund = 9200
            let tip20_token = TIP20Token::from_address(user_token.address())?;
            let user_balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(user_balance, U256::from(10000) - max_amount + refund_amount);

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx fails with insufficient liquidity
    #[test]
    fn test_collect_fee_pre_tx_insufficient_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            // Pool with very little validator token liquidity
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 100,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // Try to collect fee that would require more liquidity than available
            // 1000 * 0.997 = 997 output needed, but only 100 available
            let max_amount = U256::from(1000);

            let result = fee_manager.collect_fee_pre_tx(
                user,
                user_token.address(),
                max_amount,
                validator,
                false,
            );

            assert!(result.is_err(), "Should fail with insufficient liquidity");

            Ok(())
        })
    }

    /// Test that `skip_liquidity_check = true` bypasses the insufficient-liquidity error
    /// when `user_token != validator_token`.
    #[test]
    fn test_collect_fee_pre_tx_skip_liquidity_check() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // Skip liquidity check = false should fail
            let result = fee_manager.collect_fee_pre_tx(
                user,
                user_token.address(),
                U256::from(1000),
                validator,
                false,
            );
            assert!(
                result.is_err(),
                "Should fail without liquidity, got: {result:?}"
            );

            // Skip liquidity check = true should pass
            let result = fee_manager.collect_fee_pre_tx(
                user,
                user_token.address(),
                U256::from(1000),
                validator,
                true,
            );
            assert!(result.is_ok());
            assert_eq!(result?, user_token.address());

            Ok(())
        })
    }

    /// Test distribute_fees with zero balance is a no-op
    #[test]
    fn test_distribute_fees_zero_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("TestToken", "TEST", admin)
                .with_issuer(admin)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                Address::random(),
            )?;

            // collected_fees is zero by default
            let collected = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(collected, U256::ZERO);

            // distribute_fees should be a no-op
            let result = fee_manager.distribute_fees(validator, token.address());
            assert!(result.is_ok(), "Should succeed even with zero balance");

            // Validator balance should still be zero
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance, U256::ZERO);

            Ok(())
        })
    }

    /// Test distribute_fees transfers accumulated fees to validator
    #[test]
    fn test_distribute_fees() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Initialize token and give fee manager some tokens
            let token = TIP20Setup::create("TestToken", "TEST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(1000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator's preferred token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                Address::random(), // beneficiary != validator
            )?;

            // Simulate accumulated fees
            let fee_amount = U256::from(500);
            fee_manager.collected_fees[validator][token.address()].write(fee_amount)?;

            // Check validator balance before
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_before =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_before, U256::ZERO);

            // Distribute fees
            let mut fee_manager = TipFeeManager::new();
            fee_manager.distribute_fees(validator, token.address())?;

            // Verify validator received the fees
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_after =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_after, fee_amount);

            // Verify collected fees cleared
            let fee_manager = TipFeeManager::new();
            let remaining = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(remaining, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_initialize_sets_storage_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Before init, should not be initialized
            assert!(!fee_manager.is_initialized()?);

            // Initialize
            fee_manager.initialize()?;

            // After init, should be initialized
            assert!(fee_manager.is_initialized()?);

            // New handle should still see initialized state
            let fee_manager2 = TipFeeManager::new();
            assert!(fee_manager2.is_initialized()?);

            Ok(())
        })
    }

    struct TwoHopTokens {
        user: Address,
        hop: Address,
        validator: Address,
    }

    /// Builds the standard 3-token environment used by all TIP-1033 tests.
    fn with_two_hop_env<F>(spec: TempoHardfork, hop_quote_is_val: bool, f: F) -> eyre::Result<()>
    where
        F: FnOnce(&mut TipFeeManager, &TwoHopTokens, Address, Address) -> eyre::Result<()>,
    {
        let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let hop_token = TIP20Setup::create("HopToken", "HTK", admin)
                .with_issuer(admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .apply()?
                .address();
            let quote_token = if hop_quote_is_val {
                validator_token
            } else {
                hop_token
            };
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .quote_token(quote_token)
                .with_mint(user, U256::from(u64::MAX))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?
                .address();

            let mut fee_manager = TipFeeManager::new();
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token,
                },
                Address::random(),
            )?;

            let tokens = TwoHopTokens {
                user: user_token,
                hop: hop_token,
                validator: validator_token,
            };
            f(&mut fee_manager, &tokens, user, validator)
        })
    }

    /// Writes a pool with `validator_reserve` on both sides.
    fn write_pool(
        fm: &mut TipFeeManager,
        a: Address,
        b: Address,
        validator_reserve: u128,
    ) -> Result<()> {
        let pid = fm.pool_id(a, b);
        fm.pools[pid].write(crate::tip_fee_manager::amm::Pool {
            reserve_user_token: validator_reserve.max(1),
            reserve_validator_token: validator_reserve,
        })
    }

    #[test]
    fn test_collect_fee_pre_tx_two_hop_hardfork_gating() -> eyre::Result<()> {
        // Direct pool empty, both hop pools deep — the only fee path is the two-hop fallback.
        let setup_pools = |fm: &mut TipFeeManager, t: &TwoHopTokens| -> Result<()> {
            write_pool(fm, t.user, t.validator, 0)?;
            write_pool(fm, t.user, t.hop, 100_000)?;
            write_pool(fm, t.hop, t.validator, 100_000)?;
            Ok(())
        };

        // Pre-T5: fallback disabled — must revert.
        with_two_hop_env(TempoHardfork::T4, false, |fm, t, user, validator| {
            setup_pools(fm, t)?;
            let res = fm.collect_fee_pre_tx(user, t.user, U256::from(1_000), validator, false);
            assert_eq!(
                res.unwrap_err(),
                TIPFeeAMMError::insufficient_liquidity().into(),
                "T4: expected InsufficientLiquidity",
            );
            Ok(())
        })?;

        // T5: same setup — fallback engages successfully.
        with_two_hop_env(TempoHardfork::T5, false, |fm, t, user, validator| {
            setup_pools(fm, t)?;

            fm.collect_fee_pre_tx(user, t.user, U256::from(1_000), validator, false)?;
            assert_eq!(
                fm.pending_fee_swap_reservation[fm.pool_id(t.user, t.hop)].t_read()?,
                997 // 1st hop: floor(1000 * 9970/10000) = 997
            );
            assert_eq!(
                fm.pending_fee_swap_reservation[fm.pool_id(t.hop, t.validator)].t_read()?,
                994 // 2nd hop: floor(997 * 9970/10000) = 994
            );
            assert_eq!(
                fm.pending_fee_swap_reservation[fm.pool_id(t.user, t.validator)].t_read()?,
                0 // direct pool is NOT reserved
            );
            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_pre_tx_two_hop_no_side_effects() -> eyre::Result<()> {
        // (label, hop_quote_is_val, skip, direct, first_hop, second_hop)
        let cases: &[(&str, bool, bool, u128, u128, u128)] = &[
            ("direct pool sufficient", false, false, 100_000, 0, 0),
            ("skip_liquidity_check bypass", false, true, 0, 0, 0),
            ("1st hop empty", false, false, 0, 0, 100_000),
            ("2nd hop too small", false, false, 0, 100_000, 50),
            // `userToken.quoteToken() == validatorToken` degenerates failed direct pair.
            ("quote == validator", true, false, 0, 100_000, 100_000),
        ];

        for &(label, hop_quote_is_val, skip, direct, r1, r2) in cases {
            with_two_hop_env(
                TempoHardfork::T5,
                hop_quote_is_val,
                |fm, t, user, validator| {
                    write_pool(fm, t.user, t.validator, direct)?;
                    write_pool(fm, t.user, t.hop, r1)?;
                    write_pool(fm, t.hop, t.validator, r2)?;

                    let res =
                        fm.collect_fee_pre_tx(user, t.user, U256::from(1_000), validator, skip);
                    assert_eq!(
                        res.is_ok(),
                        direct > 0 || skip,
                        "{label}: succeeds iff the two-hop fallback isn't needed, got {res:?}",
                    );

                    // Two-hop fallback must never half-commit: neither hop pool is
                    // reserved and no intermediate token is cached.
                    for (a, b) in [(t.user, t.hop), (t.hop, t.validator)] {
                        assert_eq!(
                            fm.pending_fee_swap_reservation[fm.pool_id(a, b)].t_read()?,
                            0,
                            "{label}: hop pool reservation leaked for ({a}, {b})",
                        );
                    }
                    assert!(
                        fm.two_hop_intermediate.t_read()?.is_zero(),
                        "{label}: intermediate cache leaked",
                    );
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    #[test]
    fn test_collect_fee_post_tx_two_hop_compound_fee() -> eyre::Result<()> {
        // TIP-1033 states two-hop fee math MUST apply M = 9970/10000 sequentially
        // (amount_in, expected_out1, expected_out2):
        let cases: &[(u128, u128, u128)] = &[
            (123_456_789, 123_086_418, 122_717_158),
            (987_654_123, 984_691_160, 981_737_086),
            (456_321_789, 454_952_823, 453_587_964),
        ];

        let assert_sequential_diverges_from_combined = |amount: U256| {
            const COMBINED: U256 = uint!(99_400_900_U256); // M * M
            const SCALE: U256 = uint!(100_000_000_U256); // SCALE * SCALE
            let combined = amount * COMBINED / SCALE;

            let sequential = compute_amount_out(compute_amount_out(amount).unwrap()).unwrap();
            assert_ne!(
                sequential, combined,
                "amount={amount}: pick another value for sequential to not match combined fee math"
            );
        };

        for &(amount, expected_out1, expected_out2) in cases {
            assert_sequential_diverges_from_combined(U256::from(amount));

            with_two_hop_env(TempoHardfork::T5, false, |fm, t, user, validator| {
                // Reserves are deep enough that liquidity never bounds the result;
                // any deviation in `collected_fees` is purely a fee-math bug.
                let reserve = 10 * amount;
                write_pool(fm, t.user, t.validator, 0)?;
                write_pool(fm, t.user, t.hop, reserve)?;
                write_pool(fm, t.hop, t.validator, reserve)?;

                let amount_u = U256::from(amount);
                fm.collect_fee_pre_tx(user, t.user, amount_u, validator, false)?;
                fm.collect_fee_post_tx(user, amount_u, U256::ZERO, t.user, validator)?;

                assert_eq!(
                    fm.collected_fees[validator][t.validator].read()?,
                    U256::from(expected_out2),
                    "amount={amount}: post-tx MUST accumulate sequential floor(floor(N*M)*M)",
                );

                // pool1 (user, hop): user-side gained `amount`, hop-side lost `out1`.
                let p1 = fm.pools[fm.pool_id(t.user, t.hop)].read()?;
                assert_eq!(
                    (p1.reserve_user_token, p1.reserve_validator_token),
                    (reserve + amount, reserve - expected_out1),
                    "amount={amount}: pool1 reserves must move by (amount, out1)",
                );
                // pool2 (hop, validator): hop-side gained `out1`, validator-side lost `out2`.
                let p2 = fm.pools[fm.pool_id(t.hop, t.validator)].read()?;
                assert_eq!(
                    (p2.reserve_user_token, p2.reserve_validator_token),
                    (reserve + expected_out1, reserve - expected_out2),
                    "amount={amount}: pool2 reserves must move by (out1, out2)",
                );
                Ok(())
            })?;
        }
        Ok(())
    }
}
