pub mod amm;
pub mod dispatch;

use alloy::primitives::B256;
use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;
pub use tempo_contracts::precompiles::{
    FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent,
};

use crate::{
    DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, PATH_USD_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorableType, StorageKey},
    tip_fee_manager::amm::{Pool, compute_amount_out},
    tip20::{
        ITIP20, TIP20Token, address_to_token_id_unchecked, is_tip20_prefix, token_id_to_address,
        validate_usd_currency,
    },
    tip20_factory::TIP20Factory,
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, U256, uint};
use tempo_precompiles_macros::{Storable, contract};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Storable)]
pub struct TokenPair {
    pub user_token: u64,
    pub validator_token: u64,
}

impl StorageKey for TokenPair {
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        let mut bytes = Vec::with_capacity(Self::BYTES);
        bytes.extend_from_slice(self.user_token.as_storage_bytes().as_ref());
        bytes.extend_from_slice(self.validator_token.as_storage_bytes().as_ref());
        bytes
    }
}

#[contract(addr = TIP_FEE_MANAGER_ADDRESS)]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, U256>,
    tokens_with_fees: Vec<Address>,
    token_in_fees_array: Mapping<Address, bool>,
    pools: Mapping<B256, Pool>,
    pending_fee_swap_in: Mapping<B256, u128>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,
    pools_with_fees: Vec<TokenPair>,
    pool_in_fees_array: Mapping<TokenPair, bool>,
    validators_with_fees: Vec<Address>,
    validator_in_fees_array: Mapping<Address, bool>,
}

impl TipFeeManager {
    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    /// Initializes the contract
    ///
    /// This ensures the [`TipFeeManager`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the default fee token based on the current hardfork.
    /// Post-Allegretto returns PathUSD, pre-Allegretto returns the first TIP20 after PathUSD.
    fn default_fee_token(&self) -> Address {
        if self.storage.spec().is_allegretto() {
            DEFAULT_FEE_TOKEN_POST_ALLEGRETTO
        } else {
            DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO
        }
    }

    pub fn get_validator_token(&self, beneficiary: Address) -> Result<Address> {
        let token = self.validator_tokens.at(beneficiary).read()?;

        if token.is_zero() {
            Ok(self.default_fee_token())
        } else {
            Ok(token)
        }
    }

    pub fn set_validator_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setValidatorTokenCall,
        beneficiary: Address,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if self.storage.spec().is_allegro_moderato() {
            // Post-AllegroModerato: use factory's is_tip20 which checks both prefix and counter
            if !TIP20Factory::new().is_tip20(call.token)? {
                return Err(FeeManagerError::invalid_token().into());
            }
        } else if !is_tip20_prefix(call.token) {
            // Pre-AllegroModerato: only check prefix
            return Err(FeeManagerError::invalid_token().into());
        }

        // Prevent changing if validator already has collected fees (post-Allegretto)
        if self.storage.spec().is_allegretto() && self.validator_in_fees_array.at(sender).read()? {
            return Err(FeeManagerError::cannot_change_with_pending_fees().into());
        }

        // Prevent changing within the validator's own block
        if sender == beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        self.validator_tokens.at(sender).write(call.token)?;

        // Emit ValidatorTokenSet event
        self.emit_event(FeeManagerEvent::ValidatorTokenSet(
            IFeeManager::ValidatorTokenSet {
                validator: sender,
                token: call.token,
            },
        ))
    }

    pub fn set_user_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if self.storage.spec().is_allegro_moderato() {
            // Post-AllegroModerato: use factory's is_tip20 which checks both prefix and counter
            if !TIP20Factory::new().is_tip20(call.token)? {
                return Err(FeeManagerError::invalid_token().into());
            }
        } else if !is_tip20_prefix(call.token) {
            // Pre-AllegroModerato: only check prefix
            return Err(FeeManagerError::invalid_token().into());
        }

        // Depending on the hardfork, allow/disallow PathUSD to be set as the fee token
        // Pre moderato: Allow
        // Post moderato: Disallow
        // Post allegro moderato: Allow
        if self.storage.spec().is_moderato()
            && !self.storage.spec().is_allegro_moderato()
            && call.token == PATH_USD_ADDRESS
        {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        self.user_tokens.at(sender).write(call.token)?;

        // Emit UserTokenSet event
        self.emit_event(FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
            user: sender,
            token: call.token,
        }))
    }

    /// Checks if the pool has sufficient liquidity for a fee swap.
    ///
    /// Returns an error if the pool doesn't have enough validator tokens to execute the swap.
    fn check_sufficient_liquidity(
        &self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<()> {
        let pool_id = self.pool_id(user_token, validator_token);
        let pool = self.pools.at(pool_id).read()?;
        let amount_out = amm::compute_amount_out(amount_in)?;

        if amount_out > U256::from(pool.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        Ok(())
    }

    /// Collects fees from user before transaction execution.
    ///
    /// Determines fee token, verifies pool liquidity for swaps if needed, and transfers
    /// the max fee amount to the fee manager.
    /// Unused gas is later returned via collect_fee_post_tx
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        // Verify pool liquidity if user token differs from validator token
        if user_token != validator_token {
            if self.storage.spec().is_allegro_moderato() {
                // Post-AllegroModerato, fees are swapped after each tx, so liquidity only needs to
                // be checked for the max amount
                self.check_sufficient_liquidity(user_token, validator_token, max_amount)?;
            } else {
                // Pre-AllegroModerato: Reserve liquidity (fees batched and swapped in executeBlock)
                self.reserve_liquidity(user_token, validator_token, max_amount)?;
            }
        }

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        // Ensure that user and FeeManager are authorized to interact with the token
        tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        // Return the user's token preference
        Ok(user_token)
    }

    /// Finalizes fee collection after transaction execution.
    ///
    /// Refunds unused tokens to user and tracks actual fee amount for swapping in `execute_block`
    /// Called after transaction to settle the difference between max fee and actual usage.
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
        let validator_token = self.get_validator_token(beneficiary)?;

        if fee_token != validator_token {
            // Release Fee AMM liquidity
            self.release_liquidity(fee_token, validator_token, refund_amount)?;

            // Record the pool if there was a non-zero swap
            if !actual_spending.is_zero() {
                if !self.storage.spec().is_allegretto() {
                    // Pre-Allegretto: track in buggy token_in_fees_array
                    if !self.token_in_fees_array.at(fee_token).read()? {
                        self.tokens_with_fees.push(fee_token)?;
                        self.token_in_fees_array.at(fee_token).write(true)?;
                    }
                } else {
                    self.add_pair_to_fees_array(fee_token, validator_token)?;
                }
            }
        }

        if !self.storage.spec().is_allegretto() {
            // Pre-Allegretto: increment collected fees if no AMM swap
            if fee_token == validator_token {
                self.increment_collected_fees(beneficiary, actual_spending)?;
            }
        } else {
            // Post-Allegretto: calculate the actual fee amount and save it in per-validator collected fees
            let amount = if fee_token == validator_token {
                actual_spending
            } else {
                compute_amount_out(actual_spending)?
            };

            self.increment_collected_fees(beneficiary, amount)?;
        }

        Ok(())
    }

    pub fn execute_block(&mut self, sender: Address, beneficiary: Address) -> Result<()> {
        // Only protocol can call this
        if sender != Address::ZERO {
            return Err(FeeManagerError::only_system_contract().into());
        }

        let mut total_amount_out = U256::ZERO;
        let pools = if !self.storage.spec().is_allegretto() {
            let validator_token = self.get_validator_token(beneficiary)?;
            self.drain_tokens_with_fees()?
                .into_iter()
                .map(|token| (token, validator_token))
                .collect::<Vec<_>>()
        } else {
            self.drain_pools_with_fees()?
                .into_iter()
                .map(|pair| {
                    (
                        token_id_to_address(pair.user_token),
                        token_id_to_address(pair.validator_token),
                    )
                })
                .collect()
        };
        for (user_token, validator_token) in pools {
            total_amount_out += self.execute_pending_fee_swaps(user_token, validator_token)?;
        }

        // Pre-Allegretto: increment beneficiary's collected fees if there was a non-zero swap
        if !self.storage.spec().is_allegretto() && !total_amount_out.is_zero() {
            self.increment_collected_fees(beneficiary, total_amount_out)?;
        }

        for validator in self.drain_validators_with_fees()? {
            let collected_fees = self.collected_fees.at(validator).read()?;

            if collected_fees.is_zero() {
                continue;
            }

            let validator_token = self.get_validator_token(validator)?;
            let mut token = TIP20Token::from_address(validator_token)?;

            // If FeeManager or validator are blacklisted, we are not transferring any fees
            if token.is_transfer_authorized(self.address, beneficiary)? {
                // Bound fee transfer to contract balance
                let balance = token.balance_of(ITIP20::balanceOfCall {
                    account: self.address,
                })?;

                if !balance.is_zero() {
                    token
                        .transfer(
                            self.address,
                            ITIP20::transferCall {
                                to: beneficiary,
                                amount: collected_fees.min(balance),
                            },
                        )
                        .map_err(|_| {
                            IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                                IFeeManager::InsufficientFeeTokenBalance {},
                            )
                        })?;
                }
            }

            // Clear collected fees for the validator
            self.collected_fees.at(validator).delete()?;
        }

        Ok(())
    }

    /// Add a token to the tokens with fees array
    fn add_pair_to_fees_array(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<()> {
        let pair = TokenPair {
            user_token: address_to_token_id_unchecked(user_token),
            validator_token: address_to_token_id_unchecked(validator_token),
        };
        if !self.pool_in_fees_array.at(pair).read()? {
            self.pool_in_fees_array.at(pair).write(true)?;
            self.pools_with_fees.push(pair)?;
        }
        Ok(())
    }

    /// Drain all tokens with fees by popping from the back until empty
    /// Returns a `Vec<Address>` with all the tokens that were in storage
    /// Also sets token_in_fees_array to false for each token
    fn drain_tokens_with_fees(&mut self) -> Result<Vec<Address>> {
        let mut tokens = Vec::new();
        while let Some(token) = self.tokens_with_fees.pop()? {
            tokens.push(token);
            if self.storage.spec().is_moderato() {
                self.token_in_fees_array.at(token).write(false)?;
            }
        }

        Ok(tokens)
    }

    /// Drain all validators with fees by popping from the back until empty
    fn drain_validators_with_fees(&mut self) -> Result<Vec<Address>> {
        let mut validators = Vec::new();
        while let Some(validator) = self.validators_with_fees.pop()? {
            validators.push(validator);
            self.validator_in_fees_array.at(validator).write(false)?;
        }
        Ok(validators)
    }

    /// Drain all pools with fees by popping from the back until empty
    fn drain_pools_with_fees(&mut self) -> Result<Vec<TokenPair>> {
        let mut pools = Vec::new();
        while let Some(pool) = self.pools_with_fees.pop()? {
            pools.push(pool);
            self.pool_in_fees_array.at(pool).write(false)?;
        }
        Ok(pools)
    }

    /// Increment collected fees for the validator token
    fn increment_collected_fees(&mut self, validator: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let collected_fees = self.collected_fees.at(validator).read()?;
        self.collected_fees.at(validator).write(
            collected_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // If this is the first fee for the validator, record it in validators with fees
        if collected_fees.is_zero() {
            self.validator_in_fees_array.at(validator).write(true)?;
            self.validators_with_fees.push(validator)?;
        }

        Ok(())
    }

    pub fn user_tokens(&self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.user_tokens.at(call.user).read()
    }

    pub fn validator_tokens(&self, call: IFeeManager::validatorTokensCall) -> Result<Address> {
        let token = self.validator_tokens.at(call.validator).read()?;

        if token.is_zero() {
            Ok(self.default_fee_token())
        } else {
            Ok(token)
        }
    }

    pub fn get_fee_token_balance(
        &self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> Result<IFeeManager::getFeeTokenBalanceReturn> {
        let mut token = self.user_tokens.at(call.sender).read()?;

        if token.is_zero() {
            let validator_token = self.validator_tokens.at(call.validator).read()?;

            if validator_token.is_zero() {
                return Ok(IFeeManager::getFeeTokenBalanceReturn {
                    _0: Address::ZERO,
                    _1: U256::ZERO,
                });
            } else {
                token = validator_token;
            }
        }

        let tip20_token = TIP20Token::from_address(token)?;
        let token_balance = tip20_token.balance_of(ITIP20::balanceOfCall {
            account: call.sender,
        })?;

        Ok(IFeeManager::getFeeTokenBalanceReturn {
            _0: token,
            _1: token_balance,
        })
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
        tip20::ITIP20,
    };

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;

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
    fn test_set_user_token_cannot_be_path_usd_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let path_usd = TIP20Setup::path_usd(user).apply()?;
            let mut fee_manager = TipFeeManager::new();

            // Try to set PathUSD as user token - should fail post-Moderato
            let call = IFeeManager::setUserTokenCall {
                token: path_usd.address(),
            };
            let result = fee_manager.set_user_token(user, call);
            assert!(result.is_err_and(|err| err.to_string().contains("InvalidToken")));

            Ok(())
        })
    }

    #[test]
    fn test_set_user_token_allows_path_usd_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let path_usd = TIP20Setup::path_usd(user).apply()?;
            let mut fee_manager = TipFeeManager::new();

            // Try to set PathUSD as user token - should succeed pre-Moderato
            let call = IFeeManager::setUserTokenCall {
                token: path_usd.address(),
            };

            // Pre-Moderato: should be allowed to set PathUSD as user token
            let result = fee_manager.set_user_token(user, call);
            assert!(result.is_ok());

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

            let query_call = IFeeManager::validatorTokensCall { validator };
            let returned_token = fee_manager.validator_tokens(query_call)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token_cannot_change_with_pending_fees() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let validator = Address::random();
        let beneficiary = Address::random();
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            // Simulate validator having pending fees by setting validator_in_fees_array
            fee_manager
                .validator_in_fees_array
                .at(validator)
                .write(true)?;

            // Try to set validator token when validator has pending fees (but is not the beneficiary)
            let call = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            };
            let result = fee_manager.set_validator_token(validator, call.clone(), beneficiary);

            // Should fail with CannotChangeWithPendingFees
            assert_eq!(
                result,
                Err(TempoPrecompileError::FeeManagerError(
                    FeeManagerError::cannot_change_with_pending_fees()
                ))
            );

            // Now clear the pending fees flag and try again - should succeed
            fee_manager
                .validator_in_fees_array
                .at(validator)
                .write(false)?;
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
                fee_manager.collect_fee_pre_tx(user, token.address(), max_amount, validator);
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
            let tracked_amount = fee_manager.collected_fees.at(validator).read()?;
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

    #[test]
    fn test_prevent_insufficient_balance_transfer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            // Simulate attack: collected fees = 1000, but actual balance = 500
            let collected_fees = U256::from(1000);
            let balance = U256::from(500);

            // Create token and mint only `balance` to FeeManager (less than collected_fees)
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, balance)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                beneficiary,
            )?;

            // Simulate collected fees > actual balance by setting directly
            fee_manager.increment_collected_fees(validator, collected_fees)?;

            // Execute block
            let result = fee_manager.execute_block(Address::ZERO, validator);
            assert!(result.is_ok());

            // Verify collected fees are cleared
            let remaining_fees = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(remaining_fees, U256::ZERO);

            // Verify validator got only the available balance (not full collected_fees)
            let validator_balance =
                token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(validator_balance, balance);

            // Verify FeeManager has no balance left
            let fee_manager_balance = token.balance_of(ITIP20::balanceOfCall {
                account: TIP_FEE_MANAGER_ADDRESS,
            })?;
            assert_eq!(fee_manager_balance, U256::ZERO);

            Ok(())
        })
    }
}
