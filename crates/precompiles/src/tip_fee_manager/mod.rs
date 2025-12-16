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

    /// Collects fees from user before transaction execution.
    ///
    /// Pre-AllegroModerato: Reserves liquidity for swaps if needed, transfers max fee to fee manager.
    /// Unused gas is later returned via collect_fee_post_tx.
    ///
    /// Post-AllegroModerato: Executes fee swap immediately and accumulates fees in collected_fees.
    /// No refund mechanism - validators call distribute_fees() to collect accumulated fees.
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        // Ensure that user and FeeManager are authorized to interact with the token
        tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        if user_token != validator_token {
            if self.storage.spec().is_allegro_moderato() {
                // Post-AllegroModerato: ensure there is enough liquidity to swap `max_amount`
                self.check_sufficient_liquidity(user_token, validator_token, max_amount)?;
            } else {
                // Pre-AllegroModerato: reserve liquidity for later swap in execute_block
                self.reserve_liquidity(user_token, validator_token, max_amount)?;
            }
        }

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
            // Pre-AllegroModerato: release reserved liquidity
            // Post-AllegroModerato: no liquidity was reserved, skip release
            if !self.storage.spec().is_allegro_moderato() {
                self.release_liquidity(fee_token, validator_token, refund_amount)?;
            }

            // Record the pool if there was a non-zero swap
            if !actual_spending.is_zero() {
                if self.storage.spec().is_allegro_moderato() {
                    // Execute fee swap immediately and accumulate fees
                    self.execute_fee_swap(fee_token, validator_token, actual_spending)?;
                } else if !self.storage.spec().is_allegretto() {
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
            // Post-AllegroModerato: pending fees are removed, increment collected fees without
            if fee_token == validator_token {
                self.increment_collected_fees(beneficiary, actual_spending)?;
            }
        } else {
            // Post allegreto: calculate the actual fee amount and save it in per-validator collected fees
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

        // Pre Allegro Moderato, add fees to be processed end of block
        if !self.storage.spec().is_allegro_moderato() {
            // If this is the first fee for the validator, record it in validators with fees
            if collected_fees.is_zero() {
                self.validator_in_fees_array.at(validator).write(true)?;
                self.validators_with_fees.push(validator)?;
            }
        }
        Ok(())
    }

    /// Transfers the validator's fee balance to their address.
    pub fn distribute_fees(&mut self, validator: Address) -> Result<()> {
        let amount = self.collected_fees.at(validator).read()?;
        if amount.is_zero() {
            return Ok(());
        }
        self.collected_fees.at(validator).write(U256::ZERO)?;

        // Transfer fees to validator
        let validator_token = self.get_validator_token(validator)?;

        let mut token = TIP20Token::from_address(validator_token)?;
        token.transfer(
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
                token: validator_token,
                amount,
            },
        ))?;

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
        tip20::{ITIP20, TIP20Token},
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

    /// Test collect_fee_pre_tx pre-AllegroModerato: reserves liquidity but doesn't swap
    #[test]
    fn test_collect_fee_pre_tx_reserves_liquidity_pre_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
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
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager
                .pools
                .at(pool_id)
                .write(crate::tip_fee_manager::amm::Pool {
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

            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Pre-AllegroModerato: liquidity should be reserved, not swapped
            // collected_fees should be zero (no immediate swap)
            let collected = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(
                collected,
                U256::ZERO,
                "Pre-AllegroModerato: no immediate swap"
            );

            // Pending fee swap should be recorded
            let pending = fee_manager.get_pending_fee_swap_in(pool_id)?;
            assert_eq!(pending, 1000, "Liquidity should be reserved");

            // Pool reserves should NOT be updated yet
            let pool = fee_manager.pools.at(pool_id).read()?;
            assert_eq!(
                pool.reserve_user_token, 10000,
                "Reserves unchanged pre-swap"
            );
            assert_eq!(
                pool.reserve_validator_token, 10000,
                "Reserves unchanged pre-swap"
            );

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx post-AllegroModerato with same token (no swap needed)
    /// When user_token == validator_token, fees should be accumulated directly in collect_fee_pre_tx
    #[test]
    fn test_collect_fee_pre_tx_same_token_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create single token used by both user and validator
            let token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator's preferred token to the same token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);

            // Call collect_fee_pre_tx
            fee_manager.collect_fee_pre_tx(user, token.address(), max_amount, validator)?;

            // Post-AllegroModerato with same token: fees should be accumulated directly
            // (no swap needed since user_token == validator_token)
            let collected = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(
                collected, max_amount,
                "Same token: fees should be accumulated directly without swap"
            );

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx post-AllegroModerato with different tokens
    /// Verifies that liquidity is checked (not reserved) and no swap happens yet
    #[test]
    fn test_collect_fee_pre_tx_different_tokens_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
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
            fee_manager
                .pools
                .at(pool_id)
                .write(crate::tip_fee_manager::amm::Pool {
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
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Post-AllegroModerato with different tokens:
            // - Liquidity is checked (not reserved)
            // - No swap happens yet (swap happens in collect_fee_post_tx)
            // - collected_fees should be zero
            let collected = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(
                collected,
                U256::ZERO,
                "Different tokens: no fees accumulated in pre_tx (swap happens in post_tx)"
            );

            // Pending fee swap should NOT be recorded (post-AllegroModerato doesn't reserve)
            let pending = fee_manager.get_pending_fee_swap_in(pool_id)?;
            assert_eq!(pending, 0, "Post-AllegroModerato: no liquidity reservation");

            // Pool reserves should NOT be updated yet
            let pool = fee_manager.pools.at(pool_id).read()?;
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
    fn test_collect_fee_post_tx_immediate_swap_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
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
            fee_manager
                .pools
                .at(pool_id)
                .write(crate::tip_fee_manager::amm::Pool {
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

            // First call collect_fee_pre_tx (checks liquidity post-AllegroModerato)
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Then call collect_fee_post_tx (executes swap post-AllegroModerato)
            fee_manager.collect_fee_post_tx(
                user,
                actual_spending,
                refund_amount,
                user_token.address(),
                validator,
            )?;

            // Expected output: 800 * 9970 / 10000 = 797
            let expected_fee_amount = (actual_spending * U256::from(9970)) / U256::from(10000);
            let collected = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(collected, expected_fee_amount);

            // Pool reserves should be updated
            let pool = fee_manager.pools.at(pool_id).read()?;
            assert_eq!(pool.reserve_user_token, 10000 + 800);
            assert_eq!(pool.reserve_validator_token, 10000 - 797);

            // User balance: started with 10000, paid 1000 in pre_tx, got 200 refund = 9200
            let tip20_token = TIP20Token::from_address(user_token.address())?;
            let user_balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(user_balance, U256::from(10000) - max_amount + refund_amount);

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx post-AllegroModerato: fails with insufficient liquidity
    #[test]
    fn test_collect_fee_pre_tx_insufficient_liquidity_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
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
            fee_manager
                .pools
                .at(pool_id)
                .write(crate::tip_fee_manager::amm::Pool {
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

            let result =
                fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator);

            assert!(result.is_err(), "Should fail with insufficient liquidity");

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
            let collected = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(collected, U256::ZERO);

            // distribute_fees should be a no-op
            let result = fee_manager.distribute_fees(validator);
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
            fee_manager.collected_fees.at(validator).write(fee_amount)?;

            // Check validator balance before
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_before =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_before, U256::ZERO);

            // Distribute fees
            let mut fee_manager = TipFeeManager::new();
            fee_manager.distribute_fees(validator)?;

            // Verify validator received the fees
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_after =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_after, fee_amount);

            // Verify collected fees cleared
            let fee_manager = TipFeeManager::new();
            let remaining = fee_manager.collected_fees.at(validator).read()?;
            assert_eq!(remaining, U256::ZERO);

            Ok(())
        })
    }
}
