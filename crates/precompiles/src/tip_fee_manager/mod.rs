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
    storage::{PrecompileStorageProvider, Slot, Storable, VecSlotExt},
    tip_fee_manager::amm::Pool,
    tip20::{ITIP20, TIP20Token, is_tip20, validate_usd_currency},
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, Bytes, IntoLogData, U256, uint};
use revm::state::Bytecode;
use tempo_precompiles_macros::contract;

/// Helper type to easily interact with the `tokens_with_fees` array
type TokensWithFees = Slot<Vec<Address>, TokensWithFeesSlot>;

#[contract]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: U256,
    tokens_with_fees: Vec<Address>,
    token_in_fees_array: Mapping<Address, bool>,
    pools: Mapping<B256, Pool>,
    pending_fee_swap_in: Mapping<B256, u128>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,
}

impl<'a, S: PrecompileStorageProvider> TipFeeManager<'a, S> {
    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(TIP_FEE_MANAGER_ADDRESS, storage)
    }

    /// Initializes the contract
    ///
    /// This ensures the [`TipFeeManager`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    pub fn get_validator_token(&mut self, beneficiary: Address) -> Result<Address> {
        let token = self.sload_validator_tokens(beneficiary)?;

        if token.is_zero() {
            if self.storage.spec().is_allegretto() {
                Ok(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
            } else {
                Ok(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO)
            }
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
        if !is_tip20(call.token) {
            return Err(FeeManagerError::invalid_token().into());
        }

        if sender == beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        self.sstore_validator_tokens(sender, call.token)?;

        // Emit ValidatorTokenSet event
        self.storage.emit_event(
            self.address,
            FeeManagerEvent::ValidatorTokenSet(IFeeManager::ValidatorTokenSet {
                validator: sender,
                token: call.token,
            })
            .into_log_data(),
        )
    }

    pub fn set_user_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<()> {
        if !is_tip20(call.token) {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Forbid setting PathUSD as the user's fee token (only after Moderato hardfork)
        if self.storage.spec().is_moderato() && call.token == PATH_USD_ADDRESS {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        self.sstore_user_tokens(sender, call.token)?;

        // Emit UserTokenSet event
        self.storage.emit_event(
            self.address,
            FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
                user: sender,
                token: call.token,
            })
            .into_log_data(),
        )
    }

    /// Collects fees from user before transaction execution.
    ///
    /// Determines fee token, verifies pool liquidity for swaps if needed, reserves liquidity
    /// for the max fee amount and transfers it to the fee manager.
    /// Unused gas is later returned via collect_fee_post_tx
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        _to: Address,
        max_amount: U256,
        beneficiary: Address,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        // Verify pool liquidity if user token differs from validator token
        if user_token != validator_token {
            self.reserve_liquidity(user_token, validator_token, max_amount)?;
        }

        let mut tip20_token = TIP20Token::from_address(user_token, self.storage);

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
        let mut tip20_token = TIP20Token::from_address(fee_token, self.storage);
        tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;

        // Execute fee swap and track collected fees
        let validator_token = self.get_validator_token(beneficiary)?;

        if fee_token == validator_token {
            self.increment_collected_fees(actual_spending)?;
        } else {
            self.release_liquidity(fee_token, validator_token, refund_amount)?;

            if actual_spending.is_zero() {
                return Ok(());
            }

            // Track the token to be swapped
            if !self.sload_token_in_fees_array(fee_token)? {
                self.add_token_to_fees_array(fee_token)?;
                self.sstore_token_in_fees_array(fee_token, true)?;
            }
        }

        Ok(())
    }

    pub fn execute_block(&mut self, sender: Address, beneficiary: Address) -> Result<()> {
        // Only protocol can call this
        if sender != Address::ZERO {
            return Err(FeeManagerError::only_system_contract().into());
        }

        // Get current validator's preferred token
        // If the token is not set we return the default fee token
        let validator_token = self.get_validator_token(beneficiary)?;

        // Process all collected fees and execute pending swaps
        let mut collected_fees = self.get_collected_fees()?;
        let tokens_with_fees = self.drain_tokens_with_fees()?;

        for token in tokens_with_fees.iter() {
            if *token != validator_token {
                // Check if pool exists
                let pool_id = self.pool_id(*token, validator_token);
                let pool = self.sload_pools(pool_id)?;

                if pool.reserve_user_token > 0 || pool.reserve_validator_token > 0 {
                    collected_fees = collected_fees
                        .checked_add(self.execute_pending_fee_swaps(*token, validator_token)?)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                }
            }
        }

        if !collected_fees.is_zero() {
            let mut token = TIP20Token::from_address(validator_token, self.storage);

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

            self.clear_collected_fees()?;
        }

        Ok(())
    }

    /// Add a token to the tokens with fees array
    fn add_token_to_fees_array(&mut self, token: Address) -> Result<()> {
        TokensWithFees::push(self, token)
    }

    /// Drain all tokens with fees by popping from the back until empty
    /// Returns a `Vec<Address>` with all the tokens that were in storage
    /// Also sets token_in_fees_array to false for each token
    fn drain_tokens_with_fees(&mut self) -> Result<Vec<Address>> {
        let mut tokens = Vec::new();
        while let Some(token) = TokensWithFees::pop(self)? {
            tokens.push(token);
            if self.storage.spec().is_moderato() {
                self.sstore_token_in_fees_array(token, false)?;
            }
        }

        Ok(tokens)
    }

    /// Increment collected fees for the validator token
    fn increment_collected_fees(&mut self, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let collected_fees = self.sload_collected_fees()?;
        self.sstore_collected_fees(
            collected_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Get collected fees
    fn get_collected_fees(&mut self) -> Result<U256> {
        let fees = self.sload_collected_fees()?;
        Ok(fees)
    }

    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.sload_user_tokens(call.user)
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Result<Address> {
        let token = self.sload_validator_tokens(call.validator)?;

        if token.is_zero() {
            if self.storage.spec().is_allegretto() {
                Ok(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
            } else {
                Ok(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO)
            }
        } else {
            Ok(token)
        }
    }

    pub fn get_fee_token_balance(
        &mut self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> Result<IFeeManager::getFeeTokenBalanceReturn> {
        let mut token = self.sload_user_tokens(call.sender)?;

        if token.is_zero() {
            let validator_token = self.sload_validator_tokens(call.validator)?;

            if validator_token.is_zero() {
                return Ok(IFeeManager::getFeeTokenBalanceReturn {
                    _0: Address::ZERO,
                    _1: U256::ZERO,
                });
            } else {
                token = validator_token;
            }
        }

        let mut tip20_token = TIP20Token::from_address(token, self.storage);
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
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::hashmap::HashMapStorageProvider,
        tip20::{ISSUER_ROLE, ITIP20, TIP20Token, tests::initialize_path_usd, token_id_to_address},
    };

    fn setup_token_with_balance(
        storage: &mut HashMapStorageProvider,
        token: Address,
        user: Address,
        amount: U256,
    ) {
        initialize_path_usd(storage, user).unwrap();
        let mut tip20_token = TIP20Token::from_address(token, storage);

        // Initialize token
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                user,
                Address::ZERO,
            )
            .unwrap();

        // Grant issuer role to user and mint tokens
        tip20_token.grant_role_internal(user, *ISSUER_ROLE).unwrap();

        tip20_token
            .mint(user, ITIP20::mintCall { to: user, amount })
            .unwrap();

        // Approve fee manager
        tip20_token
            .approve(
                user,
                ITIP20::approveCall {
                    spender: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::MAX,
                },
            )
            .unwrap();
    }

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, user).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                user,
                Address::ZERO,
            )
            .unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(user, call);
        assert!(result.is_ok());

        let call = IFeeManager::userTokensCall { user };
        assert_eq!(fee_manager.user_tokens(call)?, token);
        Ok(())
    }

    #[test]
    fn test_set_user_token_cannot_be_path_usd_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let user = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, user).unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Try to set PathUSD as user token - should fail
        let call = IFeeManager::setUserTokenCall {
            token: PATH_USD_ADDRESS,
        };
        let result = fee_manager.set_user_token(user, call);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::FeeManagerError(
                FeeManagerError::InvalidToken(_)
            ))
        ));

        Ok(())
    }

    #[test]
    fn test_set_user_token_allows_path_usd_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - validation should not be enforced
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let user = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, user).unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Try to set PathUSD as user token - should succeed pre-Moderato
        let call = IFeeManager::setUserTokenCall {
            token: PATH_USD_ADDRESS,
        };
        let result = fee_manager.set_user_token(user, call);

        // Pre-Moderato: should be allowed to set PathUSD as user token
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, admin).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        let call = IFeeManager::setValidatorTokenCall { token };
        let result = fee_manager.set_validator_token(validator, call.clone(), validator);
        assert_eq!(
            result,
            Err(TempoPrecompileError::FeeManagerError(
                FeeManagerError::cannot_change_within_block()
            ))
        );

        // Now set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        let beneficiary = Address::random();
        let result = fee_manager.set_validator_token(validator, call, beneficiary);
        assert!(result.is_ok());

        let query_call = IFeeManager::validatorTokensCall { validator };
        let returned_token = fee_manager.validator_tokens(query_call)?;
        assert_eq!(returned_token, token);

        Ok(())
    }

    #[test]
    fn test_is_tip20_token() {
        let token_id = rand::random::<u64>();
        let token = token_id_to_address(token_id);
        assert!(is_tip20(token));

        let token = Address::random();
        assert!(!is_tip20(token));
    }

    #[test]
    fn test_collect_fee_pre_tx() {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let token = token_id_to_address(rand::random::<u64>());
        let max_amount = U256::from(10000);

        // Setup token with balance and approval
        setup_token_with_balance(&mut storage, token, user, U256::from(u64::MAX));

        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Set validator token
        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        let beneficiary = Address::random();
        fee_manager
            .set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall { token },
                beneficiary,
            )
            .unwrap();

        // Set user token
        fee_manager
            .set_user_token(user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        // Call collect_fee_pre_tx directly
        let result = fee_manager.collect_fee_pre_tx(user, token, validator, max_amount, validator);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), token);
    }

    #[test]
    fn test_collect_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let token = token_id_to_address(rand::random::<u64>());
        let actual_used = U256::from(6000);
        let refund_amount = U256::from(4000);

        // Setup token with balance for fee manager
        let admin = Address::random();

        // Initialize token and give fee manager tokens (simulating that collect_fee_pre_tx already happened)
        {
            initialize_path_usd(&mut storage, admin).unwrap();
            let mut tip20_token = TIP20Token::from_address(token, &mut storage);
            tip20_token
                .initialize(
                    "TestToken",
                    "TEST",
                    "USD",
                    PATH_USD_ADDRESS,
                    admin,
                    Address::ZERO,
                )
                .unwrap();

            tip20_token.grant_role_internal(admin, *ISSUER_ROLE)?;
            tip20_token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: TIP_FEE_MANAGER_ADDRESS,
                        amount: U256::from(100000000000000_u64),
                    },
                )
                .unwrap();
        }

        let validator = Address::random();
        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Set validator token
        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        fee_manager
            .set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall { token },
                Address::random(),
            )
            .unwrap();

        // Set user token
        fee_manager
            .set_user_token(user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        // Call collect_fee_post_tx directly
        let result =
            fee_manager.collect_fee_post_tx(user, actual_used, refund_amount, token, validator);
        assert!(result.is_ok());

        // Verify fees were tracked
        let tracked_amount = fee_manager.sload_collected_fees()?;
        assert_eq!(tracked_amount, actual_used);

        // Verify user got the refund
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        let balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user })?;
        assert_eq!(balance, refund_amount);

        Ok(())
    }

    #[test]
    fn test_rejects_non_usd() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let admin = Address::random();
        let token = token_id_to_address(rand::random::<u64>());
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize(
                "NonUSD",
                "NonUSD",
                "NonUSD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let validator = Address::random();
        let mut fee_manager = TipFeeManager::new(&mut storage);

        let user = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(user, call);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        let call = IFeeManager::setValidatorTokenCall { token };
        let result = fee_manager.set_validator_token(validator, call, Address::random());

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        Ok(())
    }

    #[test]
    fn test_prevent_insufficient_balance_transfer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();
        let token = token_id_to_address(rand::random::<u64>());

        // Manually set collected fees to 1000 and actual balance to 500 to simulate the attack.
        let collected_fees = U256::from(1000);
        let balance = U256::from(500);

        {
            // Initialize token
            initialize_path_usd(&mut storage, admin)?;
            let mut tip20_token = TIP20Token::from_address(token, &mut storage);
            tip20_token.initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )?;
            tip20_token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint tokens simulating `collected fees - attack burn`
            tip20_token.mint(
                admin,
                ITIP20::mintCall {
                    to: TIP_FEE_MANAGER_ADDRESS,
                    amount: balance,
                },
            )?;
        }

        {
            // Set validator token
            let mut fee_manager = TipFeeManager::new(&mut storage);
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall { token },
                Address::random(),
            )?;

            // Simulate collected fees
            fee_manager.sstore_collected_fees(collected_fees)?;

            // Execute block
            let result = fee_manager.execute_block(Address::ZERO, validator);
            assert!(result.is_ok());

            // Verify collected fees are cleared
            let remaining_fees = fee_manager.sload_collected_fees()?;
            assert_eq!(remaining_fees, U256::ZERO);
        }

        // Verify validator got the available balance
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        let validator_balance =
            tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
        assert_eq!(validator_balance, balance);

        let fee_manager_balance = tip20_token.balance_of(ITIP20::balanceOfCall {
            account: TIP_FEE_MANAGER_ADDRESS,
        })?;
        assert_eq!(fee_manager_balance, U256::ZERO);

        Ok(())
    }
}
