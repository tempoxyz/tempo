pub mod amm;
pub mod dispatch;

use alloy::primitives::B256;
pub use tempo_contracts::precompiles::{
    FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent,
};

use crate::{
    DEFAULT_FEE_TOKEN,
    error::{Result, TempoPrecompileError},
    storage::{PrecompileStorageProvider, StorageOps},
    tip_fee_manager::{
        amm::{PoolKey, TIPFeeAMM},
        slots::{collected_fees_slot, user_token_slot, validator_token_slot},
    },
    tip20::{ITIP20, TIP20Token, is_tip20, validate_usd_currency},
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, Bytes, IntoLogData, U256, uint};
use revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};

/// Storage slots for FeeManager-specific data.
///
/// IMPORTANT: FeeManager inherits from TIPFeeAMM and shares storage slots.
/// - Slots 0-3: Reserved for TIPFeeAMM data (pools, pool_exists, liquidity)
/// - Slots 4+: FeeManager-specific data starts here
///
/// This shared storage layout means that FeeManager can directly access and modify
/// AMM pool data using the same storage slots that TIPFeeAMM would use.
pub mod slots {
    use alloy::primitives::{Address, U256, uint};

    use crate::storage::slots::mapping_slot;

    // FeeManager-specific slots start at slot 4 to avoid collision with TIPFeeAMM slots (0-3)
    pub const VALIDATOR_TOKENS: U256 = uint!(4_U256);
    pub const USER_TOKENS: U256 = uint!(5_U256);
    pub const COLLECTED_FEES: U256 = uint!(6_U256);
    pub const TOKENS_WITH_FEES_LENGTH: U256 = uint!(7_U256);
    pub const TOKENS_WITH_FEES_BASE: U256 = uint!(8_U256);
    pub const TOKEN_IN_FEES_ARRAY: U256 = uint!(9_U256);

    pub fn validator_token_slot(validator: Address) -> U256 {
        mapping_slot(validator, VALIDATOR_TOKENS)
    }

    pub fn user_token_slot(user: Address) -> U256 {
        mapping_slot(user, USER_TOKENS)
    }

    pub fn collected_fees_slot() -> U256 {
        COLLECTED_FEES
    }

    /// Get slot for the length of tokens with fees array
    pub fn tokens_with_fees_length_slot() -> U256 {
        TOKENS_WITH_FEES_LENGTH
    }

    /// Get slot for specific index in tokens with fees array
    pub fn tokens_with_fees_slot(index: U256) -> U256 {
        TOKENS_WITH_FEES_BASE + index
    }

    /// Get slot for token in fees array mapping
    pub fn token_in_fees_array_slot(token: Address) -> U256 {
        mapping_slot(token, TOKEN_IN_FEES_ARRAY)
    }
}

/// TipFeeManager implements the FeeManager contract which inherits from TIPFeeAMM.
///
/// INHERITANCE MODEL:
/// - FeeManager "is-a" TIPFeeAMM, inheriting all AMM functionality
/// - They share the same contract address and storage space
/// - FeeManager delegates AMM operations to TIPFeeAMM using the same storage
///
/// STORAGE SHARING:
/// - Both contracts operate on the same storage at the same contract address
/// - TIPFeeAMM uses slots 0-3 for pool data
/// - FeeManager uses slots 4+ for fee-specific data
/// - When FeeManager creates a TIPFeeAMM instance, it passes the same address and storage
pub struct TipFeeManager<'a, S: PrecompileStorageProvider> {
    contract_address: Address,
    beneficiary: Address,
    storage: &'a mut S,
}

impl<'a, S: PrecompileStorageProvider> TipFeeManager<'a, S> {
    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    pub fn new(contract_address: Address, beneficiary: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            beneficiary,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`TipFeeManager`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.contract_address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    pub fn get_validator_token(&mut self) -> Result<Address> {
        let validator_slot = validator_token_slot(self.beneficiary);
        let token = self.sload(validator_slot)?.into_address();
        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    pub fn set_validator_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setValidatorTokenCall,
    ) -> Result<()> {
        if !is_tip20(call.token) {
            return Err(FeeManagerError::invalid_token().into());
        }

        if sender == self.beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        let slot = validator_token_slot(sender);
        self.sstore(slot, call.token.into_u256())?;

        // Emit ValidatorTokenSet event
        self.storage.emit_event(
            self.contract_address,
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

        // Validate that the fee token is USD
        validate_usd_currency(call.token, self.storage)?;

        let slot = user_token_slot(sender);
        self.sstore(slot, call.token.into_u256())?;

        // Emit UserTokenSet event
        self.storage.emit_event(
            self.contract_address,
            FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
                user: sender,
                token: call.token,
            })
            .into_log_data(),
        )
    }

    /// Collects fees from user before transaction execution.
    ///
    /// Determines fee token, verifies pool liquidity for swaps if needed, and transfers max fee amount.
    /// Unused gas is later returned via collect_fee_post_tx
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        _to: Address,
        max_amount: U256,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token()?;

        // Verify pool liquidity if user token differs from validator token
        if user_token != validator_token {
            let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
            if !amm.has_liquidity(user_token, validator_token, max_amount)? {
                return Err(FeeManagerError::insufficient_liquidity().into());
            }
        }

        let mut tip20_token = TIP20Token::from_address(user_token, self.storage);

        // Ensure that user and FeeManager are authorized to interact with the token
        tip20_token.ensure_transfer_authorized(fee_payer, self.contract_address)?;
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
    ) -> Result<()> {
        // Refund unused tokens to user
        if !refund_amount.is_zero() {
            let mut tip20_token = TIP20Token::from_address(fee_token, self.storage);
            tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;
        }

        // Execute fee swap and track collected fees
        if !actual_spending.is_zero() {
            let validator_token = self.get_validator_token()?;

            if fee_token == validator_token {
                self.increment_collected_fees(actual_spending)?;
            } else {
                let mut fee_amm = TIPFeeAMM::new(self.contract_address, self.storage);
                fee_amm.fee_swap(fee_token, validator_token, actual_spending)?;

                // Track the token to be swapped
                let slot = slots::token_in_fees_array_slot(fee_token);
                if self.sload(slot)?.is_zero() {
                    self.add_token_to_fees_array(fee_token)?;
                    self.sstore(slot, U256::from(true))?;
                }
            }
        }

        Ok(())
    }

    pub fn execute_block(&mut self, sender: Address) -> Result<()> {
        // Only protocol can call this
        if sender != Address::ZERO {
            return Err(FeeManagerError::only_system_contract().into());
        }

        // Get current validator's preferred token
        // If the token is not set we return the default fee token
        let validator_token = self.get_validator_token()?;

        // Process all collected fees and execute pending swaps
        let mut collected_fees = self.get_collected_fees()?;
        let tokens_with_fees = self.drain_tokens_with_fees()?;
        let mut fee_amm = TIPFeeAMM::new(self.contract_address, self.storage);

        for token in tokens_with_fees.iter() {
            if *token != validator_token {
                // Check if pool exists
                let pool_id = fee_amm.get_pool_id(*token, validator_token);
                let pool = fee_amm.get_pool(pool_id)?;

                if pool.reserve_user_token > 0 || pool.reserve_validator_token > 0 {
                    collected_fees = collected_fees
                        .checked_add(fee_amm.execute_pending_fee_swaps(*token, validator_token)?)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                }
            }
        }

        if !collected_fees.is_zero() {
            let mut token = TIP20Token::from_address(validator_token, self.storage);

            // If FeeManager or validator are blacklisted, we are not transferring any fees
            if token.is_transfer_authorized(self.contract_address, self.beneficiary)? {
                token
                    .transfer(
                        self.contract_address,
                        ITIP20::transferCall {
                            to: self.beneficiary,
                            amount: collected_fees,
                        },
                    )
                    .map_err(|_| {
                        IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                            IFeeManager::InsufficientFeeTokenBalance {},
                        )
                    })?;
            }

            self.clear_collected_fees()?;
        }

        Ok(())
    }

    /// Add a token to the tokens with fees array
    fn add_token_to_fees_array(&mut self, token: Address) -> Result<()> {
        let length_slot = slots::tokens_with_fees_length_slot();
        let length = self.sload(length_slot)?;
        let token_slot = slots::tokens_with_fees_slot(length);
        self.sstore(token_slot, token.into_u256())?;
        self.sstore(length_slot, length + U256::ONE)
    }

    /// Drain all tokens with fees by popping from the back until empty
    /// Returns a `Vec<Address>` with all the tokens that were in storage
    /// Also sets token_in_fees_array to false for each token
    fn drain_tokens_with_fees(&mut self) -> Result<Vec<Address>> {
        let mut tokens = Vec::new();
        let length_slot = slots::tokens_with_fees_length_slot();
        let mut length = self.sload(length_slot)?;

        while !length.is_zero() {
            let last_index = length - U256::ONE;
            let slot = slots::tokens_with_fees_slot(last_index);
            let token = self.sload(slot)?.into_address();
            tokens.push(token);

            // Set token in fees array to false
            let in_fees_slot = slots::token_in_fees_array_slot(token);
            self.sstore(in_fees_slot, U256::ZERO)?;

            length = last_index;
        }

        // Update storage with final length
        self.sstore(length_slot, U256::ZERO)?;

        Ok(tokens)
    }

    /// Increment collected fees for the validator token
    fn increment_collected_fees(&mut self, amount: U256) -> Result<()> {
        let slot = collected_fees_slot();
        let current_fees = self.sload(slot)?;
        self.sstore(
            slot,
            current_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Get collected fees
    fn get_collected_fees(&mut self) -> Result<U256> {
        let slot = collected_fees_slot();
        let fees = self.sload(slot)?;
        Ok(fees)
    }

    /// Clear collected fees
    fn clear_collected_fees(&mut self) -> Result<()> {
        let slot = collected_fees_slot();
        self.sstore(slot, U256::ZERO)
    }

    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Result<Address> {
        let slot = user_token_slot(call.user);
        Ok(self.sload(slot)?.into_address())
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Result<Address> {
        let slot = validator_token_slot(call.validator);
        let token = self.sload(slot)?.into_address();

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    pub fn get_fee_token_balance(
        &mut self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> Result<IFeeManager::getFeeTokenBalanceReturn> {
        let user_slot = user_token_slot(call.sender);
        let mut token = self.sload(user_slot)?.into_address();

        if token.is_zero() {
            let validator_slot = validator_token_slot(call.validator);
            let validator_token = self.sload(validator_slot)?.into_address();
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

    /// Retrieves pool data by ID
    pub fn pools(&mut self, call: ITIPFeeAMM::poolsCall) -> Result<ITIPFeeAMM::Pool> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        let pool = amm.get_pool(call.poolId)?;

        Ok(pool.into())
    }

    /// Mint liquidity tokens
    pub fn mint(&mut self, msg_sender: Address, call: ITIPFeeAMM::mintCall) -> Result<U256> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        let amount = amm.mint(
            msg_sender,
            call.userToken,
            call.validatorToken,
            call.amountUserToken,
            call.amountValidatorToken,
            call.to,
        )?;

        Ok(amount)
    }

    /// Burn liquidity tokens
    pub fn burn(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::burnCall,
    ) -> Result<ITIPFeeAMM::burnReturn> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.burn(
            msg_sender,
            call.userToken,
            call.validatorToken,
            call.liquidity,
            call.to,
        )
        .map(|(amount0, amount1)| ITIPFeeAMM::burnReturn {
            amountUserToken: amount0,
            amountValidatorToken: amount1,
        })
    }

    /// Get total supply of LP tokens for a pool (inherited from TIPFeeAMM)
    pub fn total_supply(&mut self, call: ITIPFeeAMM::totalSupplyCall) -> Result<U256> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_total_supply(call.poolId)
    }

    /// Get liquidity balance of a user for a pool (inherited from TIPFeeAMM)
    pub fn liquidity_balances(&mut self, call: ITIPFeeAMM::liquidityBalancesCall) -> Result<U256> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_balance_of(call.poolId, call.user)
    }

    pub fn get_pool_id(&mut self, call: ITIPFeeAMM::getPoolIdCall) -> B256 {
        let amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_pool_id(call.userToken, call.validatorToken)
    }

    pub fn get_pool(&mut self, call: ITIPFeeAMM::getPoolCall) -> Result<ITIPFeeAMM::Pool> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        let pool_key = PoolKey::new(call.userToken, call.validatorToken);
        let pool = amm.get_pool(pool_key.get_id())?;

        Ok(pool.into())
    }

    /// Execute a rebalance swap
    pub fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::rebalanceSwapCall,
    ) -> Result<U256> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.rebalance_swap(
            msg_sender,
            call.userToken,
            call.validatorToken,
            call.amountOut,
            call.to,
        )
    }
}

impl<'a, S: PrecompileStorageProvider> StorageOps for TipFeeManager<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) -> Result<()> {
        self.storage.sstore(self.contract_address, slot, value)
    }

    fn sload(&mut self, slot: U256) -> Result<U256> {
        self.storage.sload(self.contract_address, slot)
    }
}

#[cfg(test)]
mod tests {
    use tempo_contracts::precompiles::TIP20Error;

    use super::*;
    use crate::{
        LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::hashmap::HashMapStorageProvider,
        tip_fee_manager::slots::collected_fees_slot,
        tip20::{
            ISSUER_ROLE, ITIP20, TIP20Token, tests::initialize_linking_usd, token_id_to_address,
        },
    };

    fn setup_token_with_balance(
        storage: &mut HashMapStorageProvider,
        token: Address,
        user: Address,
        amount: U256,
    ) {
        initialize_linking_usd(storage, user).unwrap();
        let mut tip20_token = TIP20Token::from_address(token, storage);

        // Initialize token
        tip20_token
            .initialize("TestToken", "TEST", "USD", LINKING_USD_ADDRESS, user)
            .unwrap();

        // Grant issuer role to user and mint tokens
        let mut roles = tip20_token.get_roles_contract();
        roles.grant_role_internal(user, *ISSUER_ROLE).unwrap();

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
        let validator = Address::random();
        let user = Address::random();

        // Initialize LinkingUSD first
        initialize_linking_usd(&mut storage, user).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize("TestToken", "TEST", "USD", LINKING_USD_ADDRESS, user)
            .unwrap();

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(user, call);
        assert!(result.is_ok());

        let call = IFeeManager::userTokensCall { user };
        assert_eq!(fee_manager.user_tokens(call)?, token);
        Ok(())
    }

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();

        // Initialize LinkingUSD first
        initialize_linking_usd(&mut storage, admin).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize("TestToken", "TEST", "USD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        let call = IFeeManager::setValidatorTokenCall { token };
        let result = fee_manager.set_validator_token(validator, call.clone());
        assert_eq!(
            result,
            Err(TempoPrecompileError::FeeManagerError(
                FeeManagerError::cannot_change_within_block()
            ))
        );

        // Now set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        fee_manager.beneficiary = Address::random();
        let result = fee_manager.set_validator_token(validator, call);
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

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        // Set validator token
        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        fee_manager.beneficiary = Address::random();
        fee_manager
            .set_validator_token(validator, IFeeManager::setValidatorTokenCall { token })
            .unwrap();
        fee_manager.beneficiary = validator;

        // Set user token
        fee_manager
            .set_user_token(user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        // Call collect_fee_pre_tx directly
        let result = fee_manager.collect_fee_pre_tx(user, token, validator, max_amount);
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
            initialize_linking_usd(&mut storage, admin).unwrap();
            let mut tip20_token = TIP20Token::from_address(token, &mut storage);
            tip20_token
                .initialize("TestToken", "TEST", "USD", LINKING_USD_ADDRESS, admin)
                .unwrap();

            let mut roles = tip20_token.get_roles_contract();
            roles.grant_role_internal(admin, *ISSUER_ROLE)?;

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
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        // Set validator token
        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        fee_manager.beneficiary = Address::random();
        fee_manager
            .set_validator_token(validator, IFeeManager::setValidatorTokenCall { token })
            .unwrap();
        fee_manager.beneficiary = validator;

        // Set user token
        fee_manager
            .set_user_token(user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        // Call collect_fee_post_tx directly
        let result = fee_manager.collect_fee_post_tx(user, actual_used, refund_amount, token);
        assert!(result.is_ok());

        // Verify user got the refund
        {
            let mut tip20_token = TIP20Token::from_address(token, &mut storage);
            let balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(balance, refund_amount);
        }

        // Verify fees were tracked
        let fees_slot = collected_fees_slot();
        let tracked_amount = storage.sload(TIP_FEE_MANAGER_ADDRESS, fees_slot).unwrap();
        assert_eq!(tracked_amount, actual_used);

        Ok(())
    }

    #[test]
    fn test_rejects_non_usd() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let admin = Address::random();
        let token = token_id_to_address(rand::random::<u64>());
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize("NonUSD", "NonUSD", "NonUSD", LINKING_USD_ADDRESS, admin)
            .unwrap();

        let validator = Address::random();
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        let user = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(user, call);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        // Set beneficiary to a random address to avoid `CannotChangeWithinBlock` error
        fee_manager.beneficiary = Address::random();

        let call = IFeeManager::setValidatorTokenCall { token };
        let result = fee_manager.set_validator_token(validator, call);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        Ok(())
    }
}
