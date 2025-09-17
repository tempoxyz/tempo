pub mod amm;
pub mod fee;

use crate::contracts::{
    TIP20Token, address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip_fee_manager::{
        amm::{PoolKey, TIPFeeAMM},
        slots::{
            collected_fees_slot, token_in_fees_array_slot, user_token_slot, validator_token_slot,
        },
    },
    types::{FeeManagerEvent, IFeeManager, ITIP20, ITIPFeeAMM},
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, IntoLogData, U256, uint};
use alloy_primitives::Bytes;
use reth_evm::revm::{
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
    use alloy::primitives::{U256, uint};
    use alloy_primitives::Address;

    use crate::contracts::storage::slots::mapping_slot;

    // FeeManager-specific slots start at slot 4 to avoid collision with TIPFeeAMM slots (0-3)
    pub const VALIDATOR_TOKENS: U256 = uint!(4_U256);
    pub const USER_TOKENS: U256 = uint!(5_U256);
    pub const COLLECTED_FEES: U256 = uint!(6_U256);
    pub const TOKENS_WITH_FEES_LENGTH: U256 = uint!(11_U256);
    pub const TOKENS_WITH_FEES_ARRAY: U256 = uint!(12_U256);
    pub const TOKEN_IN_FEES_ARRAY: U256 = uint!(15_U256);

    pub fn validator_token_slot(validator: &Address) -> U256 {
        mapping_slot(validator, VALIDATOR_TOKENS)
    }

    pub fn user_token_slot(user: &Address) -> U256 {
        mapping_slot(user, USER_TOKENS)
    }

    pub fn collected_fees_slot(token: &Address) -> U256 {
        mapping_slot(token, COLLECTED_FEES)
    }

    pub fn token_in_fees_array_slot(token: &Address) -> U256 {
        mapping_slot(token, TOKEN_IN_FEES_ARRAY)
    }

    pub fn tokens_with_fees_array_slot(_index: U256) -> U256 {
        todo!()
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
pub struct TipFeeManager<'a, S: StorageProvider> {
    contract_address: Address,
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> TipFeeManager<'a, S> {
    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`TipFeeManager`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.contract_address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");
    }

    pub fn set_validator_token(
        &mut self,
        sender: &Address,
        call: IFeeManager::setValidatorTokenCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // TODO: ensure sender is a validator

        if call.token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        let slot = validator_token_slot(sender);
        self.sstore(slot, call.token.into_u256());

        // Emit ValidatorTokenSet event
        self.storage
            .emit_event(
                self.contract_address,
                FeeManagerEvent::ValidatorTokenSet(IFeeManager::ValidatorTokenSet {
                    validator: *sender,
                    token: call.token,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn set_user_token(
        &mut self,
        sender: &Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        if call.token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        let slot = user_token_slot(sender);
        self.sstore(slot, call.token.into_u256());

        // Emit UserTokenSet event
        self.storage
            .emit_event(
                self.contract_address,
                FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
                    user: *sender,
                    token: call.token,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn collect_fee_pre_tx(
        &mut self,
        user: Address,
        max_amount: U256,
        validator: Address,
    ) -> Result<Address, IFeeManager::IFeeManagerErrors> {
        // Get the validator's token preference
        let validator_slot = validator_token_slot(&validator);
        let validator_token = self.sload(validator_slot).into_address();

        if validator_token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        // Get the user's fee token preference (falls back to validator token if not set)
        let user_slot = user_token_slot(&user);
        let user_token_raw = self.sload(user_slot).into_address();
        let user_token = if user_token_raw.is_zero() {
            validator_token
        } else {
            user_token_raw
        };

        // Verify pool liquidity if user token differs from validator token
        if user_token != validator_token {
            let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
            let pool_key = PoolKey::new(user_token, validator_token);
            let pool_id = pool_key.get_id();

            // Check if pool exists
            if !amm.pool_exists(&pool_id) {
                return Err(IFeeManager::IFeeManagerErrors::PoolDoesNotExist(
                    IFeeManager::PoolDoesNotExist {},
                ));
            }

            // Check pool reserves for sufficient liquidity
            let pool = amm.get_pool(&pool_id);
            if U256::from(pool.reserve_user_token) < Self::MINIMUM_BALANCE
                || U256::from(pool.reserve_validator_token) < Self::MINIMUM_BALANCE
            {
                return Err(IFeeManager::IFeeManagerErrors::InsufficientPoolBalance(
                    IFeeManager::InsufficientPoolBalance {},
                ));
            }
        }

        // Transfer maximum fee from user to fee manager
        // TODO: Add validation when setting user/validator tokens to ensure they are TIP20s
        // rather than checking here. This validation should be added in setUserToken/setValidatorToken.
        let token_id = address_to_token_id_unchecked(&user_token);
        let mut tip20_token = TIP20Token::new(token_id, self.storage);

        tip20_token
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: user,
                    to: self.contract_address,
                    amount: max_amount,
                },
            )
            .map_err(|_| {
                IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                    IFeeManager::InsufficientFeeTokenBalance {},
                )
            })?;

        // Return the user's token preference
        Ok(user_token)
    }

    pub fn collect_fee_post_tx(
        &mut self,
        user: Address,
        actual_used: U256,
        refund_amount: U256,
        user_token: Address,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Refund unused tokens to user
        if refund_amount > U256::ZERO {
            let token_id = address_to_token_id_unchecked(&user_token);
            let mut tip20_token = TIP20Token::new(token_id, self.storage);

            tip20_token
                .transfer(
                    &self.contract_address,
                    ITIP20::transferCall {
                        to: user,
                        amount: refund_amount,
                    },
                )
                .map_err(|_| {
                    IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                        IFeeManager::InsufficientFeeTokenBalance {},
                    )
                })?;
        }

        // Track collected fees (only the actual used amount)
        if !actual_used.is_zero() {
            self.track_collected_fees(&user_token, actual_used)?;
        }

        Ok(())
    }

    /// Helper function to track collected fees and add token to tracking array if needed
    fn track_collected_fees(
        &mut self,
        token: &Address,
        amount: U256,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Get current collected fees for this token
        let fees_slot = collected_fees_slot(token);
        let current_amount = self.sload(fees_slot);

        // If this is the first time collecting fees for this token, add it to the tracking array
        if current_amount.is_zero() {
            let in_array_slot = token_in_fees_array_slot(token);
            let in_array = self.sload(in_array_slot) != U256::ZERO;

            if !in_array {
                // Get current array length
                let length_value = self.sload(slots::TOKENS_WITH_FEES_LENGTH);

                // Store token address in the array at current index
                let token_slot = slots::TOKENS_WITH_FEES_ARRAY + length_value;
                self.sstore(token_slot, token.into_u256());

                // Mark token as being in the array
                self.sstore(in_array_slot, U256::ONE);

                // Increment array length
                self.sstore(slots::TOKENS_WITH_FEES_LENGTH, length_value + U256::from(1));
            }
        }

        // Update collected fees amount
        let new_amount = current_amount.saturating_add(amount);
        self.sstore(fees_slot, new_amount);

        Ok(())
    }

    pub fn execute_block(
        &mut self,
        sender: &Address,
        call: IFeeManager::executeBlockCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Only protocol can call this (block-end execution)
        if *sender != Address::ZERO {
            return Err(IFeeManager::IFeeManagerErrors::OnlySystemContract(
                IFeeManager::OnlySystemContract {},
            ));
        }

        let validator = call.validator;

        // Get validator's preferred token
        let validator_slot = validator_token_slot(&validator);
        let validator_token = self.sload(validator_slot).into_address();

        if validator_token.is_zero() {
            // If no validator token set, nothing to do
            return Ok(());
        }

        // Get the number of tokens with pending fees
        let tokens_with_fees_length = self.sload(slots::TOKENS_WITH_FEES_LENGTH).to::<usize>();

        // Process each token with pending fees
        for i in 0..tokens_with_fees_length {
            // Get token address from array
            let token_slot = slots::TOKENS_WITH_FEES_ARRAY + U256::from(i);
            let token_address = self.sload(token_slot).into_address();

            if token_address == Address::ZERO {
                continue;
            }

            // Get collected fee amount for this token
            let fees_slot = collected_fees_slot(&token_address);
            let fees_value = self.sload(fees_slot);
            let fee_amount_u128 = (fees_value & U256::from(u128::MAX)).to::<u128>();

            if fee_amount_u128 == 0 {
                continue;
            }

            let fee_amount = U256::from(fee_amount_u128);

            if token_address == validator_token {
                // Token is already validator's preferred token, just transfer
                let token_id = address_to_token_id_unchecked(&validator_token);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);

                tip20_token
                    .transfer(
                        &self.contract_address,
                        ITIP20::transferCall {
                            to: validator,
                            amount: fee_amount,
                        },
                    )
                    .map_err(|_| {
                        IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                            IFeeManager::InsufficientFeeTokenBalance {},
                        )
                    })?;
            } else {
                // Need to swap to validator's token via AMM
                // TODO: Implement swap when the AMM swap function is available
                // For now, just transfer the tokens as-is
                let token_id = address_to_token_id_unchecked(&token_address);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);

                tip20_token
                    .transfer(
                        &self.contract_address,
                        ITIP20::transferCall {
                            to: validator,
                            amount: fee_amount,
                        },
                    )
                    .map_err(|_| {
                        IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                            IFeeManager::InsufficientFeeTokenBalance {},
                        )
                    })?;
            }

            // Clear the fee info for this token
            self.sstore(fees_slot, U256::ZERO);

            // Clear token from array
            self.sstore(token_slot, U256::ZERO);

            // Clear token from tracking map
            let in_array_slot = token_in_fees_array_slot(&token_address);
            self.sstore(in_array_slot, U256::ZERO);
        }

        // Reset tokens with fees tracking
        self.sstore(slots::TOKENS_WITH_FEES_LENGTH, U256::ZERO);

        Ok(())
    }

    pub fn collected_fees(&mut self, token: &Address) -> U256 {
        let slot = collected_fees_slot(token);
        self.sload(slot)
    }

    pub fn get_tokens_with_fees_length(&mut self) -> U256 {
        use crate::contracts::tip_fee_manager::slots::TOKENS_WITH_FEES_LENGTH;
        self.sload(TOKENS_WITH_FEES_LENGTH)
    }

    pub fn get_token_with_fees(&mut self, index: U256) -> Address {
        let token_slot = slots::TOKENS_WITH_FEES_ARRAY + index;
        self.sload(token_slot).into_address()
    }

    pub fn token_in_fees_array(&mut self, token: &Address) -> bool {
        let slot = token_in_fees_array_slot(token);
        !self.sload(slot).is_zero()
    }

    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Address {
        let slot = user_token_slot(&call.user);
        self.sload(slot).into_address()
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Address {
        let slot = validator_token_slot(&call.validator);
        self.sload(slot).into_address()
    }

    pub fn get_fee_token_balance(
        &mut self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> IFeeManager::getFeeTokenBalanceReturn {
        let user_slot = user_token_slot(&call.sender);
        let mut token = self.sload(user_slot).into_address();

        if token.is_zero() {
            let validator_slot = validator_token_slot(&call.validator);
            let validator_token = self.sload(validator_slot).into_address();
            if validator_token.is_zero() {
                return IFeeManager::getFeeTokenBalanceReturn {
                    _0: Address::ZERO,
                    _1: U256::ZERO,
                };
            } else {
                token = validator_token;
            }
        }

        let token_id = address_to_token_id_unchecked(&token);
        let mut tip20_token = TIP20Token::new(token_id, self.storage);
        let token_balance = tip20_token.balance_of(ITIP20::balanceOfCall {
            account: call.sender,
        });

        IFeeManager::getFeeTokenBalanceReturn {
            _0: token,
            _1: token_balance,
        }
    }

    /// Retrieves pool data by ID
    pub fn pools(&mut self, call: ITIPFeeAMM::poolsCall) -> ITIPFeeAMM::Pool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_pool(&call.poolId).into()
    }

    /// Checks if a pool exists
    pub fn pool_exists(&mut self, call: ITIPFeeAMM::poolExistsCall) -> bool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.pool_exists(&call.poolId)
    }

    /// Mint liquidity tokens
    pub fn mint(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::mintCall,
    ) -> Result<U256, ITIPFeeAMM::ITIPFeeAMMErrors> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.mint(
            msg_sender,
            call.userToken,
            call.validatorToken,
            call.amountUserToken,
            call.amountValidatorToken,
            call.to,
        )
    }

    /// Burn liquidity tokens
    pub fn burn(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::burnCall,
    ) -> Result<ITIPFeeAMM::burnReturn, ITIPFeeAMM::ITIPFeeAMMErrors> {
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
    pub fn total_supply(&mut self, call: ITIPFeeAMM::totalSupplyCall) -> U256 {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_total_supply(&call.poolId)
    }

    /// Get liquidity balance of a user for a pool (inherited from TIPFeeAMM)
    pub fn liquidity_balances(&mut self, call: ITIPFeeAMM::liquidityBalancesCall) -> U256 {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_balance_of(&call.poolId, &call.user)
    }

    /// Creates a new liquidity pool. Calls inner [`TIPFeeAMM::create_pool`] to initialize storage
    /// pool related variables.
    pub fn create_pool(
        &mut self,
        call: ITIPFeeAMM::createPoolCall,
    ) -> Result<(), ITIPFeeAMM::ITIPFeeAMMErrors> {
        // Delegate to TIPFeeAMM using the SAME contract address and storage
        // This works because FeeManager "is" a TIPFeeAMM at the storage level
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.create_pool(call.userToken, call.validatorToken)?;

        // Initialize fee tracking for the pool tokens
        let user_token_slot = collected_fees_slot(&call.userToken);
        let validator_token_slot = collected_fees_slot(&call.validatorToken);
        let fee_info_value = U256::from(1u128) << 128;
        self.sstore(user_token_slot, fee_info_value);
        self.sstore(validator_token_slot, fee_info_value);

        Ok(())
    }

    pub fn get_pool_id(&mut self, call: ITIPFeeAMM::getPoolIdCall) -> alloy::primitives::B256 {
        let amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_pool_id(call.userToken, call.validatorToken)
    }

    pub fn get_pool(&mut self, call: ITIPFeeAMM::getPoolCall) -> ITIPFeeAMM::Pool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        let pool_key = PoolKey::new(call.userToken, call.validatorToken);
        amm.get_pool(&pool_key.get_id()).into()
    }
}

impl<'a, S: StorageProvider> StorageOps for TipFeeManager<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.contract_address, slot, value)
            .expect("TODO: handle error");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.contract_address, slot)
            .expect("TODO: handle error")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        contracts::{HashMapStorageProvider, tip20::ISSUER_ROLE},
    };

    fn setup_token_with_balance(
        storage: &mut HashMapStorageProvider,
        token: Address,
        user: Address,
        amount: U256,
    ) {
        let token_id = address_to_token_id_unchecked(&token);
        let mut tip20_token = TIP20Token::new(token_id, storage);

        // Initialize token
        tip20_token
            .initialize("TestToken", "TEST", "USD", &user)
            .unwrap();

        // Grant issuer role to user and mint tokens
        let mut roles = tip20_token.get_roles_contract();
        roles.grant_role_internal(&user, *ISSUER_ROLE);

        tip20_token
            .mint(&user, ITIP20::mintCall { to: user, amount })
            .unwrap();

        // Approve fee manager
        tip20_token
            .approve(
                &user,
                ITIP20::approveCall {
                    spender: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::MAX,
                },
            )
            .unwrap();
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        let token_a = Address::random();
        let token_b = Address::random();
        let call = ITIPFeeAMM::createPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        };

        let result = fee_manager.create_pool(call);
        assert!(result.is_ok());

        let pool_key = PoolKey::new(token_a, token_b);
        let pool_id = pool_key.get_id();
        let exists_call = ITIPFeeAMM::poolExistsCall { poolId: pool_id };
        assert!(fee_manager.pool_exists(exists_call));
    }

    #[test]
    fn test_set_user_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        let user = Address::random();
        let token = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(&user, call);
        assert!(result.is_ok());

        let call = IFeeManager::userTokensCall { user };
        assert_eq!(fee_manager.user_tokens(call), token);
    }

    #[test]
    fn test_set_validator_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        let validator = Address::random();
        let token = Address::random();

        let call = IFeeManager::setValidatorTokenCall { token };
        let result = fee_manager.set_validator_token(&validator, call);
        assert!(result.is_ok());

        let query_call = IFeeManager::validatorTokensCall { validator };
        let returned_token = fee_manager.validator_tokens(query_call);
        assert_eq!(returned_token, token);
    }

    #[test]
    fn test_collect_fee_pre_tx() {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let token = Address::random();
        let max_amount = U256::from(10000);

        // Setup token with balance and approval
        setup_token_with_balance(&mut storage, token, user, U256::from(100000));

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        // Set validator token
        fee_manager
            .set_validator_token(&validator, IFeeManager::setValidatorTokenCall { token })
            .unwrap();

        // Set user token (same as validator for simplicity)
        fee_manager
            .set_user_token(&user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        // Call collect_fee_pre_tx directly
        let result = fee_manager.collect_fee_pre_tx(user, max_amount, validator);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), token);
    }

    #[test]
    fn test_collect_fee_post_tx() {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let token = Address::random();
        let actual_used = U256::from(6000);
        let refund_amount = U256::from(4000);

        // Setup token with balance for fee manager
        let token_id = address_to_token_id_unchecked(&token);
        let admin = Address::random();

        // Initialize token and give fee manager tokens (simulating that collect_fee_pre_tx already happened)
        {
            let mut tip20_token = TIP20Token::new(token_id, &mut storage);
            tip20_token
                .initialize("TestToken", "TEST", "USD", &admin)
                .unwrap();

            let mut roles = tip20_token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            tip20_token
                .mint(
                    &admin,
                    ITIP20::mintCall {
                        to: TIP_FEE_MANAGER_ADDRESS,
                        amount: U256::from(10000),
                    },
                )
                .unwrap();
        }

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        // Call collect_fee_post_tx directly
        let result = fee_manager.collect_fee_post_tx(user, actual_used, refund_amount, token);
        assert!(result.is_ok());

        // Verify user got the refund
        {
            let mut tip20_token = TIP20Token::new(token_id, &mut storage);
            let balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user });
            assert_eq!(balance, refund_amount);
        }

        // Verify fees were tracked
        let fees_slot = collected_fees_slot(&token);
        let tracked_amount = storage.sload(TIP_FEE_MANAGER_ADDRESS, fees_slot).unwrap();
        assert_eq!(tracked_amount, actual_used);
    }
}
