use crate::contracts::{
    TIP20Token, address_to_token_id_unchecked,
    storage::{StorageProvider, slots::mapping_slot},
    tip_fee_amm::TIPFeeAMM,
    types::{IFeeManager, ITIP20, ITIPFeeAMM},
};

// Re-export PoolKey for backward compatibility with tests
pub use crate::contracts::tip_fee_amm::PoolKey;
use alloy::primitives::{Address, U256};
use reth_evm::revm::interpreter::instructions::utility::{IntoAddress, IntoU256};

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

    // FeeManager-specific slots start at slot 4 to avoid collision with TIPFeeAMM slots (0-3)
    pub const VALIDATOR_TOKENS: U256 = uint!(4_U256);
    pub const USER_TOKENS: U256 = uint!(5_U256);
    pub const COLLECTED_FEES: U256 = uint!(6_U256);
    pub const TOKENS_WITH_FEES: U256 = uint!(7_U256); // Array of tokens with pending fees
    pub const TOKENS_WITH_FEES_LENGTH: U256 = uint!(11_U256);
    pub const TOKEN_IN_FEES_ARRAY: U256 = uint!(15_U256);
}

#[derive(Debug)]
pub enum FeeToken {
    User(TokenBalance),
    Validator(TokenBalance),
}

#[derive(Debug)]
pub struct TokenBalance {
    pub address: Address,
    pub balance: U256,
}

impl TokenBalance {
    pub fn new(address: Address, balance: U256) -> Self {
        Self { address, balance }
    }
}

impl FeeToken {
    /// Returns the balance from the fee token
    pub fn balance(&self) -> U256 {
        match self {
            Self::User(token_balance) => token_balance.balance,
            Self::Validator(token_balance) => token_balance.balance,
        }
    }

    /// Returns the token address from the fee token
    pub fn address(&self) -> Address {
        match self {
            Self::User(token_balance) => token_balance.address,
            Self::Validator(token_balance) => token_balance.address,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Deposit,
    Withdraw,
}

impl From<u8> for OperationType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Deposit,
            1 => Self::Withdraw,
            _ => panic!("Invalid operation type: {value}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedOperation {
    pub op_type: OperationType,
    pub user: Address,
    pub pool_key: PoolKey,
    // NOTE: for deposits, token amount. For withdrawals, liquidity amount
    pub amount: U256,
    // NOTE: for deposits, deposit token, for withdrawals, default withdrawal token
    pub token: Address,
}

impl From<QueuedOperation> for ITIPFeeAMM::QueuedOperation {
    fn from(op: QueuedOperation) -> Self {
        Self {
            opType: op.op_type as u8,
            user: op.user,
            poolKey: op.pool_key.get_id(),
            amount: op.amount,
            token: op.token,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeeInfo {
    pub amount: u128,
    pub has_been_set: bool,
}

impl From<FeeInfo> for IFeeManager::FeeInfo {
    fn from(fee_info: FeeInfo) -> Self {
        Self {
            amount: fee_info.amount,
            hasBeenSet: fee_info.has_been_set,
        }
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
    pub const MINIMUM_BALANCE: U256 = U256::from_limbs([1_000_000_000u64, 0, 0, 0]); // 1e9

    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
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

        let slot = self.get_validator_token_slot(sender);
        let token = call.token.into_u256();

        self.storage
            .sstore(self.contract_address, slot, token)
            .expect("TODO: handle error");

        // TODO: emit event

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

        let slot = self.get_user_token_slot(sender);
        let token = call.token.into_u256();
        self.storage
            .sstore(self.contract_address, slot, token)
            .expect("TODO: handle error");

        // TODO: emit event

        Ok(())
    }

    /// Creates a new liquidity pool. This demonstrates the inheritance relationship:
    /// FeeManager delegates to TIPFeeAMM for core AMM operations while adding fee tracking.
    pub fn create_pool(
        &mut self,
        call: ITIPFeeAMM::createPoolCall,
    ) -> Result<(), ITIPFeeAMM::ITIPFeeAMMErrors> {
        // Delegate to TIPFeeAMM using the SAME contract address and storage
        // This works because FeeManager "is" a TIPFeeAMM at the storage level
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.create_pool(call.clone())?;

        // Initialize fee tracking for the pool tokens
        let pool_key = PoolKey::new(call.tokenA, call.tokenB);
        let token0_fees_slot = self.get_collected_fees_slot(&pool_key.token0);
        let token1_fees_slot = self.get_collected_fees_slot(&pool_key.token1);
        let fee_info_value = U256::from(1u128) << 128;
        self.storage
            .sstore(self.contract_address, token0_fees_slot, fee_info_value)
            .expect("TODO: handle error");
        self.storage
            .sstore(self.contract_address, token1_fees_slot, fee_info_value)
            .expect("TODO: handle error");

        Ok(())
    }

    /// Delegates pool ID calculation to TIPFeeAMM (inherited functionality)
    pub fn get_pool_id(&mut self, call: ITIPFeeAMM::getPoolIdCall) -> alloy::primitives::B256 {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_pool_id(call)
    }

    /// Delegates pool data retrieval to TIPFeeAMM (inherited functionality)
    pub fn get_pool(&mut self, call: ITIPFeeAMM::getPoolCall) -> ITIPFeeAMM::Pool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.get_pool(call)
    }

    // TODO: swap function
    pub fn collect_fee(
        &mut self,
        user: Address,
        coinbase: Address,
        amount: U256,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        let validator_token = self.get_validator_token(&coinbase)?;
        let user_token = self.get_user_token(&user, &validator_token);

        if user_token != validator_token {
            // Create TIPFeeAMM instance to access inherited pool functionality
            // Uses same address and storage - demonstrating shared state
            let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);

            // Check if pool exists (using inherited TIPFeeAMM functionality)
            if !amm.pool_exists_for_tokens(user_token, validator_token) {
                return Err(IFeeManager::IFeeManagerErrors::PoolDoesNotExist(
                    IFeeManager::PoolDoesNotExist {},
                ));
            }

            // Check pool reserves
            let pool_key = PoolKey::new(user_token, validator_token);
            let pool_id = pool_key.get_id();
            let (reserve0, reserve1) = amm.get_pool_reserves(&pool_id);

            if reserve0 < Self::MINIMUM_BALANCE || reserve1 < Self::MINIMUM_BALANCE {
                return Err(IFeeManager::IFeeManagerErrors::InsufficientPoolBalance(
                    IFeeManager::InsufficientPoolBalance {},
                ));
            }
        }

        let token_id = address_to_token_id_unchecked(&user_token);
        let mut tip20_token = TIP20Token::new(token_id, self.storage);

        dbg!("getting here");
        tip20_token
            .transfer(
                &user,
                ITIP20::transferCall {
                    to: self.contract_address,
                    amount,
                },
            )
            .expect("TODO: handle error");

        // Cache fee info to minimize storage access
        let mut fee_info = self.get_fee_info(&user_token);

        // Add to tracking array only if this is the first time collecting fees for this token
        if fee_info.amount == 0 && !fee_info.has_been_set {
            let in_array_slot = self.get_token_in_fees_array_slot(&user_token);
            let in_array = self
                .storage
                .sload(self.contract_address, in_array_slot)
                .expect("TODO: handle error")
                != U256::ZERO;

            if !in_array {
                // Mark token as being in the array
                self.storage
                    .sstore(self.contract_address, in_array_slot, U256::ONE)
                    .expect("TODO: handle error");

                // Get current array length
                let length_value = self
                    .storage
                    .sload(self.contract_address, slots::TOKENS_WITH_FEES_LENGTH)
                    .expect("TODO: handle error");

                // Store token address in the array at current index
                let token_slot = slots::TOKENS_WITH_FEES + length_value;
                self.storage
                    .sstore(self.contract_address, token_slot, user_token.into_u256())
                    .expect("TODO: handle error");

                // Increment array length
                self.storage
                    .sstore(
                        self.contract_address,
                        slots::TOKENS_WITH_FEES_LENGTH,
                        length_value + U256::from(1),
                    )
                    .expect("TODO: handle error");
            }
        }

        // Update fee info in single storage write
        fee_info.amount = fee_info.amount.saturating_add(amount.to::<u128>());
        fee_info.has_been_set = true;

        self.set_fee_info(&user_token, &fee_info);

        Ok(())
    }

    fn get_validator_token(
        &mut self,
        validator: &Address,
    ) -> Result<Address, IFeeManager::IFeeManagerErrors> {
        let validator_slot = self.get_validator_token_slot(validator);
        let validator_token = self
            .storage
            .sload(self.contract_address, validator_slot)
            .expect("TODO: handle error")
            .into_address();

        if validator_token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        Ok(validator_token)
    }

    fn get_user_token(&mut self, user: &Address, validator_token: &Address) -> Address {
        let user_slot = self.get_user_token_slot(user);
        let user_token = self
            .storage
            .sload(self.contract_address, user_slot)
            .expect("TODO: handle error")
            .into_address();

        if user_token.is_zero() {
            *validator_token
        } else {
            user_token
        }
    }

    fn get_fee_info(&mut self, token: &Address) -> FeeInfo {
        let fees_slot = self.get_collected_fees_slot(token);
        let fees_value = self
            .storage
            .sload(self.contract_address, fees_slot)
            .expect("TODO: handle error");

        let amount = (fees_value & U256::from(u128::MAX)).to::<u128>();
        let has_been_set = fees_value >= (U256::from(1u128) << 128);

        FeeInfo {
            amount,
            has_been_set,
        }
    }

    fn set_fee_info(&mut self, token: &Address, fee_info: &FeeInfo) {
        let fees_slot = self.get_collected_fees_slot(token);
        let fees_value = if fee_info.has_been_set {
            (U256::from(1u128) << 128) | U256::from(fee_info.amount)
        } else {
            U256::from(fee_info.amount)
        };
        self.storage
            .sstore(self.contract_address, fees_slot, fees_value)
            .expect("TODO: handle error");
    }

    pub fn collect_fee_pre_tx(
        &mut self,
        sender: &Address,
        user: Address,
        max_amount: U256,
        validator: Address,
    ) -> Result<Address, IFeeManager::IFeeManagerErrors> {
        // Only protocol can call this
        if *sender != Address::ZERO {
            return Err(IFeeManager::IFeeManagerErrors::OnlySystemContract(
                IFeeManager::OnlySystemContract {},
            ));
        }

        // Get the validator's token preference
        let validator_token = self.get_validator_token(&validator)?;
        // Get the user's fee token preference (falls back to validator token if not set)
        let user_token = self.get_user_token(&user, &validator_token);

        // Verify pool liquidity if user token differs from validator token
        if user_token != validator_token {
            let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);

            // Check if pool exists
            if !amm.pool_exists_for_tokens(user_token, validator_token) {
                return Err(IFeeManager::IFeeManagerErrors::PoolDoesNotExist(
                    IFeeManager::PoolDoesNotExist {},
                ));
            }

            // Check pool reserves for sufficient liquidity
            let pool_key = PoolKey::new(user_token, validator_token);
            let pool_id = pool_key.get_id();
            let (reserve0, reserve1) = amm.get_pool_reserves(&pool_id);

            if reserve0 < Self::MINIMUM_BALANCE || reserve1 < Self::MINIMUM_BALANCE {
                return Err(IFeeManager::IFeeManagerErrors::InsufficientPoolBalance(
                    IFeeManager::InsufficientPoolBalance {},
                ));
            }
        }

        // Transfer maximum fee from user to fee manager
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
        sender: &Address,
        user: Address,
        max_amount: U256,
        actual_used: U256,
        user_token: Address,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Only protocol can call this
        if *sender != Address::ZERO {
            return Err(IFeeManager::IFeeManagerErrors::OnlySystemContract(
                IFeeManager::OnlySystemContract {},
            ));
        }

        // Calculate refund amount (max - actual)
        let refund_amount = max_amount.saturating_sub(actual_used);

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

        // Queue the actual used amount for fee swaps
        // Track fee info for later swap execution
        let mut fee_info = self.get_fee_info(&user_token);

        // Add to tracking array if first time collecting fees for this token
        if fee_info.amount == 0 && !fee_info.has_been_set {
            let in_array_slot = self.get_token_in_fees_array_slot(&user_token);
            let in_array = self
                .storage
                .sload(self.contract_address, in_array_slot)
                .expect("TODO: handle error")
                != U256::ZERO;

            if !in_array {
                // Mark token as being in the array
                self.storage
                    .sstore(self.contract_address, in_array_slot, U256::ONE)
                    .expect("TODO: handle error");

                // Get current array length
                let length_value = self
                    .storage
                    .sload(self.contract_address, slots::TOKENS_WITH_FEES_LENGTH)
                    .expect("TODO: handle error");

                // Store token address in the array at current index
                let token_slot = slots::TOKENS_WITH_FEES + length_value;
                self.storage
                    .sstore(self.contract_address, token_slot, user_token.into_u256())
                    .expect("TODO: handle error");

                // Increment array length
                self.storage
                    .sstore(
                        self.contract_address,
                        slots::TOKENS_WITH_FEES_LENGTH,
                        length_value + U256::from(1),
                    )
                    .expect("TODO: handle error");
            }
        }

        // Update fee info with actual used amount
        fee_info.amount = fee_info.amount.saturating_add(actual_used.to::<u128>());
        fee_info.has_been_set = true;
        self.set_fee_info(&user_token, &fee_info);

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
        let validator_token = match self.get_validator_token(&validator) {
            Ok(token) => token,
            Err(_) => {
                // If no validator token set, nothing to do
                return Ok(());
            }
        };

        // Get the number of tokens with pending fees
        let tokens_with_fees_length = self
            .storage
            .sload(self.contract_address, slots::TOKENS_WITH_FEES_LENGTH)
            .expect("TODO: handle error")
            .to::<usize>();

        // Process each token with pending fees
        for i in 0..tokens_with_fees_length {
            // Get token address from array using dynamic array access
            let token_slot = slots::TOKENS_WITH_FEES + U256::from(i);
            let token_address = self
                .storage
                .sload(self.contract_address, token_slot)
                .expect("TODO: handle error")
                .into_address();

            if token_address == Address::ZERO {
                continue;
            }

            // Get collected fee amount for this token
            let fee_info = self.get_fee_info(&token_address);
            if fee_info.amount == 0 {
                continue;
            }

            let fee_amount = U256::from(fee_info.amount);

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
            self.set_fee_info(
                &token_address,
                &FeeInfo {
                    amount: 0,
                    has_been_set: false,
                },
            );

            // Clear token from array
            self.storage
                .sstore(self.contract_address, token_slot, U256::ZERO)
                .expect("TODO: handle error");

            // Clear token from tracking map
            let in_array_slot = self.get_token_in_fees_array_slot(&token_address);
            self.storage
                .sstore(self.contract_address, in_array_slot, U256::ZERO)
                .expect("TODO: handle error");
        }

        // Reset tokens with fees tracking
        self.storage
            .sstore(
                self.contract_address,
                slots::TOKENS_WITH_FEES_LENGTH,
                U256::ZERO,
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // TODO: swap for validator token

    // TODO: queue deposit

    // TODO: queue withdrawal

    // TODO: _executeDeposit

    // TODO: _executeWithdrawal

    // TODO: _determineWithdrawalStrategy

    // TODO: _updatePendingReservesForMixed

    // TODO: _getTokenWithFees

    // TODO: _cleanupTokensWithFees

    // Helper methods for storage slots

    fn get_validator_token_slot(&self, validator: &Address) -> U256 {
        mapping_slot(validator, slots::VALIDATOR_TOKENS)
    }

    fn get_user_token_slot(&self, user: &Address) -> U256 {
        mapping_slot(user, slots::USER_TOKENS)
    }

    fn get_collected_fees_slot(&self, token: &Address) -> U256 {
        mapping_slot(token, slots::COLLECTED_FEES)
    }

    fn get_token_in_fees_array_slot(&self, token: &Address) -> U256 {
        mapping_slot(token, slots::TOKEN_IN_FEES_ARRAY)
    }

    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Address {
        let slot = self.get_user_token_slot(&call.user);
        self.storage
            .sload(self.contract_address, slot)
            .expect("TODO: handle error")
            .into_address()
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Address {
        let slot = self.get_validator_token_slot(&call.validator);
        self.storage
            .sload(self.contract_address, slot)
            .expect("TODO: handle error")
            .into_address()
    }

    pub fn get_fee_token_balance(
        &mut self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> IFeeManager::getFeeTokenBalanceReturn {
        let user_slot = self.get_user_token_slot(&call.sender);
        let mut token = self
            .storage
            .sload(self.contract_address, user_slot)
            .expect("TODO: handle error")
            .into_address();

        if token.is_zero() {
            let validator_slot = self.get_validator_token_slot(&call.validator);
            let validator_token = self
                .storage
                .sload(self.contract_address, validator_slot)
                .expect("TODO: handle error")
                .into_address();
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

    /// Retrieves pool data by ID (inherited from TIPFeeAMM)
    pub fn pools(&mut self, call: ITIPFeeAMM::poolsCall) -> ITIPFeeAMM::Pool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.pools(call)
    }

    /// Checks if a pool exists (inherited from TIPFeeAMM)
    pub fn pool_exists(&mut self, call: ITIPFeeAMM::poolExistsCall) -> bool {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.pool_exists(call)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        contracts::{HashMapStorageProvider, tip20::ISSUER_ROLE},
    };

    #[test]
    fn test_pool_key_ordering() {
        let addr1 = Address::from([1u8; 20]);
        let addr2 = Address::from([2u8; 20]);

        let key1 = PoolKey::new(addr1, addr2);
        assert_eq!(key1.token0, addr1);
        assert_eq!(key1.token1, addr2);

        let key2 = PoolKey::new(addr2, addr1);
        assert_eq!(key2.token0, addr1);
        assert_eq!(key2.token1, addr2);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        let token_a = Address::random();
        let token_b = Address::random();
        let call = ITIPFeeAMM::createPoolCall {
            tokenA: token_a,
            tokenB: token_b,
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
    fn test_collect_fee() {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let token = Address::random();
        let amount = U256::from(1000);

        // Setup TIP20 token
        let token_id = address_to_token_id_unchecked(&token);
        let mut tip20_token = TIP20Token::new(token_id, &mut storage);

        // Initialize token with admin, set the transfer policy to always allow
        tip20_token
            .initialize("TestToken", "TEST", "USD", &user)
            .unwrap();

        // Grant issuer role to admin and mint tokens to user
        let mut roles = tip20_token.get_roles_contract();
        roles.grant_role_internal(&user, *ISSUER_ROLE);
        tip20_token
            .mint(
                &user,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        // Set allowance for fee manager to transfer tokens
        tip20_token
            .approve(
                &user,
                ITIP20::approveCall {
                    spender: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, tip20_token.storage);

        // Set fee tokens
        fee_manager
            .set_validator_token(&validator, IFeeManager::setValidatorTokenCall { token })
            .unwrap();

        fee_manager
            .set_user_token(&user, IFeeManager::setUserTokenCall { token })
            .unwrap();

        let initial_balance = fee_manager
            .get_fee_token_balance(IFeeManager::getFeeTokenBalanceCall {
                validator: Address::ZERO,
                sender: user,
            })
            ._1;

        // Collect fee and verify balances
        let result = fee_manager.collect_fee(user, validator, amount);
        assert!(result.is_ok());

        let result = fee_manager.get_fee_token_balance(IFeeManager::getFeeTokenBalanceCall {
            validator: Address::ZERO,
            sender: user,
        });
        assert_eq!(result._0, token);
        assert_eq!(result._1, initial_balance - amount);
    }
}
