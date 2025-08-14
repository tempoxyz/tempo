use crate::contracts::{
    storage::{
        StorageProvider,
        slots::{double_mapping_slot, mapping_slot, to_u256},
    },
    types::IFeeManager,
};
use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::{SolCall, SolValue},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Deposit,
    Withdraw,
}

impl From<u8> for OperationType {
    fn from(value: u8) -> Self {
        match value {
            0 => OperationType::Deposit,
            1 => OperationType::Withdraw,
            _ => panic!("Invalid operation type: {}", value),
        }
    }
}

impl From<OperationType> for u8 {
    fn from(op_type: OperationType) -> Self {
        op_type as u8
    }
}

#[derive(Debug, Clone)]
pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            reserve0: 0,
            reserve1: 0,
        }
    }
}

impl From<Pool> for IFeeManager::Pool {
    fn from(pool: Pool) -> Self {
        IFeeManager::Pool {
            reserve0: pool.reserve0,
            reserve1: pool.reserve1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedOperation {
    pub op_type: OperationType,
    pub user: Address,
    pub pool_key: PoolKey,
    pub amount: U256,
    pub token: Address,
}

impl From<QueuedOperation> for IFeeManager::QueuedOperation {
    fn from(op: QueuedOperation) -> Self {
        IFeeManager::QueuedOperation {
            opType: u8::from(op.op_type),
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
        IFeeManager::FeeInfo {
            amount: fee_info.amount,
            hasBeenSet: fee_info.has_been_set,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: Address,
    pub token1: Address,
}

impl PoolKey {
    pub fn new(token_a: Address, token_b: Address) -> Self {
        let (token0, token1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        Self { token0, token1 }
    }

    pub fn get_id(&self) -> B256 {
        keccak256((self.token0, self.token1).abi_encode())
    }
}

impl From<PoolKey> for IFeeManager::PoolKey {
    fn from(key: PoolKey) -> Self {
        IFeeManager::PoolKey {
            token0: key.token0,
            token1: key.token1,
        }
    }
}

impl From<IFeeManager::PoolKey> for PoolKey {
    fn from(key: IFeeManager::PoolKey) -> Self {
        PoolKey::new(key.token0, key.token1)
    }
}

mod slots {
    use crate::contracts::storage::slots::to_u256;
    use alloy::primitives::U256;

    // Pool state mappings
    pub const POOLS: U256 = to_u256(0);
    pub const TOTAL_SUPPLY: U256 = to_u256(1);
    pub const POOL_EXISTS: U256 = to_u256(2);
    pub const LIQUIDITY_BALANCES: U256 = to_u256(3);

    // Token preferences
    pub const VALIDATOR_TOKENS: U256 = to_u256(4);
    pub const USER_TOKENS: U256 = to_u256(5);

    // Fee tracking
    pub const COLLECTED_FEES: U256 = to_u256(6);

    // Pending operations
    pub const PENDING_RESERVE0: U256 = to_u256(7);
    pub const PENDING_RESERVE1: U256 = to_u256(8);

    // Arrays (stored as packed data)
    pub const OPERATION_QUEUE_LENGTH: U256 = to_u256(9);
    pub const OPERATION_QUEUE_BASE: U256 = to_u256(10);
    pub const TOKENS_WITH_FEES_LENGTH: U256 = to_u256(11);
    pub const TOKENS_WITH_FEES_BASE: U256 = to_u256(12);
    pub const POOLS_WITH_PENDING_OPS_LENGTH: U256 = to_u256(13);
    pub const POOLS_WITH_PENDING_OPS_BASE: U256 = to_u256(14);
    pub const TOKEN_IN_FEES_ARRAY: U256 = to_u256(15);
}

pub struct TipFeeManager<S: StorageProvider> {
    contract_address: Address,
    storage: S,
}

impl<S: StorageProvider> TipFeeManager<S> {
    pub fn new(contract_address: Address, storage: S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = U256::from_limbs([1_000_000_000u64, 0, 0, 0]); // 1e9

    // Helper methods for storage slots
    fn get_pool_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::POOLS)
    }

    fn get_total_supply_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::TOTAL_SUPPLY)
    }

    fn get_pool_exists_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::POOL_EXISTS)
    }

    fn get_liquidity_balance_slot(&self, pool_id: &B256, user: &Address) -> U256 {
        double_mapping_slot(pool_id, user, slots::LIQUIDITY_BALANCES)
    }

    fn get_validator_token_slot(&self, validator: &Address) -> U256 {
        mapping_slot(validator, slots::VALIDATOR_TOKENS)
    }

    fn get_user_token_slot(&self, user: &Address) -> U256 {
        mapping_slot(user, slots::USER_TOKENS)
    }

    fn get_collected_fees_slot(&self, token: &Address) -> U256 {
        mapping_slot(token, slots::COLLECTED_FEES)
    }

    fn get_pending_reserve0_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::PENDING_RESERVE0)
    }

    fn get_pending_reserve1_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::PENDING_RESERVE1)
    }

    fn get_token_in_fees_array_slot(&self, token: &Address) -> U256 {
        mapping_slot(token, slots::TOKEN_IN_FEES_ARRAY)
    }

    pub fn set_validator_token(
        &mut self,
        sender: &Address,
        call: IFeeManager::setValidatorTokenCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Validate sender is current builder/validator
        // TODO: FIXME:: In real implementation, this would check block.coinbase
        // For now, we'll allow any sender for testing

        if call.token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::ZeroAddress(
                IFeeManager::ZeroAddress {},
            ));
        }

        let slot = self.get_validator_token_slot(sender);
        let token_value = U256::from_be_bytes(call.token.into_array());
        self.storage
            .sstore(self.contract_address, slot, token_value);

        // TODO: emit event
        Ok(())
    }

    pub fn set_user_token(
        &mut self,
        sender: &Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        if call.token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::ZeroAddress(
                IFeeManager::ZeroAddress {},
            ));
        }

        let slot = self.get_user_token_slot(sender);
        let token_value = U256::from_be_bytes(call.token.into_array());
        self.storage
            .sstore(self.contract_address, slot, token_value);

        Ok(())
    }

    pub fn create_pool(
        &mut self,
        sender: &Address,
        call: IFeeManager::createPoolCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        if call.tokenA == call.tokenB {
            return Err(IFeeManager::IFeeManagerErrors::IdenticalAddresses(
                IFeeManager::IdenticalAddresses {},
            ));
        }

        let pool_key = PoolKey::new(call.tokenA, call.tokenB);

        if pool_key.token0.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::ZeroAddress(
                IFeeManager::ZeroAddress {},
            ));
        }

        let pool_id = pool_key.get_id();

        // Check if pool already exists
        let exists_slot = self.get_pool_exists_slot(&pool_id);
        if self.storage.sload(self.contract_address, exists_slot) != U256::ZERO {
            return Err(IFeeManager::IFeeManagerErrors::PoolExists(
                IFeeManager::PoolExists {},
            ));
        }

        // Create the pool - reserve0 and reserve1 both start at 0
        let pool_slot = self.get_pool_slot(&pool_id);
        // Store as packed uint128 values. reserve1 in high 128 bits, reserve0 in low 128 bits
        let pool_value = U256::ZERO;
        self.storage
            .sstore(self.contract_address, pool_slot, pool_value);

        // Mark pool as existing
        self.storage
            .sstore(self.contract_address, exists_slot, U256::ONE);

        let token0_fees_slot = self.get_collected_fees_slot(&pool_key.token0);
        let token1_fees_slot = self.get_collected_fees_slot(&pool_key.token1);
        let fee_info_value = U256::from(1u128) << 128;
        self.storage
            .sstore(self.contract_address, token0_fees_slot, fee_info_value);
        self.storage
            .sstore(self.contract_address, token1_fees_slot, fee_info_value);

        Ok(())
    }

    pub fn get_pool_id(&mut self, call: IFeeManager::getPoolIdCall) -> B256 {
        let pool_key = PoolKey::from(call.key);
        pool_key.get_id()
    }

    pub fn get_pool(&mut self, call: IFeeManager::getPoolCall) -> IFeeManager::Pool {
        let pool_key = PoolKey::from(call.key);
        let pool_id = pool_key.get_id();
        let pool_slot = self.get_pool_slot(&pool_id);

        let pool_value = self.storage.sload(self.contract_address, pool_slot);
        // Unpack: reserve1 in high 128 bits, reserve0 in low 128 bits
        let reserve0 = (pool_value & U256::from((1u128 << 128) - 1)).to::<u128>();
        let reserve1 = (pool_value / U256::from(1u128 << 128)).to::<u128>();

        IFeeManager::Pool { reserve0, reserve1 }
    }

    pub fn collect_fee(
        &mut self,
        sender: &Address,
        call: IFeeManager::collectFeeCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        // Get validator's preferred token
        let validator_slot = self.get_validator_token_slot(sender); // In real implementation, use block.coinbase
        let validator_token_value = self.storage.sload(self.contract_address, validator_slot);
        let validator_token = Address::from_slice(&validator_token_value.to_be_bytes::<32>()[12..]);

        if validator_token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        // Get user's preferred token, default to validator's token if not set
        let user_slot = self.get_user_token_slot(&call.user);
        let user_token_value = self.storage.sload(self.contract_address, user_slot);
        let user_token = Address::from_slice(&user_token_value.to_be_bytes::<32>()[12..]);
        let user_token = if user_token.is_zero() {
            validator_token
        } else {
            user_token
        };

        // If user token is different from validator token, check pool exists and has minimum balance
        if user_token != validator_token {
            let pool_key = PoolKey::new(user_token, validator_token);
            let pool_id = pool_key.get_id();

            let exists_slot = self.get_pool_exists_slot(&pool_id);
            let pool_exists = self.storage.sload(self.contract_address, exists_slot) != U256::ZERO;

            if !pool_exists {
                return Err(IFeeManager::IFeeManagerErrors::PoolDoesNotExist(
                    IFeeManager::PoolDoesNotExist {},
                ));
            }

            let pool_slot = self.get_pool_slot(&pool_id);
            let pool_value = self.storage.sload(self.contract_address, pool_slot);
            let reserve0 = U256::from((pool_value & U256::from((1u128 << 128) - 1)).to::<u128>());
            let reserve1 = U256::from((pool_value / U256::from(1u128 << 128)).to::<u128>());

            if reserve0 < Self::MINIMUM_BALANCE || reserve1 < Self::MINIMUM_BALANCE {
                return Err(IFeeManager::IFeeManagerErrors::InsufficientPoolBalance(
                    IFeeManager::InsufficientPoolBalance {},
                ));
            }
        }

        // Update collected fees
        let fees_slot = self.get_collected_fees_slot(&user_token);
        let fees_value = self.storage.sload(self.contract_address, fees_slot);

        // Unpack current fee info: hasBeenSet in bit 128, amount in lower 128 bits
        let current_amount = (fees_value & U256::from((1u128 << 128) - 1)).to::<u128>();
        let has_been_set = fees_value >= (U256::from(1u128) << 128);

        // Add to tracking array if first time collecting fees for this token
        if current_amount == 0 && !has_been_set {
            let in_array_slot = self.get_token_in_fees_array_slot(&user_token);
            let in_array = self.storage.sload(self.contract_address, in_array_slot) != U256::ZERO;

            if !in_array {
                // For simplicity, just mark as in array - full array management would be more complex
                self.storage
                    .sstore(self.contract_address, in_array_slot, U256::ONE);

                // Increment tokens with fees length
                let length_value = self
                    .storage
                    .sload(self.contract_address, slots::TOKENS_WITH_FEES_LENGTH);
                self.storage.sstore(
                    self.contract_address,
                    slots::TOKENS_WITH_FEES_LENGTH,
                    length_value + U256::from(1),
                );
            }
        }

        // Update fee info - pack: hasBeenSet in bit 128, new amount in lower 128 bits
        let new_amount = current_amount.saturating_add(call.amount.try_into().unwrap_or(0));
        let new_fees_value = (U256::from(1u128) << 128) | U256::from(new_amount);
        self.storage
            .sstore(self.contract_address, fees_slot, new_fees_value);

        Ok(())
    }

    // View functions
    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Address {
        let slot = self.get_user_token_slot(&call.user);
        let token_value = self.storage.sload(self.contract_address, slot);
        Address::from_slice(&token_value.to_be_bytes::<32>()[12..])
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Address {
        let slot = self.get_validator_token_slot(&call.validator);
        let token_value = self.storage.sload(self.contract_address, slot);
        Address::from_slice(&token_value.to_be_bytes::<32>()[12..])
    }

    pub fn get_fee_token_balance(
        &mut self,
        call: IFeeManager::getFeeTokenBalanceCall,
    ) -> IFeeManager::getFeeTokenBalanceReturn {
        let user_slot = self.get_user_token_slot(&call.sender);
        let user_token_value = self.storage.sload(self.contract_address, user_slot);
        let user_token = Address::from_slice(&user_token_value.to_be_bytes::<32>()[12..]);

        if user_token.is_zero() {
            return IFeeManager::getFeeTokenBalanceReturn {
                _0: Address::ZERO,
                _1: U256::ZERO,
            };
        }

        let fees_slot = self.get_collected_fees_slot(&user_token);
        let fees_value = self.storage.sload(self.contract_address, fees_slot);
        // Unpack: amount in lower 128 bits
        let amount = fees_value & U256::from((1u128 << 128) - 1);

        IFeeManager::getFeeTokenBalanceReturn {
            _0: user_token,
            _1: amount,
        }
    }

    pub fn basis_points(&self) -> U256 {
        U256::from(Self::BASIS_POINTS)
    }

    pub fn fee_bps(&self) -> U256 {
        U256::from(Self::FEE_BPS)
    }

    pub fn pools(&mut self, call: IFeeManager::poolsCall) -> IFeeManager::Pool {
        let pool_slot = self.get_pool_slot(&call.poolId);
        let pool_value = self.storage.sload(self.contract_address, pool_slot);
        // Unpack: reserve1 in high 128 bits, reserve0 in low 128 bits
        let reserve0 = (pool_value & U256::from((1u128 << 128) - 1)).to::<u128>();
        let reserve1 = (pool_value / U256::from(1u128 << 128)).to::<u128>();

        IFeeManager::Pool { reserve0, reserve1 }
    }

    pub fn total_supply(&mut self, call: IFeeManager::totalSupplyCall) -> U256 {
        let slot = self.get_total_supply_slot(&call.poolId);
        self.storage.sload(self.contract_address, slot)
    }

    pub fn pool_exists(&mut self, call: IFeeManager::poolExistsCall) -> bool {
        let slot = self.get_pool_exists_slot(&call.poolId);
        self.storage.sload(self.contract_address, slot) != U256::ZERO
    }

    pub fn liquidity_balances(&mut self, call: IFeeManager::liquidityBalancesCall) -> U256 {
        let slot = self.get_liquidity_balance_slot(&call.poolId, &call.user);
        self.storage.sload(self.contract_address, slot)
    }

    pub fn pending_reserve0(&mut self, call: IFeeManager::pendingReserve0Call) -> U256 {
        let slot = self.get_pending_reserve0_slot(&call.poolId);
        self.storage.sload(self.contract_address, slot)
    }

    pub fn pending_reserve1(&mut self, call: IFeeManager::pendingReserve1Call) -> U256 {
        let slot = self.get_pending_reserve1_slot(&call.poolId);
        self.storage.sload(self.contract_address, slot)
    }

    // Additional view functions for compatibility
    pub fn get_tokens_with_fees_length(&mut self) -> U256 {
        self.storage
            .sload(self.contract_address, slots::TOKENS_WITH_FEES_LENGTH)
    }

    pub fn get_operation_queue_length(&mut self) -> U256 {
        self.storage
            .sload(self.contract_address, slots::OPERATION_QUEUE_LENGTH)
    }

    pub fn get_deposit_queue_length(&self) -> U256 {
        // For now, return 0 - would need more complex queue tracking
        U256::ZERO
    }

    pub fn get_withdraw_queue_length(&self) -> U256 {
        // For now, return 0 - would need more complex queue tracking
        U256::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::HashMapStorageProvider;

    #[test]
    fn test_pool_key_ordering() {
        let addr1 = Address::from([1u8; 20]);
        let addr2 = Address::from([2u8; 20]);

        let key1 = PoolKey::new(addr1, addr2);
        let key2 = PoolKey::new(addr2, addr1);

        assert_eq!(key1.token0, addr1);
        assert_eq!(key1.token1, addr2);
        assert_eq!(key2.token0, addr1);
        assert_eq!(key2.token1, addr2);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_create_pool() {
        let storage = HashMapStorageProvider::new(1);
        let contract_addr = Address::from([0u8; 20]);
        let mut fee_manager = TipFeeManager::new(contract_addr, storage);

        let sender = Address::from([1u8; 20]);
        let token_a = Address::from([10u8; 20]);
        let token_b = Address::from([20u8; 20]);

        let call = IFeeManager::createPoolCall {
            tokenA: token_a,
            tokenB: token_b,
        };

        let result = fee_manager.create_pool(&sender, call);
        assert!(result.is_ok());

        // Verify pool exists
        let pool_key = PoolKey::new(token_a, token_b);
        let pool_id = pool_key.get_id();
        let exists_call = IFeeManager::poolExistsCall { poolId: pool_id };
        assert!(fee_manager.pool_exists(exists_call));
    }

    #[test]
    fn test_set_user_token() {
        let storage = HashMapStorageProvider::new(1);
        let contract_addr = Address::from([0u8; 20]);
        let mut fee_manager = TipFeeManager::new(contract_addr, storage);

        let user = Address::from([1u8; 20]);
        let token = Address::from([10u8; 20]);

        let call = IFeeManager::setUserTokenCall { token };
        let result = fee_manager.set_user_token(&user, call);
        assert!(result.is_ok());

        // Verify token was set
        let query = IFeeManager::userTokensCall { user };
        assert_eq!(fee_manager.user_tokens(query), token);
    }

    #[test]
    fn test_collect_fee() {
        let storage = HashMapStorageProvider::new(1);
        let contract_addr = Address::from([0u8; 20]);
        let mut fee_manager = TipFeeManager::new(contract_addr, storage);

        let validator = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let token = Address::from([10u8; 20]);
        let amount = U256::from(1000);

        // Set validator token
        let set_validator_call = IFeeManager::setValidatorTokenCall { token };
        fee_manager
            .set_validator_token(&validator, set_validator_call)
            .unwrap();

        // Set user token (same as validator for simplicity)
        let set_user_call = IFeeManager::setUserTokenCall { token };
        fee_manager.set_user_token(&user, set_user_call).unwrap();

        // Collect fee
        let collect_call = IFeeManager::collectFeeCall { user, amount };
        let result = fee_manager.collect_fee(&validator, collect_call);
        assert!(result.is_ok());

        // Verify fee was collected
        let balance_call = IFeeManager::getFeeTokenBalanceCall { sender: user };
        let result = fee_manager.get_fee_token_balance(balance_call);
        assert_eq!(result._0, token);
        assert_eq!(result._1, amount);
    }
}

// Solidity reference
// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.13;
//
// import { TIP20 } from "./TIP20.sol";
//
// contract TIP1559 {
//     struct PoolKey {
//         address token0;
//         address token1;
//     }
//
//     struct Pool {
//         uint128 reserve0;
//         uint128 reserve1;
//     }
//
//     enum OperationType {
//         Deposit,
//         Withdraw
//     }
//
//     struct QueuedOperation {
//         OperationType opType;
//         address user;
//         PoolKey poolKey;
//         uint256 amount; // For deposits: token amount, for withdrawals: liquidity amount
//         address token; // For deposits: deposit token, for withdrawals: default withdrawal token
//     }
//
//     uint256 public constant FEE_BPS = 25; // 0.25% fee
//     uint256 public constant BASIS_POINTS = 10000;
//     uint256 public constant MINIMUM_BALANCE = 1e9; // Minimum balance required for pool validity
//
//     // Pool state
//     mapping(bytes32 => Pool) public pools;
//     mapping(bytes32 => uint256) public totalSupply; // poolId => total LP supply
//     mapping(bytes32 => bool) public poolExists; // poolId => exists
//
//     // Liquidity token balances: poolId => user => balance
//     mapping(bytes32 => mapping(address => uint256)) public liquidityBalances;
//
//     // Validator token preferences
//     mapping(address => address) public validatorTokens;
//
//     // User token preferences
//     mapping(address => address) public userTokens;
//
//     // Fee collection tracking - optimized for warm storage access
//     struct FeeInfo {
//         uint128 amount;    // Fee amount collected
//         bool hasBeenSet;   // Whether this token has ever had fees collected (for gas optimization)
//     }
//
//     // Private to reduce risk of any kind of probabilistic backrunning MEV
//     mapping(address => FeeInfo) private collectedFees; // token => fee info
//
//     // Pending reserves tracking: poolId => (pendingReserve0, pendingReserve1)
//     // Public so that any rebalancing MEV is an orderly race at the top of the block
//     mapping(bytes32 => uint256) public pendingReserve0;
//     mapping(bytes32 => uint256) public pendingReserve1;
//
//     // Track which pools have pending operations to reset efficiently
//     bytes32[] private poolsWithPendingOps;
//
//     // Track tokens that have collected fees
//     address[] private tokensWithFees;
//     mapping(address => bool) private tokenInFeesArray; // Track if token is already in tokensWithFees array
//
//     // Unified operation queue
//     QueuedOperation[] public operationQueue;
//
//     event PoolCreated(address indexed token0, address indexed token1);
//     event DepositQueued(
//         address indexed user, address indexed token0, address indexed token1, uint256 amount, address token
//     );
//     event WithdrawQueued(address indexed user, address indexed token0, address indexed token1, uint256 liquidity);
//     event BlockExecuted(uint256 deposits, uint256 withdraws, uint256 feeSwaps);
//     event ValidatorTokenSet(address indexed validator, address indexed token);
//     event UserTokenSet(address indexed user, address indexed token);
//     event Deposit(
//         address indexed user,
//         address indexed token0,
//         address indexed token1,
//         address depositToken,
//         uint256 amount,
//         uint256 liquidity
//     );
//     event Withdrawal(
//         address indexed user,
//         address indexed token0,
//         address indexed token1,
//         uint256 token0Amount,
//         uint256 token1Amount,
//         uint256 liquidity
//     );
//     event Swap(
//         address indexed token0,
//         address indexed token1,
//         address indexed to,
//         address tokenIn,
//         address tokenOut,
//         uint256 amountIn,
//         uint256 amountOut
//     );
//
//     function setValidatorToken(address token) external {
//         require(msg.sender == block.coinbase, "ONLY_CURRENT_BUILDER");
//         require(token != address(0), "INVALID_TOKEN");
//         validatorTokens[msg.sender] = token;
//         emit ValidatorTokenSet(msg.sender, token);
//     }
//
//     function setUserToken(address token) external {
//         require(token != address(0), "INVALID_TOKEN");
//         userTokens[msg.sender] = token;
//         emit UserTokenSet(msg.sender, token);
//     }
//
//     function createPool(address tokenA, address tokenB) external {
//         require(tokenA != tokenB, "IDENTICAL_ADDRESSES");
//         (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
//         require(token0 != address(0), "ZERO_ADDRESS");
//
//         PoolKey memory key = PoolKey({token0: token0, token1: token1});
//         bytes32 poolId = getPoolId(key);
//         require(!poolExists[poolId], "POOL_EXISTS");
//
//         pools[poolId] = Pool({reserve0: 0, reserve1: 0});
//         poolExists[poolId] = true;
//
//         // Pre-warm storage for fee collection by setting hasBeenSet flags
//         // This makes future fee collection more gas-efficient for these tokens
//         if (!collectedFees[token0].hasBeenSet) {
//             collectedFees[token0].hasBeenSet = true;
//         }
//         if (!collectedFees[token1].hasBeenSet) {
//             collectedFees[token1].hasBeenSet = true;
//         }
//
//         emit PoolCreated(token0, token1);
//     }
//
//     function getPoolId(PoolKey memory key) public pure returns (bytes32) {
//         return keccak256(abi.encode(key.token0, key.token1));
//     }
//
//     function getPool(PoolKey memory key) external view returns (Pool memory) {
//         bytes32 poolId = getPoolId(key);
//         return pools[poolId];
//     }
//
//     function swap(PoolKey memory key, address tokenIn, uint256 amountIn, address to) external {
//         bytes32 poolId = getPoolId(key);
//         Pool storage pool = pools[poolId];
//         require(poolExists[poolId], "POOL_DOES_NOT_EXIST");
//         require(tokenIn == key.token0 || tokenIn == key.token1, "INVALID_TOKEN");
//
//         TIP20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
//
//         uint256 amountOut = (amountIn * (BASIS_POINTS - FEE_BPS)) / BASIS_POINTS;
//
//         if (tokenIn == key.token0) {
//             require(amountOut <= pool.reserve1, "INSUFFICIENT_LIQUIDITY");
//             pool.reserve0 = uint128(uint256(pool.reserve0) + amountIn);
//             pool.reserve1 = uint128(uint256(pool.reserve1) - amountOut);
//             TIP20(key.token1).transfer(to, amountOut);
//             emit Swap(key.token0, key.token1, to, key.token0, key.token1, amountIn, amountOut);
//         } else {
//             require(amountOut <= pool.reserve0, "INSUFFICIENT_LIQUIDITY");
//             pool.reserve1 = uint128(uint256(pool.reserve1) + amountIn);
//             pool.reserve0 = uint128(uint256(pool.reserve0) - amountOut);
//             TIP20(key.token0).transfer(to, amountOut);
//             emit Swap(key.token0, key.token1, to, key.token1, key.token0, amountIn, amountOut);
//         }
//     }
//
//     function _swapForValidatorToken(PoolKey memory key, address tokenIn, uint256 amountIn, address to) private {
//         bytes32 poolId = getPoolId(key);
//         Pool storage pool = pools[poolId];
//
//         uint256 amountOut = (amountIn * (BASIS_POINTS - FEE_BPS)) / BASIS_POINTS;
//
//         if (tokenIn == key.token0) {
//             pool.reserve0 = uint128(uint256(pool.reserve0) + amountIn);
//             pool.reserve1 = uint128(uint256(pool.reserve1) - amountOut);
//             TIP20(key.token1).transfer(to, amountOut);
//             emit Swap(key.token0, key.token1, to, key.token0, key.token1, amountIn, amountOut);
//         } else {
//             pool.reserve1 = uint128(uint256(pool.reserve1) + amountIn);
//             pool.reserve0 = uint128(uint256(pool.reserve0) - amountOut);
//             TIP20(key.token0).transfer(to, amountOut);
//             emit Swap(key.token0, key.token1, to, key.token1, key.token0, amountIn, amountOut);
//         }
//     }
//
//     function collectFee(address user, uint256 amount) external {
//         // Get validator's preferred token
//         address validatorToken = validatorTokens[block.coinbase];
//         require(validatorToken != address(0), "VALIDATOR_TOKEN_NOT_SET");
//
//         // Get user's preferred token, default to the validator's token if not set
//         address userToken = userTokens[user];
//         if (userToken == address(0)) {
//             userToken = validatorToken;
//         }
//
//         // If user token is different from validator token, check that a pair exists and has minimum balance
//         if (userToken != validatorToken) {
//             // Inline pool ID calculation to avoid memory allocation
//             bytes32 poolId = userToken < validatorToken
//                 ? keccak256(abi.encode(userToken, validatorToken))
//                 : keccak256(abi.encode(validatorToken, userToken));
//
//             require(poolExists[poolId], "NO_POOL_FOR_TOKEN_PAIR");
//
//             // Load pool once and check both conditions
//             Pool storage pool = pools[poolId];
//             require(pool.reserve0 >= MINIMUM_BALANCE && pool.reserve1 >= MINIMUM_BALANCE, "INSUFFICIENT_POOL_BALANCE");
//         }
//
//         TIP20(userToken).transferFrom(user, address(this), amount);
//
//         // Cache fee info to minimize storage access
//         FeeInfo memory feeInfo = collectedFees[userToken];
//
//         // Add to tracking array only if this is the first time collecting fees for this token
//         if (feeInfo.amount == 0 && !tokenInFeesArray[userToken]) {
//             tokensWithFees.push(userToken);
//             tokenInFeesArray[userToken] = true;
//         }
//
//         // Update fee info in single storage write
//         unchecked {
//             collectedFees[userToken] = FeeInfo({
//                 amount: feeInfo.amount + uint128(amount),
//                 hasBeenSet: true  // Always set to true (may already be true from pool creation)
//             });
//         }
//     }
//
//     function queueDeposit(PoolKey memory key, uint256 amount, address depositToken) external {
//         bytes32 poolId = getPoolId(key);
//         require(poolExists[poolId], "POOL_DOES_NOT_EXIST");
//         require(depositToken == key.token0 || depositToken == key.token1, "INVALID_DEPOSIT_TOKEN");
//
//         TIP20(depositToken).transferFrom(msg.sender, address(this), amount);
//
//         // Track pending reserves
//         if (pendingReserve0[poolId] == 0 && pendingReserve1[poolId] == 0) {
//             poolsWithPendingOps.push(poolId);
//         }
//         if (depositToken == key.token0) {
//             pendingReserve0[poolId] += amount;
//         } else {
//             pendingReserve1[poolId] += amount;
//         }
//
//         operationQueue.push(
//             QueuedOperation({
//                 opType: OperationType.Deposit,
//                 user: msg.sender,
//                 poolKey: key,
//                 amount: amount,
//                 token: depositToken
//             })
//         );
//
//         emit DepositQueued(msg.sender, key.token0, key.token1, amount, depositToken);
//     }
//
//     function queueWithdraw(PoolKey memory key, uint256 liquidity) external {
//         bytes32 poolId = getPoolId(key);
//         require(poolExists[poolId], "POOL_DOES_NOT_EXIST");
//         require(liquidityBalances[poolId][msg.sender] >= liquidity, "INSUFFICIENT_LIQUIDITY_BALANCE");
//
//         // Track pool with pending operations
//         if (pendingReserve0[poolId] == 0 && pendingReserve1[poolId] == 0) {
//             poolsWithPendingOps.push(poolId);
//         }
//
//         // Get current pending reserves (including all queued deposits and withdrawals)
//         Pool memory pool = pools[poolId];
//         uint256 currentPendingReserve0 = pool.reserve0 + pendingReserve0[poolId];
//         uint256 currentPendingReserve1 = pool.reserve1 + pendingReserve1[poolId];
//
//         // Calculate withdrawal value
//         uint256 totalValue = currentPendingReserve0 + currentPendingReserve1;
//         uint256 poolTotalSupply = totalSupply[poolId];
//         uint256 withdrawValue = poolTotalSupply > 0 ? (liquidity * totalValue) / poolTotalSupply : 0;
//
//         // Determine withdrawal strategy to prevent inequality flipping
//         address defaultWithdrawalToken = _determineWithdrawalStrategy(
//             poolId,
//             key,
//             currentPendingReserve0,
//             currentPendingReserve1,
//             withdrawValue,
//             pool.reserve0,
//             pool.reserve1
//         );
//
//         // Move LP tokens from user balance to pending withdrawal
//         liquidityBalances[poolId][msg.sender] -= liquidity;
//
//         operationQueue.push(
//             QueuedOperation({
//                 opType: OperationType.Withdraw,
//                 user: msg.sender,
//                 poolKey: key,
//                 amount: liquidity,
//                 token: defaultWithdrawalToken
//             })
//         );
//
//         emit WithdrawQueued(msg.sender, key.token0, key.token1, liquidity);
//     }
//
//     function executeBlock() external {
//         uint256 feeSwaps = 0;
//         uint256 deposits = 0;
//         uint256 withdraws = 0;
//
//         // Get current validator's preferred token
//         address validatorToken = validatorTokens[block.coinbase];
//         require(validatorToken != address(0), "VALIDATOR_TOKEN_NOT_SET");
//
//         // 1. Swap all collected fees to validator token
//         for (uint256 i = 0; i < 256; i++) {
//             // Limit iterations to prevent gas issues
//             address token = _getTokenWithFees(i);
//             if (token == address(0)) break;
//
//             uint256 amount = uint256(collectedFees[token].amount);
//             if (amount > 0 && token != validatorToken) {
//                 PoolKey memory key = PoolKey({
//                     token0: token < validatorToken ? token : validatorToken,
//                     token1: token < validatorToken ? validatorToken : token
//                 });
//                 bytes32 poolId = getPoolId(key);
//                 if (poolExists[poolId]) {
//                     TIP20(token).transfer(address(this), amount);
//                     // Calculate output amount (same logic as in swapForValidatorToken)
//                     uint256 amountOut = (amount * (BASIS_POINTS - FEE_BPS)) / BASIS_POINTS;
//                     _swapForValidatorToken(key, token, amount, address(this));
//
//                     // Track validator token fees if first time collecting
//                     FeeInfo memory validatorFeeInfo = collectedFees[validatorToken];
//                     if (validatorFeeInfo.amount == 0 && !tokenInFeesArray[validatorToken]) {
//                         tokensWithFees.push(validatorToken);
//                         tokenInFeesArray[validatorToken] = true;
//                     }
//
//                     // Update validator token fees in single write
//                     unchecked {
//                         collectedFees[validatorToken] = FeeInfo({
//                             amount: validatorFeeInfo.amount + uint128(amountOut),
//                             hasBeenSet: true
//                         });
//                     }
//                     collectedFees[token].amount = 0;
//                     feeSwaps++;
//                 }
//             }
//         }
//
//         // 2. Execute all operations in order
//         uint256 operationCount = operationQueue.length;
//         for (uint256 i = 0; i < operationCount; i++) {
//             QueuedOperation memory operation = operationQueue[i];
//
//             if (operation.opType == OperationType.Deposit) {
//                 TIP20(operation.token).transfer(address(this), operation.amount);
//                 _executeDeposit(operation.user, operation.poolKey, operation.token, operation.amount);
//                 deposits++;
//             } else if (operation.opType == OperationType.Withdraw) {
//                 _executeWithdrawal(operation.user, operation.poolKey, operation.amount, operation.token);
//                 withdraws++;
//             }
//         }
//
//         // Clear queue and reset pending reserves for all affected pools
//         for (uint256 i = 0; i < poolsWithPendingOps.length; i++) {
//             bytes32 poolId = poolsWithPendingOps[i];
//             pendingReserve0[poolId] = 0;
//             pendingReserve1[poolId] = 0;
//         }
//         delete poolsWithPendingOps;
//         delete operationQueue;
//
//         // Clean up tokens with fees array - remove tokens with zero fees
//         _cleanupTokensWithFees();
//
//         emit BlockExecuted(deposits, withdraws, feeSwaps);
//     }
//
//     function _executeDeposit(address user, PoolKey memory key, address depositToken, uint256 amount) private {
//         bytes32 poolId = getPoolId(key);
//         Pool storage pool = pools[poolId];
//         require(poolExists[poolId], "POOL_DOES_NOT_EXIST");
//         require(depositToken == key.token0 || depositToken == key.token1, "INVALID_TOKEN");
//
//         uint256 liquidity;
//
//         if (totalSupply[poolId] == 0) {
//             // First deposit - mint liquidity equal to deposit amount
//             liquidity = amount;
//
//             if (depositToken == key.token0) {
//                 pool.reserve0 = uint128(uint256(pool.reserve0) + amount);
//             } else {
//                 pool.reserve1 = uint128(uint256(pool.reserve1) + amount);
//             }
//         } else {
//             // Check if pool is imbalanced
//             bool poolImbalanced = pool.reserve0 != pool.reserve1;
//
//             if (poolImbalanced) {
//                 // Must deposit in the token with lower balance
//                 address lowerToken = pool.reserve0 < pool.reserve1 ? key.token0 : key.token1;
//                 require(depositToken == lowerToken, "MUST_DEPOSIT_LOWER_BALANCE_TOKEN");
//
//                 // Mint liquidity proportional to the increase in total value
//                 uint256 oldTotalValue = uint256(pool.reserve0) + uint256(pool.reserve1);
//                 liquidity = (amount * totalSupply[poolId]) / oldTotalValue;
//
//                 if (depositToken == key.token0) {
//                     pool.reserve0 = uint128(uint256(pool.reserve0) + amount);
//                 } else {
//                     pool.reserve1 = uint128(uint256(pool.reserve1) + amount);
//                 }
//             } else {
//                 // Pool is balanced - can deposit either token
//                 liquidity = (amount * totalSupply[poolId]) / (uint256(pool.reserve0) + uint256(pool.reserve1));
//
//                 if (depositToken == key.token0) {
//                     pool.reserve0 = uint128(uint256(pool.reserve0) + amount);
//                 } else {
//                     pool.reserve1 = uint128(uint256(pool.reserve1) + amount);
//                 }
//             }
//         }
//
//         require(liquidity > 0, "INSUFFICIENT_LIQUIDITY_MINTED");
//         totalSupply[poolId] += liquidity;
//         liquidityBalances[poolId][user] += liquidity;
//
//         emit Deposit(user, key.token0, key.token1, depositToken, amount, liquidity);
//     }
//
//     function _executeWithdrawal(address user, PoolKey memory key, uint256 liquidity, address defaultWithdrawalToken) private {
//         bytes32 poolId = getPoolId(key);
//         Pool storage pool = pools[poolId];
//         require(poolExists[poolId], "POOL_DOES_NOT_EXIST");
//         require(liquidity > 0, "INSUFFICIENT_LIQUIDITY");
//         require(defaultWithdrawalToken == key.token0 || defaultWithdrawalToken == key.token1 || defaultWithdrawalToken == address(0), "INVALID_DESIRED_TOKEN");
//
//         uint256 amount0 = 0;
//         uint256 amount1 = 0;
//
//         // Calculate total withdrawal value
//         uint256 totalValue = uint256(pool.reserve0) + uint256(pool.reserve1);
//         uint256 withdrawValue = (liquidity * totalValue) / totalSupply[poolId];
//
//         // Handle mixed withdrawal (address(0) means withdraw from both tokens)
//         if (defaultWithdrawalToken == address(0)) {
//             // Mixed withdrawal - split proportionally or as close to balanced as possible
//             uint256 targetAmount0 = withdrawValue / 2;
//             uint256 targetAmount1 = withdrawValue - targetAmount0;
//
//             // Ensure we don't withdraw more than available
//             amount0 = targetAmount0 <= pool.reserve0 ? targetAmount0 : pool.reserve0;
//             amount1 = targetAmount1 <= pool.reserve1 ? targetAmount1 : pool.reserve1;
//
//             // If one reserve is insufficient, take the remainder from the other
//             uint256 actualTotal = amount0 + amount1;
//             if (actualTotal < withdrawValue) {
//                 uint256 remaining = withdrawValue - actualTotal;
//                 if (amount0 < targetAmount0 && pool.reserve1 >= amount1 + remaining) {
//                     // Reserve0 was insufficient, take more from reserve1
//                     amount1 += remaining;
//                 } else if (amount1 < targetAmount1 && pool.reserve0 >= amount0 + remaining) {
//                     // Reserve1 was insufficient, take more from reserve0
//                     amount0 += remaining;
//                 }
//             }
//
//             // Execute the mixed withdrawal
//             if (amount0 > 0) {
//                 pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                 TIP20(key.token0).transfer(user, amount0);
//             }
//             if (amount1 > 0) {
//                 pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//                 TIP20(key.token1).transfer(user, amount1);
//             }
//         } else {
//             // Original single-token withdrawal logic
//             // Check if pool is imbalanced
//             bool poolImbalanced = pool.reserve0 != pool.reserve1;
//
//             if (poolImbalanced) {
//                 // For imbalanced pools, try to honor default withdrawal token if it's the higher balance token
//                 address higherToken = pool.reserve0 > pool.reserve1 ? key.token0 : key.token1;
//
//                 if (defaultWithdrawalToken == higherToken) {
//                     // Can honor default withdrawal token - withdraw entirely in higher balance token
//                     if (defaultWithdrawalToken == key.token0) {
//                         amount0 = withdrawValue;
//                         if (amount0 <= pool.reserve0) {
//                             pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                             TIP20(key.token0).transfer(user, amount0);
//                         } else {
//                             // Fallback: give all available token0, rest in token1
//                             amount0 = pool.reserve0;
//                             amount1 = withdrawValue - amount0;
//                             require(amount1 <= pool.reserve1, "INSUFFICIENT_RESERVES");
//                             pool.reserve0 = 0;
//                             pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//                             TIP20(key.token0).transfer(user, amount0);
//                             TIP20(key.token1).transfer(user, amount1);
//                         }
//                     } else {
//                         amount1 = withdrawValue;
//                         if (amount1 <= pool.reserve1) {
//                             pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//                             TIP20(key.token1).transfer(user, amount1);
//                         } else {
//                             // Fallback: give all available token1, rest in token0
//                             amount1 = pool.reserve1;
//                             amount0 = withdrawValue - amount1;
//                             require(amount0 <= pool.reserve0, "INSUFFICIENT_RESERVES");
//                             pool.reserve1 = 0;
//                             pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                             TIP20(key.token1).transfer(user, amount1);
//                             TIP20(key.token0).transfer(user, amount0);
//                         }
//                     }
//                 } else {
//                     // Default withdrawal token is not the higher balance token - fallback to higher balance token
//                     if (higherToken == key.token0) {
//                         amount0 = withdrawValue;
//                         require(amount0 <= pool.reserve0, "INSUFFICIENT_RESERVE0");
//                         pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                         TIP20(key.token0).transfer(user, amount0);
//                     } else {
//                         amount1 = withdrawValue;
//                         require(amount1 <= pool.reserve1, "INSUFFICIENT_RESERVE1");
//                         pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//                         TIP20(key.token1).transfer(user, amount1);
//                     }
//                 }
//             } else {
//                 // Pool is balanced - try to honor default withdrawal token preference
//                 if (defaultWithdrawalToken == key.token0 && withdrawValue <= pool.reserve0) {
//                     // Can withdraw entirely in default withdrawal token0
//                     amount0 = withdrawValue;
//                     pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                     TIP20(key.token0).transfer(user, amount0);
//                 } else if (defaultWithdrawalToken == key.token1 && withdrawValue <= pool.reserve1) {
//                     // Can withdraw entirely in default withdrawal token1
//                     amount1 = withdrawValue;
//                     pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//                     TIP20(key.token1).transfer(user, amount1);
//                 } else {
//                     // Fallback: split evenly
//                     amount0 = withdrawValue / 2;
//                     amount1 = withdrawValue / 2;
//
//                     require(amount0 <= pool.reserve0 && amount1 <= pool.reserve1, "INSUFFICIENT_RESERVES");
//
//                     pool.reserve0 = uint128(uint256(pool.reserve0) - amount0);
//                     pool.reserve1 = uint128(uint256(pool.reserve1) - amount1);
//
//                     if (amount0 > 0) TIP20(key.token0).transfer(user, amount0);
//                     if (amount1 > 0) TIP20(key.token1).transfer(user, amount1);
//                 }
//             }
//         }
//
//         totalSupply[poolId] -= liquidity;
//
//         emit Withdrawal(user, key.token0, key.token1, amount0, amount1, liquidity);
//     }
//
//     function _determineWithdrawalStrategy(
//         bytes32 poolId,
//         PoolKey memory key,
//         uint256 currentPendingReserve0,
//         uint256 currentPendingReserve1,
//         uint256 withdrawValue,
//         uint256 poolReserve0,
//         uint256 poolReserve1
//     ) private returns (address defaultWithdrawalToken) {
//         if (currentPendingReserve0 == currentPendingReserve1) {
//             // Pool is balanced - withdraw evenly from both
//             defaultWithdrawalToken = address(0);
//             _updatePendingReservesForMixed(poolId, withdrawValue, poolReserve0, poolReserve1);
//             return defaultWithdrawalToken;
//         }
//
//         // Pool is imbalanced - check if withdrawal would flip the inequality
//         bool reserve0Higher = currentPendingReserve0 > currentPendingReserve1;
//         uint256 higherReserve = reserve0Higher ? currentPendingReserve0 : currentPendingReserve1;
//         uint256 lowerReserve = reserve0Higher ? currentPendingReserve1 : currentPendingReserve0;
//
//         // If withdrawing all from higher reserve would make it lower than the current lower reserve,
//         // we should withdraw from both to maintain better balance
//         if (higherReserve - withdrawValue < lowerReserve) {
//             defaultWithdrawalToken = address(0); // Signal mixed withdrawal
//             _updatePendingReservesForMixed(poolId, withdrawValue, poolReserve0, poolReserve1);
//         } else {
//             // Safe to withdraw from higher balance token without flipping
//             defaultWithdrawalToken = reserve0Higher ? key.token0 : key.token1;
//             if (reserve0Higher) {
//                 pendingReserve0[poolId] = currentPendingReserve0 > poolReserve0 + withdrawValue
//                     ? pendingReserve0[poolId] - withdrawValue : 0;
//             } else {
//                 pendingReserve1[poolId] = currentPendingReserve1 > poolReserve1 + withdrawValue
//                     ? pendingReserve1[poolId] - withdrawValue : 0;
//             }
//         }
//     }
//
//     function _updatePendingReservesForMixed(
//         bytes32 poolId,
//         uint256 withdrawValue,
//         uint256 poolReserve0,
//         uint256 poolReserve1
//     ) private {
//         uint256 withdraw0 = withdrawValue / 2;
//         uint256 withdraw1 = withdrawValue - withdraw0;
//
//         pendingReserve0[poolId] = pendingReserve0[poolId] > poolReserve0 + withdraw0
//             ? pendingReserve0[poolId] - withdraw0 : 0;
//         pendingReserve1[poolId] = pendingReserve1[poolId] > poolReserve1 + withdraw1
//             ? pendingReserve1[poolId] - withdraw1 : 0;
//     }
//
//     function _getTokenWithFees(uint256 index) private view returns (address) {
//         if (index >= tokensWithFees.length) {
//             return address(0);
//         }
//         return tokensWithFees[index];
//     }
//
//     function _cleanupTokensWithFees() private {
//         uint256 writeIndex = 0;
//         for (uint256 readIndex = 0; readIndex < tokensWithFees.length; readIndex++) {
//             address token = tokensWithFees[readIndex];
//             if (collectedFees[token].amount > 0) {
//                 // Keep token in array by copying to write position
//                 tokensWithFees[writeIndex] = token;
//                 writeIndex++;
//             } else {
//                 // Token has no fees, remove from tracking mapping
//                 tokenInFeesArray[token] = false;
//             }
//         }
//         // Trim array to remove gaps
//         while (tokensWithFees.length > writeIndex) {
//             tokensWithFees.pop();
//         }
//     }
//
//     function getTokensWithFeesLength() external view returns (uint256) {
//         return tokensWithFees.length;
//     }
//
//     function getOperationQueueLength() external view returns (uint256) {
//         return operationQueue.length;
//     }
//
//     function getDepositQueueLength() external view returns (uint256) {
//         uint256 count = 0;
//         for (uint256 i = 0; i < operationQueue.length; i++) {
//             if (operationQueue[i].opType == OperationType.Deposit) {
//                 count++;
//             }
//         }
//         return count;
//     }
//
//     function getWithdrawQueueLength() external view returns (uint256) {
//         uint256 count = 0;
//         for (uint256 i = 0; i < operationQueue.length; i++) {
//             if (operationQueue[i].opType == OperationType.Withdraw) {
//                 count++;
//             }
//         }
//         return count;
//     }
//
//     function isPoolImbalanced(PoolKey memory key) external view returns (bool) {
//         bytes32 poolId = getPoolId(key);
//         Pool memory pool = pools[poolId];
//         return pool.reserve0 != pool.reserve1;
//     }
//
//     function getLowerBalanceToken(PoolKey memory key) external view returns (address) {
//         bytes32 poolId = getPoolId(key);
//         Pool memory pool = pools[poolId];
//         if (pool.reserve0 < pool.reserve1) {
//             return key.token0;
//         } else if (pool.reserve1 < pool.reserve0) {
//             return key.token1;
//         } else {
//             return address(0); // Balanced
//         }
//     }
//
//     function getHigherBalanceToken(PoolKey memory key) external view returns (address) {
//         bytes32 poolId = getPoolId(key);
//         Pool memory pool = pools[poolId];
//         if (pool.reserve0 > pool.reserve1) {
//             return key.token0;
//         } else if (pool.reserve1 > pool.reserve0) {
//             return key.token1;
//         } else {
//             return address(0); // Balanced
//         }
//     }
//
//     function getLiquidityBalance(PoolKey memory key, address user) external view returns (uint256) {
//         bytes32 poolId = getPoolId(key);
//         return liquidityBalances[poolId][user];
//     }
// }
