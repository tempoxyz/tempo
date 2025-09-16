pub mod amm;
pub mod pool;

use crate::contracts::{
    TIP20Token, address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip_fee_manager::{
        amm::TIPFeeAMM,
        pool::PoolKey,
        slots::{
            collected_fees_slot, token_in_fees_array_slot, user_token_slot, validator_token_slot,
        },
    },
    types::{IFeeManager, ITIP20, ITIPFeeAMM},
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, U256, uint};
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

        // TODO: emit event

        Ok(())
    }

    fn get_validator_token(
        &mut self,
        validator: &Address,
    ) -> Result<Address, IFeeManager::IFeeManagerErrors> {
        let validator_slot = validator_token_slot(validator);
        let validator_token = self.sload(validator_slot).into_address();

        if validator_token.is_zero() {
            return Err(IFeeManager::IFeeManagerErrors::InvalidToken(
                IFeeManager::InvalidToken {},
            ));
        }

        Ok(validator_token)
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

        // TODO: emit event

        Ok(())
    }

    fn get_user_token(&mut self, user: &Address, validator_token: &Address) -> Address {
        let user_slot = user_token_slot(user);
        let user_token = self.sload(user_slot).into_address();

        if user_token.is_zero() {
            *validator_token
        } else {
            user_token
        }
    }

    pub fn collect_fee_pre_tx(
        &mut self,
        _sender: &Address,
        _call: IFeeManager::collectFeePreTxCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        todo!()
    }

    pub fn collect_fee_post_tx(
        &mut self,
        _sender: &Address,
        _call: IFeeManager::collectFeePostTxCall,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        todo!()
    }

    pub fn execute_block(
        &mut self,
        _sender: &Address,
    ) -> Result<(), IFeeManager::IFeeManagerErrors> {
        todo!()
    }

    pub fn collected_fees(&mut self, token: &Address) -> U256 {
        let slot = collected_fees_slot(token);
        self.sload(slot)
    }

    pub fn get_tokens_with_fees_length(&mut self) -> U256 {
        use crate::contracts::tip_fee_manager::slots::TOKENS_WITH_FEES_LENGTH;
        self.sload(TOKENS_WITH_FEES_LENGTH)
    }

    pub fn get_token_with_fees(&mut self, _index: U256) -> Address {
        todo!()
    }

    pub fn token_in_fees_array(&mut self, token: &Address) -> bool {
        let slot = token_in_fees_array_slot(token);
        self.sload(slot) != U256::ZERO
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
        amm.pools(call)
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
        amm.mint(msg_sender, call)
    }

    /// Burn liquidity tokens
    pub fn burn(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::burnCall,
    ) -> Result<ITIPFeeAMM::burnReturn, ITIPFeeAMM::ITIPFeeAMMErrors> {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.burn(msg_sender, call)
            .map(|(amount0, amount1)| ITIPFeeAMM::burnReturn { amount0, amount1 })
    }

    /// Get total supply of LP tokens for a pool (inherited from TIPFeeAMM)
    pub fn total_supply(&mut self, call: ITIPFeeAMM::totalSupplyCall) -> U256 {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.total_supply(call)
    }

    /// Get liquidity balance of a user for a pool (inherited from TIPFeeAMM)
    pub fn liquidity_balances(&mut self, call: ITIPFeeAMM::liquidityBalancesCall) -> U256 {
        let mut amm = TIPFeeAMM::new(self.contract_address, self.storage);
        amm.liquidity_balances(call)
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
        amm.create_pool(call.clone())?;

        // Initialize fee tracking for the pool tokens
        let pool_key = PoolKey::new(call.tokenA, call.tokenB);
        let token_0_slot = collected_fees_slot(&pool_key.token0);
        let token_1_slot = collected_fees_slot(&pool_key.token1);
        let fee_info_value = U256::from(1u128) << 128;
        self.sstore(token_0_slot, fee_info_value);
        self.sstore(token_1_slot, fee_info_value);

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
        let pool_id = amm.get_pool_id(ITIPFeeAMM::getPoolIdCall { key: call.key });
        amm.get_pool(&pool_id).into()
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

        let pool_key = PoolKey::new(token_b, token_a);
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
}
