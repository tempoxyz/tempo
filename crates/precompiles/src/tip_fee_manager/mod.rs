pub mod amm;
pub mod dispatch;

use alloy::primitives::B256;
use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;
pub use tempo_contracts::precompiles::{
    FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent,
};

use crate::{
    DEFAULT_FEE_TOKEN, PATH_USD_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{PrecompileStorageProvider, Slot, Storable, StorageKey, VecSlotExt},
    tip_fee_manager::amm::{Pool, compute_amount_out},
    tip20::{
        ITIP20, TIP20Token, address_to_token_id_unchecked, is_tip20, token_id_to_address,
        validate_usd_currency,
    },
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, Bytes, IntoLogData, U256, uint};
use revm::state::Bytecode;
use tempo_precompiles_macros::{Storable, contract};

/// Helper type to easily interact with the `pools_with_fees` array
type PoolsWithFees = Slot<Vec<TokenPair>, PoolsWithFeesSlot>;

/// Helper type to easily interact with the `validators_with_fees` array
type ValidatorsWithFees = Slot<Vec<Address>, ValidatorsWithFeesSlot>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Storable)]
struct TokenPair {
    user_token: u64,
    validator_token: u64,
}

impl StorageKey for TokenPair {
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.user_token.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.validator_token.to_be_bytes());
        bytes
    }
}

#[contract]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, U256>,
    pools_with_fees: Vec<TokenPair>,
    pool_in_fees_array: Mapping<TokenPair, bool>,
    pools: Mapping<B256, Pool>,
    pending_fee_swap_in: Mapping<B256, u128>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,
    validators_with_fees: Vec<Address>,
    validator_in_fees_array: Mapping<Address, bool>,
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
            Ok(DEFAULT_FEE_TOKEN)
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

        if sender == beneficiary || self.sload_validator_in_fees_array(sender)? {
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

        if fee_token != validator_token {
            // Release Fee AMM liquidity
            self.release_liquidity(fee_token, validator_token, refund_amount)?;

            // Record the pool if there was a non-zero swap
            if !actual_spending.is_zero() {
                self.add_pair_to_fees_array(fee_token, validator_token)?;
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
        for pair in self.drain_pools_with_fees()? {
            let user_token = token_id_to_address(pair.user_token);
            let validator_token = token_id_to_address(pair.validator_token);

            total_amount_out += self.execute_pending_fee_swaps(user_token, validator_token)?;
        }

        // Pre-Allegretto: increment beneficiary's collected fees if there was a non-zero swap
        if !self.storage.spec().is_allegretto() && !total_amount_out.is_zero() {
            self.increment_collected_fees(beneficiary, total_amount_out)?;
        }

        for validator in self.drain_validators_with_fees()? {
            let collected_fees = self.sload_collected_fees(validator)?;

            if collected_fees.is_zero() {
                continue;
            }

            let validator_token = self.get_validator_token(validator)?;
            let mut token = TIP20Token::from_address(validator_token, self.storage);

            // If FeeManager or validator are blacklisted, we are not transferring any fees
            if token.is_transfer_authorized(self.address, validator)? {
                token
                    .transfer(
                        self.address,
                        ITIP20::transferCall {
                            to: validator,
                            amount: collected_fees,
                        },
                    )
                    .map_err(|_| {
                        IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(
                            IFeeManager::InsufficientFeeTokenBalance {},
                        )
                    })?;
            }

            // Clear collected fees for the validator
            self.sstore_collected_fees(validator, U256::ZERO)?;
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
        if !self.sload_pool_in_fees_array(pair)? {
            self.sstore_pool_in_fees_array(pair, true)?;
            PoolsWithFees::push(self, pair)?;
        }
        Ok(())
    }

    /// Drain all validators with fees by popping from the back until empty
    fn drain_validators_with_fees(&mut self) -> Result<Vec<Address>> {
        let mut validators = Vec::new();
        while let Some(validator) = ValidatorsWithFees::pop(self)? {
            validators.push(validator);
            self.sstore_validator_in_fees_array(validator, false)?;
        }
        Ok(validators)
    }

    /// Drain all pools with fees by popping from the back until empty
    fn drain_pools_with_fees(&mut self) -> Result<Vec<TokenPair>> {
        let mut pools = Vec::new();
        while let Some(pool) = PoolsWithFees::pop(self)? {
            pools.push(pool);
            self.sstore_pool_in_fees_array(pool, false)?;
        }
        Ok(pools)
    }

    /// Increment collected fees for the validator token
    fn increment_collected_fees(&mut self, validator: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let collected_fees = self.sload_collected_fees(validator)?;
        self.sstore_collected_fees(
            validator,
            collected_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // If this is the first fee for the validator, record it in validators with fees
        if collected_fees.is_zero() {
            self.sstore_validator_in_fees_array(validator, true)?;
            ValidatorsWithFees::push(self, validator)?;
        }

        Ok(())
    }

    pub fn user_tokens(&mut self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.sload_user_tokens(call.user)
    }

    pub fn validator_tokens(&mut self, call: IFeeManager::validatorTokensCall) -> Result<Address> {
        let token = self.sload_validator_tokens(call.validator)?;

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
            .initialize("TestToken", "TEST", "USD", PATH_USD_ADDRESS, user)
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
            .initialize("TestToken", "TEST", "USD", PATH_USD_ADDRESS, user)
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
            .initialize("TestToken", "TEST", "USD", PATH_USD_ADDRESS, admin)
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
                .initialize("TestToken", "TEST", "USD", PATH_USD_ADDRESS, admin)
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
        let tracked_amount = fee_manager.sload_collected_fees(validator)?;
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
            .initialize("NonUSD", "NonUSD", "NonUSD", PATH_USD_ADDRESS, admin)
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
}
