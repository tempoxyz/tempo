// Module for tip20_factory precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP20Factory, TIP20FactoryEvent};
use tempo_precompiles_macros::contract;

use crate::{
    TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::{
        TIP20Error, TIP20Token, address_to_token_id_unchecked, is_tip20_prefix, token_id_to_address,
    },
};
use alloy::primitives::{Address, U256};
use tracing::trace;

#[contract(addr = TIP20_FACTORY_ADDRESS)]
pub struct TIP20Factory {
    token_id_counter: U256,
}

// Precompile functions
impl TIP20Factory {
    /// Initializes the TIP20 factory contract.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.__initialize()
    }

    /// Returns true if the factory has been initialized (has code set).
    pub fn is_initialized(&self) -> Result<bool> {
        self.storage
            .with_account_info(TIP20_FACTORY_ADDRESS, |info| Ok(info.code.is_some()))
    }

    /// Returns true if the address is a valid TIP20 token.
    ///
    /// Checks both:
    /// 1. The address has the correct TIP20 prefix
    /// 2. The token ID (lower 8 bytes) is less than tokenIdCounter
    pub fn is_tip20(&self, token: Address) -> Result<bool> {
        if !is_tip20_prefix(token) {
            return Ok(false);
        }
        let token_id = U256::from(address_to_token_id_unchecked(token));
        Ok(token_id < self.token_id_counter()?)
    }

    pub fn create_token(
        &mut self,
        sender: Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<Address> {
        // TODO: We should update `token_id_counter` to be u64 in storage if we assume we can cast
        // to u64 here. Or we should update `token_id_to_address` to take a larger value
        let token_id = self
            .token_id_counter()?
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;

        trace!(%sender, %token_id, ?call, "Create token");

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        // Note that the token Id increments on each deployment.

        // Require that the first TIP20 deployed has a quote token of address(0)
        if token_id == 0 {
            if !call.quoteToken.is_zero() {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else {
            // Quote token must be a valid deployed TIP20
            if !is_tip20_prefix(call.quoteToken)
                || address_to_token_id_unchecked(call.quoteToken) >= token_id
            {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        // Initialize with default fee_recipient (Address::ZERO)
        // Fee recipient can be set later via setFeeRecipient()
        TIP20Token::new(token_id).initialize(
            &call.name,
            &call.symbol,
            &call.currency,
            call.quoteToken,
            call.admin,
            Address::ZERO,
        )?;

        let token_address = token_id_to_address(token_id);
        let token_id = U256::from(token_id);
        self.emit_event(TIP20FactoryEvent::TokenCreated(
            ITIP20Factory::TokenCreated {
                token: token_address,
                tokenId: token_id,
                name: call.name,
                symbol: call.symbol,
                currency: call.currency,
                quoteToken: call.quoteToken,
                admin: call.admin,
            },
        ))?;

        // increase the token counter
        self.token_id_counter.write(
            token_id
                .checked_add(U256::ONE)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(token_address)
    }

    pub fn token_id_counter(&self) -> Result<U256> {
        self.token_id_counter.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::tests::initialize_path_usd,
    };
    use alloy::primitives::Address;

    #[test]
    fn test_create_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            let path_usd = TIP20Setup::path_usd(sender).apply()?;

            let call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: path_usd.address(),
                admin: sender,
            };

            let token_addr_0 = factory.create_token(sender, call.clone())?;
            let token_addr_1 = factory.create_token(sender, call)?;

            let token_id_0 = address_to_token_id_unchecked(token_addr_0);
            let token_id_1 = address_to_token_id_unchecked(token_addr_1);
            let expected = vec![
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                    token: path_usd.address(),
                    tokenId: U256::ZERO,
                    name: "PathUSD".to_string(),
                    symbol: "PUSD".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: Address::ZERO,
                    admin: sender,
                }),
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                    token: token_addr_0,
                    tokenId: U256::from(token_id_0),
                    name: "Test Token".to_string(),
                    symbol: "TEST".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: path_usd.address(),
                    admin: sender,
                }),
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                    token: token_addr_1,
                    tokenId: U256::from(token_id_1),
                    name: "Test Token".to_string(),
                    symbol: "TEST".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: path_usd.address(),
                    admin: sender,
                }),
            ];
            factory.assert_emitted_events(expected);

            Ok(())
        })
    }

    #[test]
    fn test_create_token_invalid_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;

            let invalid_call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: Address::random(),
                admin: sender,
            };

            let result = factory.create_token(sender, invalid_call);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_quote_token_not_deployed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;

            let non_existent_tip20 = token_id_to_address(5);
            let invalid_call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: non_existent_tip20,
                admin: sender,
            };

            let result = factory.create_token(sender, invalid_call);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_off_by_one_rejected() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            // Test that using token_id as quote token is rejected
            let mut factory = TIP20Setup::factory()?;
            TIP20Setup::path_usd(sender).apply()?;

            // Get the current token_id (should be 1 after PathUSD deployment)
            let current_token_id = factory.token_id_counter()?;
            assert_eq!(current_token_id, U256::from(1));

            // Try to use token_id 1 (the token being created) as the quote token
            // This should be rejected because token 1 doesn't exist yet
            let same_id_quote_token = token_id_to_address(1);
            let call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: same_id_quote_token,
                admin: sender,
            };

            let result = factory.create_token(sender, call);
            // Should fail with InvalidQuoteToken error because token 1 doesn't exist yet
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );
            Ok(())
        })
    }

    #[test]
    fn test_token_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let factory = TIP20Setup::factory()?;

            // Initially, token counter should be 0
            let current_token_id = factory.token_id_counter()?;
            assert_eq!(current_token_id, U256::ZERO);

            let _path_usd = TIP20Setup::path_usd(sender).apply()?;
            let token_id_after_path_usd = factory.token_id_counter()?;
            assert_eq!(token_id_after_path_usd, U256::from(1));

            for i in 1..=50 {
                let token = TIP20Setup::create("Test", "Test", sender).apply()?;
                // Note that this is +1 because PathUSD is token 0
                let expected_counter = U256::from(i + 1);
                let actual_counter = factory.token_id_counter()?;
                assert_eq!(actual_counter, expected_counter);
                assert_eq!(address_to_token_id_unchecked(token.address()), i as u64);
            }

            Ok(())
        })
    }

    #[test]
    fn test_create_token_first_token_validation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;

            let call_fail = ITIP20Factory::createTokenCall {
                name: "Test".to_string(),
                symbol: "Test".to_string(),
                currency: "USD".to_string(),
                quoteToken: token_id_to_address(0),
                admin: sender,
            };

            let result = factory.create_token(sender, call_fail);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );

            let call = ITIP20Factory::createTokenCall {
                name: "Test".to_string(),
                symbol: "Test".to_string(),
                currency: "USD".to_string(),
                quoteToken: Address::ZERO,
                admin: sender,
            };

            factory.create_token(sender, call)?;
            Ok(())
        })
    }

    #[test]
    fn test_is_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            // initialize_path_usd deploys PathUSD via factory
            // which properly increments tokenIdCounter to 1
            initialize_path_usd(sender)?;

            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            // Verify tokenIdCounter was set by factory deployment
            assert_eq!(factory.token_id_counter()?, U256::from(1));

            // PATH_USD (token ID 0) should be valid since 0 < 1
            assert!(factory.is_tip20(crate::PATH_USD_ADDRESS)?);

            // Token ID >= tokenIdCounter should be invalid
            let token_id_counter: u64 = factory.token_id_counter()?.to();
            let non_existent_tip20 = token_id_to_address(token_id_counter + 100);
            assert!(!factory.is_tip20(non_existent_tip20)?);

            // Non-TIP20 address should be invalid
            assert!(!factory.is_tip20(Address::random())?);

            Ok(())
        })
    }

    #[test]
    fn test_is_tip20_prefix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            // Valid TIP20 address
            let token_id = rand::random::<u64>();
            let token = token_id_to_address(token_id);
            assert!(is_tip20_prefix(token));

            // Random address is not TIP20
            let random = Address::random();
            assert!(!is_tip20_prefix(random));

            Ok(())
        })
    }
}
