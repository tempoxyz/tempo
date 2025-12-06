// Module for tip20_factory precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP20Factory, TIP20FactoryEvent};
use tempo_precompiles_macros::contract;

use crate::{
    TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
    tip20::{
        TIP20Error, TIP20Token, address_to_token_id_unchecked, is_tip20_prefix, token_id_to_address,
    },
};
use alloy::primitives::{Address, Bytes, IntoLogData, U256};
use revm::state::Bytecode;
use tracing::trace;

#[contract]
pub struct TIP20Factory {
    // TODO: It would be nice to have a `#[initial_value=`n`]` macro
    // to mimic setting an initial value in solidity
    token_id_counter: U256,
}

// Precompile functions
impl<'a, S: PrecompileStorageProvider> TIP20Factory<'a, S> {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(TIP20_FACTORY_ADDRESS, storage)
    }

    /// Initializes the TIP20 factory contract.
    ///
    /// Ensures the [`TIP20Factory`] account isn't empty and prevents state clear by setting
    /// placeholder bytecode.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            TIP20_FACTORY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Returns true if the factory has been initialized (has code set).
    pub fn is_initialized(&mut self) -> Result<bool> {
        let info = self.storage.get_account_info(TIP20_FACTORY_ADDRESS)?;
        Ok(info.code.is_some())
    }

    /// Returns true if the address is a valid TIP20 token.
    ///
    /// Post-AllegroModerato: Matches the Solidity implementation which checks both:
    /// 1. The address has the correct TIP20 prefix
    /// 2. The token ID (lower 8 bytes) is less than tokenIdCounter
    ///
    /// Pre-AllegroModerato: Only checks the address prefix for backwards compatibility.
    pub fn is_tip20(&mut self, token: Address) -> Result<bool> {
        if !is_tip20_prefix(token) {
            return Ok(false);
        }
        // Post-AllegroModerato: also check that token ID < tokenIdCounter
        if self.storage.spec().is_allegro_moderato() {
            let token_id = U256::from(address_to_token_id_unchecked(token));
            return Ok(token_id < self.token_id_counter()?);
        }
        Ok(true)
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

        // Post-Allegretto, require that the first TIP20 deployed has a quote token of address(0)
        if self.storage.spec().is_allegretto() && token_id == 0 {
            if !call.quoteToken.is_zero() {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else if self.storage.spec().is_moderato() {
            // Post-Moderato: Fixed validation - quote token id must be < current token_id (strictly less than).
            if !is_tip20_prefix(call.quoteToken)
                || address_to_token_id_unchecked(call.quoteToken) >= token_id
            {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else {
            // Pre-Moderato: Original validation with off-by-one bug for consensus compatibility.
            // The buggy check allowed quote_token_id == token_id to pass.
            if !is_tip20_prefix(call.quoteToken)
                || address_to_token_id_unchecked(call.quoteToken) > token_id
            {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        // Initialize with default fee_recipient (Address::ZERO)
        // Fee recipient can be set later via setFeeRecipient()
        TIP20Token::new(token_id, self.storage).initialize(
            &call.name,
            &call.symbol,
            &call.currency,
            call.quoteToken,
            call.admin,
            Address::ZERO,
        )?;

        let token_address = token_id_to_address(token_id);
        let token_id = U256::from(token_id);
        self.storage.emit_event(
            TIP20_FACTORY_ADDRESS,
            TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                token: token_address,
                tokenId: token_id,
                name: call.name,
                symbol: call.symbol,
                currency: call.currency,
                quoteToken: call.quoteToken,
                admin: call.admin,
            })
            .into_log_data(),
        )?;

        // increase the token counter
        self.sstore_token_id_counter(
            token_id
                .checked_add(U256::ONE)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(token_address)
    }

    pub fn token_id_counter(&mut self) -> Result<U256> {
        let counter = self.sload_token_id_counter()?;

        // Pre Allegreto, start the counter at 1
        if !self.storage.spec().is_allegretto() && counter.is_zero() {
            Ok(U256::ONE)
        } else {
            Ok(counter)
        }
    }

    /// Sets the token ID counter.
    ///
    /// This is primarily used in tests to simulate tokens created outside the factory.
    #[cfg(test)]
    pub fn set_token_id_counter(&mut self, value: U256) -> Result<()> {
        self.sstore_token_id_counter(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError, storage::hashmap::HashMapStorageProvider,
        tip20::tests::initialize_path_usd,
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_create_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender).unwrap();

        let mut factory = TIP20Factory::new(&mut storage);

        factory
            .initialize()
            .expect("Factory initialization should succeed");
        let call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::PATH_USD_ADDRESS,
            admin: sender,
        };

        let token_addr_0 = factory
            .create_token(sender, call.clone())
            .expect("Token creation should succeed");

        let token_addr_1 = factory
            .create_token(sender, call)
            .expect("Token creation should succeed");

        let factory_events = storage.events.get(&TIP20_FACTORY_ADDRESS).unwrap();
        // Note that we expect 3 events including the initial token creation event when deploying
        // PathUSD
        assert_eq!(factory_events.len(), 3);

        let token_id_0 = address_to_token_id_unchecked(token_addr_0);
        let expected_event_0 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_0,
            tokenId: U256::from(token_id_0),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::PATH_USD_ADDRESS,
            admin: sender,
        });
        assert_eq!(factory_events[1], expected_event_0.into_log_data());

        let token_id_1 = address_to_token_id_unchecked(token_addr_1);
        let expected_event_1 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_1,
            tokenId: U256::from(token_id_1),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::PATH_USD_ADDRESS,
            admin: sender,
        });

        assert_eq!(factory_events[2], expected_event_1.into_log_data());
    }

    #[test]
    fn test_create_token_invalid_quote_token_post_moderato() {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut factory = TIP20Factory::new(&mut storage);

        factory
            .initialize()
            .expect("Factory initialization should succeed");

        let sender = Address::random();

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
    }

    #[test]
    fn test_create_token_quote_token_not_deployed_post_moderato() {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut factory = TIP20Factory::new(&mut storage);

        factory
            .initialize()
            .expect("Factory initialization should succeed");

        let sender = Address::random();
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
    }

    #[test]
    fn test_create_token_off_by_one_rejected_post_moderato() {
        // Test the off-by-one bug fix: using token_id as quote token should be rejected post-Moderato
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender).unwrap();

        let mut factory = TIP20Factory::new(&mut storage);
        factory
            .initialize()
            .expect("Factory initialization should succeed");

        // Get the current token_id (should be 1)
        let current_token_id = factory.token_id_counter().unwrap();
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
        // Should fail with InvalidQuoteToken error because token 1 doesn't exist yet (off-by-one)
        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
        );
    }

    #[test]
    fn test_create_token_future_quote_token_pre_moderato() {
        // Test that pre-Moderato SHOULD still validate that quote tokens exist
        // Using a TIP20 address with ID > current token_id should fail (not yet created)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender).unwrap();

        let mut factory = TIP20Factory::new(&mut storage);
        factory
            .initialize()
            .expect("Factory initialization should succeed");

        // Current token_id should be 1
        assert_eq!(factory.token_id_counter().unwrap(), U256::from(1));

        // Try to use token ID 5 as quote token (doesn't exist yet)
        // This should fail factory validation even pre-Moderato
        let future_quote_token = token_id_to_address(5);
        let call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "EUR".to_string(), // Use non-USD to avoid TIP20Token::initialize validation
            quoteToken: future_quote_token,
            admin: sender,
        };

        let result = factory.create_token(sender, call);

        // This should fail with InvalidQuoteToken from factory validation
        // Currently this test will PASS (not fail) because factory validation is skipped pre-Moderato
        assert!(
            result.is_err(),
            "Should fail when using a not-yet-created token as quote token"
        );
        if let Err(e) = result {
            assert_eq!(
                e,
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token()),
                "Should fail with InvalidQuoteToken from factory validation"
            );
        }
    }

    #[test]
    fn test_create_token_off_by_one_allowed_pre_moderato() {
        // Test the off-by-one bug: using token_id as quote token is allowed pre-Moderato (buggy behavior)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender).unwrap();

        let mut factory = TIP20Factory::new(&mut storage);
        factory
            .initialize()
            .expect("Factory initialization should succeed");

        // Get the current token_id (should be 1)
        let current_token_id = factory.token_id_counter().unwrap();
        assert_eq!(current_token_id, U256::from(1));

        // Try to use token_id 1 (the token being created) as the quote token
        // Pre-Moderato, the old buggy validation (> instead of >=) allows this to pass
        let same_id_quote_token = token_id_to_address(1);
        let call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: same_id_quote_token,
            admin: sender,
        };

        let result = factory.create_token(sender, call);

        // Pre-Moderato: the old buggy validation (> token_id) allows quote_token_id == token_id
        // The operation may succeed or fail with a different error later, but it should NOT
        // fail with InvalidQuoteToken from validation
        match result {
            Ok(_) => {
                // Operation succeeded - the buggy validation allowed it through
            }
            Err(e) => {
                // If it fails, it should NOT be due to InvalidQuoteToken validation
                assert!(
                    !matches!(
                        e,
                        TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(_))
                    ),
                    "Pre-Moderato should not reject with InvalidQuoteToken when quote_token_id == token_id (buggy > logic)"
                );
            }
        }
    }

    #[test]
    fn test_token_id_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize()?;

        let current_token_id = factory.token_id_counter()?;
        assert_eq!(current_token_id, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_create_token_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let sender = Address::random();
        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize()?;

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
    }

    #[test]
    fn test_is_tip20_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender)?;

        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize()?;

        // Set tokenIdCounter to 1 (simulating PATH_USD was created through factory)
        factory.sstore_token_id_counter(U256::from(1))?;

        // PATH_USD (token ID 0) should be valid since 0 < 1
        assert!(factory.is_tip20(crate::PATH_USD_ADDRESS)?);

        // Token ID >= tokenIdCounter should be invalid
        let token_id_counter: u64 = factory.token_id_counter()?.to();
        let non_existent_tip20 = token_id_to_address(token_id_counter + 100);
        assert!(!factory.is_tip20(non_existent_tip20)?);

        // Non-TIP20 address should be invalid
        assert!(!factory.is_tip20(Address::random())?);

        Ok(())
    }

    #[test]
    fn test_is_tip20_pre_allegro_moderato() -> eyre::Result<()> {
        // Pre-AllegroModerato: only check prefix, not tokenIdCounter
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let sender = Address::random();
        initialize_path_usd(&mut storage, sender)?;

        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize()?;

        // PATH_USD (token ID 0) should be valid
        assert!(factory.is_tip20(crate::PATH_USD_ADDRESS)?);

        // Token ID >= tokenIdCounter should still be valid (only checks prefix pre-AllegroModerato)
        let token_id_counter: u64 = factory.token_id_counter()?.to();
        let non_existent_tip20 = token_id_to_address(token_id_counter + 100);
        assert!(
            factory.is_tip20(non_existent_tip20)?,
            "Pre-AllegroModerato: should only check prefix"
        );

        // Non-TIP20 address should still be invalid (wrong prefix)
        assert!(!factory.is_tip20(Address::random())?);

        Ok(())
    }
}
