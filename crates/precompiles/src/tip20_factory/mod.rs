// Module for tip20_factory precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP20Factory, TIP20FactoryEvent};
use tempo_precompiles_macros::contract;

use crate::{
    TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
    tip20::{TIP20Error, TIP20Token, address_to_token_id_unchecked, is_tip20, token_id_to_address},
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
    /// Sets the initial token counter to 1, reserving token ID 0 for the PathUSD precompile.
    /// Also ensures the [`TIP20Factory`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            TIP20_FACTORY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_token(
        &mut self,
        sender: Address,
        name: String,
        symbol: String,
        currency: String,
        quote_token: Address,
        admin: Address,
        fee_recipient: Address,
    ) -> Result<Address> {
        // TODO: We should update `token_id_counter` to be u64 in storage if we assume we can cast
        // to u64 here. Or we should update `token_id_to_address` to take a larger value
        let token_id = self
            .token_id_counter()?
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;

        trace!(%sender, %token_id, %name, %symbol, %currency, %quote_token, %admin, %fee_recipient, "Create token");

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        // Note that the token Id increments on each deployment.
        // NOTE: start counter at 0

        // Post-Allegretto, require that the first TIP20 deployed has a quote token of address(0)
        if self.storage.spec().is_allegretto() && token_id == 0 {
            if !quote_token.is_zero() {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else if self.storage.spec().is_moderato() {
            // Post-Moderato: Fixed validation - quote token id must be < current token_id (strictly less than).
            if !is_tip20(quote_token) || address_to_token_id_unchecked(quote_token) >= token_id {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        } else {
            // Pre-Moderato: Original validation with off-by-one bug for consensus compatibility.
            // The buggy check allowed quote_token_id == token_id to pass.
            if !is_tip20(quote_token) || address_to_token_id_unchecked(quote_token) > token_id {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        TIP20Token::new(token_id, self.storage).initialize(
            &name,
            &symbol,
            &currency,
            quote_token,
            admin,
            fee_recipient,
        )?;

        let token_address = token_id_to_address(token_id);
        let token_id = U256::from(token_id);

        // Emit different events based on hardfork to maintain consensus
        if self.storage.spec().is_allegretto() {
            // Post-allegretto: emit event with feeRecipient
            self.storage.emit_event(
                TIP20_FACTORY_ADDRESS,
                TIP20FactoryEvent::TokenCreatedWithFeeRecipient(
                    ITIP20Factory::TokenCreatedWithFeeRecipient {
                        token: token_address,
                        tokenId: token_id,
                        name,
                        symbol,
                        currency,
                        quoteToken: quote_token,
                        admin,
                        feeRecipient: fee_recipient,
                    },
                )
                .into_log_data(),
            )?;
        } else {
            // Pre-allegretto: emit event without feeRecipient
            self.storage.emit_event(
                TIP20_FACTORY_ADDRESS,
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                    token: token_address,
                    tokenId: token_id,
                    name,
                    symbol,
                    currency,
                    quoteToken: quote_token,
                    admin,
                })
                .into_log_data(),
            )?;
        }

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
        let token_addr_0 = factory
            .create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                crate::PATH_USD_ADDRESS,
                sender,
                Address::ZERO,
            )
            .expect("Token creation should succeed");

        let token_addr_1 = factory
            .create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                crate::PATH_USD_ADDRESS,
                sender,
                Address::ZERO,
            )
            .expect("Token creation should succeed");

        let factory_events = storage.events.get(&TIP20_FACTORY_ADDRESS).unwrap();
        assert_eq!(factory_events.len(), 2);

        let token_id_0 = address_to_token_id_unchecked(token_addr_0);
        // Pre-allegretto storage, so expect old event without feeRecipient
        let expected_event_0 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_0,
            tokenId: U256::from(token_id_0),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::PATH_USD_ADDRESS,
            admin: sender,
        });
        assert_eq!(factory_events[0], expected_event_0.into_log_data());

        let token_id_1 = address_to_token_id_unchecked(token_addr_1);
        // Pre-allegretto storage, so expect old event without feeRecipient
        let expected_event_1 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_1,
            tokenId: U256::from(token_id_1),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::PATH_USD_ADDRESS,
            admin: sender,
        });

        assert_eq!(factory_events[1], expected_event_1.into_log_data());
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

        let result = factory.create_token(
            sender,
            "Test Token".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            Address::random(),
            sender,
            Address::ZERO,
        );
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
        let result = factory.create_token(
            sender,
            "Test Token".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            non_existent_tip20,
            sender,
            Address::ZERO,
        );
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

        let result = factory.create_token(
            sender,
            "Test Token".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            same_id_quote_token,
            sender,
            Address::ZERO,
        );
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

        let result = factory.create_token(
            sender,
            "Test Token".to_string(),
            "TEST".to_string(),
            "EUR".to_string(), // Use non-USD to avoid TIP20Token::initialize validation
            future_quote_token,
            sender,
            Address::ZERO,
        );

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

        let result = factory.create_token(
            sender,
            "Test Token".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            same_id_quote_token,
            sender,
            Address::ZERO,
        );

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

        let result = factory.create_token(
            sender,
            "Test".to_string(),
            "Test".to_string(),
            "USD".to_string(),
            token_id_to_address(0),
            sender,
            Address::ZERO,
        );
        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
        );

        factory.create_token(
            sender,
            "Test".to_string(),
            "Test".to_string(),
            "USD".to_string(),
            Address::ZERO,
            sender,
            Address::ZERO,
        )?;
        Ok(())
    }
}
