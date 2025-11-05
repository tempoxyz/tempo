// Module for tip20_factory precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP20Factory, TIP20FactoryEvent};

use crate::{
    TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
    tip20::{TIP20Error, TIP20Token, address_to_token_id_unchecked, is_tip20, token_id_to_address},
};
use alloy::primitives::{Address, Bytes, IntoLogData, U256};
use revm::state::Bytecode;
use tracing::trace;

mod slots {
    use alloy::primitives::U256;

    pub(super) const TOKEN_ID_COUNTER: U256 = U256::ZERO;
}

#[derive(Debug)]
pub struct TIP20Factory<'a, S: PrecompileStorageProvider> {
    pub storage: &'a mut S,
}

// Precompile functions
impl<'a, S: PrecompileStorageProvider> TIP20Factory<'a, S> {
    /// Creates an instance of the factory account.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    /// Initializes the TIP20 factory contract.
    ///
    /// Sets the initial token counter to 1, reserving token ID 0 for the LinkingUSD precompile.
    /// Also ensures the [`TIP20Factory`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            TIP20_FACTORY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    pub fn create_token(
        &mut self,
        sender: Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<Address> {
        let token_id = self.token_id_counter()?.to::<u64>();
        trace!(%sender, %token_id, ?call, "Create token");

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        // Note that the token Id increments on each deployment which ensures that the quote
        // token id must always be <= the current token_id
        if !is_tip20(call.quoteToken) || address_to_token_id_unchecked(call.quoteToken) > token_id {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        TIP20Token::new(token_id, self.storage).initialize(
            &call.name,
            &call.symbol,
            &call.currency,
            call.quoteToken,
            call.admin,
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
        self.storage.sstore(
            TIP20_FACTORY_ADDRESS,
            slots::TOKEN_ID_COUNTER,
            token_id
                .checked_add(U256::ONE)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(token_address)
    }

    pub fn token_id_counter(&mut self) -> Result<U256> {
        let counter = self
            .storage
            .sload(TIP20_FACTORY_ADDRESS, slots::TOKEN_ID_COUNTER)?;

        if counter.is_zero() {
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
        tip20::tests::initialize_linking_usd,
    };

    #[test]
    fn test_create_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        initialize_linking_usd(&mut storage, sender).unwrap();

        let mut factory = TIP20Factory::new(&mut storage);

        factory
            .initialize()
            .expect("Factory initialization should succeed");
        let call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::LINKING_USD_ADDRESS,
            admin: sender,
        };

        let token_addr_0 = factory
            .create_token(sender, call.clone())
            .expect("Token creation should succeed");

        let token_addr_1 = factory
            .create_token(sender, call)
            .expect("Token creation should succeed");

        let factory_events = storage.events.get(&TIP20_FACTORY_ADDRESS).unwrap();
        assert_eq!(factory_events.len(), 2);

        let token_id_0 = address_to_token_id_unchecked(token_addr_0);
        let expected_event_0 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_0,
            tokenId: U256::from(token_id_0),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::LINKING_USD_ADDRESS,
            admin: sender,
        });
        assert_eq!(factory_events[0], expected_event_0.into_log_data());

        let token_id_1 = address_to_token_id_unchecked(token_addr_1);
        let expected_event_1 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_1,
            tokenId: U256::from(token_id_1),
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            quoteToken: crate::LINKING_USD_ADDRESS,
            admin: sender,
        });

        assert_eq!(factory_events[1], expected_event_1.into_log_data());
    }

    #[test]
    fn test_create_token_invalid_quote_token() {
        let mut storage = HashMapStorageProvider::new(1);
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
    fn test_create_token_quote_token_not_deployed() {
        let mut storage = HashMapStorageProvider::new(1);
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
}
