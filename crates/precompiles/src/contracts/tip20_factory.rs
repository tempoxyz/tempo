use crate::{
    TIP20_FACTORY_ADDRESS,
    contracts::{
        is_tip20,
        storage::StorageProvider,
        tip20::TIP20Token,
        token_id_to_address,
        types::{ITIP20Factory, TIP20Error, TIP20FactoryEvent},
    },
};
use alloy::primitives::{Address, Bytes, IntoLogData, U256};
use revm::state::Bytecode;
use tracing::trace;

mod slots {
    use alloy::primitives::U256;

    pub(super) const TOKEN_ID_COUNTER: U256 = U256::ZERO;
}

#[derive(Debug)]
pub struct TIP20Factory<'a, S: StorageProvider> {
    pub storage: &'a mut S,
}

// Precompile functions
impl<'a, S: StorageProvider> TIP20Factory<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    /// Initializes the TIP20 factory contract.
    ///
    /// Sets the initial token counter to 1, reserving token ID 0 for the LinkingUSD precompile.
    /// Also ensures the [`TIP20Factory`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), TIP20Error> {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                TIP20_FACTORY_ADDRESS,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn create_token(
        &mut self,
        sender: &Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<U256, TIP20Error> {
        if !is_tip20(&call.linkingToken) {
            return Err(TIP20Error::invalid_linking_token());
        }

        let token_id = self.token_id_counter();
        trace!(%sender, %token_id, ?call, "Create token");

        // increase the token counter
        self.storage
            .sstore(
                TIP20_FACTORY_ADDRESS,
                slots::TOKEN_ID_COUNTER,
                token_id + U256::ONE,
            )
            .expect("TODO: handle error");

        TIP20Token::new(token_id.try_into().unwrap(), self.storage).initialize(
            &call.name,
            &call.symbol,
            &call.currency,
            call.linkingToken,
            &call.admin,
        )?;

        self.storage
            .emit_event(
                TIP20_FACTORY_ADDRESS,
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                    token: token_id_to_address(token_id.to::<u64>()),
                    tokenId: token_id,
                    name: call.name,
                    symbol: call.symbol,
                    currency: call.currency,
                    admin: call.admin,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(token_id)
    }

    pub fn token_id_counter(&mut self) -> U256 {
        let counter = self
            .storage
            .sload(TIP20_FACTORY_ADDRESS, slots::TOKEN_ID_COUNTER)
            .expect("TODO: handle error");

        if counter.is_zero() {
            U256::ONE
        } else {
            counter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{storage::hashmap::HashMapStorageProvider, types::TIP20FactoryEvent};

    #[test]
    fn test_create_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut storage);

        factory
            .initialize()
            .expect("Factory initialization should succeed");

        let sender = Address::random();
        let call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            linkingToken: crate::LINKING_USD_ADDRESS,
            admin: sender,
        };

        let token_id_0 = factory
            .create_token(&sender, call.clone())
            .expect("Token creation should succeed");

        let token_id_1 = factory
            .create_token(&sender, call)
            .expect("Token creation should succeed");

        let factory_events = storage.events.get(&TIP20_FACTORY_ADDRESS).unwrap();
        assert_eq!(factory_events.len(), 2);

        let token_addr_0 = token_id_to_address(token_id_0.to::<u64>());
        let expected_event_0 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_0,
            tokenId: token_id_0,
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            admin: sender,
        });
        assert_eq!(factory_events[0], expected_event_0.into_log_data());

        let token_addr_1 = token_id_to_address(token_id_1.to::<u64>());
        let expected_event_1 = TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
            token: token_addr_1,
            tokenId: token_id_1,
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            admin: sender,
        });

        assert_eq!(factory_events[1], expected_event_1.into_log_data());
    }
}
