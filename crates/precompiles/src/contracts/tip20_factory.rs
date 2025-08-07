use alloy::primitives::{Address, IntoLogData, U256};

use crate::contracts::{
    TIP20_FACTORY_ADDRESS,
    storage::StorageProvider,
    tip20::TIP20Token,
    types::{ITIP20Factory, TIP20Error, TIP20FactoryEvent},
};

mod slots {
    use alloy::primitives::U256;

    pub const TOKEN_ID_COUNTER: U256 = U256::ZERO;
}

#[derive(Debug)]
pub struct TIP20Factory<'a, S: StorageProvider> {
    storage: &'a mut S,
}

// Precompile functions
impl<'a, S: StorageProvider> TIP20Factory<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    pub fn create_token(
        &mut self,
        _sender: &Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<U256, TIP20Error> {
        let token_id = self.token_id_counter();
        self.storage.sstore(
            TIP20_FACTORY_ADDRESS,
            slots::TOKEN_ID_COUNTER,
            token_id + U256::ONE,
        ); // Increment.

        TIP20Token::new(token_id.try_into().unwrap(), self.storage).initialize(
            &call.name,
            &call.symbol,
            call.decimals,
            &call.currency,
            &call.admin,
        )?;
        self.storage.emit_event(
            TIP20_FACTORY_ADDRESS,
            TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
                tokenId: token_id,
                name: call.name,
                symbol: call.symbol,
                decimals: call.decimals,
                currency: call.currency,
                admin: call.admin,
            })
            .into_log_data(),
        );
        Ok(token_id)
    }

    pub fn token_id_counter(&mut self) -> U256 {
        self.storage
            .sload(TIP20_FACTORY_ADDRESS, slots::TOKEN_ID_COUNTER)
    }
}
