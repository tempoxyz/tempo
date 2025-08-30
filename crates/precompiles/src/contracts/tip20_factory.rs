use crate::{
    TIP20_FACTORY_ADDRESS,
    contracts::{
        storage::StorageProvider,
        tip20::TIP20Token,
        types::{ITIP20Factory, TIP20Error, TIP20FactoryEvent},
    },
};
use alloy::primitives::{Address, IntoLogData, U256};
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
    /// This ensures the [`TIP20Factory`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), TIP20Error> {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(TIP20_FACTORY_ADDRESS, vec![0xef])
            .expect("TODO: handle error");
        Ok(())
    }

    pub fn create_token(
        &mut self,
        sender: &Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<U256, TIP20Error> {
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
            &call.admin,
        )?;

        self.storage
            .emit_event(
                TIP20_FACTORY_ADDRESS,
                TIP20FactoryEvent::TokenCreated(ITIP20Factory::TokenCreated {
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
        self.storage
            .sload(TIP20_FACTORY_ADDRESS, slots::TOKEN_ID_COUNTER)
            .expect("TODO: handle error")
    }
}
