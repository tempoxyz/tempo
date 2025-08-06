use alloy::primitives::{Address, IntoLogData, U256};

use crate::contracts::{
    IERC20Factory::{createTokenCall, tokenIdCounterCall},
    erc20::ERC20Token,
    storage::StorageProvider,
    types::{ERC20Error, ERC20FactoryEvent, IERC20Factory},
};

mod slots {
    use alloy::primitives::U256;

    pub const TOKEN_ID_COUNTER: U256 = U256::ZERO;
}

#[derive(Debug)]
pub struct ERC20Factory<'a, S: StorageProvider> {
    storage: &'a mut S,
}

// Precompile functions
impl<'a, S: StorageProvider> ERC20Factory<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    pub fn create_token(
        &mut self,
        _sender: &Address,
        call: createTokenCall,
    ) -> Result<U256, ERC20Error> {
        let token_id = self._token_id_counter();
        self.storage
            .sstore(u64::MAX, slots::TOKEN_ID_COUNTER, token_id + U256::ONE); // Increment.

        // TODO: Get chain_id from context
        let chain_id = 1u64;

        ERC20Token::new(token_id.try_into().unwrap(), self.storage).initialize(
            &call.name,
            &call.symbol,
            call.decimals,
            &call.currency,
            &call.admin,
            chain_id,
        )?;
        self.storage.emit_event(
            token_id.try_into().unwrap(),
            ERC20FactoryEvent::TokenCreated(IERC20Factory::TokenCreated {
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

    pub fn token_id_counter(&mut self, _call: tokenIdCounterCall) -> U256 {
        self._token_id_counter()
    }

    #[inline]
    pub fn _token_id_counter(&mut self) -> U256 {
        self.storage.sload(u64::MAX, slots::TOKEN_ID_COUNTER)
    }
}
