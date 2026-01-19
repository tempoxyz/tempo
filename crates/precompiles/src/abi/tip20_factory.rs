//! TIP20Factory bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod ITIP20Factory {
    use alloy::primitives::{Address, B256};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    pub trait IFactory {
        fn is_tip20(&self, token: Address) -> Result<bool>;
        fn get_token_address(&self, sender: Address, salt: B256) -> Result<Address>;
        fn create_token(&mut self, name: String, symbol: String, currency: String, quote_token: Address, admin: Address, salt: B256) -> Result<Address>;
    }

    pub enum Error {
        AddressReserved,
        AddressNotReserved,
        InvalidQuoteToken,
        TokenAlreadyExists { token: Address },
    }

    pub enum Event {
        TokenCreated { #[indexed] token: Address, name: String, symbol: String, currency: String, quote_token: Address, admin: Address, salt: B256 },
    }
}
