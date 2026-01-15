use alloy::primitives::{Address, B256};
use tempo_precompiles_macros::abi;

#[cfg(feature = "precompile")]
use super::Result;

#[abi]
#[rustfmt::skip]
pub mod ITIP20Factory {
    use super::*;

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

pub use ITIP20Factory::*;

// Backward-compatibility type aliases
pub type TIP20FactoryError = Error;
pub type TIP20FactoryEvent = Event;
