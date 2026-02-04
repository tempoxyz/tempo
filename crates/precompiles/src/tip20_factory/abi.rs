//! TIP20 Factory ABI definitions.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod abi {
    #[cfg(feature = "precompile")]
    use crate::error::Result;

    use alloy::primitives::{Address, B256};

    /// TIP20 Factory errors.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        /// Returned when attempting to use a reserved address.
        AddressReserved,
        /// Returned when address is not in the reserved range.
        AddressNotReserved,
        /// Returned for invalid quote token.
        InvalidQuoteToken,
        /// Returned when token already exists at the given address.
        TokenAlreadyExists { token: Address },
    }

    /// TIP20 Factory events.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        /// Emitted when a new TIP20 token is created.
        TokenCreated { #[indexed] token: Address, name: String, symbol: String, currency: String, quote_token: Address, admin: Address, salt: B256 },
    }

    /// TIP20 Factory interface for creating TIP20 tokens.
    pub trait ITIP20Factory {
        /// Creates a new TIP20 token with the given parameters.
        /// Returns the address of the newly created token.
        fn create_token(&mut self, name: String, symbol: String, currency: String, quote_token: Address, admin: Address, salt: B256) -> Result<Address>;

        /// Returns true if the address is a valid TIP20 token.
        fn is_tip20(&self, token: Address) -> Result<bool>;

        /// Computes the deterministic address for a token given sender and salt.
        fn get_token_address(&self, sender: Address, salt: B256) -> Result<Address>;
    }
}

pub use abi::*;
