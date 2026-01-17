//! Nonce Manager bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod abi {
    use alloy::primitives::{Address, U256};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    /// Nonce trait for managing 2D nonces as per the Account Abstraction spec.
    ///
    /// This precompile manages user nonce keys (1-N) while protocol nonces (key 0)
    /// are handled directly by account state. Each account can have multiple
    /// independent nonce sequences identified by a nonce key.
    pub trait INonce {
        fn get_nonce(&self, account: Address, nonce_key: U256) -> Result<u64>;
    }

    // Errors
    pub enum Error {
        ProtocolNonceNotSupported,
        InvalidNonceKey,
        NonceOverflow,
    }

    // Events
    pub enum Event {
        NonceIncremented { #[indexed] account: Address, #[indexed] nonce_key: U256, new_nonce: u64 },
    }
}
