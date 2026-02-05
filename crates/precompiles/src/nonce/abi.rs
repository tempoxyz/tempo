use tempo_precompiles_macros::abi;

#[rustfmt::skip]
#[abi(no_reexport)]
pub mod INonce {
    #[cfg(feature = "precompile")]
    use crate::error::Result;
    use alloy::primitives::{Address, U256};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        ProtocolNonceNotSupported,
        InvalidNonceKey,
        NonceOverflow,
        ExpiringNonceReplay,
        ExpiringNonceSetFull,
        InvalidExpiringNonceExpiry,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        NonceIncremented { #[indexed] account: Address, #[indexed] nonce_key: U256, new_nonce: u64 },
    }

    pub trait Interface {
        /// Get the current nonce for a specific account and nonce key
        fn get_nonce(&self, account: Address, nonce_key: U256) -> Result<u64>;
    }
}
