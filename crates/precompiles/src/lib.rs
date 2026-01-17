//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod abi;

#[cfg(feature = "precompile")]
pub mod dispatch;
#[cfg(feature = "precompile")]
pub mod runtime;
#[cfg(feature = "precompile")]
pub use runtime::*;

#[cfg(feature = "precompile")]
pub mod error;
#[cfg(feature = "precompile")]
pub mod storage;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_util;

// Re-export all precompile address constants from abi module
pub use abi::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
};

// Re-export storage layout helpers for read-only contexts (e.g., pool validation)
#[cfg(feature = "precompile")]
pub use account_keychain::AuthorizedKey;
