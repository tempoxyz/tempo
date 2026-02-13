//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "precompiles")]
pub mod error;
#[cfg(feature = "precompiles")]
pub mod storage;

#[cfg(feature = "precompiles")]
pub mod runtime;
#[cfg(feature = "precompiles")]
pub use runtime::*;

pub mod contracts;

// Precompile interface and address re-exports (always available from contracts)
pub use contracts::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
    account_keychain::IAccountKeychain,
    nonce::INonce,
    stablecoin_dex::IStablecoinDEX,
    tip_fee_manager::{IFeeAMM, IFeeManager},
    tip20::{IRolesAuth, ITIP20},
    tip20_factory::ITIP20Factory,
    tip403_registry::ITIP403Registry,
    validator_config::IValidatorConfig,
};
