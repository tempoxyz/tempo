pub mod account_keychain;
pub mod common_errors;
pub mod nonce;
#[cfg(feature = "precompile")]
mod result;
pub mod stablecoin_dex;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;

#[cfg(feature = "precompile")]
pub use result::Result;

pub use account_keychain::*;
use alloy_primitives::{Address, address};
pub use common_errors::*;
pub use nonce::*;
pub use stablecoin_dex::*;
pub use tip_fee_manager::*;
pub use validator_config::*;

// Re-export ITIP20 module and types
pub use tip20::{ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event};

// Re-export TIP20Factory module and types
pub use tip20_factory::{ITIP20Factory, TIP20FactoryError, TIP20FactoryEvent};

// Re-export TIP403Registry module and types
pub use tip403_registry::{ITIP403Registry, TIP403RegistryError, TIP403RegistryEvent};

pub const TIP_FEE_MANAGER_ADDRESS: Address = address!("0xfeec000000000000000000000000000000000000");
pub const PATH_USD_ADDRESS: Address = address!("0x20C0000000000000000000000000000000000000");
pub const DEFAULT_FEE_TOKEN: Address = PATH_USD_ADDRESS;
pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const STABLECOIN_DEX_ADDRESS: Address = address!("0xdec0000000000000000000000000000000000000");
pub const NONCE_PRECOMPILE_ADDRESS: Address =
    address!("0x4E4F4E4345000000000000000000000000000000");
pub const VALIDATOR_CONFIG_ADDRESS: Address =
    address!("0xCCCCCCCC00000000000000000000000000000000");
pub const ACCOUNT_KEYCHAIN_ADDRESS: Address =
    address!("0xAAAAAAAA00000000000000000000000000000000");
