pub mod account_keychain;
pub mod address_registry;
pub mod common_errors;
pub mod nonce;
pub mod signature_verifier;
pub mod stablecoin_dex;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;
pub mod validator_config_v2;

pub use account_keychain::*;
pub use address_registry::*;
use alloy_primitives::{Address, address};
pub use common_errors::*;
pub use nonce::*;
pub use signature_verifier::*;
pub use stablecoin_dex::*;
pub use tip_fee_manager::*;
pub use tip20::*;
pub use tip20_factory::*;
pub use tip403_registry::*;
pub use validator_config::*;
pub use validator_config_v2::*;

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
pub const VALIDATOR_CONFIG_V2_ADDRESS: Address =
    address!("0xCCCCCCCC00000000000000000000000000000001");
pub const ADDRESS_REGISTRY_ADDRESS: Address =
    address!("0xFDC0000000000000000000000000000000000000");
pub const SIGNATURE_VERIFIER_ADDRESS: Address =
    address!("0x5165300000000000000000000000000000000000");
