<<<<<<< HEAD
pub mod common_errors;
=======
pub mod account_keychain;
>>>>>>> 871f550c (chore(precompiles): update keychain precompile correctly)
pub mod linking_usd;
pub mod nonce;
pub mod stablecoin_exchange;
pub mod tip20;
pub mod tip20_factory;
pub mod tip20_rewards_registry;
pub mod tip403_registry;
pub mod tip_account_registrar;
pub mod tip_fee_manager;
pub mod validator_config;

use alloy::primitives::{Address, address};
pub use common_errors::*;
pub use account_keychain::*;
pub use linking_usd::*;
pub use nonce::*;
pub use stablecoin_exchange::*;
pub use tip_account_registrar::*;
pub use tip_fee_manager::*;
pub use tip20::*;
pub use tip20_factory::*;
pub use tip20_rewards_registry::*;
pub use tip403_registry::*;
pub use validator_config::*;

pub const TIP_FEE_MANAGER_ADDRESS: Address = address!("0xfeec000000000000000000000000000000000000");
pub const LINKING_USD_ADDRESS: Address = address!("0x20C0000000000000000000000000000000000000");
pub const DEFAULT_FEE_TOKEN: Address = address!("0x20C0000000000000000000000000000000000001");
pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const TIP20_REWARDS_REGISTRY_ADDRESS: Address =
    address!("0x3000000000000000000000000000000000000000");
pub const TIP_ACCOUNT_REGISTRAR: Address = address!("0x7702ac0000000000000000000000000000000000");
pub const STABLECOIN_EXCHANGE_ADDRESS: Address =
    address!("0xdec0000000000000000000000000000000000000");
pub const NONCE_PRECOMPILE_ADDRESS: Address =
    address!("0x4E4F4E4345000000000000000000000000000000");
pub const VALIDATOR_CONFIG_ADDRESS: Address =
    address!("0xCCCCCCCC00000000000000000000000000000000");
pub const ACCOUNT_KEYCHAIN_ADDRESS: Address =
    address!("0xAAAAAAAA00000000000000000000000000000000");
