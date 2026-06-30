pub mod account_keychain;
pub mod address_registry;
pub mod common_errors;
pub mod current_committee;
pub mod nonce;
pub mod receive_policy_guard;
pub mod signature_verifier;
pub mod stablecoin_dex;
pub mod storage_credits;
pub mod tip20;
pub mod tip20_channel_reserve;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;
pub mod validator_config_v2;

pub use account_keychain::*;
pub use address_registry::*;
pub use common_errors::*;
pub use current_committee::*;
pub use nonce::*;
pub use receive_policy_guard::*;
pub use signature_verifier::*;
pub use stablecoin_dex::*;
pub use storage_credits::*;
pub use tip_fee_manager::*;
pub use tip20::*;
pub use tip20_channel_reserve::*;
pub use tip20_factory::*;
pub use tip403_registry::*;
pub use validator_config::*;
pub use validator_config_v2::*;

use alloy_primitives::{Address, address};
use tempo_hardfork::TempoHardfork;

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
pub const RECEIVE_POLICY_GUARD_ADDRESS: Address =
    address!("0xB10C000000000000000000000000000000000000");
pub const STORAGE_CREDITS_ADDRESS: Address = address!("0x1060000000000000000000000000000000000000");
pub const CURRENT_COMMITTEE_ADDRESS: Address =
    address!("0xC077E00000000000000000000000000000000000");

/// Fixed system precompile addresses and corresponding activation hardfork
pub const SYSTEM_PRECOMPILES: &[(Address, TempoHardfork)] = &[
    (TIP403_REGISTRY_ADDRESS, TempoHardfork::Genesis),
    (TIP_FEE_MANAGER_ADDRESS, TempoHardfork::Genesis),
    (STABLECOIN_DEX_ADDRESS, TempoHardfork::Genesis),
    (NONCE_PRECOMPILE_ADDRESS, TempoHardfork::Genesis),
    (ACCOUNT_KEYCHAIN_ADDRESS, TempoHardfork::Genesis),
    (VALIDATOR_CONFIG_ADDRESS, TempoHardfork::Genesis),
    (VALIDATOR_CONFIG_V2_ADDRESS, TempoHardfork::Genesis),
    (TIP20_FACTORY_ADDRESS, TempoHardfork::Genesis),
    (ADDRESS_REGISTRY_ADDRESS, TempoHardfork::T3),
    (SIGNATURE_VERIFIER_ADDRESS, TempoHardfork::T3),
    (TIP20_CHANNEL_RESERVE_ADDRESS, TempoHardfork::T5),
    (RECEIVE_POLICY_GUARD_ADDRESS, TempoHardfork::T6),
    (STORAGE_CREDITS_ADDRESS, TempoHardfork::T7),
    (CURRENT_COMMITTEE_ADDRESS, TempoHardfork::T8),
];
