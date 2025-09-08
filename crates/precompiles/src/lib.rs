//! Tempo precompile implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_primitives::{Address, address};

pub mod contracts;
pub mod precompiles;

pub const TIP_FEE_MANAGER_ADDRESS: Address = address!("0x1559000000000000000000000000000000000000");
pub const DEFAULT_FEE_TOKEN: Address = address!("0x20C0000000000000000000000000000000000000");
pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const TIP4217_REGISTRY_ADDRESS: Address =
    address!("0x4217C00000000000000000000000000000000000");
pub const TIP_ACCOUNT_REGISTRAR: Address = address!("0x7702ac0000000000000000000000000000000000");
const TIP20_TOKEN_PREFIX: [u8; 12] = [
    0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
