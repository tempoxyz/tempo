//! Tempo precompile implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_primitives::{Address, address, hex};

pub mod contracts;
pub mod precompiles;

pub const TIP_FEE_MANAGER_ADDRESS: Address = address!("0xfeec000000000000000000000000000000000000");
pub const DEFAULT_FEE_TOKEN: Address = address!("0x20C0000000000000000000000000000000000000");
pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const TIP4217_REGISTRY_ADDRESS: Address =
    address!("0x4217C00000000000000000000000000000000000");
pub const TIP_ACCOUNT_REGISTRAR: Address = address!("0x7702ac0000000000000000000000000000000000");
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("0x20C000000000000000000000");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tip20_token_prefix() {
        assert_eq!(
            TIP20_TOKEN_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..12], &TIP20_TOKEN_PREFIX);
    }
}
