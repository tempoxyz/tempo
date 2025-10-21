pub mod dispatch;

use crate::{
    TIP20_TOKEN_PREFIX,
    contracts::{EvmPrecompileStorageProvider, TIP20Token},
    tempo_precompile,
};
use alloy::primitives::Address;
use alloy_evm::precompiles::DynPrecompile;

pub fn is_tip20(token: &Address) -> bool {
    token.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// Converts a token ID to its corresponding contract address
/// Uses the pattern: TIP20_TOKEN_PREFIX ++ token_id
pub fn token_id_to_address(token_id: u64) -> Address {
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
    address_bytes[12..20].copy_from_slice(&token_id.to_be_bytes());
    Address::from(address_bytes)
}

pub fn address_to_token_id_unchecked(address: &Address) -> u64 {
    u64::from_be_bytes(address.as_slice()[12..20].try_into().unwrap())
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: &Address, chain_id: u64) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            token_id,
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id),
        ))
    }
}

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

    #[test]
    fn test_tip20_payment_prefix() {
        assert_eq!(
            TIP20_PAYMENT_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Payment prefix should start with token prefix
        assert_eq!(&TIP20_PAYMENT_PREFIX[..12], &TIP20_TOKEN_PREFIX);
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..14], &TIP20_PAYMENT_PREFIX);
    }
}
