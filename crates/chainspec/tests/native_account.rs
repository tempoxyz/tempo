#![cfg(feature = "evm")]

use alloy_primitives::{Address, U256, address};
use tempo_chainspec::{TempoHardfork, is_valid_native_account};
use tempo_contracts::precompiles::{PATH_USD_ADDRESS, SYSTEM_PRECOMPILES};
use tempo_primitives::{MasterId, TempoAddressExt, UserTag};

#[test]
fn reserved_addresses_are_not_native_accounts() {
    let reserved = [
        Address::ZERO,
        Address::with_last_byte(1),
        Address::from_word(U256::from(256).into()),
        PATH_USD_ADDRESS,
        Address::new_virtual(MasterId::ZERO, UserTag::ZERO),
        address!("5ad0000000000000000000000000000000000001"),
    ]
    .into_iter()
    .chain(SYSTEM_PRECOMPILES.iter().map(|&(precompile, _)| precompile));
    for address in reserved {
        assert!(
            !is_valid_native_account(address, TempoHardfork::T14),
            "{address}"
        );
    }
}

#[test]
fn ordinary_addresses_are_native_accounts() {
    for address in [Address::repeat_byte(0x33), Address::repeat_byte(0x71)] {
        assert!(
            is_valid_native_account(address, TempoHardfork::T14),
            "{address}"
        );
    }
}
