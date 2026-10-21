#![cfg(feature = "evm")]

use alloy_primitives::Address;
use tempo_primitives::TempoBlockExt;

#[test]
fn configurable_account_recovery_factory_treats_zero_as_unset() {
    let factory = Address::repeat_byte(0x11);
    let with = |configurable_account_recovery_factory| TempoBlockExt {
        configurable_account_recovery_factory,
        ..Default::default()
    };

    assert_eq!(with(None).configurable_account_recovery_factory(), None);
    assert_eq!(
        with(Some(Address::ZERO)).configurable_account_recovery_factory(),
        None
    );
    assert_eq!(
        with(Some(factory)).configurable_account_recovery_factory(),
        Some(factory)
    );
}
