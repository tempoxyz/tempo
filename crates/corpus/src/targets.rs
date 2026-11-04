//! Target registry: the protocol contracts a corpus index labels, one bit each of a `u64` mask.
//!
//! A target's bit is its position in [`TARGETS`]. Changing a target, its match or its order
//! changes the meaning of stored masks, so it bumps [`VERSION`].

use alloy_primitives::Address;
use tempo_contracts::precompiles::*;
use tempo_primitives::TempoAddressExt;

/// Version of [`TARGETS`], stored with every index built from it.
pub const VERSION: u32 = 1;

/// The addresses a target covers.
#[derive(Debug)]
pub enum Match {
    Address(Address),
    /// Every address starting with these bytes.
    Prefix(&'static [u8]),
}

/// Every target, by its command-line name, in bit order. Exact addresses never share a prefix
/// target's prefix.
pub const TARGETS: &[(&str, Match)] = &[
    ("tip20", Match::Prefix(&Address::TIP20_PREFIX)),
    ("tip20-factory", Match::Address(TIP20_FACTORY_ADDRESS)),
    // The fee manager hosts the fee AMM.
    ("feeamm", Match::Address(TIP_FEE_MANAGER_ADDRESS)),
    ("dex", Match::Address(STABLECOIN_DEX_ADDRESS)),
    ("keychain", Match::Address(ACCOUNT_KEYCHAIN_ADDRESS)),
    ("nonce", Match::Address(NONCE_PRECOMPILE_ADDRESS)),
    ("tip403", Match::Address(TIP403_REGISTRY_ADDRESS)),
    ("validator-config", Match::Address(VALIDATOR_CONFIG_ADDRESS)),
    (
        "validator-config-v2",
        Match::Address(VALIDATOR_CONFIG_V2_ADDRESS),
    ),
    (
        "signature-verifier",
        Match::Address(SIGNATURE_VERIFIER_ADDRESS),
    ),
    ("address-registry", Match::Address(ADDRESS_REGISTRY_ADDRESS)),
    (
        "channel-reserve",
        Match::Address(TIP20_CHANNEL_RESERVE_ADDRESS),
    ),
    (
        "receive-policy-guard",
        Match::Address(RECEIVE_POLICY_GUARD_ADDRESS),
    ),
    ("storage-credits", Match::Address(STORAGE_CREDITS_ADDRESS)),
    (
        "current-committee",
        Match::Address(CURRENT_COMMITTEE_ADDRESS),
    ),
    ("zone-factory", Match::Address(ZONE_FACTORY_ADDRESS)),
    ("zone-verifier", Match::Address(ZONE_VERIFIER_ADDRESS)),
    ("zone-portal", Match::Prefix(&Address::ZONE_PORTAL_PREFIX)),
    (
        "configurable-account",
        Match::Address(CONFIGURABLE_ACCOUNT_ADDRESS),
    ),
];

/// The bit of the target covering `address`, or `None` for an unlabelled address.
pub fn classify(address: &Address) -> Option<u8> {
    TARGETS
        .iter()
        .position(|(_, matches)| match *matches {
            Match::Address(exact) => exact == *address,
            Match::Prefix(prefix) => address.starts_with(prefix),
        })
        .map(|bit| bit as u8)
}

/// `address`'s target as a mask, zero for an unlabelled address.
pub fn mask(address: &Address) -> u64 {
    classify(address).map_or(0, |bit| 1 << bit)
}

/// The bit of the target named `name`.
pub fn bit(name: &str) -> Option<u8> {
    TARGETS
        .iter()
        .position(|(target, _)| *target == name)
        .map(|bit| bit as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_contracts::precompiles::{PATH_USD_ADDRESS, SYSTEM_PRECOMPILES};

    #[test]
    fn classifies_every_system_precompile_and_tip20() {
        assert!(TARGETS.len() <= 64);
        for (i, (name, _)) in TARGETS.iter().enumerate() {
            assert_eq!(bit(name), Some(i as u8));
        }
        for (precompile, _) in SYSTEM_PRECOMPILES {
            assert!(classify(precompile).is_some(), "{precompile} unlabelled");
        }
        for (address, name) in [
            (PATH_USD_ADDRESS, Some("tip20")),
            (Address::new_tip20(7), Some("tip20")),
            (TIP_FEE_MANAGER_ADDRESS, Some("feeamm")),
            (STABLECOIN_DEX_ADDRESS, Some("dex")),
            (address!("0x20c1000000000000000000000000000000000000"), None),
            (Address::repeat_byte(0x11), None),
        ] {
            assert_eq!(classify(&address), name.and_then(bit), "{address}");
        }
        assert_eq!(mask(&STABLECOIN_DEX_ADDRESS), 1 << bit("dex").unwrap());
    }
}
