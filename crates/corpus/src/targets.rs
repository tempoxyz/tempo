//! Target registry: the protocol contracts a corpus index labels, one bit each of a `u64` mask.
//!
//! A target's bit is its position in [`TARGETS`]. Changing a target, its match or its order
//! changes the meaning of stored masks, so it bumps [`VERSION`]. Its [`Target::modules`] are not
//! stored, so changing them does not.
//!
//! A target's modules are the Rust modules that implement it, for coverage that counts only the
//! target's own code, such as `tuner tempo cmin --target`. A function belongs to a target when
//! its own path is under one of them, so code shared by several targets is left out: the storage
//! layer, dispatch, the EVM handler, and other targets' code even where this target calls it,
//! such as the TIP-20 transfers on the fee path. What the compiler inlines into a target's
//! functions counts as theirs, and a target type's trait impls (such as its storage layout)
//! count as the target's even when the trait is shared.

use alloy_primitives::Address;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, ADDRESS_REGISTRY_ADDRESS, CONFIGURABLE_ACCOUNT_ADDRESS,
    CURRENT_COMMITTEE_ADDRESS, NONCE_PRECOMPILE_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, STABLECOIN_DEX_ADDRESS, STORAGE_CREDITS_ADDRESS,
    TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS, TIP20_FACTORY_ADDRESS,
    TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
    ZONE_FACTORY_ADDRESS, ZONE_VERIFIER_ADDRESS,
};
use tempo_primitives::TempoAddressExt;

/// Version of [`TARGETS`], stored with every index built from it.
pub const VERSION: u32 = 1;

/// A labelled protocol contract.
#[derive(Debug)]
pub struct Target {
    /// Name used on the command line, such as `feeamm`.
    pub name: &'static str,
    /// The addresses it covers.
    pub matches: Match,
    /// Paths of the modules implementing it, such as `tempo_precompiles::tip_fee_manager`.
    pub modules: &'static [&'static str],
}

impl Target {
    /// Whether the function `symbol`, demangled without hashes (such as
    /// `<tempo_precompiles::tip_fee_manager::TipFeeManager>::swap`), is in one of
    /// [`Self::modules`].
    pub fn owns(&self, symbol: &str) -> bool {
        let path = symbol.strip_prefix('<').unwrap_or(symbol);
        self.modules.iter().any(|module| {
            path.strip_prefix(module)
                .is_some_and(|rest| rest.starts_with("::"))
        })
    }
}

/// The addresses a [`Target`] covers.
#[derive(Debug)]
pub enum Match {
    Address(Address),
    /// Every address starting with these bytes.
    Prefix(&'static [u8]),
}

/// Every target, in bit order. Exact addresses never share a prefix target's prefix.
pub const TARGETS: &[Target] = &[
    target(
        "tip20",
        Match::Prefix(&Address::TIP20_PREFIX),
        &["tempo_precompiles::tip20"],
    ),
    target(
        "tip20-factory",
        Match::Address(TIP20_FACTORY_ADDRESS),
        &["tempo_precompiles::tip20_factory"],
    ),
    // The fee manager hosts the fee AMM. Its EVM-side hooks resolve fee tokens and collect fees.
    target(
        "feeamm",
        Match::Address(TIP_FEE_MANAGER_ADDRESS),
        &[
            "tempo_precompiles::tip_fee_manager",
            "tempo_evm::fee_manager",
        ],
    ),
    target(
        "dex",
        Match::Address(STABLECOIN_DEX_ADDRESS),
        &["tempo_precompiles::stablecoin_dex"],
    ),
    target(
        "keychain",
        Match::Address(ACCOUNT_KEYCHAIN_ADDRESS),
        &["tempo_precompiles::account_keychain"],
    ),
    target(
        "nonce",
        Match::Address(NONCE_PRECOMPILE_ADDRESS),
        &["tempo_precompiles::nonce"],
    ),
    target(
        "tip403",
        Match::Address(TIP403_REGISTRY_ADDRESS),
        &["tempo_precompiles::tip403_registry"],
    ),
    target(
        "validator-config",
        Match::Address(VALIDATOR_CONFIG_ADDRESS),
        &["tempo_precompiles::validator_config"],
    ),
    target(
        "validator-config-v2",
        Match::Address(VALIDATOR_CONFIG_V2_ADDRESS),
        &["tempo_precompiles::validator_config_v2"],
    ),
    target(
        "signature-verifier",
        Match::Address(SIGNATURE_VERIFIER_ADDRESS),
        &["tempo_precompiles::signature_verifier"],
    ),
    target(
        "address-registry",
        Match::Address(ADDRESS_REGISTRY_ADDRESS),
        &["tempo_precompiles::address_registry"],
    ),
    target(
        "channel-reserve",
        Match::Address(TIP20_CHANNEL_RESERVE_ADDRESS),
        &["tempo_precompiles::tip20_channel_reserve"],
    ),
    target(
        "receive-policy-guard",
        Match::Address(RECEIVE_POLICY_GUARD_ADDRESS),
        &["tempo_precompiles::receive_policy_guard"],
    ),
    target(
        "storage-credits",
        Match::Address(STORAGE_CREDITS_ADDRESS),
        &["tempo_precompiles::storage_credits"],
    ),
    target(
        "current-committee",
        Match::Address(CURRENT_COMMITTEE_ADDRESS),
        &["tempo_precompiles::current_committee"],
    ),
    // Includes the portal storage handles it creates.
    target(
        "zone-factory",
        Match::Address(ZONE_FACTORY_ADDRESS),
        &["tempo_precompiles::zone_factory"],
    ),
    target(
        "zone-verifier",
        Match::Address(ZONE_VERIFIER_ADDRESS),
        &["tempo_precompiles::zone_verifier"],
    ),
    // Portal calls run the ERC-1167 proxy and Solidity bytecode, so no Rust code is its own.
    target(
        "zone-portal",
        Match::Prefix(&Address::ZONE_PORTAL_PREFIX),
        &[],
    ),
    target(
        "configurable-account",
        Match::Address(CONFIGURABLE_ACCOUNT_ADDRESS),
        &[
            "tempo_precompiles::configurable_account",
            "tempo_evm::handler::configurable_account",
        ],
    ),
];

const fn target(name: &'static str, matches: Match, modules: &'static [&'static str]) -> Target {
    Target {
        name,
        matches,
        modules,
    }
}

/// The bit of the target covering `address`, or `None` for an unlabelled address.
pub fn classify(address: &Address) -> Option<u8> {
    TARGETS
        .iter()
        .position(|target| match target.matches {
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
        .position(|target| target.name == name)
        .map(|bit| bit as u8)
}

/// The target named `name`.
pub fn get(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_contracts::precompiles::{PATH_USD_ADDRESS, SYSTEM_PRECOMPILES};

    #[test]
    fn classifies_every_system_precompile_and_tip20() {
        assert!(TARGETS.len() <= 64);
        for (i, target) in TARGETS.iter().enumerate() {
            assert_eq!(bit(target.name), Some(i as u8));
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

    #[test]
    fn owns_only_functions_under_its_modules() {
        for (target, symbol, owned) in [
            (
                "feeamm",
                "<tempo_precompiles::tip_fee_manager::TipFeeManager>::swap",
                true,
            ),
            (
                "feeamm",
                "tempo_precompiles::tip_fee_manager::amm::compute_amount_out",
                true,
            ),
            (
                "feeamm",
                "<tempo_precompiles::tip_fee_manager::amm::Pool as tempo_precompiles::storage::Storable>::load",
                true,
            ),
            (
                "feeamm",
                "tempo_evm::fee_manager::resolve_fee_token::{closure#0}",
                true,
            ),
            (
                "feeamm",
                "<tempo_precompiles::tip20::TIP20Token>::transfer",
                false,
            ),
            (
                "feeamm",
                "<tempo_precompiles::storage::types::Mapping<alloy_primitives::Address, tempo_precompiles::tip_fee_manager::amm::Pool>>::read",
                false,
            ),
            (
                "validator-config",
                "<tempo_precompiles::validator_config_v2::ValidatorConfigV2>::add",
                false,
            ),
            (
                "validator-config-v2",
                "<tempo_precompiles::validator_config_v2::ValidatorConfigV2>::add",
                true,
            ),
            ("dex", "tempo_precompiles::stablecoin_dex_extra::f", false),
        ] {
            assert_eq!(
                get(target).unwrap().owns(symbol),
                owned,
                "{target} {symbol}"
            );
        }
    }
}
