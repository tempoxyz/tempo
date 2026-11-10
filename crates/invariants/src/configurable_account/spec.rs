//! Configuration rules written from the TIP text; hashes come from `tempo_primitives`.

use alloy_primitives::{Address, B256, keccak256};
use tempo_contracts::precompiles::SYSTEM_PRECOMPILES;
pub(crate) use tempo_primitives::transaction::configurable_account::{
    MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES as MAX_APPROVAL_BYTES,
    MAX_CONFIGURABLE_ACCOUNT_SIGNATURES as MAX_APPROVALS,
};
use tempo_primitives::{
    TempoAddressExt, is_tip20_prefix,
    transaction::configurable_account::{
        self, CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, MAX_CONFIGURABLE_ACCOUNT_OWNERS,
    },
};

use super::IConfigurableAccount::{ConfigurableAccountConfig, ConfigurableAccountOwner};

pub(crate) use tempo_primitives::account::CONFIGURABLE_ACCOUNT_CODE_HASH as MARKER_CODE_HASH;

/// The key type of a grant to a configurable delegate (TIP-1111).
pub(crate) const CONFIGURABLE_KEY_TYPE: u8 = 3;

/// `config` as the precompile's interface types it.
pub fn from_primitive(
    config: &configurable_account::ConfigurableAccountConfig,
) -> ConfigurableAccountConfig {
    ConfigurableAccountConfig {
        salt: config.salt,
        version: config.version,
        threshold: config.threshold,
        owners: config
            .owners
            .iter()
            .map(|o| ConfigurableAccountOwner {
                owner: o.owner,
                weight: o.weight,
            })
            .collect(),
    }
}

/// The first configuration rule `config` breaks, `None` when it passes them all.
// <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L74-L80>
pub(crate) fn broken_rule(
    threshold: u8,
    owners: &[ConfigurableAccountOwner],
) -> Option<&'static str> {
    if owners.is_empty() || owners.len() > MAX_CONFIGURABLE_ACCOUNT_OWNERS {
        return Some("it does not have 1 to 48 owners");
    }
    if owners.iter().any(|owner| owner.owner.is_zero()) {
        return Some("an owner address is zero");
    }
    if owners.windows(2).any(|pair| pair[0].owner >= pair[1].owner) {
        return Some("its owner addresses are not unique and ascending");
    }
    if owners.iter().any(|owner| owner.weight == 0) {
        return Some("a weight is zero");
    }
    if owners
        .iter()
        .map(|owner| u32::from(owner.weight))
        .sum::<u32>()
        > 255
    {
        return Some("its weights add up to more than 255");
    }
    if threshold == 0 {
        return Some("its threshold is zero");
    }
    let mut weights: Vec<u8> = owners.iter().map(|owner| owner.weight).collect();
    weights.sort_unstable_by(|a, b| b.cmp(a));
    if weights
        .iter()
        .take(MAX_APPROVALS)
        .map(|&w| u32::from(w))
        .sum::<u32>()
        < u32::from(threshold)
    {
        return Some("its eight largest weights add up to less than its threshold");
    }
    None
}

/// The commitment of `config`, unvalidated so invalid writes are still judged; `None` with more
/// owners than a byte counts.
pub(crate) fn commitment(config: &ConfigurableAccountConfig) -> Option<B256> {
    primitive(config).commitment_preimage().ok().map(keccak256)
}

/// The address a version-0 configuration derives, unvalidated.
pub(crate) fn derived_address(config: &ConfigurableAccountConfig) -> Option<Address> {
    primitive(config)
        .account_preimage()
        .ok()
        .map(|preimage| Address::from_word(keccak256(preimage)))
}

/// The reserved address space `account` lies in, `None` when it is outside them all.
// <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L501>
pub(crate) fn reserved(account: Address) -> Option<&'static str> {
    let bytes = account.as_slice();
    let low = u16::from_be_bytes([bytes[18], bytes[19]]);
    if account.is_zero() {
        Some("the zero address")
    } else if account.is_virtual() {
        Some("a virtual address")
    } else if is_tip20_prefix(account) {
        Some("a TIP-20 token address")
    } else if account.zone_portal_id().is_some() {
        Some("a ZonePortal address")
    } else if SYSTEM_PRECOMPILES
        .iter()
        .any(|(precompile, _)| *precompile == account)
        || (bytes[..18] == [0; 18] && ((1..=0x11).contains(&low) || low == 0x100))
    {
        Some("a precompile")
    } else {
        None
    }
}

/// The salt of `account`'s configuration after it migrates.
pub(crate) fn upgrade_salt(account: Address) -> B256 {
    keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, account.as_slice()].concat())
}

/// `config` as `tempo_primitives` types it.
fn primitive(
    config: &ConfigurableAccountConfig,
) -> configurable_account::ConfigurableAccountConfig {
    configurable_account::ConfigurableAccountConfig {
        salt: config.salt,
        version: config.version,
        threshold: config.threshold,
        owners: config
            .owners
            .iter()
            .map(|o| configurable_account::ConfigurableAccountOwner {
                owner: o.owner,
                weight: o.weight,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(byte: u8, weight: u8) -> ConfigurableAccountOwner {
        ConfigurableAccountOwner {
            owner: Address::repeat_byte(byte),
            weight,
        }
    }

    #[test]
    fn rules() {
        assert_eq!(broken_rule(1, &[owner(1, 1)]), None);
        assert!(broken_rule(1, &[]).is_some());
        assert!(broken_rule(0, &[owner(1, 1)]).is_some());
        assert!(broken_rule(1, &[owner(2, 1), owner(1, 1)]).is_some());
        assert!(broken_rule(1, &[owner(1, 1), owner(1, 1)]).is_some());
        assert!(broken_rule(1, &[owner(1, 0)]).is_some());
        assert!(broken_rule(1, &[owner(1, 200), owner(2, 56)]).is_some());
        // Nine owners of weight 1 reach at most 8 with eight approvals.
        let nine: Vec<_> = (1..=9).map(|byte| owner(byte, 1)).collect();
        assert_eq!(broken_rule(8, &nine), None);
        assert!(broken_rule(9, &nine).is_some());
        let zero = ConfigurableAccountOwner {
            owner: Address::ZERO,
            weight: 1,
        };
        assert!(broken_rule(1, &[zero]).is_some());
    }

    #[test]
    fn marker_hash() {
        assert_eq!(keccak256([0xef]), MARKER_CODE_HASH);
    }
}
