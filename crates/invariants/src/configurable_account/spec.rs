//! Configuration rules written from the TIP text; hashes come from `tempo_primitives`.

use alloy_primitives::{Address, B256, b256, keccak256};
use tempo_primitives::transaction::configurable_account::{
    self as primitives, CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, MAX_CONFIGURABLE_ACCOUNT_OWNERS,
};
pub use tempo_primitives::transaction::configurable_account::{
    MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES as MAX_APPROVAL_BYTES,
    MAX_CONFIGURABLE_ACCOUNT_SIGNATURES as MAX_APPROVALS,
    configurable_account_digest as approval_digest,
};

use super::IConfigurableAccount::{ConfigurableAccountConfig, ConfigurableAccountOwner};

/// The key type of a grant to a configurable delegate (TIP-1111).
pub const CONFIGURABLE_KEY_TYPE: u8 = 3;

/// Code hash of the account code marker, `keccak256(0xef)`.
// <https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L266-L269>
pub const MARKER_CODE_HASH: B256 =
    b256!("309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3");

/// The first configuration rule `config` breaks, `None` when it passes them all.
// <https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L74-L80>
pub fn broken_rule(threshold: u8, owners: &[ConfigurableAccountOwner]) -> Option<&'static str> {
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
    let quorum: u32 = weights
        .iter()
        .take(MAX_APPROVALS)
        .map(|&w| u32::from(w))
        .sum();
    if quorum < u32::from(threshold) {
        return Some("its eight largest weights add up to less than its threshold");
    }
    None
}

/// `config` as `tempo_primitives` types it.
fn primitive(config: &ConfigurableAccountConfig) -> primitives::ConfigurableAccountConfig {
    primitives::ConfigurableAccountConfig {
        salt: config.salt,
        version: config.version,
        threshold: config.threshold,
        owners: config
            .owners
            .iter()
            .map(|o| primitives::ConfigurableAccountOwner {
                owner: o.owner,
                weight: o.weight,
            })
            .collect(),
    }
}

/// The commitment of `config`, unvalidated so invalid writes are still judged; `None` with more
/// owners than a byte counts.
pub fn commitment(config: &ConfigurableAccountConfig) -> Option<B256> {
    primitive(config).commitment_preimage().ok().map(keccak256)
}

/// The address a version-0 configuration derives, unvalidated.
pub fn derived_address(config: &ConfigurableAccountConfig) -> Option<Address> {
    primitive(config)
        .account_preimage()
        .ok()
        .map(|preimage| Address::from_word(keccak256(preimage)))
}

/// The salt of `account`'s configuration after it migrates.
pub fn upgrade_salt(account: Address) -> B256 {
    keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, account.as_slice()].concat())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

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
            owner: address!("0x0000000000000000000000000000000000000000"),
            weight: 1,
        };
        assert!(broken_rule(1, &[zero]).is_some());
    }

    #[test]
    fn marker_hash() {
        assert_eq!(keccak256([0xef]), MARKER_CODE_HASH);
    }
}
