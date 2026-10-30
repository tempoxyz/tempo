//! The configuration rules and hashes of TIP-1107 and TIP-1113, written from the TIPs' text rather
//! than taken from the implementation, so checks compare the two.

use alloy_primitives::{Address, B256, b256, keccak256};

use super::IConfigurableAccount::{ConfigurableAccountConfig, ConfigurableAccountOwner};

/// Domain of a derived account address.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L84-L93
const ACCOUNT_DOMAIN: &[u8] = b"tempo:configurable-account:account";
/// Domain of a configuration commitment.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L180-L188
const CONFIG_DOMAIN: &[u8] = b"tempo:configurable-account:config";
/// Domain of the digest owners approve.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L121-L126
const SIGNATURE_DOMAIN: &[u8] = b"tempo:configurable-account:signature";
/// Domain of a migrated account's salt.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1113.md#L77-L80
const UPGRADE_DOMAIN: &[u8] = b"tempo:configurable-account:upgrade";

/// Most owners a configuration has.
pub const MAX_OWNERS: usize = 48;
/// Most approvals one configurable-account signature carries.
pub const MAX_APPROVALS: usize = 8;
/// Most bytes one approval takes.
pub const MAX_APPROVAL_BYTES: usize = 2049;
/// The key type of a grant to a configurable delegate (TIP-1111).
pub const CONFIGURABLE_KEY_TYPE: u8 = 3;

/// Code hash of the account code marker, `keccak256(0xef)`.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L266-L269
pub const MARKER_CODE_HASH: B256 =
    b256!("309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3");

/// The first configuration rule `config` breaks, `None` when it passes them all.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L74-L80
pub fn broken_rule(threshold: u8, owners: &[ConfigurableAccountOwner]) -> Option<&'static str> {
    if owners.is_empty() || owners.len() > MAX_OWNERS {
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

/// `uint8(threshold) || uint8(owner_count) || owner[0].address || uint8(owner[0].weight) || ...`,
/// `None` with more owners than a byte counts.
fn owner_set(threshold: u8, owners: &[ConfigurableAccountOwner]) -> Option<Vec<u8>> {
    let mut set = vec![threshold, u8::try_from(owners.len()).ok()?];
    for owner in owners {
        set.extend_from_slice(owner.owner.as_slice());
        set.push(owner.weight);
    }
    Some(set)
}

/// The commitment of `config`, `None` with more owners than a byte counts.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L180-L188
pub fn commitment(config: &ConfigurableAccountConfig) -> Option<B256> {
    let set = owner_set(config.threshold, &config.owners)?;
    Some(keccak256(
        [
            CONFIG_DOMAIN,
            config.salt.as_slice(),
            &config.version.to_be_bytes(),
            &set,
        ]
        .concat(),
    ))
}

/// The address a version-0 configuration derives.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L86-L95
pub fn derived_address(config: &ConfigurableAccountConfig) -> Option<Address> {
    let set = owner_set(config.threshold, &config.owners)?;
    Some(Address::from_word(keccak256(
        [ACCOUNT_DOMAIN, config.salt.as_slice(), &set].concat(),
    )))
}

/// The salt of `account`'s configuration after it migrates.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1113.md#L77-L82
pub fn upgrade_salt(account: Address) -> B256 {
    keccak256([UPGRADE_DOMAIN, account.as_slice()].concat())
}

/// The digest an owner of `account` approves at configuration `version` for `inner_digest`.
// https://github.com/tempoxyz/tempo/blob/868ec908f5c04a9419aa78cddb0d95d32971c4d1/tips/tip-1107.md#L121-L128
pub fn approval_digest(inner_digest: B256, account: Address, version: u64) -> B256 {
    keccak256(
        [
            SIGNATURE_DOMAIN,
            inner_digest.as_slice(),
            account.as_slice(),
            &version.to_be_bytes(),
        ]
        .concat(),
    )
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
