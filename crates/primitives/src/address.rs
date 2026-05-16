use alloy_primitives::{Address, FixedBytes, hex};

/// TIP20 token address prefix (12 bytes)
/// The full address is: TIP20_TOKEN_PREFIX (12 bytes) || derived_bytes (8 bytes)
pub const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// Returns `true` if `addr` has the TIP-20 token prefix.
///
/// NOTE: This only checks the prefix, not whether the token was actually created.
/// Use `TIP20Factory::is_tip20()` for full validation.
pub fn is_tip20_prefix(addr: Address) -> bool {
    addr.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// 4-byte master identifier derived from the registration hash.
pub type MasterId = FixedBytes<4>;

/// 6-byte user tag occupying the trailing bytes of a virtual address.
pub type UserTag = FixedBytes<6>;

/// Extension trait with helper functions for Tempo addresses.
pub trait TempoAddressExt {
    /// 12-byte prefix shared by all TIP-20 token addresses.
    ///
    /// NOTE: prefix alone does not prove a token exists — use `TIP20Factory::is_tip20()` for that.
    const TIP20_PREFIX: [u8; 12];

    /// 10-byte magic value occupying bytes `[4:14]` of every [TIP-1022] virtual address.
    ///
    /// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
    const VIRTUAL_MAGIC: [u8; 10];

    /// Returns `true` if the address has the [TIP-20] token prefix.
    ///
    /// NOTE: This only checks the prefix, not whether the token was actually created.
    /// Use `TIP20Factory::is_tip20()` for full validation.
    ///
    /// [TIP-20]: <https://docs.tempo.xyz/protocol/tip20>
    fn is_tip20(&self) -> bool;

    /// Returns `true` if the address matches the [TIP-1022] virtual-address format
    /// (bytes `[4:14]` == [`Self::VIRTUAL_MAGIC`]).
    ///
    /// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
    fn is_virtual(&self) -> bool;

    /// Returns `true` if the address is eligible to be a virtual-address master per TIP-1022.
    fn is_valid_master(&self) -> bool;

    /// Decodes a virtual address into its `(masterId, userTag)` components.
    ///
    /// Returns `None` if the address does not match the virtual-address format.
    fn decode_virtual(&self) -> Option<(MasterId, UserTag)>;

    /// Builds a [TIP-1022] virtual address from a `masterId` and `userTag`.
    ///
    /// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
    fn new_virtual(master_id: MasterId, user_tag: UserTag) -> Self;
}

impl TempoAddressExt for Address {
    const TIP20_PREFIX: [u8; 12] = TIP20_TOKEN_PREFIX;
    const VIRTUAL_MAGIC: [u8; 10] = [0xFD; 10];

    fn is_tip20(&self) -> bool {
        is_tip20_prefix(*self)
    }

    fn is_virtual(&self) -> bool {
        self.as_slice()[4..14] == Self::VIRTUAL_MAGIC
    }

    fn is_valid_master(&self) -> bool {
        !self.is_zero() && !self.is_virtual() && !self.is_tip20()
    }

    fn decode_virtual(&self) -> Option<(MasterId, UserTag)> {
        if !self.is_virtual() {
            return None;
        }
        let bytes = self.as_slice();
        Some((
            MasterId::from_slice(&bytes[0..4]),
            UserTag::from_slice(&bytes[14..20]),
        ))
    }

    fn new_virtual(master_id: MasterId, user_tag: UserTag) -> Self {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(master_id.as_slice());
        bytes[4..14].copy_from_slice(&Self::VIRTUAL_MAGIC);
        bytes[14..20].copy_from_slice(user_tag.as_slice());
        Self::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn is_tip20_prefix_variations() {
        // address with exact TIP20 prefix
        let mut bytes = [0u8; 20];
        bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
        let tip20_addr = Address::from(bytes);
        assert!(is_tip20_prefix(tip20_addr));
        assert!(tip20_addr.is_tip20());

        // zero address is not TIP20
        assert!(!Address::ZERO.is_tip20());

        // random address is not TIP20
        assert!(!address!("0x1111111111111111111111111111111111111111").is_tip20());

        // differs at byte index 1 (0xC0 → 0x00) — not TIP20
        let mut wrong = [0u8; 20];
        wrong[0] = TIP20_TOKEN_PREFIX[0];
        // skip byte 1 (leave as 0 instead of 0xC0)
        assert!(!is_tip20_prefix(Address::from(wrong)));
    }

    #[test]
    fn virtual_address_variations() {
        let master_id = MasterId::from([0xAA, 0xBB, 0xCC, 0xDD]);
        let user_tag = UserTag::from([1, 2, 3, 4, 5, 6]);

        // construct → decode roundtrip
        let vaddr = Address::new_virtual(master_id, user_tag);
        assert!(vaddr.is_virtual());
        let (decoded_master, decoded_tag) = vaddr.decode_virtual().unwrap();
        assert_eq!(decoded_master, master_id);
        assert_eq!(decoded_tag, user_tag);

        // non-virtual address returns None
        assert!(Address::ZERO.decode_virtual().is_none());
        assert!(!Address::ZERO.is_virtual());

        // zero master_id + zero user_tag
        let zero_vaddr = Address::new_virtual(MasterId::ZERO, UserTag::ZERO);
        assert!(zero_vaddr.is_virtual());
        let (m, t) = zero_vaddr.decode_virtual().unwrap();
        assert_eq!(m, MasterId::ZERO);
        assert_eq!(t, UserTag::ZERO);
    }

    #[test]
    fn is_valid_master_variations() {
        // regular address is valid master
        let regular = address!("0x1111111111111111111111111111111111111111");
        assert!(regular.is_valid_master());

        // zero address is not valid master
        assert!(!Address::ZERO.is_valid_master());

        // virtual address is not valid master
        let vaddr = Address::new_virtual(
            MasterId::from([1, 2, 3, 4]),
            UserTag::from([5, 6, 7, 8, 9, 10]),
        );
        assert!(!vaddr.is_valid_master());

        // TIP20 address is not valid master
        let mut tip20_bytes = [0u8; 20];
        tip20_bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
        assert!(!Address::from(tip20_bytes).is_valid_master());
    }
}
