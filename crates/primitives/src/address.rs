use alloy_primitives::{Address, FixedBytes, hex};

/// TIP20 token address prefix (12 bytes)
/// The full address is: TIP20_TOKEN_PREFIX (12 bytes) || derived_bytes (8 bytes)
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

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
