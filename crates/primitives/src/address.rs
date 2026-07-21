use alloy_primitives::{Address, B256, FixedBytes, U256, hex};
use tempo_contracts::{
    TempoHardfork,
    precompiles::{SYSTEM_PRECOMPILES, TEMPORARY_STORAGE_ADDRESS},
};

/// Number of blocks per [TIP-1040] epoch, approximately 24 hours at 500ms slot times.
///
/// [TIP-1040]: <https://docs.tempo.xyz/protocol/tip1040>
pub const TEMPORARY_STORAGE_EPOCH_LENGTH: u64 = 172_800;

/// A [TIP-1040] per-epoch temporary storage account: `TEMPORARY_STORAGE_ADDRESS + epoch + 1`.
///
/// Only constructible via [`Self::for_block`], so holding one is proof the address is a
/// temporary storage account. Code that only has a raw [`Address`] can classify it with
/// [`TempoAddressExt::is_temporary_storage_account`].
///
/// [TIP-1040]: <https://docs.tempo.xyz/protocol/tip1040>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TemporaryStorageAccount(Address);

impl TemporaryStorageAccount {
    /// Code deployed to epoch accounts so they are non-empty and EIP-161 state clear
    /// cannot drop their storage. These bytes are the preimage of TIP-1040's
    /// `EPOCH_ACCOUNT_CODE_HASH`.
    pub const MARKER_CODE: &'static [u8] = b"tempo.tip1040.epoch_account";

    /// Returns the account storing the data of the epoch containing `block_number`.
    pub fn for_block(block_number: u64) -> Self {
        Self::for_epoch(block_number / TEMPORARY_STORAGE_EPOCH_LENGTH)
    }

    /// Returns the account storing epoch `epoch`'s data.
    ///
    /// The `+ 1` offset reserves `TEMPORARY_STORAGE_ADDRESS` itself for the precompile
    /// dispatch logic. The sum cannot overflow 160 bits; `epoch + 1` fits the trailing
    /// 8 bytes for any epoch reachable from a block number, which is why only
    /// [`Self::for_block`] is public.
    fn for_epoch(epoch: u64) -> Self {
        let base: U256 = TEMPORARY_STORAGE_ADDRESS.into_word().into();
        Self(Address::from_word(B256::from(
            base + U256::from(epoch) + U256::ONE,
        )))
    }

    /// Returns the underlying account address.
    pub const fn address(&self) -> Address {
        self.0
    }
}

impl From<TemporaryStorageAccount> for Address {
    fn from(account: TemporaryStorageAccount) -> Self {
        account.0
    }
}

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

    /// Returns `true` if the address is a precompile. This is the case if it is either:
    /// - A TIP-20 token address.
    /// - A system precompile active at the specified `spec` hardfork.
    fn is_precompile(&self, spec: TempoHardfork) -> bool;

    /// Returns `true` if the address is a [TIP-1040] per-epoch temporary storage account
    /// (`TEMPORARY_STORAGE_ADDRESS + epoch + 1`).
    ///
    /// [TIP-1040]: <https://docs.tempo.xyz/protocol/tip1040>
    fn is_temporary_storage_account(&self) -> bool;

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

    fn is_temporary_storage_account(&self) -> bool {
        // Epoch accounts are `TEMPORARY_STORAGE_ADDRESS + epoch + 1` with `epoch` a u64,
        // so they share the base address's first 12 bytes and differ in the trailing 8.
        // The base address itself is the precompile, not a storage account.
        self.as_slice()[..12] == TEMPORARY_STORAGE_ADDRESS.as_slice()[..12]
            && *self != TEMPORARY_STORAGE_ADDRESS
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

    fn is_precompile(&self, spec: TempoHardfork) -> bool {
        self.is_tip20()
            || SYSTEM_PRECOMPILES
                .iter()
                .any(|&(a, activated)| &a == self && spec >= activated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_contracts::precompiles::PATH_USD_ADDRESS;

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

    #[test]
    fn test_temporary_storage_marker_code_hash() {
        // TIP-1040 `EPOCH_ACCOUNT_CODE_HASH`.
        assert_eq!(
            alloy_primitives::keccak256(TemporaryStorageAccount::MARKER_CODE),
            alloy_primitives::b256!(
                "0x36c6e1ae22d067a9cff9a601eb89b47b7e6b9d7170ed08dd74d663e14568066c"
            )
        );
    }

    #[test]
    fn test_temporary_storage_account_for_epoch() {
        assert_eq!(
            TemporaryStorageAccount::for_epoch(0).address(),
            Address::from(hex!("1040000000000000000000000000000000000001"))
        );
        assert_eq!(
            TemporaryStorageAccount::for_epoch(u64::from(u32::MAX)).address(),
            Address::from(hex!("1040000000000000000000000000000100000000"))
        );

        // Every constructible account satisfies the raw-address predicate.
        for epoch in [0, 1, 42, u64::from(u32::MAX), u64::MAX - 1] {
            assert!(
                TemporaryStorageAccount::for_epoch(epoch)
                    .address()
                    .is_temporary_storage_account()
            );
        }

        // The precompile itself and unrelated addresses are not storage accounts.
        assert!(!TEMPORARY_STORAGE_ADDRESS.is_temporary_storage_account());
        assert!(!Address::ZERO.is_temporary_storage_account());
        assert!(
            !Address::from(hex!("1060000000000000000000000000000000000001"))
                .is_temporary_storage_account()
        );
    }

    #[test]
    fn test_is_precompile_address() {
        for &(address, activated) in SYSTEM_PRECOMPILES {
            assert!(address.is_precompile(activated));
            assert!(address.is_precompile(TempoHardfork::T9));

            if activated != TempoHardfork::Genesis {
                assert!(!address.is_precompile(TempoHardfork::Genesis));
            }
        }

        // Assert TIP20 prefixed addresses are classified as precompiles
        assert!(PATH_USD_ADDRESS.is_tip20());
        assert!(PATH_USD_ADDRESS.is_precompile(TempoHardfork::Genesis));
    }
}
