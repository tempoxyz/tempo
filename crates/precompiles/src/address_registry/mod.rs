//! [TIP-1022] virtual address registry precompile. Enabled on `TempoHardfork::T3`.
//!
//! Provides on-chain registration of virtual-address masters and resolution of
//! [TIP-1022] virtual addresses back to their registered master EOA/contract.
//!
//! [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>

pub mod dispatch;

use crate::{
    ADDRESS_REGISTRY_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
    tip20::is_tip20_prefix,
};
use alloy::{
    primitives::{Address, FixedBytes, keccak256},
    sol_types::SolValue,
};
pub use tempo_contracts::precompiles::{AddrRegistryError, AddrRegistryEvent, IAddressRegistry};
use tempo_precompiles_macros::{Storable, contract};

/// 4-byte master identifier derived from the registration hash.
pub type MasterId = FixedBytes<4>;

/// 6-byte user tag occupying the trailing bytes of a virtual address.
pub type UserTag = FixedBytes<6>;

/// 10-byte magic value identifying virtual addresses at bytes `[4:14]`.
pub const VIRTUAL_MAGIC: [u8; 10] = [0xFD; 10];

/// Returns `true` if `addr` matches the [TIP-1022] virtual-address format
/// (bytes `[4:14]` == [`VIRTUAL_MAGIC`]).
///
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
pub fn is_virtual_address(addr: Address) -> bool {
    addr.as_slice()[4..14] == VIRTUAL_MAGIC
}

/// Returns `true` if `addr` is eligible to be a virtual-address master per TIP-1022.
pub fn is_valid_master_address(addr: Address) -> bool {
    !addr.is_zero() && !is_virtual_address(addr) && !is_tip20_prefix(addr)
}

/// Decodes a virtual address into its `(masterId, userTag)` components.
///
/// Returns `None` if the address does not match [`is_virtual_address`] format.
pub fn decode_virtual_address(addr: Address) -> Option<(MasterId, UserTag)> {
    if !is_virtual_address(addr) {
        return None;
    }

    let bytes = addr.as_slice();
    Some((
        MasterId::from_slice(&bytes[0..4]),
        UserTag::from_slice(&bytes[14..20]),
    ))
}

/// [TIP-1022] virtual address registry contract.
///
/// Maps a 4-byte [`MasterId`] to its registered master address and metadata.
/// Registration requires a 32-bit proof-of-work to prevent squatting.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
///
/// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
#[contract(addr = ADDRESS_REGISTRY_ADDRESS)]
pub struct AddressRegistry {
    /// Maps `masterId → RegistryData` (master address + metadata).
    data: Mapping<MasterId, RegistryData>,
}

/// Storage record for a registered master. Packed into a single 32-byte slot.
#[derive(Debug, Clone, Default, Storable)]
struct RegistryData {
    /// The EOA or contract that owns this `masterId`.
    master_address: Address,
    /// Reserved bytes for future use.
    reserved: FixedBytes<11>,
    /// Master type discriminator (currently unused, always `0`).
    ty: u8,
}

impl RegistryData {
    /// Returns the master address, or `None` if the slot is empty (`address(0)`).
    fn master_address(&self) -> Option<Address> {
        match self.master_address {
            Address::ZERO => None,
            master => Some(master),
        }
    }
}

impl AddressRegistry {
    /// Initializes the registry contract by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    // ────────────────── Registration ──────────────────

    /// Registers `msg_sender` as a virtual-address master.
    ///
    /// The registration hash is `keccak256(abi.encodePacked(msg.sender, salt))`.
    /// The first 4 bytes MUST be zero (32-bit proof-of-work). `masterId` is bytes `[4:8]`.
    ///
    /// # Errors
    /// - `InvalidMasterAddress` — `msg_sender` is zero, a virtual address, or a TIP-20 token
    /// - `ProofOfWorkFailed` — the first 4 bytes of the registration hash are not zero
    /// - `MasterIdCollision` — the derived `masterId` is already registered
    pub fn register_virtual_master(
        &mut self,
        msg_sender: Address,
        call: IAddressRegistry::registerVirtualMasterCall,
    ) -> Result<MasterId> {
        // Validate master address
        if !is_valid_master_address(msg_sender) {
            return Err(AddrRegistryError::invalid_master_address().into());
        }

        // Compute registration hash: keccak256(abi.encodePacked(msg.sender, salt))
        let registration_hash = keccak256((msg_sender, call.salt).abi_encode_packed());

        // 32-bit PoW: first 4 bytes must be zero
        if registration_hash[0..4] != [0u8; 4] {
            return Err(AddrRegistryError::proof_of_work_failed().into());
        }

        // masterId = bytes [4:8]
        let master_id = MasterId::from_slice(&registration_hash[4..8]);

        // Ensure no collisions
        if let Some(master) = self.data[master_id].read()?.master_address() {
            return Err(AddrRegistryError::master_id_collision(master).into());
        }

        // Store the registration
        self.data[master_id].write(RegistryData {
            master_address: msg_sender,
            reserved: FixedBytes::ZERO,
            ty: 0,
        })?;

        // Emit event
        self.emit_event(AddrRegistryEvent::MasterRegistered(
            IAddressRegistry::MasterRegistered {
                masterId: master_id,
                masterAddress: msg_sender,
            },
        ))?;

        Ok(master_id)
    }

    // ────────────────── View Functions ──────────────────

    /// Returns the registered master address for `master_id`, or `None` if unregistered.
    pub fn get_master(&self, master_id: MasterId) -> Result<Option<Address>> {
        Ok(self.data[master_id].read()?.master_address())
    }

    /// Resolves a transfer recipient using virtual address semantics.
    ///
    /// Non-virtual addresses are returned unchanged.
    /// Virtual addresses are resolved to their registered master.
    ///
    /// # Errors
    /// - `VirtualAddressUnregistered` — `to` is a virtual address whose `masterId` is not registered
    pub fn resolve_recipient(&self, to: Address) -> Result<Address> {
        // Explicit check because it isn't exclusively a view function.
        // It is also used by `tip20::Recipient`.
        if !self.storage.spec().is_t3() {
            return Ok(to);
        }

        match decode_virtual_address(to) {
            None => Ok(to),
            Some((master_id, _)) => self
                .get_master(master_id)?
                .ok_or(AddrRegistryError::virtual_address_unregistered().into()),
        }
    }

    /// Resolves a virtual address to its registered master.
    ///
    /// Returns `address(0)` if the address is not virtual or the [`MasterId`] is unregistered.
    pub fn resolve_virtual_address(&self, addr: Address) -> Result<Address> {
        match decode_virtual_address(addr) {
            None => Ok(Address::ZERO),
            Some((master_id, _)) => Ok(self.get_master(master_id)?.unwrap_or(Address::ZERO)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{VIRTUAL_MASTER, VIRTUAL_SALT, make_virtual_address},
    };
    use alloy_primitives::hex_literal::hex;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_register_virtual_master() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let (master, salt) = (VIRTUAL_MASTER, VIRTUAL_SALT.into());

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let master_id = registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt },
            )?;

            assert_eq!(registry.get_master(master_id)?, Some(master));

            Ok(())
        })
    }

    #[test]
    fn test_register_rejects_bad_pow() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let master = Address::random();
        let bad_salt = FixedBytes::<32>::ZERO;

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let result = registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt: bad_salt },
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(AddrRegistryError::ProofOfWorkFailed(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_register_rejects_zero_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let result = registry.register_virtual_master(
                Address::ZERO,
                IAddressRegistry::registerVirtualMasterCall {
                    salt: FixedBytes::ZERO,
                },
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(AddrRegistryError::InvalidMasterAddress(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_register_rejects_virtual_address_as_master() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);

        let virtual_addr = make_virtual_address(MasterId::ZERO, UserTag::ZERO);

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let result = registry.register_virtual_master(
                virtual_addr,
                IAddressRegistry::registerVirtualMasterCall {
                    salt: FixedBytes::ZERO,
                },
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(AddrRegistryError::InvalidMasterAddress(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_register_rejects_tip20_address_as_master() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let tip20_addr = crate::PATH_USD_ADDRESS;

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let result = registry.register_virtual_master(
                tip20_addr,
                IAddressRegistry::registerVirtualMasterCall {
                    salt: FixedBytes::ZERO,
                },
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(AddrRegistryError::InvalidMasterAddress(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_register_duplicate_reverts_with_collision() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let (master, salt) = (VIRTUAL_MASTER, VIRTUAL_SALT.into());

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            // First registration succeeds
            registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt },
            )?;

            // Second registration with same (address, salt) reverts
            let result = registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt },
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(AddrRegistryError::MasterIdCollision(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_is_virtual_address() {
        let random_addr = Address::random();
        assert!(!is_virtual_address(random_addr));

        let virtual_addr = make_virtual_address(
            MasterId::new(hex!("07A3B1C2")),
            UserTag::new(hex!("D4E5A7C3F19E")),
        );
        assert!(is_virtual_address(virtual_addr));
    }

    #[test]
    fn test_decode_virtual_address() {
        let mid = MasterId::new(hex!("07A3B1C2"));
        let tag = UserTag::new(hex!("D4E5A7C3F19E"));
        let addr = make_virtual_address(mid, tag);

        let (master_id, user_tag) = decode_virtual_address(addr).unwrap();
        assert_eq!(master_id, mid);
        assert_eq!(user_tag, tag);

        assert!(decode_virtual_address(Address::random()).is_none());
    }

    #[test]
    fn test_resolve_recipient_non_virtual() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let normal_addr = Address::random();

        StorageCtx::enter(&mut storage, || {
            let registry = AddressRegistry::new();

            let resolved = registry.resolve_recipient(normal_addr)?;
            assert_eq!(resolved, normal_addr);

            Ok(())
        })
    }

    #[test]
    fn test_resolve_recipient_virtual_unregistered_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let virtual_addr = make_virtual_address(MasterId::ZERO, UserTag::ZERO);

        StorageCtx::enter(&mut storage, || {
            let registry = AddressRegistry::new();

            let result = registry.resolve_recipient(virtual_addr);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::AddrRegistryError(
                    AddrRegistryError::VirtualAddressUnregistered(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn test_resolve_recipient_virtual_registered() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let (master, salt) = (VIRTUAL_MASTER, VIRTUAL_SALT.into());

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let master_id = registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt },
            )?;

            let virtual_addr = make_virtual_address(master_id, UserTag::new(hex!("010203040506")));

            let resolved = registry.resolve_recipient(virtual_addr)?;
            assert_eq!(resolved, master);

            Ok(())
        })
    }

    #[test]
    fn test_resolve_virtual_address_view() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let (master, salt) = (VIRTUAL_MASTER, VIRTUAL_SALT.into());

        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            // Non-virtual → zero
            assert_eq!(
                registry.resolve_virtual_address(Address::random())?,
                Address::ZERO
            );

            // Unregistered virtual → zero
            let unregistered = make_virtual_address(MasterId::ZERO, UserTag::ZERO);
            assert_eq!(
                registry.resolve_virtual_address(unregistered)?,
                Address::ZERO
            );

            // Registered virtual → master
            let master_id = registry.register_virtual_master(
                master,
                IAddressRegistry::registerVirtualMasterCall { salt },
            )?;
            let virtual_addr = make_virtual_address(master_id, UserTag::new(hex!("aabbccddeeff")));
            assert_eq!(registry.resolve_virtual_address(virtual_addr)?, master);

            Ok(())
        })
    }

    #[test]
    fn test_resolve_recipient_pre_t3_returns_literal() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let virtual_addr = make_virtual_address(MasterId::ZERO, UserTag::ZERO);

        StorageCtx::enter(&mut storage, || {
            let registry = AddressRegistry::new();
            assert_eq!(registry.resolve_recipient(virtual_addr)?, virtual_addr);
            Ok(())
        })
    }

    #[test]
    fn test_is_valid_master_address() {
        // Zero → invalid
        assert!(!is_valid_master_address(Address::ZERO));
        // Virtual address → invalid
        assert!(!is_valid_master_address(make_virtual_address(
            MasterId::ZERO,
            UserTag::ZERO
        )));
        // TIP-20 prefix → invalid
        assert!(!is_valid_master_address(crate::PATH_USD_ADDRESS));
        // Normal address → valid
        assert!(is_valid_master_address(Address::repeat_byte(0x42)));
    }
}
