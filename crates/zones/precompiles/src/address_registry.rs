//! TIP-1094 zone address registry precompile.
//!
//! Assigns sequential 4-byte master IDs to recipients. Bindings are immutable and have no public
//! getter: only the native inbox reads them, through `recipient_of`.

use alloc::vec::Vec;

use alloy_primitives::{Address, B256, FixedBytes};
use alloy_sol_types::SolEvent;
use evm2::precompiles::PrecompileResult;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::{
    IZoneAddressRegistry, ZONE_ADDRESS_REGISTRY_ADDRESS, ZVDA_MASTER_REQUEST_DOMAIN,
    ZoneAddressRegistryError,
};
use tempo_precompiles::{
    charge_input_cost, dispatch,
    storage::{Handler, Mapping, StorageCtx},
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;

use crate::{
    ZoneResult,
    storage::{L1State, L1StorageReader},
};

/// Exclusive upper bound of the 4-byte master ID space; also the exhausted counter value.
pub const MASTER_ID_SPACE: u64 = 1 << 32;

/// Zone-side TIP-1094 registry. Deployed at the T15 boundary.
#[contract(addr = ZONE_ADDRESS_REGISTRY_ADDRESS)]
pub struct ZoneAddressRegistry {
    /// Master ID (as a big-endian `u32`) to its recipient.
    recipients: Mapping<u32, Address>,
    /// Request hash to its master ID plus one; zero means unrecorded.
    registrations: Mapping<B256, u64>,
    /// The next master ID to assign.
    next_master_id: u64,
}

impl ZoneAddressRegistry {
    pub(crate) fn call<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        calldata: &[u8],
        msg_sender: Address,
    ) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        let zone_id = zone_id(l1.portal());

        dispatch!(
            calldata,
            |call| match call {
                IZoneAddressRegistry::IZoneAddressRegistryCalls {
                    registerMaster(call) => crate::dispatch::mutate(call, msg_sender, |_, call| {
                        self.register_master(zone_id, call.recipient, call.salt)
                    }),
                }
            },
        )
    }

    /// TIP-1094 `registerMaster`: idempotent per `(zone, recipient, salt)`, sequential otherwise.
    pub fn register_master(
        &mut self,
        zone_id: u32,
        recipient: Address,
        salt: B256,
    ) -> ZoneResult<FixedBytes<4>> {
        // The registry exists only from T15, so deposit addresses are always invalid masters.
        if !recipient.is_valid_master(TempoHardfork::T15) {
            return Err(ZoneAddressRegistryError::invalid_master_address().into());
        }

        let request_hash = request_hash(zone_id, recipient, salt)?;
        let existing = self.registrations[request_hash].read()?;
        if existing != 0 {
            return Ok(master_id_bytes(existing - 1));
        }

        let next = self.next_master_id.read()?;
        if next >= MASTER_ID_SPACE {
            return Err(ZoneAddressRegistryError::master_id_space_exhausted().into());
        }

        let master_id = master_id_bytes(next);
        self.recipients[next as u32].write(recipient)?;
        // The +1 offset lets the record of the last ID (0xFFFFFFFF) be distinguished from absence.
        self.registrations[request_hash].write(next + 1)?;
        self.next_master_id.write(next + 1)?;
        self.storage.emit_event(
            self.address,
            IZoneAddressRegistry::MasterRegistered {
                recipient,
                masterId: master_id,
            }
            .encode_log_data(),
        )?;
        Ok(master_id)
    }

    /// The recipient bound to `master_id`, or zero when unregistered.
    pub fn recipient_of(&self, master_id: FixedBytes<4>) -> tempo_precompiles::Result<Address> {
        self.recipients[u32::from_be_bytes(master_id.0)].read()
    }
}

/// The zone ID encoded in the portal address; zero in no-L1 development mode.
pub fn zone_id(portal: Address) -> u32 {
    portal
        .zone_portal_id()
        .and_then(|id| u32::try_from(id).ok())
        .unwrap_or_default()
}

fn master_id_bytes(id: u64) -> FixedBytes<4> {
    FixedBytes::from((id as u32).to_be_bytes())
}

/// `keccak256(abi.encodePacked("TEMPO-ZVDA-MASTER-v1", bytes4(zoneId), recipient, salt))`.
fn request_hash(zone_id: u32, recipient: Address, salt: B256) -> tempo_precompiles::Result<B256> {
    let mut data = Vec::with_capacity(ZVDA_MASTER_REQUEST_DOMAIN.len() + 4 + 20 + 32);
    data.extend_from_slice(ZVDA_MASTER_REQUEST_DOMAIN);
    data.extend_from_slice(&zone_id.to_be_bytes());
    data.extend_from_slice(recipient.as_slice());
    data.extend_from_slice(salt.as_slice());
    StorageCtx::default().keccak256(&data)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::storage::{StorageCtx, hashmap::HashMapStorageProvider};

    fn with_registry<R>(f: impl FnOnce(&mut ZoneAddressRegistry) -> R) -> R {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || f(&mut ZoneAddressRegistry::new()))
    }

    #[test]
    fn assigns_sequential_ids_and_is_idempotent() -> eyre::Result<()> {
        with_registry(|registry| {
            let acme = Address::repeat_byte(0xac);
            let bob = Address::repeat_byte(0xb0);
            let first = registry.register_master(7, acme, B256::repeat_byte(1))?;
            let second = registry.register_master(7, bob, B256::repeat_byte(1))?;
            let third = registry.register_master(7, acme, B256::repeat_byte(2))?;
            assert_eq!(first, FixedBytes::from([0, 0, 0, 0]));
            assert_eq!(second, FixedBytes::from([0, 0, 0, 1]));
            assert_eq!(third, FixedBytes::from([0, 0, 0, 2]));

            // A copied request returns the same ID without advancing the counter.
            assert_eq!(
                registry.register_master(7, acme, B256::repeat_byte(1))?,
                first
            );
            assert_eq!(registry.recipient_of(first)?, acme);
            assert_eq!(registry.recipient_of(second)?, bob);
            assert_eq!(registry.recipient_of(third)?, acme);
            assert_eq!(
                registry.recipient_of(FixedBytes::from([0, 0, 0, 3]))?,
                Address::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_invalid_recipients() {
        with_registry(|registry| {
            for recipient in [
                Address::ZERO,
                Address::new_tip20(1),
                Address::new_virtual(FixedBytes::ZERO, FixedBytes::ZERO),
                tempo_contracts::zones::ZoneDepositAddress {
                    zone_id: 7,
                    version: 1,
                    ciphertext: FixedBytes::ZERO,
                }
                .encode(),
            ] {
                assert!(matches!(
                    registry.register_master(7, recipient, B256::ZERO),
                    Err(crate::ZonePrecompileError::AddressRegistry(
                        ZoneAddressRegistryError::InvalidMasterAddress(_)
                    ))
                ));
            }
        });
    }

    #[test]
    fn exhaustion_keeps_the_last_id_and_retries_idempotent() -> eyre::Result<()> {
        with_registry(|registry| {
            let last = MASTER_ID_SPACE - 1;
            registry.next_master_id.write(last)?;
            let recipient = Address::repeat_byte(0x11);
            let id = registry.register_master(7, recipient, B256::ZERO)?;
            assert_eq!(id, FixedBytes::from([0xff; 4]));
            assert!(matches!(
                registry.register_master(7, recipient, B256::repeat_byte(9)),
                Err(crate::ZonePrecompileError::AddressRegistry(
                    ZoneAddressRegistryError::MasterIdSpaceExhausted(_)
                ))
            ));
            // The request record of the last ID is 0x100000000 and still resolves after exhaustion.
            assert_eq!(registry.register_master(7, recipient, B256::ZERO)?, id);
            Ok(())
        })
    }

    #[test]
    fn request_hash_binds_zone_and_recipient() -> eyre::Result<()> {
        with_registry(|_| {
            let salt = B256::repeat_byte(3);
            let base = request_hash(7, Address::repeat_byte(1), salt)?;
            assert_ne!(base, request_hash(8, Address::repeat_byte(1), salt)?);
            assert_ne!(base, request_hash(7, Address::repeat_byte(2), salt)?);
            Ok(())
        })
    }
}
