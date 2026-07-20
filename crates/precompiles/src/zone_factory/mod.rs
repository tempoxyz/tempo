//! Native ZoneFactory precompile for TIP-1091.

pub mod dispatch;
mod portal;

use crate::{
    ZONE_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::TIP20Token,
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, IntoLogData, hex};
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
    ZoneFactoryError, ZoneFactoryEvent, ZonePortalEvent,
};
use tempo_precompiles_macros::{Storable, contract};

#[cfg(test)]
use portal::PortalTokenConfig;
pub use portal::ZONE_PORTAL_PROXY_RUNTIME;
use portal::ZonePortalStorage;
/// Minimum gas consumed by a successful zone creation.
pub const ZONE_CREATION_GAS: u64 = 15_000_000;

/// Maximum number of equal sequencers in a zone settlement set.
pub const MAX_SEQUENCERS: usize = 32;

/// 12-byte prefix reserved for deterministic ZonePortal addresses.
pub const ZONE_PORTAL_PREFIX: [u8; 12] = hex!("5AD000000000000000000000");

/// Native ZoneFactory storage.
///
/// The field order mirrors the TIP-1091 Solidity reference artifact: `nextZoneId` and `owner`
/// share slot 0, and `zones` occupies slot 1.
#[contract(addr = ZONE_FACTORY_ADDRESS)]
pub struct ZoneFactory {
    next_zone_id: u32,
    owner: Address,
    zones: Mapping<u32, ZoneInfoStorage>,
}

/// Solidity-compatible storage representation of `ZoneInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
struct ZoneInfoStorage {
    zone_id: u32,
    portal: Address,
    initial_token: Address,
    admin: Address,
    sequencers: Vec<Address>,
    threshold: u8,
    verifier: Address,
    rpc_url: String,
}

impl From<ZoneInfoStorage> for IZoneFactory::zonesReturn {
    fn from(value: ZoneInfoStorage) -> Self {
        Self {
            zoneId: value.zone_id,
            portal: value.portal,
            initialToken: value.initial_token,
            admin: value.admin,
            sequencers: value.sequencers,
            threshold: value.threshold,
            verifier: value.verifier,
            rpcUrl: value.rpc_url,
        }
    }
}

impl ZoneFactory {
    /// Initializes the factory marker and activation state.
    ///
    /// This is an internal node hook, not part of the public precompile ABI.
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        if owner.is_zero() {
            return Err(ZoneFactoryError::invalid_owner().into());
        }
        self.__initialize()?;
        self.next_zone_id.write(1)?;
        self.owner.write(owner)?;
        self.emit_event(ZoneFactoryEvent::ownership_transferred(
            Address::ZERO,
            owner,
        ))
    }

    /// Returns the configured factory owner.
    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    /// Atomically transfers zone-creation authority.
    pub fn transfer_ownership(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::transferOwnershipCall,
    ) -> Result<()> {
        let previous_owner = self.owner()?;
        if msg_sender != previous_owner {
            return Err(ZoneFactoryError::not_owner().into());
        }
        self.owner.write(call.newOwner)?;
        self.emit_event(ZoneFactoryEvent::ownership_transferred(
            previous_owner,
            call.newOwner,
        ))
    }

    /// Copies a deployed runtime into the shared ZonePortal implementation account.
    pub fn set_portal_implementation(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::setPortalImplementationCall,
    ) -> Result<()> {
        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }

        let code_hash = self
            .copy_runtime(call.source, ZONE_PORTAL_IMPL_ADDRESS)?
            .ok_or_else(|| {
                TempoPrecompileError::from(ZoneFactoryError::invalid_portal_implementation())
            })?;
        self.emit_event(ZoneFactoryEvent::portal_implementation_updated(
            call.source,
            code_hash,
        ))
    }

    /// Copies a deployed runtime into the shared ZoneMessenger account.
    pub fn set_zone_messenger_implementation(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::setZoneMessengerImplementationCall,
    ) -> Result<()> {
        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }

        let code_hash =
            self.copy_runtime(call.source, ZONE_MESSENGER_ADDRESS)?
                .ok_or_else(|| {
                    TempoPrecompileError::from(
                        ZoneFactoryError::invalid_zone_messenger_implementation(),
                    )
                })?;
        self.emit_event(ZoneFactoryEvent::zone_messenger_implementation_updated(
            call.source,
            code_hash,
        ))
    }

    /// Copies a deployed runtime into the shared Verifier account.
    pub fn set_verifier_implementation(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::setVerifierImplementationCall,
    ) -> Result<()> {
        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }

        let code_hash = self
            .copy_runtime(call.source, ZONE_VERIFIER_ADDRESS)?
            .ok_or_else(|| {
                TempoPrecompileError::from(ZoneFactoryError::invalid_verifier_implementation())
            })?;
        self.emit_event(ZoneFactoryEvent::verifier_implementation_updated(
            call.source,
            code_hash,
        ))
    }

    /// Returns `None` when the source account has no deployed code.
    fn copy_runtime(&mut self, source: Address, destination: Address) -> Result<Option<B256>> {
        let (code_hash, code) = self.storage.account_code(source)?;
        if code_hash.is_zero() {
            return Ok(None);
        }
        self.storage.set_code(destination, code)?;
        Ok(Some(code_hash))
    }

    /// Creates and initializes a deterministic ZonePortal account.
    pub fn create_zone(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::createZoneCall,
    ) -> Result<IZoneFactory::createZoneReturn> {
        self.storage.deduct_gas(ZONE_CREATION_GAS)?;

        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }
        if !TIP20Factory::new().is_tip20(call.params.initialToken)? {
            return Err(ZoneFactoryError::invalid_token().into());
        }
        if call.params.admin.is_zero() {
            return Err(ZoneFactoryError::invalid_admin().into());
        }
        validate_sequencer_set(&call.params.sequencers, call.params.threshold)?;

        let zone_id = self.next_zone_id()?;
        let portal = portal_address(zone_id);

        // Read metadata before mutating factory or portal state. The TIP-20 validity check above
        // guarantees this is an initialized native token; failures remain atomic at the EVM call
        // checkpoint in production.
        let token = TIP20Token::from_address(call.params.initialToken)?;
        let token_name = token.name()?;
        let token_symbol = token.symbol()?;
        let token_currency = token.currency()?;

        self.next_zone_id.write(
            zone_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        // TIP-1091 deliberately etches the canonical runtime unconditionally. The 96-bit portal
        // prefix makes pre-existing state computationally infeasible to target with CREATE2.
        ZonePortalStorage::new(portal).initialize(zone_id, &call.params)?;

        self.zones[zone_id].write(ZoneInfoStorage {
            zone_id,
            portal,
            initial_token: call.params.initialToken,
            admin: call.params.admin,
            sequencers: call.params.sequencers.clone(),
            threshold: call.params.threshold,
            verifier: ZONE_VERIFIER_ADDRESS,
            rpc_url: call.params.rpcUrl.clone(),
        })?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::sequencer_set_updated(
                1,
                call.params.threshold,
                call.params.sequencers.clone(),
            )
            .into_log_data(),
        )?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::token_enabled(
                call.params.initialToken,
                token_name,
                token_symbol,
                token_currency,
            )
            .into_log_data(),
        )?;

        self.emit_event(ZoneFactoryEvent::zone_created(
            zone_id,
            portal,
            call.params.initialToken,
            call.params.admin,
            call.params.sequencers.clone(),
            call.params.threshold,
            ZONE_VERIFIER_ADDRESS,
        ))?;

        Ok(IZoneFactory::createZoneReturn {
            zoneId: zone_id,
            portal,
        })
    }

    /// Returns the next zone ID to assign.
    pub fn next_zone_id(&self) -> Result<u32> {
        self.next_zone_id.read()
    }

    /// Returns stored metadata for `zone_id`, or the zero/default record if it does not exist.
    pub fn zone(&self, zone_id: u32) -> Result<IZoneFactory::zonesReturn> {
        Ok(self.zones[zone_id].read()?.into())
    }

    /// Returns whether `portal` is in the created ZonePortal address range.
    pub fn is_zone_portal(&self, portal: Address) -> Result<bool> {
        let bytes = portal.as_slice();
        if bytes[..12] != ZONE_PORTAL_PREFIX {
            return Ok(false);
        }

        let mut suffix = [0u8; 8];
        suffix.copy_from_slice(&bytes[12..]);
        let zone_id = u64::from_be_bytes(suffix);
        Ok(zone_id != 0 && zone_id < u64::from(self.next_zone_id()?))
    }
}

fn validate_sequencer_set(sequencers: &[Address], threshold: u8) -> Result<()> {
    if sequencers.is_empty()
        || sequencers.len() > MAX_SEQUENCERS
        || threshold == 0
        || usize::from(threshold) > sequencers.len()
    {
        return Err(ZoneFactoryError::invalid_sequencer_set().into());
    }

    let mut previous = Address::ZERO;
    for sequencer in sequencers {
        if sequencer.is_zero() || *sequencer <= previous {
            return Err(ZoneFactoryError::invalid_sequencer_set().into());
        }
        previous = *sequencer;
    }
    Ok(())
}

/// Returns the deterministic TIP-1091 portal address for `zone_id`.
pub fn portal_address(zone_id: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&ZONE_PORTAL_PREFIX);
    bytes[12..].copy_from_slice(&u64::from(zone_id).to_be_bytes());
    Address::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::primitives::{Bytes, address};
    use revm::state::Bytecode;
    use tempo_chainspec::hardfork::TempoHardfork;

    const OWNER: Address = address!("0x0000000000000000000000000000000000000011");
    const ADMIN: Address = address!("0x0000000000000000000000000000000000000022");
    const SEQUENCER_A: Address = address!("0x0000000000000000000000000000000000000033");
    const SEQUENCER_B: Address = address!("0x0000000000000000000000000000000000000044");

    fn create_params(initial_token: Address) -> IZoneFactory::CreateZoneParams {
        IZoneFactory::CreateZoneParams {
            initialToken: initial_token,
            admin: ADMIN,
            sequencers: vec![SEQUENCER_A, SEQUENCER_B],
            threshold: 2,
            rpcUrl: "https://zone.example".to_string(),
        }
    }

    #[test]
    fn portal_address_uses_big_endian_zone_id_suffix() {
        assert_eq!(
            portal_address(1),
            address!("0x5AD0000000000000000000000000000000000001")
        );
        assert_eq!(
            portal_address(0x0102_0304),
            address!("0x5AD0000000000000000000000000000001020304")
        );
    }

    #[test]
    fn create_zone_installs_proxy_and_constructor_equivalent_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = ZoneFactory::new();
            factory.initialize(OWNER)?;

            let params = create_params(PATH_USD_ADDRESS);
            let created = factory.create_zone(
                OWNER,
                IZoneFactory::createZoneCall {
                    params: params.clone(),
                },
            )?;

            assert_eq!(created.zoneId, 1);
            assert_eq!(created.portal, portal_address(1));
            assert_eq!(factory.next_zone_id()?, 2);
            assert!(factory.is_zone_portal(created.portal)?);
            assert!(!factory.is_zone_portal(portal_address(2))?);
            assert_eq!(
                factory.zone(1)?,
                IZoneFactory::zonesReturn {
                    zoneId: 1,
                    portal: created.portal,
                    initialToken: PATH_USD_ADDRESS,
                    admin: ADMIN,
                    sequencers: vec![SEQUENCER_A, SEQUENCER_B],
                    threshold: 2,
                    verifier: ZONE_VERIFIER_ADDRESS,
                    rpcUrl: params.rpcUrl,
                }
            );

            let code = factory.storage.with_account_info(created.portal, |info| {
                Ok(info.code.clone().expect("portal code installed"))
            })?;
            assert_eq!(
                code.original_bytes().as_ref(),
                ZONE_PORTAL_PROXY_RUNTIME.as_slice()
            );

            let portal = ZonePortalStorage::new(created.portal);
            assert_eq!(portal.sequencer.read()?, SEQUENCER_A);
            assert_eq!(portal.admin.read()?, ADMIN);
            assert_eq!(portal.block_hash.read()?, B256::ZERO);
            assert_eq!(
                portal.token_configs[PATH_USD_ADDRESS].read()?,
                PortalTokenConfig {
                    enabled: true,
                    deposits_active: true,
                }
            );
            assert_eq!(portal.enabled_tokens.read()?, vec![PATH_USD_ADDRESS]);
            assert_eq!(portal.rpc_url.read()?, "https://zone.example");
            assert_eq!(portal.zone_id.read()?, 1);
            assert_eq!(portal.messenger.read()?, ZONE_MESSENGER_ADDRESS);
            assert_eq!(portal.verifier.read()?, ZONE_VERIFIER_ADDRESS);
            assert!(portal.initialized.read()?);
            assert_eq!(portal.sequencer_set_version.read()?, 1);
            assert_eq!(portal.sequencer_threshold.read()?, 2);
            assert_eq!(portal.sequencers.read()?, vec![SEQUENCER_A, SEQUENCER_B]);
            assert!(portal.is_sequencer[SEQUENCER_A].read()?);
            assert!(portal.is_sequencer[SEQUENCER_B].read()?);
            Ok(())
        })
    }

    #[test]
    fn create_zone_rejects_invalid_sequencer_sets() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = ZoneFactory::new();
            factory.initialize(OWNER)?;

            for (sequencers, threshold) in [
                (vec![], 1),
                (vec![Address::ZERO], 1),
                (vec![SEQUENCER_A, SEQUENCER_A], 1),
                (vec![SEQUENCER_B, SEQUENCER_A], 1),
                (vec![SEQUENCER_A], 0),
                (vec![SEQUENCER_A], 2),
                ((1u8..=33).map(Address::with_last_byte).collect(), 1),
            ] {
                let mut params = create_params(PATH_USD_ADDRESS);
                params.sequencers = sequencers;
                params.threshold = threshold;
                let err = factory
                    .create_zone(OWNER, IZoneFactory::createZoneCall { params })
                    .unwrap_err();
                assert_eq!(
                    err,
                    TempoPrecompileError::from(ZoneFactoryError::invalid_sequencer_set())
                );
                assert_eq!(factory.next_zone_id()?, 1);
            }
            Ok(())
        })
    }

    #[test]
    fn owner_and_input_validation_revert_before_mutation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = ZoneFactory::new();
            factory.initialize(OWNER)?;

            let err = factory
                .create_zone(
                    ADMIN,
                    IZoneFactory::createZoneCall {
                        params: create_params(PATH_USD_ADDRESS),
                    },
                )
                .unwrap_err();
            assert_eq!(
                err,
                TempoPrecompileError::from(ZoneFactoryError::not_owner())
            );
            assert_eq!(factory.next_zone_id()?, 1);

            Ok(())
        })
    }

    #[test]
    fn owner_can_install_and_upgrade_shared_runtimes() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut factory = ZoneFactory::new();
            factory.initialize(OWNER)?;
            let source = address!("0x0000000000000000000000000000000000000044");
            let runtime = Bytecode::new_legacy(Bytes::from_static(&[0x60, 0x2a]));
            factory.storage.set_code(source, runtime.clone())?;

            let err = factory
                .set_portal_implementation(
                    ADMIN,
                    IZoneFactory::setPortalImplementationCall { source },
                )
                .unwrap_err();
            assert_eq!(
                err,
                TempoPrecompileError::from(ZoneFactoryError::not_owner())
            );

            factory.set_portal_implementation(
                OWNER,
                IZoneFactory::setPortalImplementationCall { source },
            )?;
            factory.set_zone_messenger_implementation(
                OWNER,
                IZoneFactory::setZoneMessengerImplementationCall { source },
            )?;
            factory.set_verifier_implementation(
                OWNER,
                IZoneFactory::setVerifierImplementationCall { source },
            )?;
            for destination in [
                ZONE_PORTAL_IMPL_ADDRESS,
                ZONE_MESSENGER_ADDRESS,
                ZONE_VERIFIER_ADDRESS,
            ] {
                let installed = factory.storage.with_account_info(destination, |info| {
                    Ok(info.code.clone().expect("shared runtime installed"))
                })?;
                assert_eq!(installed, runtime);
            }

            // The code hash is the only source validation. Empty runtime bytecode has a nonzero
            // hash and is therefore accepted.
            let empty_source = address!("0x0000000000000000000000000000000000000055");
            factory
                .storage
                .set_code(empty_source, Bytecode::default())?;
            factory.set_verifier_implementation(
                OWNER,
                IZoneFactory::setVerifierImplementationCall {
                    source: empty_source,
                },
            )?;
            let installed = factory
                .storage
                .with_account_info(ZONE_VERIFIER_ADDRESS, |info| {
                    Ok(info.code.clone().expect("empty runtime installed"))
                })?;
            assert!(installed.is_empty());

            let err = factory
                .set_portal_implementation(
                    OWNER,
                    IZoneFactory::setPortalImplementationCall {
                        source: Address::ZERO,
                    },
                )
                .unwrap_err();
            assert_eq!(
                err,
                TempoPrecompileError::from(ZoneFactoryError::invalid_portal_implementation())
            );

            factory.transfer_ownership(
                OWNER,
                IZoneFactory::transferOwnershipCall {
                    newOwner: Address::ZERO,
                },
            )?;
            assert_eq!(factory.owner()?, Address::ZERO);
            factory.set_portal_implementation(
                Address::ZERO,
                IZoneFactory::setPortalImplementationCall { source },
            )?;
            Ok(())
        })
    }
}
