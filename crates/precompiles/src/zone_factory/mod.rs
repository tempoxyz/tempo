//! Native ZoneFactory precompile for TIP-1091.

pub mod dispatch;

use crate::{
    ZONE_FACTORY_ADDRESS,
    error::Result,
    storage::{Handler, Mapping, Slot, vec::VecHandler},
    tip20::TIP20Token,
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256, hex};
use revm::state::Bytecode;
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError,
    ZoneFactoryEvent, ZoneInfo, ZonePortalEvent,
};
use tempo_precompiles_macros::{Storable, contract};

/// Minimum gas that must remain when zone creation starts.
pub const ZONE_CREATION_GAS: u64 = 15_000_000;

/// 12-byte prefix reserved for deterministic ZonePortal addresses.
pub const ZONE_PORTAL_PREFIX: [u8; 12] = hex!("5AD000000000000000000000");

/// Exact ERC-1167 deployed proxy runtime installed at every ZonePortal address.
pub const ZONE_PORTAL_PROXY_RUNTIME: [u8; 45] = hex!(
    "363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
);

// Canonical ZonePortal storage slots from tempoxyz/zones. These are cross-domain consensus
// contracts and must stay aligned with the portal runtime pinned for T9 activation.
const PORTAL_SEQUENCER_SLOT: U256 = U256::from_limbs([0, 0, 0, 0]);
const PORTAL_ADMIN_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);
const PORTAL_BLOCK_HASH_SLOT: U256 = U256::from_limbs([4, 0, 0, 0]);
const PORTAL_TOKEN_CONFIGS_SLOT: U256 = U256::from_limbs([8, 0, 0, 0]);
const PORTAL_ENABLED_TOKENS_SLOT: U256 = U256::from_limbs([9, 0, 0, 0]);
const PORTAL_RPC_URL_SLOT: U256 = U256::from_limbs([14, 0, 0, 0]);
const PORTAL_ZONE_METADATA_SLOT: U256 = U256::from_limbs([17, 0, 0, 0]);
const PORTAL_VERIFIER_METADATA_SLOT: U256 = U256::from_limbs([18, 0, 0, 0]);

/// Native ZoneFactory storage.
///
/// The field order mirrors the TIP-1091 Solidity reference artifact:
/// `nextZoneId` at slot 0, `_zones` at slot 1, and `owner` at slot 2.
#[contract(addr = ZONE_FACTORY_ADDRESS)]
pub struct ZoneFactory {
    next_zone_id: u32,
    zones: Mapping<u32, ZoneInfoStorage>,
    owner: Address,
}

/// Solidity-compatible storage representation of `ZoneInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
struct ZoneInfoStorage {
    zone_id: u32,
    portal: Address,
    initial_token: Address,
    admin: Address,
    sequencer: Address,
    genesis_block_hash: B256,
    genesis_tempo_block_hash: B256,
    genesis_tempo_block_number: u64,
    rpc_url: String,
}

impl From<ZoneInfoStorage> for ZoneInfo {
    fn from(value: ZoneInfoStorage) -> Self {
        Self {
            zoneId: value.zone_id,
            portal: value.portal,
            initialToken: value.initial_token,
            admin: value.admin,
            sequencer: value.sequencer,
            genesisBlockHash: value.genesis_block_hash,
            genesisTempoBlockHash: value.genesis_tempo_block_hash,
            genesisTempoBlockNumber: value.genesis_tempo_block_number,
            rpcUrl: value.rpc_url,
        }
    }
}

/// Packed `TokenConfig` stored in the canonical portal mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
struct PortalTokenConfig {
    enabled: bool,
    deposits_active: bool,
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
        self.owner.write(owner)
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
        if call.newOwner.is_zero() {
            return Err(ZoneFactoryError::invalid_owner().into());
        }

        self.owner.write(call.newOwner)?;
        self.emit_event(ZoneFactoryEvent::ownership_transferred(
            previous_owner,
            call.newOwner,
        ))
    }

    /// Creates and initializes a deterministic ZonePortal account.
    pub fn create_zone(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::createZoneCall,
    ) -> Result<IZoneFactory::createZoneReturn> {
        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }
        if !TIP20Factory::new().is_tip20(call.params.initialToken)? {
            return Err(ZoneFactoryError::invalid_token().into());
        }
        if call.params.admin.is_zero() {
            return Err(ZoneFactoryError::invalid_admin().into());
        }
        if call.params.sequencer.is_zero() {
            return Err(ZoneFactoryError::invalid_sequencer().into());
        }

        // HashMapStorageProvider uses zero as its unit-test sentinel for unlimited gas.
        let gas_limit = self.storage.gas_limit();
        let gas_remaining = gas_limit.saturating_sub(self.storage.gas_used());
        if gas_limit != 0 && gas_remaining < ZONE_CREATION_GAS {
            return Err(ZoneFactoryError::insufficient_gas().into());
        }

        let zone_id = self.next_zone_id()?;
        if zone_id == u32::MAX {
            return Err(ZoneFactoryError::zone_id_overflow().into());
        }

        let portal = portal_address(zone_id);

        // Read metadata before mutating factory or portal state. The TIP-20 validity check above
        // guarantees this is an initialized native token; failures remain atomic at the EVM call
        // checkpoint in production.
        let token = TIP20Token::from_address(call.params.initialToken)?;
        let token_name = token.name()?;
        let token_symbol = token.symbol()?;
        let token_currency = token.currency()?;

        self.next_zone_id.write(zone_id + 1)?;
        self.initialize_portal(portal, zone_id, &call.params)?;

        self.zones[zone_id].write(ZoneInfoStorage {
            zone_id,
            portal,
            initial_token: call.params.initialToken,
            admin: call.params.admin,
            sequencer: call.params.sequencer,
            genesis_block_hash: call.params.zoneParams.genesisBlockHash,
            genesis_tempo_block_hash: call.params.zoneParams.genesisTempoBlockHash,
            genesis_tempo_block_number: call.params.zoneParams.genesisTempoBlockNumber,
            rpc_url: call.params.rpcUrl.clone(),
        })?;

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
            call.params.sequencer,
            ZONE_VERIFIER_ADDRESS,
            call.params.zoneParams.genesisBlockHash,
            call.params.zoneParams.genesisTempoBlockHash,
            call.params.zoneParams.genesisTempoBlockNumber,
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
    pub fn zone(&self, zone_id: u32) -> Result<ZoneInfo> {
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

    fn initialize_portal(
        &mut self,
        portal: Address,
        zone_id: u32,
        params: &IZoneFactory::CreateZoneParams,
    ) -> Result<()> {
        // TIP-1091 deliberately etches the canonical runtime unconditionally. The 96-bit portal
        // prefix makes pre-existing state computationally infeasible to target with CREATE2.
        self.storage.set_code(
            portal,
            Bytecode::new_legacy(Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME)),
        )?;

        Slot::<Address>::new(PORTAL_SEQUENCER_SLOT, portal).write(params.sequencer)?;
        Slot::<Address>::new(PORTAL_ADMIN_SLOT, portal).write(params.admin)?;
        Slot::<B256>::new(PORTAL_BLOCK_HASH_SLOT, portal)
            .write(params.zoneParams.genesisBlockHash)?;

        let mut token_configs =
            Mapping::<Address, PortalTokenConfig>::new(PORTAL_TOKEN_CONFIGS_SLOT, portal);
        token_configs[params.initialToken].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })?;
        VecHandler::<Address>::new(PORTAL_ENABLED_TOKENS_SLOT, portal)
            .write(vec![params.initialToken])?;
        Slot::<String>::new(PORTAL_RPC_URL_SLOT, portal).write(params.rpcUrl.clone())?;

        let zone_metadata =
            U256::from(zone_id) | (U256::from_be_slice(ZONE_MESSENGER_ADDRESS.as_slice()) << 32);
        self.storage
            .sstore(portal, PORTAL_ZONE_METADATA_SLOT, zone_metadata)?;

        let verifier_metadata = U256::from_be_slice(ZONE_VERIFIER_ADDRESS.as_slice())
            | (U256::from(params.zoneParams.genesisTempoBlockNumber) << 160)
            | (U256::from(1) << 224);
        self.storage
            .sstore(portal, PORTAL_VERIFIER_METADATA_SLOT, verifier_metadata)
    }
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
    use alloy::primitives::{address, b256};
    use tempo_chainspec::hardfork::TempoHardfork;

    const OWNER: Address = address!("0x0000000000000000000000000000000000000011");
    const ADMIN: Address = address!("0x0000000000000000000000000000000000000022");
    const SEQUENCER: Address = address!("0x0000000000000000000000000000000000000033");

    fn create_params(initial_token: Address) -> IZoneFactory::CreateZoneParams {
        IZoneFactory::CreateZoneParams {
            initialToken: initial_token,
            admin: ADMIN,
            sequencer: SEQUENCER,
            zoneParams: tempo_contracts::precompiles::ZoneParams {
                genesisBlockHash: b256!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                ),
                genesisTempoBlockHash: b256!(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                ),
                genesisTempoBlockNumber: 42,
            },
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
                ZoneInfo {
                    zoneId: 1,
                    portal: created.portal,
                    initialToken: PATH_USD_ADDRESS,
                    admin: ADMIN,
                    sequencer: SEQUENCER,
                    genesisBlockHash: params.zoneParams.genesisBlockHash,
                    genesisTempoBlockHash: params.zoneParams.genesisTempoBlockHash,
                    genesisTempoBlockNumber: 42,
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

            assert_eq!(
                Slot::<Address>::new(PORTAL_SEQUENCER_SLOT, created.portal).read()?,
                SEQUENCER
            );
            assert_eq!(
                Slot::<Address>::new(PORTAL_ADMIN_SLOT, created.portal).read()?,
                ADMIN
            );
            assert_eq!(
                Slot::<B256>::new(PORTAL_BLOCK_HASH_SLOT, created.portal).read()?,
                params.zoneParams.genesisBlockHash
            );
            assert_eq!(
                Mapping::<Address, PortalTokenConfig>::new(
                    PORTAL_TOKEN_CONFIGS_SLOT,
                    created.portal
                )[PATH_USD_ADDRESS]
                    .read()?,
                PortalTokenConfig {
                    enabled: true,
                    deposits_active: true,
                }
            );
            assert_eq!(
                VecHandler::<Address>::new(PORTAL_ENABLED_TOKENS_SLOT, created.portal).read()?,
                vec![PATH_USD_ADDRESS]
            );
            assert_eq!(
                Slot::<String>::new(PORTAL_RPC_URL_SLOT, created.portal).read()?,
                "https://zone.example"
            );

            let zone_metadata = factory
                .storage
                .sload(created.portal, PORTAL_ZONE_METADATA_SLOT)?;
            assert_eq!(zone_metadata & U256::from(u32::MAX), U256::from(1));
            assert_eq!(
                Address::from_word(B256::from((zone_metadata >> 32usize).to_be_bytes::<32>())),
                ZONE_MESSENGER_ADDRESS
            );

            let verifier_metadata = factory
                .storage
                .sload(created.portal, PORTAL_VERIFIER_METADATA_SLOT)?;
            assert_eq!(
                Address::from_word(B256::from(verifier_metadata.to_be_bytes::<32>())),
                ZONE_VERIFIER_ADDRESS
            );
            assert_eq!(
                ((verifier_metadata >> 160usize) & U256::from(u64::MAX)).to::<u64>(),
                42
            );
            assert_eq!((verifier_metadata >> 224usize).to::<u8>(), 1);
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

            let err = factory
                .transfer_ownership(
                    OWNER,
                    IZoneFactory::transferOwnershipCall {
                        newOwner: Address::ZERO,
                    },
                )
                .unwrap_err();
            assert_eq!(
                err,
                TempoPrecompileError::from(ZoneFactoryError::invalid_owner())
            );
            assert_eq!(factory.owner()?, OWNER);
            Ok(())
        })
    }
}
