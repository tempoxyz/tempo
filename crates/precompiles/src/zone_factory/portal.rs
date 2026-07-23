//! Solidity-compatible storage layout for ZonePortal accounts created by the native factory.
//!
//! This type is only a storage handle. It is not registered as a precompile because the current
//! REVM precompile interface cannot make the external calls required by ZonePortal. Calls to a
//! portal continue to execute the ERC-1167 proxy and the canonical Solidity implementation.

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, Bytes, U256, hex};
use revm::state::Bytecode;
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneAccessMode, ZoneGatewayMode,
    ZonePortalRole,
};
use tempo_precompiles_macros::{Storable, contract};

/// Exact ERC-1167 deployed proxy runtime installed at every ZonePortal address.
pub const ZONE_PORTAL_PROXY_RUNTIME: [u8; 45] = hex!(
    "363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
);

pub(super) const ACCOUNT_ALLOWLIST_ENFORCED_FLAG: u8 = 1 << 0;
pub(super) const GATEWAY_ALLOWLIST_ENFORCED_FLAG: u8 = 1 << 1;

/// Packed `TokenConfig` stored in the portal token registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub(super) struct PortalTokenConfig {
    pub(super) enabled: bool,
    pub(super) deposits_active: bool,
}

/// Historical encryption-key entry stored by ZonePortal.
#[derive(Debug, Clone, Copy, Storable)]
struct PortalEncryptionKeyEntry {
    x: B256,
    y_parity: u8,
    activation_block: u64,
}

/// Withdrawal queue stored by ZonePortal.
#[derive(Debug, Clone, Storable)]
struct PortalWithdrawalQueue {
    head: U256,
    tail: U256,
    #[allow(dead_code)]
    slots: Mapping<U256, B256>,
}

/// Canonical Solidity storage layout of the ZonePortal runtime installed at T9.
///
/// The generated handlers let the native factory initialize a portal without duplicating raw
/// slot numbers. This contract type is deliberately absent from the EVM precompile map.
#[contract]
pub struct ZonePortalStorage {
    admin: Address,
    zone_gas_rate: u128,
    withdrawal_batch_index: u64,
    block_hash: B256,
    current_deposit_queue_hash: B256,
    deposit_count: u64,
    last_processed_deposit_number: u64,
    last_synced_tempo_block_number: u64,
    bounceback_gas: u64,
    encryption_keys: Vec<PortalEncryptionKeyEntry>,
    token_configs: Mapping<Address, PortalTokenConfig>,
    enabled_tokens: Vec<Address>,
    refunds: Mapping<Address, Mapping<Address, u128>>,
    withdrawal_queue: PortalWithdrawalQueue,
    rpc_url: String,
    pending_admin: Address,
    withdrawal_reentrancy_status: U256,
    zone_id: u32,
    messenger: Address,
    verifier: Address,
    initialized: bool,
    sequencer_set_version: u64,
    sequencer_threshold: u8,
    zone_height: U256,
    sequencers: Vec<Address>,
    is_sequencer: Mapping<Address, bool>,
    role: Mapping<Address, u8>,
    is_access_enforced: bool,
    is_gateway_enforced: bool,
}

impl ZonePortalStorage {
    pub fn new(address: Address) -> Self {
        Self::__new(address)
    }

    pub(super) fn initialize(
        &mut self,
        zone_id: u32,
        params: &IZoneFactory::CreateZoneParams,
    ) -> Result<()> {
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME)),
        )?;

        self.admin.write(params.admin)?;
        self.token_configs[params.initialToken].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })?;
        self.enabled_tokens.write(vec![params.initialToken])?;
        self.rpc_url.write(params.rpcUrl.clone())?;
        self.zone_id.write(zone_id)?;
        self.messenger.write(ZONE_MESSENGER_ADDRESS)?;
        self.verifier.write(ZONE_VERIFIER_ADDRESS)?;
        self.initialized.write(true)?;
        self.sequencer_threshold.write(params.threshold)?;
        self.sequencers.write(params.sequencers.clone())?;
        for sequencer in &params.sequencers {
            self.is_sequencer[*sequencer].write(true)?;
        }
        self.is_access_enforced.write(params.accessMode)?;
        self.is_gateway_enforced.write(params.gatewayMode)?;
        for gateway in &params.zoneGateways {
            self.role[*gateway].write(ZonePortalRole::CallbackGateway as u8)?;
        }
        for account in &params.allowedAccounts {
            self.role[*account].write(ZonePortalRole::Account as u8)?;
        }
        Ok(())
    }
}

fn encode_enforcement_flags(access_mode: ZoneAccessMode, gateway_mode: ZoneGatewayMode) -> u8 {
    let mut flags = 0;
    if access_mode == ZoneAccessMode::Closed {
        flags |= ACCOUNT_ALLOWLIST_ENFORCED_FLAG;
    }
    if gateway_mode == ZoneGatewayMode::Enforced {
        flags |= GATEWAY_ALLOWLIST_ENFORCED_FLAG;
    }
    flags
}
