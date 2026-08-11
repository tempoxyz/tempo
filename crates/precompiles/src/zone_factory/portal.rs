//! Solidity-compatible storage layout for ZonePortal accounts created by the native factory.
//!
//! This type is only a storage handle. It is not registered as a precompile because the current
//! REVM precompile interface cannot make the external calls required by ZonePortal. Calls to a
//! portal continue to execute the ERC-1167 proxy and the canonical Solidity implementation.

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, Bytes, FixedBytes, U256, hex};
use revm::state::Bytecode;
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError, ZonePortalRole,
};
use tempo_precompiles_macros::{Storable, contract};

/// Exact ERC-1167 deployed proxy runtime installed at every ZonePortal address.
pub const ZONE_PORTAL_PROXY_RUNTIME: [u8; 45] = hex!(
    "363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
);

/// Packed `TokenConfig` stored in the portal token registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub struct PortalTokenConfig {
    pub enabled: bool,
    pub deposits_active: bool,
}

/// Historical encryption-key entry stored by ZonePortal.
#[derive(Debug, Clone, Copy, Storable)]
pub struct PortalEncryptionKeyEntry {
    x: B256,
    y_parity: u8,
    activation_block: u64,
}

/// Withdrawal queue stored by ZonePortal.
#[derive(Debug, Clone, Storable)]
pub struct PortalWithdrawalQueue {
    head: U256,
    tail: U256,
    #[expect(dead_code)]
    slots: Mapping<U256, B256>,
}

/// Canonical Solidity storage layout of the ZonePortal runtime installed at T10.
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
    /// Reserved remainder of the enforcement modes slot.
    _reserved: FixedBytes<30>,
    /// Maximum Tempo gas rate, stored in `PORTAL_MAX_TEMPO_GAS_RATE_SLOT`.
    max_tempo_gas_rate: u128,
    /// Active block-producing leader, stored in slot 23.
    leader: Address,
    /// Monotonic leadership transition epoch, packed after `leader` in slot 23.
    leader_epoch: u64,
    /// Tempo block at which the current leader became active, stored in slot 24.
    leader_activation_tempo_block: u64,
    /// Per-block deposit and token-enablement counters occupying slots 24 and 25.
    deposit_count_block: u64,
    deposits_in_current_block: u64,
    token_enable_count_block: u64,
    tokens_enabled_in_current_block: u64,
    /// Append-only commitment to the enabled token sequence and metadata, stored in slot 26.
    token_enablement_hash: B256,
}

impl ZonePortalStorage {
    pub fn new(address: Address) -> Self {
        Self::__new(address)
    }

    pub(super) fn initialize(
        &mut self,
        zone_id: u32,
        params: &IZoneFactory::CreateZoneParams,
        token_enablement_hash: B256,
    ) -> Result<()> {
        if self.initialized.read()? {
            return Err(ZoneFactoryError::already_initialized().into());
        }

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
        let leader = *params
            .sequencers
            .first()
            .ok_or_else(ZoneFactoryError::invalid_sequencer_set)?;
        self.leader.write(leader)?;
        self.leader_epoch.write(1)?;
        self.leader_activation_tempo_block
            .write(self.storage.block_number())?;
        self.token_enablement_hash.write(token_enablement_hash)?;
        for gateway in &params.zoneGateways {
            self.role[*gateway].write(ZonePortalRole::CallbackGateway as u8)?;
        }
        for account in &params.allowedAccounts {
            self.role[*account].write(ZonePortalRole::Account as u8)?;
        }
        Ok(())
    }
}
