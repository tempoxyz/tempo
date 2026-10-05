//! Solidity-compatible storage layout for ZonePortal accounts created by the native factory.
//!
//! This type is only a storage handle. It is not registered as a precompile because the current
//! REVM precompile interface cannot make the external calls required by ZonePortal. Calls to a
//! portal continue to execute the ERC-1167 proxy and the canonical Solidity implementation.

use crate::{
    error::Result,
    storage::{Handler, Mapping, Slot, vec::VecHandler},
};
use alloy::primitives::{Address, B256, Bytes, FixedBytes, U256, hex};
use revm::state::Bytecode;
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError,
    ZonePortalCapability, ZonePortalRole,
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

/// Finalized authority and retirement state for one fast epoch.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub struct PortalFastEpochConfig {
    pub protocol_version: u32,
    pub threshold: u8,
    pub proof_mode: u8,
    pub closed: bool,
    pub retired: bool,
    pub expected_peer_barriers: u16,
    pub recorded_peer_barriers: u16,
    pub finalized_peer_barriers: u16,
    pub activated_at_tempo_block: u64,
    pub roster_hash: B256,
    pub peers_hash: B256,
    pub expected_verifier_code_hash: B256,
    pub expected_verifier_config_hash: B256,
    pub closure_hash: B256,
    pub final_settlement_height: U256,
    pub final_settlement_block_hash: B256,
    pub final_settlement_withdrawal_batch_index: u64,
    pub barriers_hash: B256,
    pub final_settlement_hash: B256,
    pub next_epoch: u64,
    pub next_roster_hash: B256,
    pub checkpoint_log_term: u64,
    pub checkpoint_log_index: u64,
    pub checkpoint_height: U256,
    pub checkpoint_block_hash: B256,
    pub checkpoint_state_root: B256,
    pub checkpoint_hash: B256,
}

/// Immutable source barrier plus its terminal-resolution commitment.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub struct PortalFastPeerBarrier {
    pub recorded: bool,
    pub finalized: bool,
    pub source_epoch: u64,
    pub imported_anchor_number: u64,
    pub imported_anchor_hash: B256,
    pub log_term: u64,
    pub log_index: u64,
    pub block_height: U256,
    pub block_hash: B256,
    pub state_root: B256,
    pub lock_log_watermark: u64,
    pub complete_lock_root: B256,
    pub unresolved_root: B256,
    pub unresolved_count: u64,
    pub barrier_hash: B256,
    pub terminal_root: B256,
    pub disposition_root: B256,
    pub resolved_count: u64,
    pub remaining_unresolved_root: B256,
    pub remaining_unresolved_count: u64,
    pub resolution_hash: B256,
}

/// Accepted Zone prefix against which settlement and ancestry evidence is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalAcceptedPrefix {
    pub zone_height: U256,
    pub block_hash: B256,
    pub withdrawal_batch_index: u64,
}

/// Canonical Solidity storage layout of the ZonePortal runtime installed at T10.
///
/// The generated handlers let the native factory initialize a portal without duplicating raw
/// slot numbers. This contract type is deliberately absent from the EVM precompile map.
#[contract]
pub struct ZonePortalStorage {
    admin: Address,
    zone_gas_rate: u128,
    pub(super) withdrawal_batch_index: u64,
    pub(super) block_hash: B256,
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
    pub(super) zone_height: U256,
    sequencers: Vec<Address>,
    /// Reserved slot 19, available for future use.
    _reserved_slot_19: U256,
    role: Mapping<Address, u8>,
    is_access_enforced: bool,
    is_gateway_enforced: bool,
    /// Reserved remainder of the enforcement modes slot.
    _reserved: FixedBytes<30>,
    /// Maximum Tempo gas rate, stored in slot 22.
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
    /// End of the bounded portal pause, packed in slot 25 after the token enablement counter.
    pause_expiry: u64,
    /// Append-only commitment to the enabled token sequence and metadata, stored in slot 26.
    token_enablement_hash: B256,
    /// Capability-keyed abdication timestamps, stored as a Solidity mapping in slot 27.
    abdication_effective_at: Mapping<u8, u64>,
    /// Enabled-token prefix confirmed by accepted Zone proofs, stored in slot 28.
    last_processed_enabled_token_count: u64,
    /// Whether the token cursor has been initialized, packed into slot 28.
    token_enablement_cursor_initialized: bool,
    /// Current fast epoch, packed into the remainder of slot 28 at T14.
    pub(super) fast_epoch: u64,
    pub(super) fast_epochs: Mapping<u64, PortalFastEpochConfig>,
    pub(super) fast_epoch_members: Mapping<u64, Vec<Address>>,
    pub(super) is_fast_epoch_member: Mapping<u64, Mapping<Address, bool>>,
    pub(super) fast_epoch_peers: Mapping<u64, Vec<Address>>,
    pub(super) is_fast_epoch_peer: Mapping<u64, Mapping<Address, bool>>,
    pub(super) fast_peer_barriers: Mapping<u64, Mapping<Address, PortalFastPeerBarrier>>,
}

impl ZonePortalStorage {
    pub fn new(address: Address) -> Self {
        Self::__new(address)
    }

    /// Returns the storage handler for the current pause expiry timestamp.
    pub fn pause_expiry(&self) -> &Slot<u64> {
        &self.pause_expiry
    }

    /// Returns the storage handler for a capability's abdication timestamp.
    pub fn abdication_effective_at(&self, capability: ZonePortalCapability) -> &Slot<u64> {
        &self.abdication_effective_at[u8::from(capability)]
    }

    /// Returns the canonical handler for the packed current-epoch field in slot 28.
    pub fn fast_epoch_handler(&self) -> &Slot<u64> {
        &self.fast_epoch
    }

    /// Returns the canonical historical epoch-configuration mapping handler.
    pub fn fast_epochs_handler(&self) -> &Mapping<u64, PortalFastEpochConfig> {
        &self.fast_epochs
    }

    /// Returns the canonical historical member-array mapping handler.
    pub fn fast_epoch_members_handler(&self) -> &Mapping<u64, Vec<Address>> {
        &self.fast_epoch_members
    }

    /// Returns the canonical typed vector handler for one historical epoch's members.
    pub fn fast_epoch_members_at(&self, epoch: u64) -> &VecHandler<Address> {
        self.fast_epoch_members.at(&epoch)
    }

    /// Returns the canonical historical member-identity mapping handler.
    pub fn fast_epoch_member_flags_handler(&self) -> &Mapping<u64, Mapping<Address, bool>> {
        &self.is_fast_epoch_member
    }

    /// Returns the canonical membership slot for one historical member.
    pub fn fast_epoch_member_at(&self, epoch: u64, member: Address) -> &Slot<bool> {
        self.is_fast_epoch_member.at(&epoch).at(&member)
    }

    /// Returns the canonical exact peer-array mapping handler.
    pub fn fast_epoch_peers_handler(&self) -> &Mapping<u64, Vec<Address>> {
        &self.fast_epoch_peers
    }

    /// Returns the canonical typed vector handler for one historical epoch's exact peers.
    pub fn fast_epoch_peers_at(&self, epoch: u64) -> &VecHandler<Address> {
        self.fast_epoch_peers.at(&epoch)
    }

    /// Returns the canonical historical peer-identity mapping handler.
    pub fn fast_epoch_peer_flags_handler(&self) -> &Mapping<u64, Mapping<Address, bool>> {
        &self.is_fast_epoch_peer
    }

    /// Returns the canonical peer-membership slot for one historical peer Portal.
    pub fn fast_epoch_peer_at(&self, epoch: u64, peer: Address) -> &Slot<bool> {
        self.is_fast_epoch_peer.at(&epoch).at(&peer)
    }

    /// Returns the canonical per-peer barrier mapping handler.
    pub fn fast_peer_barriers_handler(
        &self,
    ) -> &Mapping<u64, Mapping<Address, PortalFastPeerBarrier>> {
        &self.fast_peer_barriers
    }

    /// Returns the canonical typed barrier slot for one historical source Portal.
    pub fn fast_peer_barrier_at(&self, epoch: u64, peer: Address) -> &PortalFastPeerBarrierHandler {
        self.fast_peer_barriers.at(&epoch).at(&peer)
    }

    /// Returns the canonical typed epoch-configuration slot.
    pub fn fast_epoch_config_at(&self, epoch: u64) -> &PortalFastEpochConfigHandler {
        self.fast_epochs.at(&epoch)
    }

    /// Returns the accepted Zone height handler.
    pub fn accepted_zone_height_handler(&self) -> &Slot<U256> {
        &self.zone_height
    }

    /// Returns the accepted Zone block-hash handler.
    pub fn accepted_block_hash_handler(&self) -> &Slot<B256> {
        &self.block_hash
    }

    /// Returns the accepted withdrawal-batch-index handler.
    pub fn accepted_withdrawal_batch_index_handler(&self) -> &Slot<u64> {
        &self.withdrawal_batch_index
    }

    /// Reads the Portal's currently selected fast epoch.
    pub fn current_fast_epoch(&self) -> Result<u64> {
        self.fast_epoch.read()
    }

    /// Reads the permanent configuration and retirement record for `epoch`.
    pub fn fast_epoch_config(&self, epoch: u64) -> Result<PortalFastEpochConfig> {
        self.fast_epochs[epoch].read()
    }

    /// Reads the three historical authority members for `epoch`.
    pub fn fast_epoch_members(&self, epoch: u64) -> Result<Vec<Address>> {
        self.fast_epoch_members[epoch].read()
    }

    /// Returns whether `member` belongs to the historical authority for `epoch`.
    pub fn is_fast_epoch_member(&self, epoch: u64, member: Address) -> Result<bool> {
        self.is_fast_epoch_member[epoch][member].read()
    }

    /// Reads the exact historical peer Portal roster for `epoch`.
    pub fn fast_epoch_peers(&self, epoch: u64) -> Result<Vec<Address>> {
        self.fast_epoch_peers[epoch].read()
    }

    /// Returns whether `peer` belongs to the historical peer roster for `epoch`.
    pub fn is_fast_epoch_peer(&self, epoch: u64, peer: Address) -> Result<bool> {
        self.is_fast_epoch_peer[epoch][peer].read()
    }

    /// Reads the permanent barrier record for one exact historical peer.
    pub fn fast_peer_barrier(&self, epoch: u64, peer: Address) -> Result<PortalFastPeerBarrier> {
        self.fast_peer_barriers[epoch][peer].read()
    }

    /// Reads the currently accepted Zone prefix used by settlement and ancestry checks.
    pub fn accepted_prefix(&self) -> Result<PortalAcceptedPrefix> {
        Ok(PortalAcceptedPrefix {
            zone_height: self.zone_height.read()?,
            block_hash: self.block_hash.read()?,
            withdrawal_batch_index: self.withdrawal_batch_index.read()?,
        })
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
            self.role[*sequencer].write(u8::from(ZonePortalRole::Sequencer))?;
        }
        self.is_access_enforced.write(params.accessMode)?;
        self.is_gateway_enforced.write(params.gatewayMode)?;
        let leader = *params
            .sequencers
            .first()
            .ok_or_else(ZoneFactoryError::invalid_sequencer_set)?;
        self.leader.write(leader)?;
        self.leader_epoch.write(1)?;
        let creation_block = self.storage.block_number();
        self.leader_activation_tempo_block.write(creation_block)?;
        self.token_enable_count_block.write(creation_block)?;
        self.tokens_enabled_in_current_block.write(1)?;
        self.token_enablement_hash.write(token_enablement_hash)?;
        if self.storage.spec().is_t13() {
            self.token_enablement_cursor_initialized.write(true)?;
        }
        for gateway in &params.zoneGateways {
            self.role[*gateway].write(u8::from(ZonePortalRole::CallbackGateway))?;
        }
        for account in &params.allowedAccounts {
            self.role[*account].write(u8::from(ZonePortalRole::Account))?;
        }
        Ok(())
    }
}
