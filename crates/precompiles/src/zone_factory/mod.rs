//! Native ZoneFactory precompile for TIP-1091.

pub mod dispatch;
pub mod portal;

use crate::{
    ZONE_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    has_duplicates_metered,
    signature_verifier::SignatureVerifier,
    storage::{Handler, Mapping},
    tip20::TIP20Token,
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use alloy::{
    primitives::{Address, B256, Bytes, IntoLogData, U256, keccak256},
    sol_types::SolValue,
};
use std::collections::{HashMap, HashSet};
use tempo_contracts::precompiles::{
    FAST_EMPTY_UNRESOLVED_ROOT, FAST_PROOF_MODE_OPERATOR_ATTESTED, FAST_PROOF_MODE_REQUIRED,
    FAST_PROTOCOL_NATIVE_PIN, IZoneFactory, T13_PROTOTYPE_VERIFIER_CODE_HASH,
    ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError, ZoneFactoryEvent, ZoneInfo,
    ZonePortalEvent, ZonePortalRole,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt;

/// Generated storage slots for ZonePortal accounts.
pub use portal::slots as zone_portal_slots;
pub use portal::{
    PortalAcceptedPrefix, PortalFastEpochConfig, PortalFastPeerBarrier, ZONE_PORTAL_PROXY_RUNTIME,
    ZonePortalStorage,
};
/// Minimum gas consumed by a successful zone creation.
pub const ZONE_CREATION_GAS: u64 = 15_000_000;

/// Maximum number of equal sequencers in a zone settlement set.
pub const MAX_SEQUENCERS: usize = 8;
/// Maximum UTF-8 byte length of enabled token metadata strings.
const MAX_TOKEN_METADATA_BYTES: usize = 31;
const FAST_MEMBER_COUNT: usize = 3;
const FAST_THRESHOLD: u8 = 2;
const FAST_PEER_COUNT: usize = 9;
const FAST_BARRIER_DOMAIN: &str = "TEMPO_ZONE_FAST_BARRIER_T14_V1";
const FAST_BARRIER_RESOLUTION_DOMAIN: &str = "TEMPO_ZONE_FAST_BARRIER_RESOLUTION_T14_V1";
const FAST_FINAL_SETTLEMENT_DOMAIN: &str = "TEMPO_ZONE_FAST_FINAL_SETTLEMENT_T14_V1";
const FAST_CHECKPOINT_DOMAIN: &str = "TEMPO_ZONE_FAST_CHECKPOINT_T14_V1";

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
    access_mode: bool,
    gateway_mode: bool,
    admin: Address,
    sequencers: Vec<Address>,
    threshold: u8,
    verifier: Address,
    rpc_url: String,
}

impl From<ZoneInfoStorage> for ZoneInfo {
    fn from(value: ZoneInfoStorage) -> Self {
        Self {
            zoneId: value.zone_id,
            portal: value.portal,
            accessMode: value.access_mode,
            gatewayMode: value.gateway_mode,
            admin: value.admin,
            sequencers: value.sequencers,
            threshold: value.threshold,
            verifier: value.verifier,
            rpcUrl: value.rpc_url,
        }
    }
}

impl ZoneFactory {
    fn verify_signers(
        &self,
        digest: B256,
        signatures: &[Bytes],
        is_member: impl Fn(Address) -> Result<bool>,
    ) -> Result<()> {
        if signatures.len() != FAST_THRESHOLD as usize {
            return Err(ZoneFactoryError::invalid_fast_certificate().into());
        }
        let verifier = SignatureVerifier::new();
        let mut recovered = [Address::ZERO; FAST_THRESHOLD as usize];
        for (index, signature) in signatures.iter().enumerate() {
            let signer = verifier
                .recover(digest, signature.clone())
                .map_err(|_| ZoneFactoryError::invalid_fast_certificate())?;
            if !is_member(signer)? || recovered[..index].contains(&signer) {
                return Err(ZoneFactoryError::invalid_fast_certificate().into());
            }
            recovered[index] = signer;
        }
        Ok(())
    }

    fn verify_historical_quorum(
        &self,
        portal: Address,
        epoch: u64,
        digest: B256,
        signatures: &[Bytes],
    ) -> Result<()> {
        let portal = ZonePortalStorage::new(portal);
        let config = portal.fast_epochs[epoch].read()?;
        if epoch == 0 || config.threshold != FAST_THRESHOLD || config.roster_hash == B256::ZERO {
            return Err(ZoneFactoryError::invalid_fast_certificate().into());
        }
        self.verify_signers(digest, signatures, |signer| {
            portal.is_fast_epoch_member[epoch][signer].read()
        })
    }

    fn verify_next_roster_quorum(
        &self,
        members: &[Address],
        digest: B256,
        signatures: &[Bytes],
    ) -> Result<()> {
        if members.len() != FAST_MEMBER_COUNT
            || members.iter().any(|member| member.is_zero())
            || members[0] == members[1]
            || members[0] == members[2]
            || members[1] == members[2]
        {
            return Err(ZoneFactoryError::invalid_fast_certificate().into());
        }
        self.verify_signers(digest, signatures, |signer| Ok(members.contains(&signer)))
    }

    fn require_owner(&self, msg_sender: Address) -> Result<()> {
        if msg_sender != self.owner()? {
            return Err(ZoneFactoryError::not_owner().into());
        }
        Ok(())
    }

    fn require_fast_protocol(&self) -> Result<()> {
        if !self.storage.spec().is_t14() {
            return Err(ZoneFactoryError::fast_protocol_unavailable().into());
        }
        Ok(())
    }

    fn require_portal(&self, portal: Address) -> Result<()> {
        if !self.is_zone_portal(portal)? {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        Ok(())
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
        if TIP403Registry::new()
            .registered_token_transfer_policy_id(call.params.initialToken)?
            .is_none()
        {
            return Err(ZoneFactoryError::token_transfer_policy_not_set().into());
        }
        validate_closed_loop_config(
            &mut self.storage,
            &call.params.allowedAccounts,
            &call.params.zoneGateways,
            &call.params.sequencers,
        )?;
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
        validate_token_metadata(&token_name, &token_symbol, &token_currency)?;
        let token_enablement_hash = keccak256(
            (
                B256::ZERO,
                call.params.initialToken,
                token_name.clone(),
                token_symbol.clone(),
                token_currency.clone(),
            )
                .abi_encode_params(),
        );

        self.next_zone_id.write(
            zone_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        // TIP-1091 deliberately etches the canonical runtime unconditionally. The 96-bit portal
        // prefix makes pre-existing state computationally infeasible to target with CREATE2.
        ZonePortalStorage::new(portal).initialize(zone_id, &call.params, token_enablement_hash)?;

        self.zones[zone_id].write(ZoneInfoStorage {
            zone_id,
            portal,
            access_mode: call.params.accessMode,
            gateway_mode: call.params.gatewayMode,
            admin: call.params.admin,
            sequencers: call.params.sequencers.clone(),
            threshold: call.params.threshold,
            verifier: ZONE_VERIFIER_ADDRESS,
            rpc_url: call.params.rpcUrl.clone(),
        })?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::enforcement_modes_updated(
                call.params.accessMode,
                call.params.gatewayMode,
            )
            .into_log_data(),
        )?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::sequencer_set_updated(
                0,
                call.params.threshold,
                call.params.sequencers.clone(),
            )
            .into_log_data(),
        )?;

        self.storage.emit_event(
            portal,
            ZonePortalEvent::leader_updated(
                Address::ZERO,
                call.params.sequencers[0],
                1,
                self.storage.block_number(),
            )
            .into_log_data(),
        )?;

        let mut emitted_roles = HashMap::new();
        for gateway in &call.params.zoneGateways {
            let previous = emitted_roles
                .insert(*gateway, ZonePortalRole::CallbackGateway)
                .unwrap_or(ZonePortalRole::None);
            self.storage.emit_event(
                portal,
                ZonePortalEvent::role_updated(*gateway, previous, ZonePortalRole::CallbackGateway)
                    .into_log_data(),
            )?;
        }

        for account in &call.params.allowedAccounts {
            let previous = emitted_roles
                .insert(*account, ZonePortalRole::Account)
                .unwrap_or(ZonePortalRole::None);
            self.storage.emit_event(
                portal,
                ZonePortalEvent::role_updated(*account, previous, ZonePortalRole::Account)
                    .into_log_data(),
            )?;
        }

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
            call.params.accessMode,
            call.params.gatewayMode,
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

    /// Installs a three-member, two-signature authority and its exact peer roster.
    pub fn configure_fast_epoch(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::configureFastEpochCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        if call.epoch == 0
            || call.protocolVersion == 0
            || !matches!(
                call.proofMode,
                FAST_PROOF_MODE_OPERATOR_ATTESTED | FAST_PROOF_MODE_REQUIRED
            )
            || call.expectedVerifierCodeHash == B256::ZERO
            || call.expectedVerifierConfigHash == B256::ZERO
            || call.members.len() != FAST_MEMBER_COUNT
            || call.peerPortals.len() != FAST_PEER_COUNT
            || call.rosterHash == B256::ZERO
            || call.members.iter().any(|address| address.is_zero())
            || call.peerPortals.iter().any(|address| address.is_zero())
            || has_duplicates_metered(&mut self.storage, call.members.iter().copied())?
            || has_duplicates_metered(&mut self.storage, call.peerPortals.iter().copied())?
            || call.peerPortals.contains(&call.portal)
        {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        let (actual_verifier_code_hash, _) = self.storage.account_code(ZONE_VERIFIER_ADDRESS)?;
        if actual_verifier_code_hash != call.expectedVerifierCodeHash
            || (call.proofMode == FAST_PROOF_MODE_REQUIRED
                && actual_verifier_code_hash == T13_PROTOTYPE_VERIFIER_CODE_HASH)
        {
            return Err(ZoneFactoryError::invalid_fast_proof_configuration().into());
        }
        for peer in &call.peerPortals {
            if !self.is_zone_portal(*peer)? {
                return Err(ZoneFactoryError::invalid_fast_peer(*peer).into());
            }
        }

        let expected_roster_hash = keccak256(
            (
                keccak256("TEMPO_ZONE_FAST_ROSTER_T14_V1"),
                call.portal,
                call.epoch,
                call.protocolVersion,
                U256::from(FAST_THRESHOLD),
                U256::from(call.proofMode),
                call.expectedVerifierCodeHash,
                call.expectedVerifierConfigHash,
                call.members.clone(),
                call.peerPortals.clone(),
            )
                .abi_encode(),
        );
        if call.rosterHash != expected_roster_hash {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        let peers_hash = keccak256(call.peerPortals.abi_encode());
        let mut portal = ZonePortalStorage::new(call.portal);
        let previous = portal.fast_epoch.read()?;
        if call.epoch <= previous {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        if previous != 0 {
            let prior = portal.fast_epochs[previous].read()?;
            if !prior.retired {
                return Err(ZoneFactoryError::fast_epoch_active(previous).into());
            }
            if prior.next_epoch != call.epoch {
                return Err(ZoneFactoryError::invalid_fast_epoch().into());
            }
            if prior.next_roster_hash != call.rosterHash || prior.checkpoint_hash == B256::ZERO {
                return Err(ZoneFactoryError::invalid_fast_certificate().into());
            }
        }

        portal.fast_epoch_members[call.epoch].write(call.members.clone())?;
        for member in &call.members {
            portal.is_fast_epoch_member[call.epoch][*member].write(true)?;
        }
        portal.fast_epoch_peers[call.epoch].write(call.peerPortals.clone())?;
        for peer in &call.peerPortals {
            portal.is_fast_epoch_peer[call.epoch][*peer].write(true)?;
        }
        portal.fast_epochs[call.epoch].write(PortalFastEpochConfig {
            protocol_version: call.protocolVersion,
            threshold: FAST_THRESHOLD,
            proof_mode: call.proofMode,
            closed: false,
            retired: false,
            expected_peer_barriers: FAST_PEER_COUNT as u16,
            recorded_peer_barriers: 0,
            finalized_peer_barriers: 0,
            activated_at_tempo_block: self.storage.block_number(),
            roster_hash: call.rosterHash,
            peers_hash,
            expected_verifier_code_hash: call.expectedVerifierCodeHash,
            expected_verifier_config_hash: call.expectedVerifierConfigHash,
            closure_hash: B256::ZERO,
            final_settlement_height: U256::ZERO,
            final_settlement_block_hash: B256::ZERO,
            final_settlement_withdrawal_batch_index: 0,
            barriers_hash: B256::ZERO,
            final_settlement_hash: B256::ZERO,
            next_epoch: 0,
            next_roster_hash: B256::ZERO,
            checkpoint_log_term: 0,
            checkpoint_log_index: 0,
            checkpoint_height: U256::ZERO,
            checkpoint_block_hash: B256::ZERO,
            checkpoint_state_root: B256::ZERO,
            checkpoint_hash: B256::ZERO,
        })?;
        portal.fast_epoch.write(call.epoch)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_epoch_activated(
                call.epoch,
                call.protocolVersion,
                call.rosterHash,
                peers_hash,
                call.proofMode,
                call.expectedVerifierCodeHash,
                call.expectedVerifierConfigHash,
                call.members,
                call.peerPortals,
            )
            .into_log_data(),
        )
    }

    pub fn close_fast_epoch(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::closeFastEpochCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let mut portal = ZonePortalStorage::new(call.portal);
        let mut config = portal.fast_epochs[call.epoch].read()?;
        if call.epoch == 0
            || portal.fast_epoch.read()? != call.epoch
            || config.closed
            || config.retired
            || call.closureHash == B256::ZERO
        {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        config.closed = true;
        config.closure_hash = call.closureHash;
        portal.fast_epochs[call.epoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_epoch_closed(call.epoch, call.closureHash).into_log_data(),
        )
    }

    pub fn record_fast_peer_barrier(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::recordFastPeerBarrierCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let statement = &call.statement;
        let mut portal = ZonePortalStorage::new(call.portal);
        let mut config = portal.fast_epochs[statement.destinationEpoch].read()?;
        if statement.destinationPortal != call.portal
            || statement.destinationEpoch == 0
            || portal.fast_epoch.read()? != statement.destinationEpoch
            || !config.closed
            || config.retired
            || statement.closureHash != config.closure_hash
            || statement.sourcePortal == call.portal
            || statement.sourceEpoch == 0
            || statement.importedAnchorHash == B256::ZERO
            || statement.blockHash == B256::ZERO
            || statement.stateRoot == B256::ZERO
            || statement.completeLockRoot == B256::ZERO
            || (statement.unresolvedCount == 0
                && statement.unresolvedRoot != FAST_EMPTY_UNRESOLVED_ROOT)
            || (statement.unresolvedCount != 0
                && (statement.unresolvedRoot == B256::ZERO
                    || statement.unresolvedRoot == FAST_EMPTY_UNRESOLVED_ROOT))
        {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        if !portal.is_fast_epoch_peer[statement.destinationEpoch][statement.sourcePortal].read()? {
            return Err(ZoneFactoryError::invalid_fast_peer(statement.sourcePortal).into());
        }
        let barrier =
            portal.fast_peer_barriers[statement.destinationEpoch][statement.sourcePortal].read()?;
        if barrier.recorded {
            return Err(ZoneFactoryError::fast_peer_barrier_already_recorded(
                statement.sourcePortal,
            )
            .into());
        }
        let barrier_hash = keccak256(
            (
                keccak256(FAST_BARRIER_DOMAIN),
                U256::from(self.storage.chain_id()),
                statement.clone(),
            )
                .abi_encode(),
        );
        self.verify_historical_quorum(
            statement.sourcePortal,
            statement.sourceEpoch,
            barrier_hash,
            &call.signatures,
        )?;
        portal.fast_peer_barriers[statement.destinationEpoch][statement.sourcePortal].write(
            PortalFastPeerBarrier {
                recorded: true,
                finalized: false,
                source_epoch: statement.sourceEpoch,
                imported_anchor_number: statement.importedAnchorNumber,
                imported_anchor_hash: statement.importedAnchorHash,
                log_term: statement.logTerm,
                log_index: statement.logIndex,
                block_height: statement.blockHeight,
                block_hash: statement.blockHash,
                state_root: statement.stateRoot,
                lock_log_watermark: statement.lockLogWatermark,
                complete_lock_root: statement.completeLockRoot,
                unresolved_root: statement.unresolvedRoot,
                unresolved_count: statement.unresolvedCount,
                barrier_hash,
                terminal_root: B256::ZERO,
                disposition_root: B256::ZERO,
                resolved_count: 0,
                remaining_unresolved_root: B256::ZERO,
                remaining_unresolved_count: 0,
                resolution_hash: B256::ZERO,
            },
        )?;
        config.recorded_peer_barriers += 1;
        portal.fast_epochs[statement.destinationEpoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_peer_barrier_recorded(
                statement.destinationEpoch,
                statement.sourcePortal,
                statement.sourceEpoch,
                statement.lockLogWatermark,
                barrier_hash,
                statement.completeLockRoot,
                statement.unresolvedRoot,
                statement.unresolvedCount,
            )
            .into_log_data(),
        )
    }

    pub fn finalize_fast_peer_barrier(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::finalizeFastPeerBarrierCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let mut portal = ZonePortalStorage::new(call.portal);
        let mut config = portal.fast_epochs[call.epoch].read()?;
        if !config.closed || config.retired {
            return Err(ZoneFactoryError::invalid_fast_epoch().into());
        }
        let mut barrier = portal.fast_peer_barriers[call.epoch][call.peerPortal].read()?;
        if !barrier.recorded {
            return Err(ZoneFactoryError::fast_peer_barrier_not_recorded(call.peerPortal).into());
        }
        if barrier.finalized {
            return Err(
                ZoneFactoryError::fast_peer_barrier_already_finalized(call.peerPortal).into(),
            );
        }
        if call.resolution.barrierHash != barrier.barrier_hash
            || call.resolution.terminalRoot == B256::ZERO
            || call.resolution.dispositionRoot == B256::ZERO
            || call.resolution.resolvedCount != barrier.unresolved_count
            || call.resolution.remainingUnresolvedRoot != FAST_EMPTY_UNRESOLVED_ROOT
            || call.resolution.remainingUnresolvedCount != 0
        {
            return Err(ZoneFactoryError::invalid_fast_certificate().into());
        }
        let resolution_hash = keccak256(
            (
                keccak256(FAST_BARRIER_RESOLUTION_DOMAIN),
                U256::from(self.storage.chain_id()),
                call.portal,
                call.epoch,
                call.peerPortal,
                call.resolution.clone(),
            )
                .abi_encode(),
        );
        self.verify_historical_quorum(
            call.peerPortal,
            barrier.source_epoch,
            resolution_hash,
            &call.signatures,
        )?;
        barrier.finalized = true;
        barrier.terminal_root = call.resolution.terminalRoot;
        barrier.disposition_root = call.resolution.dispositionRoot;
        barrier.resolved_count = call.resolution.resolvedCount;
        barrier.remaining_unresolved_root = call.resolution.remainingUnresolvedRoot;
        barrier.remaining_unresolved_count = call.resolution.remainingUnresolvedCount;
        barrier.resolution_hash = resolution_hash;
        portal.fast_peer_barriers[call.epoch][call.peerPortal].write(barrier)?;
        config.finalized_peer_barriers += 1;
        portal.fast_epochs[call.epoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_peer_barrier_finalized(
                call.epoch,
                call.peerPortal,
                resolution_hash,
                call.resolution.terminalRoot,
                call.resolution.dispositionRoot,
            )
            .into_log_data(),
        )
    }

    pub fn record_fast_final_settlement(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::recordFastFinalSettlementCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let mut portal = ZonePortalStorage::new(call.portal);
        let mut config = portal.fast_epochs[call.epoch].read()?;
        if !config.closed
            || config.retired
            || config.recorded_peer_barriers != config.expected_peer_barriers
            || config.finalized_peer_barriers != config.expected_peer_barriers
            || config.final_settlement_hash != B256::ZERO
            || portal.zone_height.read()? != call.zoneHeight
            || portal.block_hash.read()? != call.blockHash
            || portal.withdrawal_batch_index.read()? != call.withdrawalBatchIndex
        {
            return Err(ZoneFactoryError::fast_epoch_not_drained(call.epoch).into());
        }
        let peers = portal.fast_epoch_peers[call.epoch].read()?;
        let mut barriers_hash = keccak256("TEMPO_ZONE_FAST_BARRIERS_T14_V1");
        for peer in peers {
            let barrier = portal.fast_peer_barriers[call.epoch][peer].read()?;
            if !barrier.finalized || barrier.resolution_hash == B256::ZERO {
                return Err(ZoneFactoryError::fast_epoch_not_drained(call.epoch).into());
            }
            barriers_hash = keccak256(
                (
                    barriers_hash,
                    peer,
                    barrier.barrier_hash,
                    barrier.resolution_hash,
                )
                    .abi_encode(),
            );
        }
        let settlement_hash = keccak256(
            (
                keccak256(FAST_FINAL_SETTLEMENT_DOMAIN),
                U256::from(self.storage.chain_id()),
                call.portal,
                call.epoch,
                config.roster_hash,
                config.closure_hash,
                call.zoneHeight,
                call.blockHash,
                call.withdrawalBatchIndex,
                barriers_hash,
            )
                .abi_encode(),
        );
        self.verify_historical_quorum(call.portal, call.epoch, settlement_hash, &call.signatures)?;
        config.final_settlement_height = call.zoneHeight;
        config.final_settlement_block_hash = call.blockHash;
        config.final_settlement_withdrawal_batch_index = call.withdrawalBatchIndex;
        config.barriers_hash = barriers_hash;
        config.final_settlement_hash = settlement_hash;
        portal.fast_epochs[call.epoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_final_settlement_recorded(
                call.epoch,
                call.zoneHeight,
                call.blockHash,
                call.withdrawalBatchIndex,
                settlement_hash,
            )
            .into_log_data(),
        )
    }

    pub fn install_fast_checkpoint(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::installFastCheckpointCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let mut portal = ZonePortalStorage::new(call.portal);
        let statement = &call.statement;
        let mut config = portal.fast_epochs[statement.oldEpoch].read()?;
        if config.final_settlement_hash == B256::ZERO
            || config.checkpoint_hash != B256::ZERO
            || statement.portal != call.portal
            || statement.oldEpoch == 0
            || statement.nextEpoch <= statement.oldEpoch
            || statement.nextRosterHash == B256::ZERO
            || statement.finalZoneHeight != config.final_settlement_height
            || statement.finalBlockHash != config.final_settlement_block_hash
            || statement.finalWithdrawalBatchIndex != config.final_settlement_withdrawal_batch_index
            || statement.finalSettlementHash != config.final_settlement_hash
            || statement.checkpointStateRoot == B256::ZERO
        {
            return Err(ZoneFactoryError::fast_epoch_not_drained(statement.oldEpoch).into());
        }
        let checkpoint_hash = keccak256(
            (
                keccak256(FAST_CHECKPOINT_DOMAIN),
                U256::from(self.storage.chain_id()),
                statement.clone(),
            )
                .abi_encode(),
        );
        self.verify_next_roster_quorum(&call.nextMembers, checkpoint_hash, &call.signatures)?;
        config.next_epoch = statement.nextEpoch;
        config.next_roster_hash = statement.nextRosterHash;
        config.checkpoint_log_term = statement.checkpointLogTerm;
        config.checkpoint_log_index = statement.checkpointLogIndex;
        config.checkpoint_height = statement.checkpointHeight;
        config.checkpoint_block_hash = statement.checkpointBlockHash;
        config.checkpoint_state_root = statement.checkpointStateRoot;
        config.checkpoint_hash = checkpoint_hash;
        portal.fast_epochs[statement.oldEpoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_checkpoint_installed(
                statement.oldEpoch,
                statement.nextEpoch,
                checkpoint_hash,
            )
            .into_log_data(),
        )
    }

    pub fn retire_fast_epoch(
        &mut self,
        msg_sender: Address,
        call: IZoneFactory::retireFastEpochCall,
    ) -> Result<()> {
        self.require_fast_protocol()?;
        self.require_owner(msg_sender)?;
        self.require_portal(call.portal)?;
        let mut portal = ZonePortalStorage::new(call.portal);
        let mut config = portal.fast_epochs[call.epoch].read()?;
        if !config.closed
            || config.retired
            || config.recorded_peer_barriers != config.expected_peer_barriers
            || config.finalized_peer_barriers != config.expected_peer_barriers
            || config.final_settlement_hash == B256::ZERO
            || config.checkpoint_hash == B256::ZERO
        {
            return Err(ZoneFactoryError::fast_epoch_not_drained(call.epoch).into());
        }
        config.retired = true;
        portal.fast_epochs[call.epoch].write(config)?;
        self.storage.emit_event(
            call.portal,
            ZonePortalEvent::fast_epoch_retired(call.epoch).into_log_data(),
        )
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
        let Some(zone_id) = portal.zone_portal_id() else {
            return Ok(false);
        };

        Ok(zone_id != 0 && zone_id < u64::from(self.next_zone_id()?))
    }

    pub const fn fast_protocol_native_pin(&self) -> B256 {
        FAST_PROTOCOL_NATIVE_PIN
    }
}

fn validate_token_metadata(name: &str, symbol: &str, currency: &str) -> Result<()> {
    if [name, symbol, currency]
        .into_iter()
        .any(|value| value.len() > MAX_TOKEN_METADATA_BYTES)
    {
        return Err(ZoneFactoryError::token_metadata_too_long().into());
    }
    Ok(())
}

fn validate_closed_loop_config(
    storage: &mut crate::storage::StorageCtx,
    allowed_accounts: &[Address],
    zone_gateways: &[Address],
    sequencers: &[Address],
) -> Result<()> {
    if allowed_accounts.contains(&ZONE_MESSENGER_ADDRESS) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }

    if storage.spec().is_t11() {
        if has_duplicates_metered(
            storage,
            allowed_accounts
                .iter()
                .chain(zone_gateways)
                .chain(sequencers)
                .copied(),
        )? {
            return Err(ZoneFactoryError::invalid_closed_loop_config().into());
        }
        return Ok(());
    }

    let mut seen =
        HashSet::with_capacity(allowed_accounts.len().saturating_add(zone_gateways.len()));
    seen.extend(allowed_accounts.iter().copied());
    if zone_gateways.iter().any(|gateway| seen.contains(gateway)) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }
    seen.extend(zone_gateways.iter().copied());

    if sequencers.iter().any(|sequencer| seen.contains(sequencer)) {
        return Err(ZoneFactoryError::invalid_closed_loop_config().into());
    }
    Ok(())
}

fn validate_sequencer_set(sequencers: &[Address], threshold: u8) -> Result<()> {
    if sequencers.is_empty()
        || sequencers.len() > MAX_SEQUENCERS
        || threshold == 0
        || usize::from(threshold) > sequencers.len()
    {
        return Err(ZoneFactoryError::invalid_sequencer_set().into());
    }

    for (index, sequencer) in sequencers.iter().enumerate() {
        if sequencer.is_zero() || sequencers[..index].contains(sequencer) {
            return Err(ZoneFactoryError::invalid_sequencer_set().into());
        }
    }
    Ok(())
}

/// Returns the deterministic TIP-1091 portal address for `zone_id`.
pub fn portal_address(zone_id: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..12].copy_from_slice(&Address::ZONE_PORTAL_PREFIX);
    bytes[12..].copy_from_slice(&u64::from(zone_id).to_be_bytes());
    Address::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::{
        primitives::{B256, Bytes, U256, address, keccak256},
        sol_types::SolValue,
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use portal::PortalTokenConfig;
    use revm::state::Bytecode;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::{precompiles::ZonePortalCapability, zones::T13_ZONE_VERIFIER_RUNTIME};

    const OWNER: Address = address!("0x0000000000000000000000000000000000000011");
    const ADMIN: Address = address!("0x0000000000000000000000000000000000000022");
    const SEQUENCER_A: Address = address!("0x0000000000000000000000000000000000000033");
    const SEQUENCER_B: Address = address!("0x0000000000000000000000000000000000000044");
    const ALLOWED_ACCOUNT: Address = address!("0x0000000000000000000000000000000000000055");
    const ZONE_GATEWAY: Address = address!("0x0000000000000000000000000000000000000066");
    const CREATION_BLOCK: u64 = 42;

    fn create_params(initial_token: Address) -> IZoneFactory::CreateZoneParams {
        IZoneFactory::CreateZoneParams {
            initialToken: initial_token,
            accessMode: true,
            gatewayMode: true,
            allowedAccounts: vec![ALLOWED_ACCOUNT],
            zoneGateways: vec![ZONE_GATEWAY],
            admin: ADMIN,
            sequencers: vec![SEQUENCER_A, SEQUENCER_B],
            threshold: 2,
            rpcUrl: "https://zone.example".to_string(),
        }
    }

    fn factory_with_owner(owner: Address) -> Result<ZoneFactory> {
        let mut factory = ZoneFactory::new();
        factory.next_zone_id.write(1)?;
        factory.owner.write(owner)?;
        Ok(factory)
    }

    fn fast_signers() -> [PrivateKeySigner; FAST_MEMBER_COUNT] {
        std::array::from_fn(|_| PrivateKeySigner::random())
    }

    fn signer_addresses(signers: &[PrivateKeySigner; FAST_MEMBER_COUNT]) -> Vec<Address> {
        signers.iter().map(PrivateKeySigner::address).collect()
    }

    fn sign_fast(
        signers: &[PrivateKeySigner; FAST_MEMBER_COUNT],
        digest: B256,
    ) -> eyre::Result<Vec<Bytes>> {
        signers[..FAST_THRESHOLD as usize]
            .iter()
            .map(|signer| {
                signer
                    .sign_hash_sync(&digest)
                    .map(|signature| Bytes::copy_from_slice(&signature.as_bytes()))
                    .map_err(Into::into)
            })
            .collect()
    }

    fn sign_pair(
        first: &PrivateKeySigner,
        second: &PrivateKeySigner,
        digest: B256,
    ) -> eyre::Result<Vec<Bytes>> {
        [first, second]
            .into_iter()
            .map(|signer| {
                signer
                    .sign_hash_sync(&digest)
                    .map(|signature| Bytes::copy_from_slice(&signature.as_bytes()))
                    .map_err(Into::into)
            })
            .collect()
    }

    fn install_prototype_verifier() -> Result<()> {
        StorageCtx.set_code(
            ZONE_VERIFIER_ADDRESS,
            Bytecode::new_legacy(T13_ZONE_VERIFIER_RUNTIME),
        )
    }

    fn fast_roster_hash(
        portal: Address,
        epoch: u64,
        protocol_version: u32,
        proof_mode: u8,
        verifier_config_hash: B256,
        members: &[Address],
        peers: &[Address],
    ) -> B256 {
        keccak256(
            (
                keccak256("TEMPO_ZONE_FAST_ROSTER_T14_V1"),
                portal,
                epoch,
                protocol_version,
                U256::from(FAST_THRESHOLD),
                U256::from(proof_mode),
                T13_PROTOTYPE_VERIFIER_CODE_HASH,
                verifier_config_hash,
                members.to_vec(),
                peers.to_vec(),
            )
                .abi_encode(),
        )
    }

    fn configure_call(
        portal: Address,
        epoch: u64,
        members: &[Address],
        peers: &[Address],
    ) -> IZoneFactory::configureFastEpochCall {
        let verifier_config_hash = keccak256([]);
        IZoneFactory::configureFastEpochCall {
            portal,
            epoch,
            protocolVersion: 1,
            proofMode: FAST_PROOF_MODE_OPERATOR_ATTESTED,
            expectedVerifierCodeHash: T13_PROTOTYPE_VERIFIER_CODE_HASH,
            expectedVerifierConfigHash: verifier_config_hash,
            rosterHash: fast_roster_hash(
                portal,
                epoch,
                1,
                FAST_PROOF_MODE_OPERATOR_ATTESTED,
                verifier_config_hash,
                members,
                peers,
            ),
            members: members.to_vec(),
            peerPortals: peers.to_vec(),
        }
    }

    fn create_ten_zones(factory: &mut ZoneFactory) -> Result<Vec<Address>> {
        (0..10)
            .map(|_| {
                factory
                    .create_zone(
                        OWNER,
                        IZoneFactory::createZoneCall {
                            params: create_params(PATH_USD_ADDRESS),
                        },
                    )
                    .map(|created| created.portal)
            })
            .collect()
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        storage.set_block_number(CREATION_BLOCK);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;

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
                    accessMode: true,
                    gatewayMode: true,
                    admin: ADMIN,
                    sequencers: vec![SEQUENCER_A, SEQUENCER_B],
                    threshold: 2,
                    verifier: ZONE_VERIFIER_ADDRESS,
                    rpcUrl: params.rpcUrl.clone(),
                }
            );

            let code = factory.storage.with_account_info(created.portal, |info| {
                Ok(info.code.clone().expect("portal code installed"))
            })?;
            assert_eq!(
                code.original_bytes().as_ref(),
                ZONE_PORTAL_PROXY_RUNTIME.as_slice()
            );

            let mut portal = ZonePortalStorage::new(created.portal);
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
            assert_eq!(portal.sequencer_set_version.read()?, 0);
            assert_eq!(portal.sequencer_threshold.read()?, 2);
            assert_eq!(portal.sequencers.read()?, vec![SEQUENCER_A, SEQUENCER_B]);
            assert_eq!(portal.last_processed_enabled_token_count.read()?, 0);
            assert!(!portal.token_enablement_cursor_initialized.read()?);
            assert_eq!(
                portal.role[SEQUENCER_A].read()?,
                u8::from(ZonePortalRole::Sequencer)
            );
            assert_eq!(
                portal.role[SEQUENCER_B].read()?,
                u8::from(ZonePortalRole::Sequencer)
            );
            assert_eq!(
                portal.role[ALLOWED_ACCOUNT].read()?,
                u8::from(ZonePortalRole::Account)
            );
            assert_eq!(
                portal.role[ZONE_GATEWAY].read()?,
                u8::from(ZonePortalRole::CallbackGateway)
            );
            assert!(portal.is_access_enforced.read()?);
            assert!(portal.is_gateway_enforced.read()?);
            assert_eq!(portal.max_tempo_gas_rate.read()?, 0);
            assert_eq!(portal.leader.read()?, SEQUENCER_A);
            assert_eq!(portal.leader_epoch.read()?, 1);
            assert_eq!(portal.leader_activation_tempo_block.read()?, CREATION_BLOCK);
            assert_eq!(portal.token_enable_count_block.read()?, CREATION_BLOCK);
            assert_eq!(portal.tokens_enabled_in_current_block.read()?, 1);
            assert_eq!(portal.pause_expiry.read()?, 0);
            assert_eq!(
                portal
                    .abdication_effective_at(ZonePortalCapability::PausePortal)
                    .read()?,
                0
            );
            assert_eq!(
                portal
                    .abdication_effective_at(ZonePortalCapability::AccessPolicy)
                    .read()?,
                0
            );
            let expected_token_enablement_hash = keccak256(
                (B256::ZERO, PATH_USD_ADDRESS, "pathUSD", "pathUSD", "USD").abi_encode_params(),
            );
            assert_eq!(
                portal.token_enablement_hash.read()?,
                expected_token_enablement_hash
            );

            // Pin the native storage handlers to the canonical Solidity layout.
            assert_eq!(
                StorageCtx.sload(created.portal, U256::ZERO)?,
                U256::from_be_slice(ADMIN.as_slice())
            );
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(18))?,
                U256::from(2)
            );
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(19))?,
                U256::ZERO
            );
            let membership_slot =
                U256::from_be_bytes(keccak256((SEQUENCER_A, U256::from(20)).abi_encode()).0);
            assert_eq!(
                StorageCtx.sload(created.portal, membership_slot)?,
                U256::from(u8::from(ZonePortalRole::Sequencer))
            );
            let role_slot =
                U256::from_be_bytes(keccak256((ALLOWED_ACCOUNT, U256::from(20)).abi_encode()).0);
            assert_eq!(
                StorageCtx.sload(created.portal, role_slot)?,
                U256::from(u8::from(ZonePortalRole::Account))
            );
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(21))?,
                U256::from(0x0101)
            );
            assert_eq!(portal.max_tempo_gas_rate.slot(), U256::from(22));
            assert_eq!(portal.leader.slot(), U256::from(23));
            assert_eq!(portal.leader_epoch.slot(), U256::from(23));
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(23))?,
                U256::from_be_slice(SEQUENCER_A.as_slice()) | (U256::ONE << 160)
            );
            assert_eq!(portal.leader_activation_tempo_block.slot(), U256::from(24));
            assert_eq!(portal.token_enable_count_block.slot(), U256::from(24));
            assert_eq!(
                portal.tokens_enabled_in_current_block.slot(),
                U256::from(25)
            );
            assert_eq!(portal.pause_expiry.slot(), U256::from(25));
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(24))?,
                U256::from(CREATION_BLOCK) | (U256::from(CREATION_BLOCK) << 192)
            );
            assert_eq!(StorageCtx.sload(created.portal, U256::from(25))?, U256::ONE);
            assert_eq!(portal.token_enablement_hash.slot(), U256::from(26));
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(26))?,
                U256::from_be_bytes(expected_token_enablement_hash.0)
            );
            assert_eq!(portal.abdication_effective_at.slot(), U256::from(27));
            assert_eq!(
                StorageCtx.sload(created.portal, U256::from(28))?,
                U256::ZERO
            );
            let access_abdication_slot = U256::from_be_bytes(
                keccak256(
                    (
                        U256::from(u8::from(ZonePortalCapability::AccessPolicy)),
                        U256::from(27),
                    )
                        .abi_encode(),
                )
                .0,
            );
            assert_eq!(
                portal
                    .abdication_effective_at(ZonePortalCapability::AccessPolicy)
                    .slot(),
                access_abdication_slot
            );

            // Ensure portal can't be re-initialized
            assert_eq!(
                portal.initialize(1, &params, B256::ZERO),
                Err(ZoneFactoryError::already_initialized().into())
            );
            Ok(())
        })
    }

    #[test]
    fn create_zone_initializes_token_cursor_at_t13() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T12, TempoHardfork::T13] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                TIP20Setup::path_usd(ADMIN).apply()?;
                let mut factory = factory_with_owner(OWNER)?;
                let created = factory.create_zone(
                    OWNER,
                    IZoneFactory::createZoneCall {
                        params: create_params(PATH_USD_ADDRESS),
                    },
                )?;

                let portal = ZonePortalStorage::new(created.portal);
                assert_eq!(portal.last_processed_enabled_token_count.read()?, 0);
                assert_eq!(
                    portal.token_enablement_cursor_initialized.read()?,
                    hardfork.is_t13()
                );
                assert_eq!(
                    StorageCtx.sload(created.portal, U256::from(28))?,
                    U256::from(u64::from(hardfork.is_t13())) << 64
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn create_zone_rejects_oversized_initial_token_metadata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut factory = factory_with_owner(OWNER)?;

            let long_name = TIP20Setup::create("nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", "N", ADMIN)
                .apply()?
                .address();
            let long_symbol =
                TIP20Setup::create("Symbol", "ssssssssssssssssssssssssssssssss", ADMIN)
                    .apply()?
                    .address();
            let long_currency = TIP20Setup::create("Currency", "C", ADMIN)
                .currency("cccccccccccccccccccccccccccccccc")
                .apply()?
                .address();

            for token in [long_name, long_symbol, long_currency] {
                let err = factory
                    .create_zone(
                        OWNER,
                        IZoneFactory::createZoneCall {
                            params: create_params(token),
                        },
                    )
                    .unwrap_err();
                assert_eq!(err, ZoneFactoryError::token_metadata_too_long().into());
                assert_eq!(factory.next_zone_id()?, 1);
            }
            Ok(())
        })
    }

    #[test]
    fn create_zone_emits_constructor_events_in_order_with_duplicate_roles() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        storage.set_block_number(CREATION_BLOCK);
        let portal = StorageCtx::enter(&mut storage, || -> eyre::Result<Address> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;
            let mut params = create_params(PATH_USD_ADDRESS);
            params.zoneGateways = vec![ZONE_GATEWAY, ZONE_GATEWAY];
            params.allowedAccounts = vec![ALLOWED_ACCOUNT, ALLOWED_ACCOUNT];

            Ok(factory
                .create_zone(OWNER, IZoneFactory::createZoneCall { params })?
                .portal)
        })?;

        let events = storage.get_events(portal);
        assert!(events.len() >= 7);
        assert_eq!(
            &events[..7],
            &[
                ZonePortalEvent::enforcement_modes_updated(true, true).into_log_data(),
                ZonePortalEvent::sequencer_set_updated(0, 2, vec![SEQUENCER_A, SEQUENCER_B],)
                    .into_log_data(),
                ZonePortalEvent::leader_updated(Address::ZERO, SEQUENCER_A, 1, CREATION_BLOCK,)
                    .into_log_data(),
                ZonePortalEvent::role_updated(
                    ZONE_GATEWAY,
                    ZonePortalRole::None,
                    ZonePortalRole::CallbackGateway,
                )
                .into_log_data(),
                ZonePortalEvent::role_updated(
                    ZONE_GATEWAY,
                    ZonePortalRole::CallbackGateway,
                    ZonePortalRole::CallbackGateway,
                )
                .into_log_data(),
                ZonePortalEvent::role_updated(
                    ALLOWED_ACCOUNT,
                    ZonePortalRole::None,
                    ZonePortalRole::Account,
                )
                .into_log_data(),
                ZonePortalEvent::role_updated(
                    ALLOWED_ACCOUNT,
                    ZonePortalRole::Account,
                    ZonePortalRole::Account,
                )
                .into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn create_zone_rejects_duplicate_roles_at_t11() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;
            let mut params = create_params(PATH_USD_ADDRESS);
            params.allowedAccounts = vec![ALLOWED_ACCOUNT, ALLOWED_ACCOUNT];

            let err = factory
                .create_zone(OWNER, IZoneFactory::createZoneCall { params })
                .unwrap_err();
            assert_eq!(err, ZoneFactoryError::invalid_closed_loop_config().into());
            Ok(())
        })
    }

    #[test]
    fn create_zone_allows_empty_role_sets_and_open_modes() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;

            let mut params = create_params(PATH_USD_ADDRESS);
            params.allowedAccounts.clear();
            params.zoneGateways.clear();
            let closed = factory.create_zone(
                OWNER,
                IZoneFactory::createZoneCall {
                    params: params.clone(),
                },
            )?;
            let closed_portal = ZonePortalStorage::new(closed.portal);
            assert!(closed_portal.is_access_enforced.read()?);
            assert!(closed_portal.is_gateway_enforced.read()?);

            params.accessMode = false;
            params.gatewayMode = false;
            let open = factory.create_zone(OWNER, IZoneFactory::createZoneCall { params })?;
            let open_portal = ZonePortalStorage::new(open.portal);
            assert!(!open_portal.is_access_enforced.read()?);
            assert!(!open_portal.is_gateway_enforced.read()?);
            assert!(!factory.zone(open.zoneId)?.accessMode);
            assert!(!factory.zone(open.zoneId)?.gatewayMode);
            Ok(())
        })
    }

    #[test]
    fn create_zone_rejects_invalid_closed_loop_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;

            for (allowed_accounts, zone_gateways) in [
                (vec![ZONE_MESSENGER_ADDRESS], vec![ZONE_GATEWAY]),
                (vec![ALLOWED_ACCOUNT], vec![ALLOWED_ACCOUNT]),
                (vec![SEQUENCER_A], vec![ZONE_GATEWAY]),
                (vec![ALLOWED_ACCOUNT], vec![SEQUENCER_A]),
            ] {
                let mut params = create_params(PATH_USD_ADDRESS);
                params.allowedAccounts = allowed_accounts;
                params.zoneGateways = zone_gateways;
                let err = factory
                    .create_zone(OWNER, IZoneFactory::createZoneCall { params })
                    .unwrap_err();
                assert_eq!(
                    err,
                    TempoPrecompileError::from(ZoneFactoryError::invalid_closed_loop_config())
                );
                assert_eq!(factory.next_zone_id()?, 1);
            }
            Ok(())
        })
    }

    #[test]
    fn create_zone_rejects_invalid_sequencer_sets() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;

            for (sequencers, threshold) in [
                (vec![], 1),
                (vec![Address::ZERO], 1),
                (vec![SEQUENCER_A, SEQUENCER_A], 1),
                (vec![SEQUENCER_A], 0),
                (vec![SEQUENCER_A], 2),
                ((1u8..=9).map(Address::with_last_byte).collect(), 1),
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

            let mut params = create_params(PATH_USD_ADDRESS);
            params.sequencers = vec![SEQUENCER_B, SEQUENCER_A];
            factory.create_zone(OWNER, IZoneFactory::createZoneCall { params })?;
            assert_eq!(factory.zone(1)?.sequencers, vec![SEQUENCER_B, SEQUENCER_A]);
            Ok(())
        })
    }

    #[test]
    fn create_zone_allows_admin_as_sequencer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;
            let mut params = create_params(PATH_USD_ADDRESS);
            params.sequencers = vec![ADMIN];
            params.threshold = 1;

            let created = factory.create_zone(OWNER, IZoneFactory::createZoneCall { params })?;

            assert_eq!(factory.zone(created.zoneId)?.admin, ADMIN);
            assert_eq!(factory.zone(created.zoneId)?.sequencers, vec![ADMIN]);
            let portal = ZonePortalStorage::new(created.portal);
            assert_eq!(portal.admin.read()?, ADMIN);
            assert_eq!(portal.sequencers.read()?, vec![ADMIN]);
            assert_eq!(
                portal.role[ADMIN].read()?,
                u8::from(ZonePortalRole::Sequencer)
            );
            Ok(())
        })
    }

    #[test]
    fn create_zone_requires_initial_token_policy_binding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;
            StorageCtx.set_spec(TempoHardfork::T10);

            let err = factory
                .create_zone(
                    OWNER,
                    IZoneFactory::createZoneCall {
                        params: create_params(PATH_USD_ADDRESS),
                    },
                )
                .unwrap_err();
            assert_eq!(
                err,
                TempoPrecompileError::from(ZoneFactoryError::token_transfer_policy_not_set())
            );
            assert_eq!(factory.next_zone_id()?, 1);
            assert!(!factory.is_zone_portal(portal_address(1))?);

            TIP403Registry::new().set_token_transfer_policy(PATH_USD_ADDRESS, 1)?;
            factory.create_zone(
                OWNER,
                IZoneFactory::createZoneCall {
                    params: create_params(PATH_USD_ADDRESS),
                },
            )?;
            assert_eq!(factory.next_zone_id()?, 2);

            Ok(())
        })
    }

    #[test]
    fn owner_and_input_validation_revert_before_mutation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = factory_with_owner(OWNER)?;

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
    fn fast_epoch_is_t14_only_and_requires_exact_distinct_rosters() -> eyre::Result<()> {
        std::thread::Builder::new()
            .name("fast-epoch-configuration".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(fast_epoch_is_t14_only_and_requires_exact_distinct_rosters_impl)?
            .join()
            .expect("fast epoch configuration test thread panicked")
    }

    fn fast_epoch_is_t14_only_and_requires_exact_distinct_rosters_impl() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T13, TempoHardfork::T14] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                TIP20Setup::path_usd(ADMIN).apply()?;
                install_prototype_verifier()?;
                let mut factory = factory_with_owner(OWNER)?;
                let portals = create_ten_zones(&mut factory)?;
                let portal = portals[0];
                let peers = portals[1..].to_vec();
                let members = signer_addresses(&fast_signers());
                let call = configure_call(portal, 1, &members, &peers);

                if hardfork == TempoHardfork::T13 {
                    assert_eq!(
                        factory.configure_fast_epoch(OWNER, call).unwrap_err(),
                        ZoneFactoryError::fast_protocol_unavailable().into()
                    );
                    return Ok(());
                }

                assert_eq!(
                    factory
                        .configure_fast_epoch(ADMIN, call.clone())
                        .unwrap_err(),
                    ZoneFactoryError::not_owner().into()
                );
                assert_eq!(
                    factory
                        .configure_fast_epoch(
                            OWNER,
                            IZoneFactory::configureFastEpochCall {
                                proofMode: 0,
                                ..call.clone()
                            },
                        )
                        .unwrap_err(),
                    ZoneFactoryError::invalid_fast_epoch().into()
                );
                assert_eq!(
                    factory
                        .configure_fast_epoch(
                            OWNER,
                            IZoneFactory::configureFastEpochCall {
                                proofMode: FAST_PROOF_MODE_REQUIRED,
                                ..call.clone()
                            },
                        )
                        .unwrap_err(),
                    ZoneFactoryError::invalid_fast_proof_configuration().into()
                );
                assert_eq!(
                    factory
                        .configure_fast_epoch(
                            OWNER,
                            IZoneFactory::configureFastEpochCall {
                                expectedVerifierCodeHash: B256::repeat_byte(0xff),
                                ..call.clone()
                            },
                        )
                        .unwrap_err(),
                    ZoneFactoryError::invalid_fast_proof_configuration().into()
                );
                let mut duplicate_members = members.clone();
                duplicate_members[2] = duplicate_members[0];
                assert_eq!(
                    factory
                        .configure_fast_epoch(
                            OWNER,
                            IZoneFactory::configureFastEpochCall {
                                rosterHash: configure_call(portal, 1, &duplicate_members, &peers,)
                                    .rosterHash,
                                members: duplicate_members,
                                ..call.clone()
                            },
                        )
                        .unwrap_err(),
                    ZoneFactoryError::invalid_fast_epoch().into()
                );
                let mut duplicate_peers = peers.clone();
                duplicate_peers[8] = duplicate_peers[0];
                assert_eq!(
                    factory
                        .configure_fast_epoch(
                            OWNER,
                            IZoneFactory::configureFastEpochCall {
                                rosterHash: configure_call(portal, 1, &members, &duplicate_peers,)
                                    .rosterHash,
                                peerPortals: duplicate_peers,
                                ..call.clone()
                            },
                        )
                        .unwrap_err(),
                    ZoneFactoryError::invalid_fast_epoch().into()
                );

                factory.configure_fast_epoch(OWNER, call)?;
                let portal_state = ZonePortalStorage::new(portal);
                assert_eq!(portal_state.fast_epoch.slot(), U256::from(28));
                assert_eq!(portal_state.fast_epochs.slot(), U256::from(29));
                assert_eq!(portal_state.fast_epoch_members.slot(), U256::from(30));
                assert_eq!(portal_state.is_fast_epoch_member.slot(), U256::from(31));
                assert_eq!(portal_state.fast_epoch_peers.slot(), U256::from(32));
                assert_eq!(portal_state.is_fast_epoch_peer.slot(), U256::from(33));
                assert_eq!(portal_state.fast_peer_barriers.slot(), U256::from(34));
                assert_eq!(portal_state.fast_epoch.read()?, 1);
                assert_eq!(portal_state.fast_epoch_members[1].read()?, members);
                assert_eq!(portal_state.fast_epoch_peers[1].read()?, peers);
                assert_eq!(portal_state.fast_epochs[1].read()?.threshold, 2);
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn fast_epoch_retirement_requires_every_exact_peer_and_checkpoint() -> eyre::Result<()> {
        std::thread::Builder::new()
            .name("fast-epoch-retirement".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(fast_epoch_retirement_requires_every_exact_peer_and_checkpoint_impl)?
            .join()
            .expect("fast epoch retirement test thread panicked")
    }

    fn fast_epoch_retirement_requires_every_exact_peer_and_checkpoint_impl() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            install_prototype_verifier()?;
            let mut factory = factory_with_owner(OWNER)?;
            let portals = create_ten_zones(&mut factory)?;
            let portal = portals[0];
            let peers = portals[1..].to_vec();
            let signers = fast_signers();
            let members = signer_addresses(&signers);
            for (index, configured_portal) in portals.iter().copied().enumerate() {
                let configured_peers = portals
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(peer_index, peer)| (peer_index != index).then_some(peer))
                    .collect::<Vec<_>>();
                factory.configure_fast_epoch(
                    OWNER,
                    configure_call(configured_portal, 7, &members, &configured_peers),
                )?;
            }
            factory.close_fast_epoch(
                OWNER,
                IZoneFactory::closeFastEpochCall {
                    portal,
                    epoch: 7,
                    closureHash: B256::repeat_byte(0x11),
                },
            )?;

            let statement_for =
                |peer: Address, lock_root: B256| IZoneFactory::FastBarrierStatement {
                    destinationPortal: portal,
                    destinationEpoch: 7,
                    closureHash: B256::repeat_byte(0x11),
                    sourcePortal: peer,
                    sourceEpoch: 7,
                    importedAnchorNumber: 90,
                    importedAnchorHash: B256::repeat_byte(0x12),
                    logTerm: 3,
                    logIndex: 99,
                    blockHeight: U256::from(98),
                    blockHash: B256::repeat_byte(0x13),
                    stateRoot: B256::repeat_byte(0x14),
                    lockLogWatermark: 97,
                    completeLockRoot: lock_root,
                    unresolvedRoot: FAST_EMPTY_UNRESOLVED_ROOT,
                    unresolvedCount: 0,
                };
            let barrier_digest = |statement: IZoneFactory::FastBarrierStatement| {
                keccak256((keccak256(FAST_BARRIER_DOMAIN), U256::from(1), statement).abi_encode())
            };

            let first_statement = statement_for(peers[0], B256::repeat_byte(0x20));
            assert_eq!(
                factory
                    .record_fast_peer_barrier(
                        OWNER,
                        IZoneFactory::recordFastPeerBarrierCall {
                            portal,
                            statement: first_statement.clone(),
                            signatures: Vec::new(),
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );
            let first_digest = barrier_digest(first_statement.clone());
            let wrong_domain_digest = keccak256(
                (
                    keccak256("WRONG_FAST_BARRIER_DOMAIN"),
                    U256::from(1),
                    first_statement.clone(),
                )
                    .abi_encode(),
            );
            assert_eq!(
                factory
                    .record_fast_peer_barrier(
                        OWNER,
                        IZoneFactory::recordFastPeerBarrierCall {
                            portal,
                            statement: first_statement.clone(),
                            signatures: sign_fast(&signers, wrong_domain_digest)?,
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );
            let outsider = PrivateKeySigner::random();
            assert_eq!(
                factory
                    .record_fast_peer_barrier(
                        OWNER,
                        IZoneFactory::recordFastPeerBarrierCall {
                            portal,
                            statement: first_statement.clone(),
                            signatures: sign_pair(&signers[0], &outsider, first_digest)?,
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );
            let mut fabricated = first_statement.clone();
            fabricated.completeLockRoot = B256::repeat_byte(0xff);
            assert_eq!(
                factory
                    .record_fast_peer_barrier(
                        OWNER,
                        IZoneFactory::recordFastPeerBarrierCall {
                            portal,
                            statement: fabricated,
                            signatures: sign_fast(&signers, first_digest)?,
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );

            for (index, peer) in peers.iter().copied().enumerate() {
                let statement = statement_for(peer, B256::repeat_byte(0x40 + index as u8));
                let digest = barrier_digest(statement.clone());
                let barrier_call = IZoneFactory::recordFastPeerBarrierCall {
                    portal,
                    statement,
                    signatures: sign_fast(&signers, digest)?,
                };
                factory.record_fast_peer_barrier(OWNER, barrier_call.clone())?;
                assert_eq!(
                    factory
                        .record_fast_peer_barrier(OWNER, barrier_call)
                        .unwrap_err(),
                    ZoneFactoryError::fast_peer_barrier_already_recorded(peer).into()
                );
                let barrier = ZonePortalStorage::new(portal).fast_peer_barriers[7][peer].read()?;
                let resolution = IZoneFactory::FastBarrierResolution {
                    barrierHash: barrier.barrier_hash,
                    terminalRoot: B256::repeat_byte(0x60 + index as u8),
                    dispositionRoot: B256::repeat_byte(0x70 + index as u8),
                    resolvedCount: 0,
                    remainingUnresolvedRoot: FAST_EMPTY_UNRESOLVED_ROOT,
                    remainingUnresolvedCount: 0,
                };
                let resolution_digest = keccak256(
                    (
                        keccak256(FAST_BARRIER_RESOLUTION_DOMAIN),
                        U256::from(1),
                        portal,
                        7_u64,
                        peer,
                        resolution.clone(),
                    )
                        .abi_encode(),
                );
                if index == 0 {
                    let mut incomplete = resolution.clone();
                    incomplete.remainingUnresolvedCount = 1;
                    assert_eq!(
                        factory
                            .finalize_fast_peer_barrier(
                                OWNER,
                                IZoneFactory::finalizeFastPeerBarrierCall {
                                    portal,
                                    epoch: 7,
                                    peerPortal: peer,
                                    resolution: incomplete,
                                    signatures: sign_fast(&signers, resolution_digest)?,
                                },
                            )
                            .unwrap_err(),
                        ZoneFactoryError::invalid_fast_certificate().into()
                    );
                }
                factory.finalize_fast_peer_barrier(
                    OWNER,
                    IZoneFactory::finalizeFastPeerBarrierCall {
                        portal,
                        epoch: 7,
                        peerPortal: peer,
                        resolution,
                        signatures: sign_fast(&signers, resolution_digest)?,
                    },
                )?;
            }

            assert_eq!(
                factory
                    .retire_fast_epoch(
                        OWNER,
                        IZoneFactory::retireFastEpochCall { portal, epoch: 7 },
                    )
                    .unwrap_err(),
                ZoneFactoryError::fast_epoch_not_drained(7).into()
            );
            let mut accepted = ZonePortalStorage::new(portal);
            accepted.zone_height.write(U256::from(100))?;
            accepted.block_hash.write(B256::repeat_byte(0x77))?;
            let config = accepted.fast_epochs[7].read()?;
            let mut barriers_hash = keccak256("TEMPO_ZONE_FAST_BARRIERS_T14_V1");
            for peer in &peers {
                let barrier = accepted.fast_peer_barriers[7][*peer].read()?;
                barriers_hash = keccak256(
                    (
                        barriers_hash,
                        *peer,
                        barrier.barrier_hash,
                        barrier.resolution_hash,
                    )
                        .abi_encode(),
                );
            }
            let settlement_hash = keccak256(
                (
                    keccak256(FAST_FINAL_SETTLEMENT_DOMAIN),
                    U256::from(1),
                    portal,
                    7_u64,
                    config.roster_hash,
                    config.closure_hash,
                    U256::from(100),
                    B256::repeat_byte(0x77),
                    0_u64,
                    barriers_hash,
                )
                    .abi_encode(),
            );
            assert_eq!(
                factory
                    .record_fast_final_settlement(
                        OWNER,
                        IZoneFactory::recordFastFinalSettlementCall {
                            portal,
                            epoch: 7,
                            zoneHeight: U256::from(100),
                            blockHash: B256::repeat_byte(0x77),
                            withdrawalBatchIndex: 0,
                            signatures: Vec::new(),
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );
            factory.record_fast_final_settlement(
                OWNER,
                IZoneFactory::recordFastFinalSettlementCall {
                    portal,
                    epoch: 7,
                    zoneHeight: U256::from(100),
                    blockHash: B256::repeat_byte(0x77),
                    withdrawalBatchIndex: 0,
                    signatures: sign_fast(&signers, settlement_hash)?,
                },
            )?;
            let next_signers = fast_signers();
            let next_members = signer_addresses(&next_signers);
            let next_call = configure_call(portal, 8, &next_members, &peers);
            let settled = ZonePortalStorage::new(portal).fast_epochs[7].read()?;
            let checkpoint_statement = IZoneFactory::FastCheckpointStatement {
                portal,
                oldEpoch: 7,
                nextEpoch: 8,
                nextRosterHash: next_call.rosterHash,
                finalZoneHeight: settled.final_settlement_height,
                finalBlockHash: settled.final_settlement_block_hash,
                finalWithdrawalBatchIndex: settled.final_settlement_withdrawal_batch_index,
                finalSettlementHash: settled.final_settlement_hash,
                checkpointLogTerm: 4,
                checkpointLogIndex: 101,
                checkpointHeight: U256::from(100),
                checkpointBlockHash: B256::repeat_byte(0x77),
                checkpointStateRoot: B256::repeat_byte(0x88),
            };
            let checkpoint_hash = keccak256(
                (
                    keccak256(FAST_CHECKPOINT_DOMAIN),
                    U256::from(1),
                    checkpoint_statement.clone(),
                )
                    .abi_encode(),
            );
            assert_eq!(
                factory
                    .install_fast_checkpoint(
                        OWNER,
                        IZoneFactory::installFastCheckpointCall {
                            portal,
                            statement: checkpoint_statement.clone(),
                            nextMembers: next_members.clone(),
                            signatures: Vec::new(),
                        },
                    )
                    .unwrap_err(),
                ZoneFactoryError::invalid_fast_certificate().into()
            );
            factory.install_fast_checkpoint(
                OWNER,
                IZoneFactory::installFastCheckpointCall {
                    portal,
                    statement: checkpoint_statement,
                    nextMembers: next_members,
                    signatures: sign_fast(&next_signers, checkpoint_hash)?,
                },
            )?;
            factory.retire_fast_epoch(
                OWNER,
                IZoneFactory::retireFastEpochCall { portal, epoch: 7 },
            )?;
            factory.configure_fast_epoch(OWNER, next_call)?;

            let state = ZonePortalStorage::new(portal);
            let config = state.fast_epochs[7].read()?;
            assert!(config.retired);
            assert_eq!(config.recorded_peer_barriers, 9);
            assert_eq!(config.finalized_peer_barriers, 9);
            assert_eq!(state.fast_epoch_members[7].read()?, members);
            assert_eq!(state.fast_epoch_peers[7].read()?, peers);
            assert!(state.fast_peer_barriers[7][portals[1]].read()?.finalized);
            assert_eq!(state.fast_epoch.read()?, 8);
            Ok(())
        })
    }
}
