//! Configuration, roles, sequencer set, leadership, pause and abdication, token enablement and encryption keys.

use super::{
    ABDICATION_DELAY, MAX_GAS_FEE_RATE, MAX_UNPROCESSED_TOKEN_ENABLEMENTS, PAUSE_DURATION,
    PortalEncryptionKeyEntry, PortalTokenConfig, ZonePortalStorage,
    secp256k1::{derive_address, is_valid_x},
};
use crate::{
    ECRECOVER_GAS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, ZONE_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::Handler,
};
use alloy::{
    consensus::crypto::secp256k1::recover_signer_unchecked,
    primitives::{Address, B256, Signature, U256},
    sol_types::SolValue,
};
use tempo_contracts::{
    precompiles::{
        ITIP20, ITIP20Factory, ITIP403Registry, MAX_SEQUENCERS, ZonePortalCapability,
        ZonePortalError, ZonePortalEvent, ZonePortalRole,
    },
    zones::{MAX_TOKEN_METADATA_BYTES, ZonePortal},
};

impl ZonePortalStorage {
    /// Solidity `abdicate`.
    pub fn abdicate(&mut self, sender: Address, call: ZonePortal::abdicateCall) -> Result<()> {
        self.only_admin(sender)?;
        self.when_not_paused()?;
        let capability = call.capability;
        if self.abdication_effective_at[u8::from(capability)].read()? != 0 {
            return Err(ZonePortalError::abdication_already_scheduled(capability).into());
        }
        let effective_at = self
            .storage
            .timestamp()
            .wrapping_to::<u64>()
            .checked_add(ABDICATION_DELAY)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.abdication_effective_at[u8::from(capability)].write(effective_at)?;
        self.emit(ZonePortalEvent::abdication_scheduled(
            capability,
            effective_at,
        ))
    }

    /// Solidity `acceptAdmin`.
    pub fn accept_admin(
        &mut self,
        sender: Address,
        _call: ZonePortal::acceptAdminCall,
    ) -> Result<()> {
        let pending_admin = self.pending_admin.read()?;
        if pending_admin.is_zero() || sender != pending_admin {
            return Err(ZonePortalError::not_pending_admin().into());
        }
        let previous_admin = self.admin.read()?;
        self.admin.write(pending_admin)?;
        self.pending_admin.write(Address::ZERO)?;
        self.emit(ZonePortalEvent::admin_transferred(
            previous_admin,
            pending_admin,
        ))
    }

    /// Solidity `enableToken` with `_enableTokenInternal`.
    pub fn enable_token(
        &mut self,
        sender: Address,
        call: ZonePortal::enableTokenCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        let token = call.token;
        if self.token_configs[token].read()?.enabled {
            return Err(ZonePortalError::token_already_enabled().into());
        }
        if !self
            .external_static_call(TIP20_FACTORY_ADDRESS, &ITIP20Factory::isTIP20Call { token })?
        {
            return Err(ZonePortalError::token_not_enabled().into());
        }
        if !self.token_enablement_cursor_initialized.read()? {
            return Err(ZonePortalError::token_enablement_cursor_not_initialized().into());
        }
        let unprocessed = (self.enabled_tokens.len()? as u64)
            .checked_sub(self.last_processed_enabled_token_count.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if unprocessed >= MAX_UNPROCESSED_TOKEN_ENABLEMENTS {
            return Err(ZonePortalError::token_enablement_block_capacity_exceeded(
                MAX_UNPROCESSED_TOKEN_ENABLEMENTS,
            )
            .into());
        }

        // _enableTokenInternal: bound the metadata copied into the zone before mutating state.
        let name = self.external_static_call(token, &ITIP20::nameCall {})?;
        let symbol = self.external_static_call(token, &ITIP20::symbolCall {})?;
        let currency = self.external_static_call(token, &ITIP20::currencyCall {})?;
        if [&name, &symbol, &currency]
            .into_iter()
            .any(|value| value.len() > MAX_TOKEN_METADATA_BYTES)
        {
            return Err(ZonePortalError::token_metadata_too_long().into());
        }

        let policy_id_call = ITIP403Registry::tokenTransferPolicyIdCall { token };
        let mut is_set = self
            .external_static_call(TIP403_REGISTRY_ADDRESS, &policy_id_call)?
            .isSet;
        if !is_set {
            self.external_call(
                TIP403_REGISTRY_ADDRESS,
                &ITIP403Registry::migrateTransferPolicyIdsCall {
                    tokens: vec![token],
                },
            )?;
            is_set = self
                .external_static_call(TIP403_REGISTRY_ADDRESS, &policy_id_call)?
                .isSet;
        }
        if !is_set {
            return Err(ZonePortalError::token_transfer_policy_not_set().into());
        }

        let preimage = (
            self.token_enablement_hash.read()?,
            token,
            name.clone(),
            symbol.clone(),
            currency.clone(),
        )
            .abi_encode_params();
        let token_enablement_hash = self.storage.keccak256(&preimage)?;
        self.token_enablement_hash.write(token_enablement_hash)?;
        self.token_configs[token].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })?;
        self.enabled_tokens.push(token)?;
        self.emit(ZonePortalEvent::token_enabled(
            token, name, symbol, currency,
        ))
    }

    /// Solidity `initialize`. The native factory initializes portals through
    /// `initialize_from_factory`, so only the guards are reachable here.
    pub fn initialize(&mut self, sender: Address, _call: ZonePortal::initializeCall) -> Result<()> {
        // `onlyDelegateCall` is moot: native dispatch only serves `ZONE_PORTAL_PREFIX` addresses.
        if sender != ZONE_FACTORY_ADDRESS {
            return Err(ZonePortalError::not_factory().into());
        }
        if self.initialized.read()? {
            return Err(ZonePortalError::already_initialized().into());
        }
        // Dispatch serves only initialized portals, and the native factory never calls this.
        Err(TempoPrecompileError::Fatal(
            "ZonePortal::initialize reached on an uninitialized portal".into(),
        ))
    }

    /// Solidity `pause`.
    pub fn pause(&mut self, sender: Address, _call: ZonePortal::pauseCall) -> Result<()> {
        self.when_not_paused()?;
        self.require_capability_active(ZonePortalCapability::PausePortal)?;
        if sender != self.admin.read()?
            && !matches!(
                self.role_of(sender)?,
                ZonePortalRole::Sequencer | ZonePortalRole::PauseGuardian
            )
        {
            return Err(ZonePortalError::not_pause_authority().into());
        }
        let pause_expiry = self
            .storage
            .timestamp()
            .wrapping_to::<u64>()
            .checked_add(PAUSE_DURATION)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.pause_expiry.write(pause_expiry)?;
        self.emit(ZonePortalEvent::portal_paused(sender))
    }

    /// Solidity `pauseDeposits`.
    pub fn pause_deposits(
        &mut self,
        sender: Address,
        call: ZonePortal::pauseDepositsCall,
    ) -> Result<()> {
        self.set_deposits_active(sender, call.token, false)?;
        self.emit(ZonePortalEvent::deposits_paused(call.token))
    }

    /// Solidity `resume`.
    pub fn resume(&mut self, sender: Address, _call: ZonePortal::resumeCall) -> Result<()> {
        self.only_admin(sender)?;
        self.pause_expiry.write(0)?;
        self.emit(ZonePortalEvent::portal_resumed(sender))
    }

    /// Solidity `resumeDeposits`.
    pub fn resume_deposits(
        &mut self,
        sender: Address,
        call: ZonePortal::resumeDepositsCall,
    ) -> Result<()> {
        self.set_deposits_active(sender, call.token, true)?;
        self.emit(ZonePortalEvent::deposits_resumed(call.token))
    }

    /// Solidity `setAccessMode`.
    pub fn set_access_mode(
        &mut self,
        sender: Address,
        call: ZonePortal::setAccessModeCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.require_capability_active(ZonePortalCapability::AccessPolicy)?;
        self.is_access_enforced.write(call.enforced)?;
        let gateway_enforced = self.is_gateway_enforced.read()?;
        self.emit(ZonePortalEvent::enforcement_modes_updated(
            call.enforced,
            gateway_enforced,
        ))
    }

    /// Solidity `setAllowedAccount`.
    pub fn set_allowed_account(
        &mut self,
        sender: Address,
        call: ZonePortal::setAllowedAccountCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.require_capability_active(ZonePortalCapability::AccessPolicy)?;
        if call.allowed {
            Self::require(call.account != self.messenger.read()?)?;
        }
        self.set_role(call.account, call.allowed, ZonePortalRole::Account)
    }

    /// Solidity `setBouncebackGas`.
    pub fn set_bounceback_gas(
        &mut self,
        sender: Address,
        call: ZonePortal::setBouncebackGasCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.bounceback_gas.write(call.newBouncebackGas)?;
        self.emit(ZonePortalEvent::bounceback_gas_updated(
            call.newBouncebackGas,
        ))
    }

    /// Solidity `setGateway`.
    pub fn set_gateway(&mut self, sender: Address, call: ZonePortal::setGatewayCall) -> Result<()> {
        self.only_admin(sender)?;
        self.require_capability_active(ZonePortalCapability::AccessPolicy)?;
        self.set_role(call.account, call.allowed, ZonePortalRole::CallbackGateway)
    }

    /// Solidity `setGatewayMode`.
    pub fn set_gateway_mode(
        &mut self,
        sender: Address,
        call: ZonePortal::setGatewayModeCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.require_capability_active(ZonePortalCapability::AccessPolicy)?;
        self.is_gateway_enforced.write(call.enforced)?;
        let access_enforced = self.is_access_enforced.read()?;
        self.emit(ZonePortalEvent::enforcement_modes_updated(
            access_enforced,
            call.enforced,
        ))
    }

    /// Solidity `setLeader` with `_setLeader`.
    pub fn set_leader(&mut self, sender: Address, call: ZonePortal::setLeaderCall) -> Result<()> {
        self.only_sequencer_or_admin(sender)?;
        if !self.is_sequencer_account(call.newLeader)? {
            return Err(ZonePortalError::invalid_leader().into());
        }
        let previous = self.leader.read()?;
        // Idempotent fanout: only the first relayed call transitions.
        if call.newLeader == previous {
            return Ok(());
        }
        let epoch = self.leader_epoch.read()?;
        if epoch != call.expectedEpoch {
            return Err(ZonePortalError::stale_leadership_epoch(call.expectedEpoch, epoch).into());
        }
        let activation_tempo_block = self.storage.block_number();
        if self.leader_activation_tempo_block.read()? == activation_tempo_block {
            return Err(ZonePortalError::leader_already_updated_this_block().into());
        }

        self.leader.write(call.newLeader)?;
        let epoch = epoch
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.leader_epoch.write(epoch)?;
        self.leader_activation_tempo_block
            .write(activation_tempo_block)?;
        self.emit(ZonePortalEvent::leader_updated(
            previous,
            call.newLeader,
            epoch,
            activation_tempo_block,
        ))
    }

    /// Solidity `setMaxTempoGasRate`.
    pub fn set_max_tempo_gas_rate(
        &mut self,
        sender: Address,
        call: ZonePortal::setMaxTempoGasRateCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        if call.newMaxTempoGasRate > MAX_GAS_FEE_RATE {
            return Err(ZonePortalError::gas_fee_rate_too_high().into());
        }
        self.max_tempo_gas_rate.write(call.newMaxTempoGasRate)?;
        self.emit(ZonePortalEvent::max_tempo_gas_rate_updated(
            call.newMaxTempoGasRate,
        ))
    }

    /// Solidity `setPauseGuardian`.
    pub fn set_pause_guardian(
        &mut self,
        sender: Address,
        call: ZonePortal::setPauseGuardianCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.require_capability_active(ZonePortalCapability::PausePortal)?;
        self.set_role(call.account, call.allowed, ZonePortalRole::PauseGuardian)
    }

    /// Solidity `setRpcUrl`.
    pub fn set_rpc_url(&mut self, sender: Address, call: ZonePortal::setRpcUrlCall) -> Result<()> {
        self.only_sequencer(sender)?;
        self.rpc_url.write(call.rpcUrl.clone())?;
        self.emit(ZonePortalEvent::rpc_url_updated(call.rpcUrl))
    }

    /// Solidity `setSequencerEncryptionKey`.
    pub fn set_sequencer_encryption_key(
        &mut self,
        sender: Address,
        call: ZonePortal::setSequencerEncryptionKeyCall,
    ) -> Result<()> {
        self.only_sequencer_or_admin(sender)?;
        if !matches!(call.yParity, 0x02 | 0x03) || !is_valid_x(call.x) {
            return Err(ZonePortalError::invalid_ephemeral_pubkey().into());
        }

        let message = self
            .storage
            .keccak256(&(self.address, call.x, U256::from(call.yParity)).abi_encode_params())?;
        let recovered = self.ecrecover(message, call.popV, call.popR, call.popS)?;
        let expected = derive_address(call.x, call.yParity)?;
        if recovered != Some(expected) {
            return Err(ZonePortalError::invalid_proof_of_possession().into());
        }

        let activation_block = self.storage.block_number();
        self.encryption_keys.push(PortalEncryptionKeyEntry {
            x: call.x,
            y_parity: call.yParity,
            activation_block,
        })?;
        let key_index = self.encryption_keys.len()? - 1;
        self.emit(ZonePortalEvent::sequencer_encryption_key_updated(
            call.x,
            call.yParity,
            expected,
            U256::from(key_index),
            activation_block,
        ))
    }

    /// Solidity `setSequencerSet` with `_replaceSequencerSet(newSequencers, newThreshold, true)`.
    pub fn set_sequencer_set(
        &mut self,
        sender: Address,
        call: ZonePortal::setSequencerSetCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        let new_sequencers = call.newSequencers;
        let new_threshold = call.newThreshold;
        let length = new_sequencers.len();
        if length == 0
            || length > MAX_SEQUENCERS
            || new_threshold == 0
            || usize::from(new_threshold) > length
        {
            return Err(ZonePortalError::invalid_sequencer_set().into());
        }

        for (index, &signer) in new_sequencers.iter().enumerate() {
            if signer.is_zero() {
                return Err(ZonePortalError::invalid_sequencer_set().into());
            }
            Self::require(matches!(
                self.role_of(signer)?,
                ZonePortalRole::None | ZonePortalRole::Sequencer
            ))?;
            if new_sequencers[..index].contains(&signer) {
                return Err(ZonePortalError::invalid_sequencer_set().into());
            }
        }

        let old_sequencers = self.sequencers.read()?;
        let mut members_unchanged = length == old_sequencers.len();
        if members_unchanged {
            for &signer in &new_sequencers {
                if !self.is_sequencer_account(signer)? {
                    members_unchanged = false;
                    break;
                }
            }
        }
        if members_unchanged && new_threshold == self.sequencer_threshold.read()? {
            return Err(ZonePortalError::sequencer_configuration_unchanged().into());
        }

        for signer in old_sequencers {
            self.role[signer].write(u8::from(ZonePortalRole::None))?;
            self.emit(ZonePortalEvent::role_updated(
                signer,
                ZonePortalRole::Sequencer,
                ZonePortalRole::None,
            ))?;
        }
        // Replacing the array clears the stale tail, matching `delete _sequencers` + `push`.
        self.sequencers.write(new_sequencers.clone())?;
        for &signer in &new_sequencers {
            self.role[signer].write(u8::from(ZonePortalRole::Sequencer))?;
            self.emit(ZonePortalEvent::role_updated(
                signer,
                ZonePortalRole::None,
                ZonePortalRole::Sequencer,
            ))?;
        }
        // Rotating out the active leader would strand block production.
        let leader = self.leader.read()?;
        if !leader.is_zero() && !self.is_sequencer_account(leader)? {
            return Err(ZonePortalError::active_leader_removed().into());
        }

        self.sequencer_threshold.write(new_threshold)?;
        let nonce = self
            .sequencer_set_version
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.sequencer_set_version.write(nonce)?;
        self.emit(ZonePortalEvent::sequencer_set_updated(
            nonce,
            new_threshold,
            new_sequencers,
        ))
    }

    /// Solidity `setZoneGasRate`.
    pub fn set_zone_gas_rate(
        &mut self,
        sender: Address,
        call: ZonePortal::setZoneGasRateCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        if call.newZoneGasRate > MAX_GAS_FEE_RATE {
            return Err(ZonePortalError::gas_fee_rate_too_high().into());
        }
        self.zone_gas_rate.write(call.newZoneGasRate)?;
        self.emit(ZonePortalEvent::zone_gas_rate_updated(call.newZoneGasRate))
    }

    /// Solidity `transferAdmin`.
    pub fn transfer_admin(
        &mut self,
        sender: Address,
        call: ZonePortal::transferAdminCall,
    ) -> Result<()> {
        self.only_admin(sender)?;
        self.pending_admin.write(call.newAdmin)?;
        // `onlyAdmin` established `sender == admin`.
        self.emit(ZonePortalEvent::admin_transfer_started(
            sender,
            call.newAdmin,
        ))
    }

    /// Solidity `onlySequencerOrAdmin`.
    fn only_sequencer_or_admin(&self, sender: Address) -> Result<()> {
        if sender != self.admin.read()? && !self.is_sequencer_account(sender)? {
            return Err(ZonePortalError::not_sequencer().into());
        }
        Ok(())
    }

    /// Solidity `_requireCapabilityActive`.
    fn require_capability_active(&self, capability: ZonePortalCapability) -> Result<()> {
        let effective_at = self.abdication_effective_at[u8::from(capability)].read()?;
        if effective_at != 0 && self.storage.timestamp() >= U256::from(effective_at) {
            return Err(ZonePortalError::capability_abdicated(capability).into());
        }
        Ok(())
    }

    /// Shared body of `setAllowedAccount`, `setGateway` and `setPauseGuardian`: toggles
    /// `account` between `Role.None` and `granted`, returning early when already configured.
    fn set_role(&mut self, account: Address, allowed: bool, granted: ZonePortalRole) -> Result<()> {
        let previous = self.role_of(account)?;
        let next = if allowed {
            granted
        } else {
            ZonePortalRole::None
        };
        if previous == next {
            return Ok(());
        }
        Self::require(
            previous
                == if allowed {
                    ZonePortalRole::None
                } else {
                    granted
                },
        )?;
        self.role[account].write(u8::from(next))?;
        self.emit(ZonePortalEvent::role_updated(account, previous, next))
    }

    /// Shared body of `pauseDeposits` and `resumeDeposits` before their events.
    fn set_deposits_active(&mut self, sender: Address, token: Address, active: bool) -> Result<()> {
        self.only_admin(sender)?;
        let mut config = self.token_configs[token].read()?;
        if !config.enabled {
            return Err(ZonePortalError::token_not_enabled().into());
        }
        config.deposits_active = active;
        self.token_configs[token].write(config)
    }

    /// Solidity `ecrecover` (precompile `0x01`): `v` must be 27 or 28 and, unlike
    /// [`StorageCtx::recover_signer`](crate::storage::StorageCtx::recover_signer), high-`s`
    /// signatures are accepted.
    fn ecrecover(&mut self, digest: B256, v: u8, r: B256, s: B256) -> Result<Option<Address>> {
        self.storage.deduct_gas(ECRECOVER_GAS)?;
        if v != 27 && v != 28 {
            return Ok(None);
        }
        let signature = Signature::from_scalars_and_parity(r, s, v == 28);
        Ok(recover_signer_unchecked(&signature, digest)
            .ok()
            .filter(|signer| !signer.is_zero()))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::secp256k1::SECP256K1_P, *};
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        zone_factory::ZoneFactory,
    };
    use alloy::primitives::{Bytes, IntoLogData, uint};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IZoneFactory, ZONE_MESSENGER_ADDRESS};

    const OWNER: Address = Address::with_last_byte(0x11);
    const ADMIN: Address = Address::with_last_byte(0x22);
    const SEQUENCER_A: Address = Address::with_last_byte(0x33);
    const SEQUENCER_B: Address = Address::with_last_byte(0x44);
    const ALLOWED_ACCOUNT: Address = Address::with_last_byte(0x55);
    const ZONE_GATEWAY: Address = Address::with_last_byte(0x66);
    const OUTSIDER: Address = Address::with_last_byte(0x77);
    const SEQUENCER_C: Address = Address::with_last_byte(0x88);
    const CREATION_BLOCK: u64 = 42;
    const START_TIME: u64 = 1_000;
    /// secp256k1 group order.
    const SECP256K1_N: U256 =
        uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);

    fn empty_revert() -> TempoPrecompileError {
        TempoPrecompileError::RawRevert(Bytes::new())
    }

    /// Runs `f` on a fresh portal created by the native factory at T15, then returns the
    /// provider for event assertions.
    fn with_portal(
        f: impl FnOnce(&mut ZonePortalStorage) -> eyre::Result<()>,
    ) -> eyre::Result<(HashMapStorageProvider, Address)> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_block_number(CREATION_BLOCK);
        storage.set_timestamp(U256::from(START_TIME));
        let portal = StorageCtx::enter(&mut storage, || -> eyre::Result<Address> {
            TIP20Setup::path_usd(ADMIN).apply()?;
            let mut factory = ZoneFactory::new();
            factory.next_zone_id.write(1)?;
            factory.owner.write(OWNER)?;
            let created = factory.create_zone(
                OWNER,
                IZoneFactory::createZoneCall {
                    params: IZoneFactory::CreateZoneParams {
                        initialToken: PATH_USD_ADDRESS,
                        accessMode: true,
                        gatewayMode: true,
                        allowedAccounts: vec![ALLOWED_ACCOUNT],
                        zoneGateways: vec![ZONE_GATEWAY],
                        admin: ADMIN,
                        sequencers: vec![SEQUENCER_A, SEQUENCER_B],
                        threshold: 2,
                        rpcUrl: "https://zone.example".to_string(),
                    },
                },
            )?;
            let mut portal = ZonePortalStorage::new(created.portal);
            f(&mut portal)?;
            Ok(created.portal)
        })?;
        Ok((storage, portal))
    }

    /// Events the portal emitted after the factory's creation events.
    fn events_after_creation(
        storage: &HashMapStorageProvider,
        portal: Address,
    ) -> Vec<alloy::primitives::LogData> {
        let events = storage.get_events(portal);
        // EnforcementModesUpdated, SequencerSetUpdated, LeaderUpdated, two RoleUpdated, TokenEnabled.
        events[6..].to_vec()
    }

    #[test]
    fn gas_rate_and_bounceback_setters() -> eyre::Result<()> {
        let (storage, portal) = with_portal(|portal| {
            let call = ZonePortal::setZoneGasRateCall { newZoneGasRate: 7 };
            assert_eq!(
                portal.set_zone_gas_rate(OUTSIDER, call.clone()),
                Err(ZonePortalError::not_admin().into())
            );
            assert_eq!(
                portal.set_zone_gas_rate(
                    ADMIN,
                    ZonePortal::setZoneGasRateCall {
                        newZoneGasRate: MAX_GAS_FEE_RATE + 1
                    }
                ),
                Err(ZonePortalError::gas_fee_rate_too_high().into())
            );
            portal.set_zone_gas_rate(ADMIN, call)?;
            assert_eq!(portal.zone_gas_rate.read()?, 7);

            assert_eq!(
                portal.set_max_tempo_gas_rate(
                    ADMIN,
                    ZonePortal::setMaxTempoGasRateCall {
                        newMaxTempoGasRate: MAX_GAS_FEE_RATE + 1
                    }
                ),
                Err(ZonePortalError::gas_fee_rate_too_high().into())
            );
            portal.set_max_tempo_gas_rate(
                ADMIN,
                ZonePortal::setMaxTempoGasRateCall {
                    newMaxTempoGasRate: MAX_GAS_FEE_RATE,
                },
            )?;
            assert_eq!(portal.max_tempo_gas_rate.read()?, MAX_GAS_FEE_RATE);

            portal.set_bounceback_gas(
                ADMIN,
                ZonePortal::setBouncebackGasCall {
                    newBouncebackGas: 9,
                },
            )?;
            assert_eq!(portal.bounceback_gas.read()?, 9);
            Ok(())
        })?;
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::zone_gas_rate_updated(7).into_log_data(),
                ZonePortalEvent::max_tempo_gas_rate_updated(MAX_GAS_FEE_RATE).into_log_data(),
                ZonePortalEvent::bounceback_gas_updated(9).into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn admin_transfer_is_two_step() -> eyre::Result<()> {
        let (storage, portal) = with_portal(|portal| {
            assert_eq!(
                portal.accept_admin(Address::ZERO, ZonePortal::acceptAdminCall {}),
                Err(ZonePortalError::not_pending_admin().into())
            );
            assert_eq!(
                portal.transfer_admin(
                    OUTSIDER,
                    ZonePortal::transferAdminCall { newAdmin: OUTSIDER }
                ),
                Err(ZonePortalError::not_admin().into())
            );
            portal.transfer_admin(ADMIN, ZonePortal::transferAdminCall { newAdmin: OUTSIDER })?;
            assert_eq!(
                portal.accept_admin(SEQUENCER_A, ZonePortal::acceptAdminCall {}),
                Err(ZonePortalError::not_pending_admin().into())
            );
            portal.accept_admin(OUTSIDER, ZonePortal::acceptAdminCall {})?;
            assert_eq!(portal.admin.read()?, OUTSIDER);
            assert_eq!(portal.pending_admin.read()?, Address::ZERO);
            Ok(())
        })?;
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::admin_transfer_started(ADMIN, OUTSIDER).into_log_data(),
                ZonePortalEvent::admin_transferred(ADMIN, OUTSIDER).into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn set_sequencer_set_validates_and_replaces() -> eyre::Result<()> {
        let set = |sequencers: Vec<Address>, threshold: u8| ZonePortal::setSequencerSetCall {
            newSequencers: sequencers,
            newThreshold: threshold,
        };
        let (storage, portal) = with_portal(|portal| {
            assert_eq!(
                portal.set_sequencer_set(SEQUENCER_A, set(vec![SEQUENCER_A], 1)),
                Err(ZonePortalError::not_admin().into())
            );
            for (sequencers, threshold) in [
                (vec![], 1),
                (vec![SEQUENCER_A], 0),
                (vec![SEQUENCER_A], 2),
                (vec![SEQUENCER_A, Address::ZERO], 1),
                (vec![SEQUENCER_A, SEQUENCER_A], 1),
                ((1u8..=9).map(Address::with_last_byte).collect(), 1),
            ] {
                assert_eq!(
                    portal.set_sequencer_set(ADMIN, set(sequencers, threshold)),
                    Err(ZonePortalError::invalid_sequencer_set().into())
                );
            }
            assert_eq!(
                portal.set_sequencer_set(ADMIN, set(vec![SEQUENCER_A, ALLOWED_ACCOUNT], 1)),
                Err(empty_revert())
            );
            assert_eq!(
                portal.set_sequencer_set(ADMIN, set(vec![SEQUENCER_B, SEQUENCER_A], 2)),
                Err(ZonePortalError::sequencer_configuration_unchanged().into())
            );

            portal.set_sequencer_set(ADMIN, set(vec![SEQUENCER_A, SEQUENCER_C], 1))?;
            assert_eq!(portal.sequencers.read()?, vec![SEQUENCER_A, SEQUENCER_C]);
            assert_eq!(portal.sequencer_threshold.read()?, 1);
            assert_eq!(portal.sequencer_set_version.read()?, 1);
            assert_eq!(portal.role_of(SEQUENCER_B)?, ZonePortalRole::None);
            assert!(portal.is_sequencer_account(SEQUENCER_C)?);

            // Same members with a new threshold is a change.
            portal.set_sequencer_set(ADMIN, set(vec![SEQUENCER_C, SEQUENCER_A], 2))?;
            assert_eq!(portal.sequencers.read()?, vec![SEQUENCER_C, SEQUENCER_A]);
            assert_eq!(portal.sequencer_set_version.read()?, 2);

            // Last: the leader check runs after the role writes, which only the EVM frame rolls back.
            assert_eq!(
                portal.set_sequencer_set(ADMIN, set(vec![SEQUENCER_C], 1)),
                Err(ZonePortalError::active_leader_removed().into())
            );
            Ok(())
        })?;
        let events = events_after_creation(&storage, portal);
        let role = |account, prev, next| {
            ZonePortalEvent::role_updated(account, prev, next).into_log_data()
        };
        assert_eq!(
            events[..5],
            [
                role(SEQUENCER_A, ZonePortalRole::Sequencer, ZonePortalRole::None),
                role(SEQUENCER_B, ZonePortalRole::Sequencer, ZonePortalRole::None),
                role(SEQUENCER_A, ZonePortalRole::None, ZonePortalRole::Sequencer),
                role(SEQUENCER_C, ZonePortalRole::None, ZonePortalRole::Sequencer),
                ZonePortalEvent::sequencer_set_updated(1, 1, vec![SEQUENCER_A, SEQUENCER_C])
                    .into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn set_leader_fences_epoch_and_block() -> eyre::Result<()> {
        let set_leader = |leader, epoch| ZonePortal::setLeaderCall {
            newLeader: leader,
            expectedEpoch: epoch,
        };
        let (storage, portal) = with_portal(|portal| {
            assert_eq!(
                portal.set_leader(OUTSIDER, set_leader(SEQUENCER_B, 1)),
                Err(ZonePortalError::not_sequencer().into())
            );
            assert_eq!(
                portal.set_leader(ADMIN, set_leader(OUTSIDER, 1)),
                Err(ZonePortalError::invalid_leader().into())
            );
            // The current leader is a no-op, whatever the epoch.
            portal.set_leader(SEQUENCER_B, set_leader(SEQUENCER_A, 9))?;
            assert_eq!(
                portal.set_leader(SEQUENCER_B, set_leader(SEQUENCER_B, 0)),
                Err(ZonePortalError::stale_leadership_epoch(0, 1).into())
            );
            assert_eq!(
                portal.set_leader(SEQUENCER_B, set_leader(SEQUENCER_B, 1)),
                Err(ZonePortalError::leader_already_updated_this_block().into())
            );
            StorageCtx.set_block_number(CREATION_BLOCK + 1);
            portal.set_leader(ADMIN, set_leader(SEQUENCER_B, 1))?;
            assert_eq!(portal.leader.read()?, SEQUENCER_B);
            assert_eq!(portal.leader_epoch.read()?, 2);
            assert_eq!(
                portal.leader_activation_tempo_block.read()?,
                CREATION_BLOCK + 1
            );
            Ok(())
        })?;
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::leader_updated(SEQUENCER_A, SEQUENCER_B, 2, CREATION_BLOCK + 1)
                    .into_log_data()
            ]
        );
        Ok(())
    }

    #[test]
    fn role_setters_toggle_only_from_none() -> eyre::Result<()> {
        let (storage, portal) = with_portal(|portal| {
            let allow = |account, allowed| ZonePortal::setAllowedAccountCall { account, allowed };
            assert_eq!(
                portal.set_allowed_account(OUTSIDER, allow(OUTSIDER, true)),
                Err(ZonePortalError::not_admin().into())
            );
            assert_eq!(
                portal.set_allowed_account(ADMIN, allow(ZONE_MESSENGER_ADDRESS, true)),
                Err(empty_revert())
            );
            assert_eq!(
                portal.set_allowed_account(ADMIN, allow(ZONE_GATEWAY, true)),
                Err(empty_revert())
            );
            assert_eq!(
                portal.set_allowed_account(ADMIN, allow(ZONE_GATEWAY, false)),
                Err(empty_revert())
            );
            // Already configured: no write, no event.
            portal.set_allowed_account(ADMIN, allow(ALLOWED_ACCOUNT, true))?;
            portal.set_allowed_account(ADMIN, allow(OUTSIDER, true))?;
            assert_eq!(portal.role_of(OUTSIDER)?, ZonePortalRole::Account);

            portal.set_gateway(
                ADMIN,
                ZonePortal::setGatewayCall {
                    account: ZONE_GATEWAY,
                    allowed: false,
                },
            )?;
            assert_eq!(portal.role_of(ZONE_GATEWAY)?, ZonePortalRole::None);
            assert_eq!(
                portal.set_pause_guardian(
                    ADMIN,
                    ZonePortal::setPauseGuardianCall {
                        account: SEQUENCER_A,
                        allowed: true
                    }
                ),
                Err(empty_revert())
            );
            portal.set_pause_guardian(
                ADMIN,
                ZonePortal::setPauseGuardianCall {
                    account: ZONE_GATEWAY,
                    allowed: true,
                },
            )?;
            assert_eq!(portal.role_of(ZONE_GATEWAY)?, ZonePortalRole::PauseGuardian);
            Ok(())
        })?;
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::role_updated(
                    OUTSIDER,
                    ZonePortalRole::None,
                    ZonePortalRole::Account
                )
                .into_log_data(),
                ZonePortalEvent::role_updated(
                    ZONE_GATEWAY,
                    ZonePortalRole::CallbackGateway,
                    ZonePortalRole::None
                )
                .into_log_data(),
                ZonePortalEvent::role_updated(
                    ZONE_GATEWAY,
                    ZonePortalRole::None,
                    ZonePortalRole::PauseGuardian
                )
                .into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn pause_resume_and_abdication() -> eyre::Result<()> {
        let (storage, portal) = with_portal(|portal| {
            let guardian = ZonePortal::setPauseGuardianCall {
                account: OUTSIDER,
                allowed: true,
            };
            assert_eq!(
                portal.pause(OUTSIDER, ZonePortal::pauseCall {}),
                Err(ZonePortalError::not_pause_authority().into())
            );
            portal.set_pause_guardian(ADMIN, guardian)?;
            portal.pause(OUTSIDER, ZonePortal::pauseCall {})?;
            assert_eq!(portal.pause_expiry.read()?, START_TIME + PAUSE_DURATION);
            assert_eq!(
                portal.pause(SEQUENCER_A, ZonePortal::pauseCall {}),
                Err(ZonePortalError::portal_is_paused().into())
            );
            let abdicate = |capability| ZonePortal::abdicateCall { capability };
            assert_eq!(
                portal.abdicate(ADMIN, abdicate(ZonePortalCapability::AccessPolicy)),
                Err(ZonePortalError::portal_is_paused().into())
            );
            assert_eq!(
                portal.resume(SEQUENCER_A, ZonePortal::resumeCall {}),
                Err(ZonePortalError::not_admin().into())
            );
            portal.resume(ADMIN, ZonePortal::resumeCall {})?;
            assert_eq!(portal.pause_expiry.read()?, 0);

            portal.abdicate(ADMIN, abdicate(ZonePortalCapability::AccessPolicy))?;
            assert_eq!(
                portal.abdicate(ADMIN, abdicate(ZonePortalCapability::AccessPolicy)),
                Err(ZonePortalError::abdication_already_scheduled(
                    ZonePortalCapability::AccessPolicy
                )
                .into())
            );
            // Still active until the delay elapses.
            StorageCtx.set_timestamp(U256::from(START_TIME + ABDICATION_DELAY - 1));
            portal.set_access_mode(ADMIN, ZonePortal::setAccessModeCall { enforced: false })?;
            StorageCtx.set_timestamp(U256::from(START_TIME + ABDICATION_DELAY));
            let abdicated = Err(ZonePortalError::capability_abdicated(
                ZonePortalCapability::AccessPolicy,
            )
            .into());
            assert_eq!(
                portal.set_access_mode(ADMIN, ZonePortal::setAccessModeCall { enforced: true }),
                abdicated
            );
            assert_eq!(
                portal.set_gateway_mode(ADMIN, ZonePortal::setGatewayModeCall { enforced: false }),
                abdicated
            );
            assert_eq!(
                portal.set_gateway(
                    ADMIN,
                    ZonePortal::setGatewayCall {
                        account: OUTSIDER,
                        allowed: false
                    }
                ),
                abdicated
            );
            // The pause capability is independent.
            portal.pause(SEQUENCER_A, ZonePortal::pauseCall {})?;
            Ok(())
        })?;
        let events = events_after_creation(&storage, portal);
        assert_eq!(
            events[1..5],
            [
                ZonePortalEvent::portal_paused(OUTSIDER).into_log_data(),
                ZonePortalEvent::portal_resumed(ADMIN).into_log_data(),
                ZonePortalEvent::abdication_scheduled(
                    ZonePortalCapability::AccessPolicy,
                    START_TIME + ABDICATION_DELAY
                )
                .into_log_data(),
                ZonePortalEvent::enforcement_modes_updated(false, true).into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn token_deposit_toggles_and_enable_guards() -> eyre::Result<()> {
        let (storage, portal) = with_portal(|portal| {
            assert_eq!(
                portal.pause_deposits(ADMIN, ZonePortal::pauseDepositsCall { token: OUTSIDER }),
                Err(ZonePortalError::token_not_enabled().into())
            );
            assert_eq!(
                portal.pause_deposits(
                    SEQUENCER_A,
                    ZonePortal::pauseDepositsCall {
                        token: PATH_USD_ADDRESS
                    }
                ),
                Err(ZonePortalError::not_admin().into())
            );
            portal.pause_deposits(
                ADMIN,
                ZonePortal::pauseDepositsCall {
                    token: PATH_USD_ADDRESS,
                },
            )?;
            assert_eq!(
                portal.token_configs[PATH_USD_ADDRESS].read()?,
                PortalTokenConfig {
                    enabled: true,
                    deposits_active: false
                }
            );
            portal.resume_deposits(
                ADMIN,
                ZonePortal::resumeDepositsCall {
                    token: PATH_USD_ADDRESS,
                },
            )?;
            assert!(
                portal.token_configs[PATH_USD_ADDRESS]
                    .read()?
                    .deposits_active
            );

            assert_eq!(
                portal.enable_token(
                    OUTSIDER,
                    ZonePortal::enableTokenCall {
                        token: PATH_USD_ADDRESS
                    }
                ),
                Err(ZonePortalError::not_admin().into())
            );
            assert_eq!(
                portal.enable_token(
                    ADMIN,
                    ZonePortal::enableTokenCall {
                        token: PATH_USD_ADDRESS
                    }
                ),
                Err(ZonePortalError::token_already_enabled().into())
            );
            Ok(())
        })?;
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::deposits_paused(PATH_USD_ADDRESS).into_log_data(),
                ZonePortalEvent::deposits_resumed(PATH_USD_ADDRESS).into_log_data(),
            ]
        );
        Ok(())
    }

    #[test]
    fn rpc_url_and_initialize_guards() -> eyre::Result<()> {
        with_portal(|portal| {
            let url = ZonePortal::setRpcUrlCall {
                rpcUrl: "https://new.example".to_string(),
            };
            assert_eq!(
                portal.set_rpc_url(ADMIN, url.clone()),
                Err(ZonePortalError::not_sequencer().into())
            );
            portal.set_rpc_url(SEQUENCER_B, url)?;
            assert_eq!(portal.rpc_url.read()?, "https://new.example");

            let init = ZonePortal::initializeCall {
                zoneId: 1,
                initialToken: PATH_USD_ADDRESS,
                accessMode: false,
                gatewayMode: false,
                allowedAccounts: vec![],
                zoneGateways: vec![],
                admin: ADMIN,
                messenger: ZONE_MESSENGER_ADDRESS,
                sequencers: vec![SEQUENCER_A],
                threshold: 1,
                verifier: Address::ZERO,
                rpcUrl: String::new(),
            };
            assert_eq!(
                portal.initialize(ADMIN, init.clone()),
                Err(ZonePortalError::not_factory().into())
            );
            assert_eq!(
                portal.initialize(ZONE_FACTORY_ADDRESS, init),
                Err(ZonePortalError::already_initialized().into())
            );
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn set_sequencer_encryption_key_checks_proof_of_possession() -> eyre::Result<()> {
        let signer = PrivateKeySigner::random();
        let compressed = signer.credential().verifying_key().to_encoded_point(true);
        let y_parity = compressed.as_bytes()[0];
        let x = B256::from_slice(&compressed.as_bytes()[1..]);

        let mut key_calls = Vec::new();
        let (storage, portal) = with_portal(|portal| {
            let message = alloy::primitives::keccak256(
                (portal.address, x, U256::from(y_parity)).abi_encode_params(),
            );
            let signature = signer.sign_hash_sync(&message)?;
            let call = |x, y_parity, v: u8, s: U256| ZonePortal::setSequencerEncryptionKeyCall {
                x,
                yParity: y_parity,
                popV: v,
                popR: signature.r().into(),
                popS: s.into(),
            };
            let v = 27 + u8::from(signature.v());
            let valid = call(x, y_parity, v, signature.s());

            assert_eq!(
                portal.set_sequencer_encryption_key(OUTSIDER, valid.clone()),
                Err(ZonePortalError::not_sequencer().into())
            );
            for invalid in [
                call(x, 0x04, v, signature.s()),
                call(B256::ZERO, y_parity, v, signature.s()),
                call(SECP256K1_P.into(), y_parity, v, signature.s()),
            ] {
                assert_eq!(
                    portal.set_sequencer_encryption_key(ADMIN, invalid),
                    Err(ZonePortalError::invalid_ephemeral_pubkey().into())
                );
            }
            for invalid in [
                // Wrong parity prefix derives the negated point's address.
                call(x, y_parity ^ 1, v, signature.s()),
                // ecrecover accepts only 27 or 28.
                call(x, y_parity, v - 27, signature.s()),
                call(x, y_parity, 55 - v, signature.s()),
            ] {
                assert_eq!(
                    portal.set_sequencer_encryption_key(ADMIN, invalid),
                    Err(ZonePortalError::invalid_proof_of_possession().into())
                );
            }

            portal.set_sequencer_encryption_key(SEQUENCER_A, valid)?;
            // Like the ecrecover precompile, a high-s signature also recovers.
            StorageCtx.set_block_number(CREATION_BLOCK + 1);
            portal.set_sequencer_encryption_key(
                ADMIN,
                call(x, y_parity, 55 - v, SECP256K1_N - signature.s()),
            )?;
            assert_eq!(portal.encryption_keys.len()?, 2);
            key_calls.push(portal.encryption_keys[1].read()?.activation_block);
            Ok(())
        })?;
        assert_eq!(key_calls, vec![CREATION_BLOCK + 1]);
        assert_eq!(
            events_after_creation(&storage, portal),
            vec![
                ZonePortalEvent::sequencer_encryption_key_updated(
                    x,
                    y_parity,
                    signer.address(),
                    U256::ZERO,
                    CREATION_BLOCK
                )
                .into_log_data(),
                ZonePortalEvent::sequencer_encryption_key_updated(
                    x,
                    y_parity,
                    signer.address(),
                    U256::ONE,
                    CREATION_BLOCK + 1
                )
                .into_log_data(),
            ]
        );
        Ok(())
    }
}
