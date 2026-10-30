//! Read-only getters, constants and derived views.

use super::{
    ABDICATION_DELAY, FIXED_DEPOSIT_GAS, MAX_GAS_FEE_RATE, MAX_UNPROCESSED_DEPOSITS,
    MAX_UNPROCESSED_TOKEN_ENABLEMENTS, PAUSE_DURATION, ZonePortalConstants, ZonePortalStorage,
};
use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, NestedCall},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256, address, uint},
    sol_types::{Revert, SolError},
};
use tempo_contracts::{
    precompiles::{MAX_SEQUENCERS, ZonePortalError},
    zones::{MAX_TOKEN_METADATA_BYTES, MAX_WITHDRAWAL_GAS_LIMIT, ZonePortal},
};

/// `ENCRYPTION_KEY_GRACE_PERIOD` from `IZone.sol`: blocks a superseded key stays valid.
const ENCRYPTION_KEY_GRACE_PERIOD: u64 = 86_400;

/// The MODEXP precompile `Secp256k1Lib` calls.
const MODEXP_ADDRESS: Address = address!("0x0000000000000000000000000000000000000005");

/// `Secp256k1Lib.SECP256K1_P`.
const SECP256K1_P: U256 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_U256);

/// `Secp256k1Lib.SECP256K1_SQRT_EXP`: `(p + 1) / 4`.
const SECP256K1_SQRT_EXP: U256 =
    uint!(0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C_U256);

impl ZonePortalStorage {
    /// Solidity `ABDICATION_DELAY`.
    pub fn abdication_delay(
        &self,
        _call: ZonePortalConstants::ABDICATION_DELAYCall,
    ) -> Result<u64> {
        Ok(ABDICATION_DELAY)
    }

    /// Solidity `FIXED_DEPOSIT_GAS`.
    pub fn fixed_deposit_gas(&self, _call: ZonePortal::FIXED_DEPOSIT_GASCall) -> Result<u64> {
        Ok(FIXED_DEPOSIT_GAS)
    }

    /// Solidity `MAX_GAS_FEE_RATE`.
    pub fn max_gas_fee_rate(&self, _call: ZonePortal::MAX_GAS_FEE_RATECall) -> Result<u128> {
        Ok(MAX_GAS_FEE_RATE)
    }

    /// Solidity `MAX_SEQUENCERS`.
    pub fn max_sequencers(&self, _call: ZonePortalConstants::MAX_SEQUENCERSCall) -> Result<U256> {
        Ok(U256::from(MAX_SEQUENCERS))
    }

    /// Solidity `MAX_TOKEN_METADATA_BYTES`.
    pub fn max_token_metadata_bytes(
        &self,
        _call: ZonePortal::MAX_TOKEN_METADATA_BYTESCall,
    ) -> Result<U256> {
        Ok(U256::from(MAX_TOKEN_METADATA_BYTES))
    }

    /// Solidity `MAX_UNPROCESSED_DEPOSITS`.
    pub fn max_unprocessed_deposits(
        &self,
        _call: ZonePortal::MAX_UNPROCESSED_DEPOSITSCall,
    ) -> Result<u64> {
        Ok(MAX_UNPROCESSED_DEPOSITS)
    }

    /// Solidity `MAX_UNPROCESSED_TOKEN_ENABLEMENTS`.
    pub fn max_unprocessed_token_enablements(
        &self,
        _call: ZonePortal::MAX_UNPROCESSED_TOKEN_ENABLEMENTSCall,
    ) -> Result<u64> {
        Ok(MAX_UNPROCESSED_TOKEN_ENABLEMENTS)
    }

    /// Solidity `MAX_WITHDRAWAL_GAS_LIMIT`.
    pub fn max_withdrawal_gas_limit(
        &self,
        _call: ZonePortal::MAX_WITHDRAWAL_GAS_LIMITCall,
    ) -> Result<u64> {
        Ok(MAX_WITHDRAWAL_GAS_LIMIT)
    }

    /// Solidity `PAUSE_DURATION`.
    pub fn pause_duration(&self, _call: ZonePortalConstants::PAUSE_DURATIONCall) -> Result<u64> {
        Ok(PAUSE_DURATION)
    }

    /// Solidity `abdicationEffectiveAt`.
    pub fn abdication_effective_at(
        &self,
        call: ZonePortal::abdicationEffectiveAtCall,
    ) -> Result<u64> {
        self.abdication_effective_at_slot(call.capability).read()
    }

    /// Solidity `admin`.
    pub fn admin(&self, _call: ZonePortal::adminCall) -> Result<Address> {
        self.admin.read()
    }

    /// Solidity `areDepositsActive`.
    pub fn are_deposits_active(&self, call: ZonePortal::areDepositsActiveCall) -> Result<bool> {
        if self.is_paused()? {
            return Ok(false);
        }
        let config = self.token_configs[call.token].read()?;
        Ok(config.enabled && config.deposits_active)
    }

    /// Solidity `blockHash`.
    pub fn block_hash(&self, _call: ZonePortal::blockHashCall) -> Result<B256> {
        self.block_hash.read()
    }

    /// Solidity `bouncebackGas`.
    pub fn bounceback_gas(&self, _call: ZonePortal::bouncebackGasCall) -> Result<u64> {
        self.bounceback_gas.read()
    }

    /// Solidity `currentDepositQueueHash`.
    pub fn current_deposit_queue_hash(
        &self,
        _call: ZonePortal::currentDepositQueueHashCall,
    ) -> Result<B256> {
        self.current_deposit_queue_hash.read()
    }

    /// Solidity `depositCount`.
    pub fn deposit_count(&self, _call: ZonePortal::depositCountCall) -> Result<u64> {
        self.deposit_count.read()
    }

    /// Solidity `enabledTokenAt`: panics with array out-of-bounds past the end.
    pub fn enabled_token_at(&self, call: ZonePortal::enabledTokenAtCall) -> Result<Address> {
        let index = usize::try_from(call.index).map_err(|_| TempoPrecompileError::array_oob())?;
        self.enabled_tokens
            .at(index)?
            .ok_or_else(TempoPrecompileError::array_oob)?
            .read()
    }

    /// Solidity `enabledTokenCount`.
    pub fn enabled_token_count(&self, _call: ZonePortal::enabledTokenCountCall) -> Result<U256> {
        Ok(U256::from(self.enabled_tokens.len()?))
    }

    /// Solidity `encryptionKeyAt`.
    pub fn encryption_key_at(
        &self,
        call: ZonePortal::encryptionKeyAtCall,
    ) -> Result<ZonePortal::EncryptionKeyEntry> {
        let len = self.encryption_keys.len()?;
        let Some(index) = usize::try_from(call.index)
            .ok()
            .filter(|index| *index < len)
        else {
            return Err(ZonePortalError::invalid_encryption_key_index(call.index).into());
        };
        let entry = self.encryption_keys[index].read()?;
        Ok(ZonePortal::EncryptionKeyEntry {
            x: entry.x,
            yParity: entry.y_parity,
            activationBlock: entry.activation_block,
        })
    }

    /// Solidity `encryptionKeyAtBlock`: binary search for the last key activated at or before
    /// `tempoBlockNumber`.
    pub fn encryption_key_at_block(
        &self,
        call: ZonePortal::encryptionKeyAtBlockCall,
    ) -> Result<ZonePortal::encryptionKeyAtBlockReturn> {
        let block = call.tempoBlockNumber;
        let len = self.encryption_keys.len()?;
        if len == 0 || block < self.encryption_keys[0].activation_block.read()? {
            return Err(ZonePortalError::no_encryption_key_at_block(block).into());
        }

        let (mut low, mut high) = (0, len - 1);
        while low < high {
            let mid = (low + high).div_ceil(2);
            if self.encryption_keys[mid].activation_block.read()? <= block {
                low = mid;
            } else {
                high = mid - 1;
            }
        }

        let entry = &self.encryption_keys[low];
        Ok(ZonePortal::encryptionKeyAtBlockReturn {
            x: entry.x.read()?,
            yParity: entry.y_parity.read()?,
            keyIndex: U256::from(low),
        })
    }

    /// Solidity `encryptionKeyCount`.
    pub fn encryption_key_count(&self, _call: ZonePortal::encryptionKeyCountCall) -> Result<U256> {
        Ok(U256::from(self.encryption_keys.len()?))
    }

    /// Solidity `hasRole`.
    pub fn has_role(&self, call: ZonePortal::hasRoleCall) -> Result<bool> {
        self.has_role_of(call.account, call.role)
    }

    /// Solidity `isAccessEnforced`.
    pub fn is_access_enforced(&self, _call: ZonePortal::isAccessEnforcedCall) -> Result<bool> {
        self.is_access_enforced.read()
    }

    /// Solidity `isEncryptionKeyValid`: whether a key may still be used for new deposits, and
    /// the block it expires at (0 for the current key or an unknown index).
    pub fn is_encryption_key_valid(
        &self,
        call: ZonePortal::isEncryptionKeyValidCall,
    ) -> Result<ZonePortal::isEncryptionKeyValidReturn> {
        let len = self.encryption_keys.len()?;
        let Some(index) = usize::try_from(call.keyIndex)
            .ok()
            .filter(|index| *index < len)
        else {
            return Ok(ZonePortal::isEncryptionKeyValidReturn {
                valid: false,
                expiresAtBlock: 0,
            });
        };

        if index == len - 1 {
            return Ok(ZonePortal::isEncryptionKeyValidReturn {
                valid: true,
                expiresAtBlock: 0,
            });
        }

        let expiration = self.encryption_keys[index + 1]
            .activation_block
            .read()?
            .checked_add(ENCRYPTION_KEY_GRACE_PERIOD)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        Ok(ZonePortal::isEncryptionKeyValidReturn {
            valid: self.storage.block_number() < expiration,
            expiresAtBlock: expiration,
        })
    }

    /// Solidity `isGatewayOpen`.
    pub fn is_gateway_open(&self, _call: ZonePortal::isGatewayOpenCall) -> Result<bool> {
        Ok(!self.is_gateway_enforced.read()?)
    }

    /// Solidity `isSequencer`.
    pub fn is_sequencer(&self, call: ZonePortal::isSequencerCall) -> Result<bool> {
        self.is_sequencer_account(call.account)
    }

    /// Solidity `isTokenEnabled`.
    pub fn is_token_enabled(&self, call: ZonePortal::isTokenEnabledCall) -> Result<bool> {
        Ok(self.token_configs[call.token].read()?.enabled)
    }

    /// Solidity `lastProcessedDepositNumber`.
    pub fn last_processed_deposit_number(
        &self,
        _call: ZonePortal::lastProcessedDepositNumberCall,
    ) -> Result<u64> {
        self.last_processed_deposit_number.read()
    }

    /// Solidity `lastProcessedEnabledTokenCount`.
    pub fn last_processed_enabled_token_count(
        &self,
        _call: ZonePortal::lastProcessedEnabledTokenCountCall,
    ) -> Result<u64> {
        self.last_processed_enabled_token_count.read()
    }

    /// Solidity `lastSyncedTempoBlockNumber`.
    pub fn last_synced_tempo_block_number(
        &self,
        _call: ZonePortal::lastSyncedTempoBlockNumberCall,
    ) -> Result<u64> {
        self.last_synced_tempo_block_number.read()
    }

    /// Solidity `leader`.
    pub fn leader(&self, _call: ZonePortal::leaderCall) -> Result<Address> {
        self.leader.read()
    }

    /// Solidity `leaderActivationTempoBlock`.
    pub fn leader_activation_tempo_block(
        &self,
        _call: ZonePortal::leaderActivationTempoBlockCall,
    ) -> Result<u64> {
        self.leader_activation_tempo_block.read()
    }

    /// Solidity `leaderEpoch`.
    pub fn leader_epoch(&self, _call: ZonePortal::leaderEpochCall) -> Result<u64> {
        self.leader_epoch.read()
    }

    /// Solidity `maxTempoGasRate`.
    pub fn max_tempo_gas_rate(&self, _call: ZonePortal::maxTempoGasRateCall) -> Result<u128> {
        self.max_tempo_gas_rate.read()
    }

    /// Solidity `messenger`.
    pub fn messenger(&self, _call: ZonePortal::messengerCall) -> Result<Address> {
        self.messenger.read()
    }

    /// Solidity `pauseExpiry`.
    pub fn pause_expiry(&self, _call: ZonePortal::pauseExpiryCall) -> Result<u64> {
        self.pause_expiry.read()
    }

    /// Solidity `paused`.
    pub fn paused(&self, _call: ZonePortal::pausedCall) -> Result<bool> {
        self.is_paused()
    }

    /// Solidity `pendingAdmin`.
    pub fn pending_admin(&self, _call: ZonePortal::pendingAdminCall) -> Result<Address> {
        self.pending_admin.read()
    }

    /// Solidity `refunds`.
    pub fn refunds(&self, call: ZonePortal::refundsCall) -> Result<u128> {
        self.refunds[call.token][call.owner].read()
    }

    /// Solidity `rpcUrl`.
    pub fn rpc_url(&self, _call: ZonePortal::rpcUrlCall) -> Result<String> {
        self.rpc_url.read()
    }

    /// Solidity `sequencerAt`: panics with array out-of-bounds past the end.
    pub fn sequencer_at(&self, call: ZonePortal::sequencerAtCall) -> Result<Address> {
        let index = usize::try_from(call.index).map_err(|_| TempoPrecompileError::array_oob())?;
        self.sequencers
            .at(index)?
            .ok_or_else(TempoPrecompileError::array_oob)?
            .read()
    }

    /// Solidity `sequencerCount`.
    pub fn sequencer_count(&self, _call: ZonePortal::sequencerCountCall) -> Result<U256> {
        Ok(U256::from(self.sequencers.len()?))
    }

    /// Solidity `sequencerEncryptionKey`.
    pub fn sequencer_encryption_key(
        &self,
        _call: ZonePortal::sequencerEncryptionKeyCall,
    ) -> Result<ZonePortal::sequencerEncryptionKeyReturn> {
        let len = self.encryption_keys.len()?;
        if len == 0 {
            return Err(ZonePortalError::no_encryption_key_set().into());
        }
        let current = &self.encryption_keys[len - 1];
        let (x, y_parity) = (current.x.read()?, current.y_parity.read()?);
        Ok(ZonePortal::sequencerEncryptionKeyReturn {
            x,
            yParity: y_parity,
            pubkey: self.derive_encryption_key_address(x, y_parity)?,
        })
    }

    /// Solidity `sequencerSetVersion`.
    pub fn sequencer_set_version(&self, _call: ZonePortal::sequencerSetVersionCall) -> Result<u64> {
        self.sequencer_set_version.read()
    }

    /// Solidity `sequencerThreshold`.
    pub fn sequencer_threshold(&self, _call: ZonePortal::sequencerThresholdCall) -> Result<u8> {
        self.sequencer_threshold.read()
    }

    /// Solidity `tokenConfig`.
    pub fn token_config(
        &self,
        call: ZonePortal::tokenConfigCall,
    ) -> Result<ZonePortal::TokenConfig> {
        let config = self.token_configs[call.token].read()?;
        Ok(ZonePortal::TokenConfig {
            enabled: config.enabled,
            depositsActive: config.deposits_active,
        })
    }

    /// Solidity `tokenEnablementCursorInitialized`.
    pub fn token_enablement_cursor_initialized(
        &self,
        _call: ZonePortal::tokenEnablementCursorInitializedCall,
    ) -> Result<bool> {
        self.token_enablement_cursor_initialized.read()
    }

    /// Solidity `tokenEnablementHash`.
    pub fn token_enablement_hash(
        &self,
        _call: ZonePortal::tokenEnablementHashCall,
    ) -> Result<B256> {
        self.token_enablement_hash.read()
    }

    /// Solidity `verifier`.
    pub fn verifier(&self, _call: ZonePortal::verifierCall) -> Result<Address> {
        self.verifier.read()
    }

    /// Solidity `withdrawalBatchIndex`.
    pub fn withdrawal_batch_index(
        &self,
        _call: ZonePortal::withdrawalBatchIndexCall,
    ) -> Result<u64> {
        self.withdrawal_batch_index.read()
    }

    /// Solidity `zoneGasRate`.
    pub fn zone_gas_rate(&self, _call: ZonePortal::zoneGasRateCall) -> Result<u128> {
        self.zone_gas_rate.read()
    }

    /// Solidity `zoneHeight`.
    pub fn zone_height(&self, _call: ZonePortal::zoneHeightCall) -> Result<U256> {
        self.zone_height.read()
    }

    /// Solidity `zoneId`.
    pub fn zone_id(&self, _call: ZonePortal::zoneIdCall) -> Result<u32> {
        self.zone_id.read()
    }

    /// `Secp256k1Lib.deriveAddress`: recovers `y` with a static call to MODEXP, then hashes
    /// the uncompressed key into an address.
    fn derive_encryption_key_address(&self, x: B256, y_parity: u8) -> Result<Address> {
        let px = U256::from_be_bytes(x.0);
        let rhs = px
            .mul_mod(px, SECP256K1_P)
            .mul_mod(px, SECP256K1_P)
            .add_mod(U256::from(7), SECP256K1_P);
        let word_len = U256::from(32);
        let input = [
            word_len,
            word_len,
            word_len,
            rhs,
            SECP256K1_SQRT_EXP,
            SECP256K1_P,
        ]
        .iter()
        .flat_map(|word| word.to_be_bytes::<32>())
        .collect::<Bytes>();
        let result = super::storage().call(NestedCall {
            target: MODEXP_ADDRESS,
            input,
            gas_limit: u64::MAX,
            is_static: true,
        })?;
        if !result.success || result.output.len() != 32 {
            return Err(TempoPrecompileError::RawRevert(
                Revert::from("modexp failed").abi_encode().into(),
            ));
        }

        let mut y = U256::from_be_slice(&result.output);
        if (y % U256::from(2) == U256::ZERO) != (y_parity == 0x02) {
            y = SECP256K1_P - y;
        }

        let mut packed = [0u8; 64];
        packed[..32].copy_from_slice(&px.to_be_bytes::<32>());
        packed[32..].copy_from_slice(&y.to_be_bytes::<32>());
        Ok(Address::from_word(self.storage.keccak256(&packed)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        zone_factory::{ZoneFactory, portal::PortalEncryptionKeyEntry},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IZoneFactory, ZonePortalCapability, ZonePortalRole};

    const OWNER: Address = Address::with_last_byte(0x11);
    const ADMIN: Address = Address::with_last_byte(0x22);
    const SEQUENCER_A: Address = Address::with_last_byte(0x33);
    const SEQUENCER_B: Address = Address::with_last_byte(0x44);
    const ALLOWED_ACCOUNT: Address = Address::with_last_byte(0x55);
    const ZONE_GATEWAY: Address = Address::with_last_byte(0x66);

    /// Runs `f` on a portal the native factory created at T15.
    fn with_portal(f: impl FnOnce(&mut ZonePortalStorage) -> eyre::Result<()>) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_block_number(42);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
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
            f(&mut ZonePortalStorage::new(created.portal))
        })
    }

    fn push_key(portal: &mut ZonePortalStorage, x: u8, activation_block: u64) -> eyre::Result<()> {
        portal.encryption_keys.push(PortalEncryptionKeyEntry {
            x: B256::repeat_byte(x),
            y_parity: 0x02,
            activation_block,
        })?;
        Ok(())
    }

    #[test]
    fn constants_match_solidity() -> eyre::Result<()> {
        with_portal(|portal| {
            assert_eq!(
                portal.abdication_delay(ZonePortalConstants::ABDICATION_DELAYCall {})?,
                2_592_000
            );
            assert_eq!(
                portal.pause_duration(ZonePortalConstants::PAUSE_DURATIONCall {})?,
                2_592_000
            );
            assert_eq!(
                portal.fixed_deposit_gas(ZonePortal::FIXED_DEPOSIT_GASCall {})?,
                100_000
            );
            assert_eq!(
                portal.max_gas_fee_rate(ZonePortal::MAX_GAS_FEE_RATECall {})?,
                1_000_000_000_000_000_000
            );
            assert_eq!(
                portal.max_sequencers(ZonePortalConstants::MAX_SEQUENCERSCall {})?,
                uint!(8_U256)
            );
            assert_eq!(
                portal.max_token_metadata_bytes(ZonePortal::MAX_TOKEN_METADATA_BYTESCall {})?,
                uint!(31_U256)
            );
            assert_eq!(
                portal.max_unprocessed_deposits(ZonePortal::MAX_UNPROCESSED_DEPOSITSCall {})?,
                230
            );
            assert_eq!(
                portal.max_unprocessed_token_enablements(
                    ZonePortal::MAX_UNPROCESSED_TOKEN_ENABLEMENTSCall {}
                )?,
                8
            );
            assert_eq!(
                portal.max_withdrawal_gas_limit(ZonePortal::MAX_WITHDRAWAL_GAS_LIMITCall {})?,
                10_000_000
            );
            Ok(())
        })
    }

    #[test]
    fn sequencer_role_and_token_views() -> eyre::Result<()> {
        with_portal(|portal| {
            assert_eq!(portal.admin(ZonePortal::adminCall {})?, ADMIN);
            assert_eq!(portal.zone_id(ZonePortal::zoneIdCall {})?, 1);
            assert_eq!(portal.leader(ZonePortal::leaderCall {})?, SEQUENCER_A);
            assert_eq!(
                portal.sequencer_count(ZonePortal::sequencerCountCall {})?,
                uint!(2_U256)
            );
            assert_eq!(
                portal.sequencer_at(ZonePortal::sequencerAtCall {
                    index: uint!(1_U256)
                })?,
                SEQUENCER_B
            );
            for index in [uint!(2_U256), U256::MAX] {
                assert_eq!(
                    portal.sequencer_at(ZonePortal::sequencerAtCall { index }),
                    Err(TempoPrecompileError::array_oob())
                );
            }
            assert!(portal.is_sequencer(ZonePortal::isSequencerCall {
                account: SEQUENCER_A
            })?);
            assert!(!portal.is_sequencer(ZonePortal::isSequencerCall { account: ADMIN })?);
            assert!(portal.has_role(ZonePortal::hasRoleCall {
                account: ZONE_GATEWAY,
                role: ZonePortalRole::CallbackGateway,
            })?);
            assert!(!portal.has_role(ZonePortal::hasRoleCall {
                account: ZONE_GATEWAY,
                role: ZonePortalRole::Account,
            })?);
            assert!(portal.is_access_enforced(ZonePortal::isAccessEnforcedCall {})?);
            assert!(!portal.is_gateway_open(ZonePortal::isGatewayOpenCall {})?);

            assert_eq!(
                portal.enabled_token_count(ZonePortal::enabledTokenCountCall {})?,
                uint!(1_U256)
            );
            assert_eq!(
                portal.enabled_token_at(ZonePortal::enabledTokenAtCall { index: U256::ZERO })?,
                PATH_USD_ADDRESS
            );
            assert_eq!(
                portal.enabled_token_at(ZonePortal::enabledTokenAtCall {
                    index: uint!(1_U256)
                }),
                Err(TempoPrecompileError::array_oob())
            );
            assert_eq!(
                portal.token_config(ZonePortal::tokenConfigCall {
                    token: PATH_USD_ADDRESS
                })?,
                ZonePortal::TokenConfig {
                    enabled: true,
                    depositsActive: true,
                }
            );
            assert!(!portal.is_token_enabled(ZonePortal::isTokenEnabledCall { token: ADMIN })?);
            assert_eq!(
                portal.abdication_effective_at(ZonePortal::abdicationEffectiveAtCall {
                    capability: ZonePortalCapability::PausePortal,
                })?,
                0
            );
            Ok(())
        })
    }

    #[test]
    fn pause_disables_deposits_until_expiry() -> eyre::Result<()> {
        with_portal(|portal| {
            let call = || ZonePortal::areDepositsActiveCall {
                token: PATH_USD_ADDRESS,
            };
            assert!(portal.are_deposits_active(call())?);
            assert!(!portal.paused(ZonePortal::pausedCall {})?);

            let expiry = portal.storage.timestamp().to::<u64>() + 1;
            portal.pause_expiry.write(expiry)?;
            assert!(portal.paused(ZonePortal::pausedCall {})?);
            assert!(!portal.are_deposits_active(call())?);
            assert_eq!(portal.pause_expiry(ZonePortal::pauseExpiryCall {})?, expiry);

            portal.storage.set_timestamp(U256::from(expiry));
            assert!(!portal.paused(ZonePortal::pausedCall {})?);
            assert!(portal.are_deposits_active(call())?);
            Ok(())
        })
    }

    #[test]
    fn encryption_key_views_without_keys() -> eyre::Result<()> {
        with_portal(|portal| {
            assert_eq!(
                portal.encryption_key_count(ZonePortal::encryptionKeyCountCall {})?,
                U256::ZERO
            );
            assert_eq!(
                portal.sequencer_encryption_key(ZonePortal::sequencerEncryptionKeyCall {}),
                Err(ZonePortalError::no_encryption_key_set().into())
            );
            assert_eq!(
                portal.encryption_key_at(ZonePortal::encryptionKeyAtCall { index: U256::ZERO }),
                Err(ZonePortalError::invalid_encryption_key_index(U256::ZERO).into())
            );
            assert_eq!(
                portal.encryption_key_at_block(ZonePortal::encryptionKeyAtBlockCall {
                    tempoBlockNumber: u64::MAX,
                }),
                Err(ZonePortalError::no_encryption_key_at_block(u64::MAX).into())
            );
            assert_eq!(
                portal.is_encryption_key_valid(ZonePortal::isEncryptionKeyValidCall {
                    keyIndex: U256::ZERO,
                })?,
                ZonePortal::isEncryptionKeyValidReturn {
                    valid: false,
                    expiresAtBlock: 0,
                }
            );
            Ok(())
        })
    }

    #[test]
    fn encryption_key_history_lookups() -> eyre::Result<()> {
        with_portal(|portal| {
            push_key(portal, 0xa1, 100)?;
            push_key(portal, 0xa2, 200)?;
            push_key(portal, 0xa3, 200)?;
            push_key(portal, 0xa4, 300)?;

            assert_eq!(
                portal.encryption_key_count(ZonePortal::encryptionKeyCountCall {})?,
                uint!(4_U256)
            );
            assert_eq!(
                portal.encryption_key_at(ZonePortal::encryptionKeyAtCall {
                    index: uint!(1_U256)
                })?,
                ZonePortal::EncryptionKeyEntry {
                    x: B256::repeat_byte(0xa2),
                    yParity: 0x02,
                    activationBlock: 200,
                }
            );
            assert_eq!(
                portal.encryption_key_at(ZonePortal::encryptionKeyAtCall { index: U256::MAX }),
                Err(ZonePortalError::invalid_encryption_key_index(U256::MAX).into())
            );

            assert_eq!(
                portal.encryption_key_at_block(ZonePortal::encryptionKeyAtBlockCall {
                    tempoBlockNumber: 99,
                }),
                Err(ZonePortalError::no_encryption_key_at_block(99).into())
            );
            for (block, x, index) in [
                (100, 0xa1, 0),
                (199, 0xa1, 0),
                (200, 0xa3, 2),
                (299, 0xa3, 2),
                (300, 0xa4, 3),
                (u64::MAX, 0xa4, 3),
            ] {
                assert_eq!(
                    portal.encryption_key_at_block(ZonePortal::encryptionKeyAtBlockCall {
                        tempoBlockNumber: block,
                    })?,
                    ZonePortal::encryptionKeyAtBlockReturn {
                        x: B256::repeat_byte(x),
                        yParity: 0x02,
                        keyIndex: U256::from(index),
                    },
                    "block {block}"
                );
            }
            Ok(())
        })
    }

    #[test]
    fn encryption_key_validity_follows_grace_period() -> eyre::Result<()> {
        with_portal(|portal| {
            push_key(portal, 0xa1, 10)?;
            push_key(portal, 0xa2, 100)?;
            let valid = |portal: &ZonePortalStorage, key_index: u64| {
                portal.is_encryption_key_valid(ZonePortal::isEncryptionKeyValidCall {
                    keyIndex: U256::from(key_index),
                })
            };
            let expiration = 100 + ENCRYPTION_KEY_GRACE_PERIOD;

            assert_eq!(
                valid(portal, 1)?,
                ZonePortal::isEncryptionKeyValidReturn {
                    valid: true,
                    expiresAtBlock: 0,
                }
            );
            assert_eq!(
                valid(portal, 2)?,
                ZonePortal::isEncryptionKeyValidReturn {
                    valid: false,
                    expiresAtBlock: 0,
                }
            );
            portal.storage.set_block_number(expiration - 1);
            assert_eq!(
                valid(portal, 0)?,
                ZonePortal::isEncryptionKeyValidReturn {
                    valid: true,
                    expiresAtBlock: expiration,
                }
            );
            portal.storage.set_block_number(expiration);
            assert_eq!(
                valid(portal, 0)?,
                ZonePortal::isEncryptionKeyValidReturn {
                    valid: false,
                    expiresAtBlock: expiration,
                }
            );

            push_key(portal, 0xa3, u64::MAX)?;
            assert_eq!(
                valid(portal, 1),
                Err(TempoPrecompileError::under_overflow())
            );
            Ok(())
        })
    }
}
