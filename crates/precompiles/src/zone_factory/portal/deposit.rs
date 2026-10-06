//! Storage phases of a native portal deposit.
//!
//! Preparation releases the storage context before the runtime calls TIP-20
//! `transferFrom` and the optional fee transfer. Commit must run after those
//! calls in the same EVM frame. Any failure rolls back the enclosing frame,
//! including transfers. These phases do not register a native entrypoint.

use super::ZonePortalStorage;
use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::{TIP20Error, TIP20Token},
    tip403_registry::{AuthRole, TIP403Registry},
};
use alloy::{
    primitives::{Address, IntoLogData, U256},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::zone_portal::{Deposit, ZonePortal, ZonePortalError};

const FIXED_DEPOSIT_GAS: u128 = 100_000;
const TEMPO_BASE_FEE_SCALE: u128 = 1_000_000_000_000;
const ENCRYPTION_KEY_GRACE_PERIOD: u64 = 86_400;
const MAX_UNPROCESSED_DEPOSITS: u64 = 230;
const CALLBACK_DEPOSIT_RESERVE: u64 = 20;
const CALLBACK_DEPOSIT_AVAILABLE: u64 = 2;
const CALLBACK_DEPOSIT_CONSUMED: u64 = 3;
const CIPHERTEXT_BYTES: usize = 64;
/// Conservative CPU charge for one compressed secp256k1 point validation.
const POINT_VALIDATION_GAS: u64 = 3_000;

/// Validated, bounded deposit parameters retained outside the storage borrow.
#[derive(Debug)]
pub struct PreparedDeposit {
    portal: Address,
    /// Amount collected from the caller before fees.
    amount: u128,
    /// Amount paid to the portal administrator.
    fee: u128,
    /// Administrator receiving the deposit fee.
    admin: Address,
    /// Queue entry carrying the net backing amount.
    deposit: Deposit,
}

impl PreparedDeposit {
    /// Native TIP-20 dependency holding the deposited assets.
    pub const fn token(&self) -> Address {
        self.deposit.token
    }
    /// Gross funds the runtime must collect from the caller.
    pub const fn amount(&self) -> u128 {
        self.amount
    }

    /// Fee the runtime must transfer after collecting funds.
    pub const fn fee(&self) -> u128 {
        self.fee
    }

    /// Administrator receiving the fee.
    pub const fn admin(&self) -> Address {
        self.admin
    }
}

impl ZonePortalStorage {
    /// Returns key validity using the existing append-only key history.
    pub fn is_encryption_key_valid(&self, key_index: U256) -> Result<(bool, u64)> {
        let len = self.encryption_keys.len()?;
        if key_index >= U256::from(len) {
            return Ok((false, 0));
        }
        let index = key_index.to::<usize>();
        if index == len - 1 {
            return Ok((true, 0));
        }
        let next = self.encryption_keys[index + 1].read()?;
        let expiration = next
            .activation_block
            .checked_add(ENCRYPTION_KEY_GRACE_PERIOD)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        Ok((self.storage.block_number() < expiration, expiration))
    }

    /// Validates deposit authorization, encryption, and amounts before child calls.
    pub fn prepare_deposit(
        &mut self,
        sender: Address,
        call: ZonePortal::depositCall,
    ) -> Result<PreparedDeposit> {
        if self.storage.timestamp() < U256::from(self.pause_expiry.read()?) {
            return Err(ZonePortalError::PortalIsPaused(ZonePortal::PortalIsPaused {}).into());
        }
        if call.tempoRefundRecipient.is_zero() {
            return Err(ZonePortalError::InvalidBouncebackRecipient(
                ZonePortal::InvalidBouncebackRecipient {},
            )
            .into());
        }
        if self.is_access_enforced.read()? {
            let gateway_exemption =
                self.is_gateway_enforced.read()? && self.role[sender].read()? == 3;
            if !gateway_exemption && self.role[sender].read()? != 2 {
                return Err(
                    ZonePortalError::AccountNotAllowed(ZonePortal::AccountNotAllowed {
                        account: sender,
                    })
                    .into(),
                );
            }
            if self.role[call.tempoRefundRecipient].read()? != 2 {
                return Err(
                    ZonePortalError::AccountNotAllowed(ZonePortal::AccountNotAllowed {
                        account: call.tempoRefundRecipient,
                    })
                    .into(),
                );
            }
        }
        let config = self.token_configs[call.token].read()?;
        if !config.enabled {
            return Err(ZonePortalError::TokenNotEnabled(ZonePortal::TokenNotEnabled {}).into());
        }
        if !config.deposits_active {
            return Err(
                ZonePortalError::DepositsNotActive(ZonePortal::DepositsNotActive {}).into(),
            );
        }
        let token = TIP20Token::from_address(call.token)?;
        let policy_id = token.transfer_policy_id()?;
        if !TIP403Registry::new().is_authorized_as(
            policy_id,
            call.tempoRefundRecipient,
            AuthRole::Recipient,
        )? {
            return Err(TIP20Error::policy_forbids().into());
        }
        self.storage.deduct_gas(POINT_VALIDATION_GAS)?;
        let mut point = [0; 33];
        point[0] = call.encrypted.ephemeralPubkeyYParity;
        point[1..].copy_from_slice(call.encrypted.ephemeralPubkeyX.as_slice());
        if !matches!(point[0], 2 | 3) || secp256k1::PublicKey::from_slice(&point).is_err() {
            return Err(ZonePortalError::InvalidEphemeralPubkey(
                ZonePortal::InvalidEphemeralPubkey {},
            )
            .into());
        }
        if call.encrypted.ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(ZonePortalError::InvalidCiphertextLength(
                ZonePortal::InvalidCiphertextLength {
                    actual: U256::from(call.encrypted.ciphertext.len()),
                    expected: U256::from(CIPHERTEXT_BYTES),
                },
            )
            .into());
        }
        if !self.is_encryption_key_valid(call.keyIndex)?.0 {
            let len = self.encryption_keys.len()?;
            if call.keyIndex >= U256::from(len) {
                return Err(ZonePortalError::InvalidEncryptionKeyIndex(
                    ZonePortal::InvalidEncryptionKeyIndex {
                        keyIndex: call.keyIndex,
                    },
                )
                .into());
            }
            let index = call.keyIndex.to::<usize>();
            return Err(
                ZonePortalError::EncryptionKeyExpired(ZonePortal::EncryptionKeyExpired {
                    keyIndex: call.keyIndex,
                    activationBlock: self.encryption_keys[index].read()?.activation_block,
                    supersededAtBlock: self.encryption_keys[index + 1].read()?.activation_block,
                })
                .into(),
            );
        }
        let fee = self
            .zone_gas_rate
            .read()?
            .checked_mul(FIXED_DEPOSIT_GAS)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let base_fee = self.storage.with_block_env(|env| env.basefee);
        let bounceback_fee = U256::from(self.bounceback_gas.read()?)
            .checked_mul(base_fee)
            .and_then(|fee| fee.checked_add(U256::from(TEMPO_BASE_FEE_SCALE - 1)))
            .ok_or_else(TempoPrecompileError::under_overflow)?
            / U256::from(TEMPO_BASE_FEE_SCALE);
        // Match the explicit uint128 cast in the deployed Solidity fee calculation.
        let bounceback_fee = bounceback_fee.wrapping_to::<u128>();
        let minimum = fee
            .checked_add(bounceback_fee)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if call.amount < minimum {
            return Err(ZonePortalError::DepositTooSmall(ZonePortal::DepositTooSmall {}).into());
        }
        Ok(PreparedDeposit {
            portal: self.address,
            amount: call.amount,
            fee,
            admin: self.admin.read()?,
            deposit: Deposit {
                token: call.token,
                sender,
                amount: call.amount - fee,
                tempoRefundRecipient: call.tempoRefundRecipient,
                keyIndex: call.keyIndex,
                encrypted: call.encrypted,
            },
        })
    }

    /// Appends the funded deposit using current queue and callback state.
    pub fn commit_deposit(&mut self, prepared: PreparedDeposit) -> Result<alloy::primitives::B256> {
        if prepared.portal != self.address {
            return Err(TempoPrecompileError::Fatal(
                "deposit plan belongs to another portal".into(),
            ));
        }
        let status = self.withdrawal_reentrancy_status.read()?;
        let maximum = if status == U256::from(CALLBACK_DEPOSIT_AVAILABLE) {
            MAX_UNPROCESSED_DEPOSITS
        } else {
            MAX_UNPROCESSED_DEPOSITS - CALLBACK_DEPOSIT_RESERVE
        };
        let count = self.deposit_count.read()?;
        let outstanding = count
            .checked_sub(self.last_processed_deposit_number.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if outstanding >= maximum {
            return Err(ZonePortalError::DepositBlockCapacityExceeded(
                ZonePortal::DepositBlockCapacityExceeded { maximum },
            )
            .into());
        }
        let number = count
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let deposit = prepared.deposit;
        let hash = self.storage.keccak256(
            &(
                U256::from(1),
                deposit.clone(),
                self.current_deposit_queue_hash.read()?,
            )
                .abi_encode_params(),
        )?;
        if status == U256::from(CALLBACK_DEPOSIT_AVAILABLE) {
            self.withdrawal_reentrancy_status
                .write(U256::from(CALLBACK_DEPOSIT_CONSUMED))?;
        }
        self.current_deposit_queue_hash.write(hash)?;
        self.deposit_count.write(number)?;
        self.storage.emit_event(
            self.address,
            ZonePortal::DepositMade {
                newCurrentDepositQueueHash: hash,
                sender: deposit.sender,
                token: deposit.token,
                netAmount: deposit.amount,
                fee: prepared.fee,
                keyIndex: deposit.keyIndex,
                ephemeralPubkeyX: deposit.encrypted.ephemeralPubkeyX,
                ephemeralPubkeyYParity: deposit.encrypted.ephemeralPubkeyYParity,
                ciphertext: deposit.encrypted.ciphertext,
                nonce: deposit.encrypted.nonce,
                tag: deposit.encrypted.tag,
                tempoRefundRecipient: deposit.tempoRefundRecipient,
                depositNumber: number,
            }
            .into_log_data(),
        )?;
        Ok(hash)
    }
}

#[cfg(test)]
pub(in crate::zone_factory::portal) mod tests {
    use super::{
        super::{PortalEncryptionKeyEntry, PortalTokenConfig},
        *,
    };
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::{
        primitives::{B256, Bytes, LogData, address},
        sol_types::SolEvent,
    };
    use tempo_contracts::TempoHardfork;

    const PORTAL: Address = address!("5ad0000000000000000000000000000000000001");

    fn baseline_log() -> LogData {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/zone-portal-deposit.json"))
                .unwrap();
        LogData::new_unchecked(
            fixture["log"]["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|topic| topic.as_str().unwrap().parse::<B256>().unwrap())
                .collect(),
            fixture["log"]["data"]
                .as_str()
                .unwrap()
                .parse::<Bytes>()
                .unwrap(),
        )
    }

    pub(in crate::zone_factory::portal) fn baseline_call() -> (Address, ZonePortal::depositCall) {
        let event = ZonePortal::DepositMade::decode_log_data(&baseline_log()).unwrap();
        (
            event.sender,
            ZonePortal::depositCall {
                token: event.token,
                amount: event.netAmount + event.fee,
                keyIndex: event.keyIndex,
                encrypted: ZonePortal::DepositPayload {
                    ephemeralPubkeyX: event.ephemeralPubkeyX,
                    ephemeralPubkeyYParity: event.ephemeralPubkeyYParity,
                    ciphertext: event.ciphertext,
                    nonce: event.nonce,
                    tag: event.tag,
                },
                tempoRefundRecipient: event.tempoRefundRecipient,
            },
        )
    }

    fn setup(sender: Address) -> Result<ZonePortalStorage> {
        TIP20Setup::path_usd(sender).apply()?;
        let mut portal = ZonePortalStorage::new(PORTAL);
        portal.initialized.write(true)?;
        portal.admin.write(sender)?;
        portal.token_configs[PATH_USD_ADDRESS].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })?;
        portal
            .encryption_keys
            .write(vec![PortalEncryptionKeyEntry {
                x: baseline_call().1.encrypted.ephemeralPubkeyX,
                y_parity: 2,
                activation_block: 0,
            }])?;
        Ok(portal)
    }

    #[test]
    fn native_commit_matches_real_solidity_deposit_hash_and_log() -> Result<()> {
        let (sender, call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            let prepared = portal.prepare_deposit(sender, call)?;
            assert_eq!(prepared.amount(), 1_000_000);
            assert_eq!(prepared.fee(), 0);
            let hash = portal.commit_deposit(prepared)?;
            assert_eq!(hash, baseline_log().topics()[1]);
            assert_eq!(portal.deposit_count.read()?, 1);
            assert_eq!(portal.current_deposit_queue_hash.read()?, hash);
            Ok(())
        })?;
        assert_eq!(storage.get_events(PORTAL), &vec![baseline_log()]);
        Ok(())
    }

    #[test]
    fn superseded_key_expires_at_the_exact_grace_boundary() -> Result<()> {
        let (sender, mut call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        storage.set_block_number(100 + ENCRYPTION_KEY_GRACE_PERIOD - 1);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            let key = portal.encryption_keys[0].read()?;
            portal.encryption_keys.write(vec![
                key,
                PortalEncryptionKeyEntry {
                    activation_block: 100,
                    ..key
                },
            ])?;
            assert_eq!(portal.is_encryption_key_valid(U256::ZERO)?, (true, 86_500));
            portal.prepare_deposit(sender, call.clone())?;
            Ok(())
        })?;
        storage.set_block_number(86_500);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = ZonePortalStorage::new(PORTAL);
            assert!(matches!(
                portal.prepare_deposit(sender, call.clone()),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::EncryptionKeyExpired(_)
                ))
            ));
            call.keyIndex = U256::from(1);
            portal.prepare_deposit(sender, call.clone())?;
            call.keyIndex = U256::MAX;
            assert!(matches!(
                portal.prepare_deposit(sender, call),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::InvalidEncryptionKeyIndex(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn callback_consumes_only_one_reserved_deposit_slot() -> Result<()> {
        let (sender, call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            portal.deposit_count.write(210)?;
            let prepared = portal.prepare_deposit(sender, call.clone())?;
            assert!(matches!(
                portal.commit_deposit(prepared),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::DepositBlockCapacityExceeded(_)
                ))
            ));
            assert_eq!(portal.deposit_count.read()?, 210);
            portal
                .withdrawal_reentrancy_status
                .write(U256::from(CALLBACK_DEPOSIT_AVAILABLE))?;
            let prepared = portal.prepare_deposit(sender, call.clone())?;
            portal.commit_deposit(prepared)?;
            assert_eq!(portal.deposit_count.read()?, 211);
            assert_eq!(
                portal.withdrawal_reentrancy_status.read()?,
                U256::from(CALLBACK_DEPOSIT_CONSUMED)
            );
            let prepared = portal.prepare_deposit(sender, call)?;
            assert!(matches!(
                portal.commit_deposit(prepared),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::DepositBlockCapacityExceeded(_)
                ))
            ));
            assert_eq!(portal.deposit_count.read()?, 211);
            Ok(())
        })
    }

    #[test]
    fn deposit_minimum_includes_rounded_up_bounceback_fee() -> Result<()> {
        let (sender, mut call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        storage.set_base_fee(U256::from(1));
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            portal.zone_gas_rate.write(2)?;
            portal.bounceback_gas.write(1)?;
            call.amount = 200_000;
            assert!(matches!(
                portal.prepare_deposit(sender, call.clone()),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::DepositTooSmall(_)
                ))
            ));
            call.amount += 1;
            let prepared = portal.prepare_deposit(sender, call)?;
            assert_eq!(prepared.fee(), 200_000);
            assert_eq!(prepared.deposit.amount, 1);
            Ok(())
        })
    }

    #[test]
    fn gateway_depositor_exemption_does_not_exempt_refund_recipient() -> Result<()> {
        let (sender, mut call) = baseline_call();
        let recipient = Address::with_last_byte(0x22);
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            portal.is_access_enforced.write(true)?;
            portal.is_gateway_enforced.write(true)?;
            portal.role[sender].write(3)?;
            call.tempoRefundRecipient = recipient;
            assert!(matches!(portal.prepare_deposit(sender, call.clone()),
                Err(TempoPrecompileError::ZonePortalError(ZonePortalError::AccountNotAllowed(error)))
                if error.account == recipient));
            portal.role[recipient].write(2)?;
            portal.prepare_deposit(sender, call.clone())?;
            portal.is_gateway_enforced.write(false)?;
            assert!(matches!(portal.prepare_deposit(sender, call),
                Err(TempoPrecompileError::ZonePortalError(ZonePortalError::AccountNotAllowed(error)))
                if error.account == sender));
            assert_eq!(portal.deposit_count.read()?, 0);
            Ok(())
        })
    }

    #[test]
    fn malformed_encryption_and_forbidden_refund_cannot_append_deposit() -> Result<()> {
        let (sender, call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            for parity in [0, 1, 4, 255] {
                let mut invalid = call.clone();
                invalid.encrypted.ephemeralPubkeyYParity = parity;
                assert!(matches!(
                    portal.prepare_deposit(sender, invalid),
                    Err(TempoPrecompileError::ZonePortalError(
                        ZonePortalError::InvalidEphemeralPubkey(_)
                    ))
                ));
            }
            let mut invalid = call.clone();
            invalid.encrypted.ephemeralPubkeyX = B256::repeat_byte(0xff);
            assert!(matches!(
                portal.prepare_deposit(sender, invalid),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::InvalidEphemeralPubkey(_)
                ))
            ));
            for len in [0, 63, 65, 1024] {
                let mut invalid = call.clone();
                invalid.encrypted.ciphertext = Bytes::from(vec![0; len]);
                assert!(matches!(
                    portal.prepare_deposit(sender, invalid),
                    Err(TempoPrecompileError::ZonePortalError(
                        ZonePortalError::InvalidCiphertextLength(_)
                    ))
                ));
            }
            let mut invalid = call.clone();
            invalid.tempoRefundRecipient = Address::ZERO;
            assert!(matches!(
                portal.prepare_deposit(sender, invalid),
                Err(TempoPrecompileError::ZonePortalError(
                    ZonePortalError::InvalidBouncebackRecipient(_)
                ))
            ));
            TIP403Registry::new().set_token_transfer_policy(call.token, 0)?;
            assert!(matches!(
                portal.prepare_deposit(sender, call),
                Err(TempoPrecompileError::TIP20(_))
            ));
            assert_eq!(portal.deposit_count.read()?, 0);
            assert_eq!(portal.current_deposit_queue_hash.read()?, B256::ZERO);
            Ok(())
        })?;
        assert!(storage.get_events(PORTAL).is_empty());
        Ok(())
    }

    #[test]
    fn prepared_deposit_is_bound_to_its_portal() -> Result<()> {
        let (sender, call) = baseline_call();
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = setup(sender)?;
            let prepared = portal.prepare_deposit(sender, call)?;
            let mut other = ZonePortalStorage::new(Address::with_last_byte(0x55));
            assert!(matches!(
                other.commit_deposit(prepared),
                Err(TempoPrecompileError::Fatal(_))
            ));
            assert_eq!(other.deposit_count.read()?, 0);
            assert_eq!(portal.deposit_count.read()?, 0);
            Ok(())
        })
    }
}
