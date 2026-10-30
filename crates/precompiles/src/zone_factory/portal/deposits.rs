//! Deposits into the zone and the shared deposit queue.

use super::{
    CALLBACK_DEPOSIT_AVAILABLE, CALLBACK_DEPOSIT_CONSUMED, FIXED_DEPOSIT_GAS,
    MAX_UNPROCESSED_DEPOSITS, TEMPO_BASE_FEE_SCALE, WITHDRAWAL_PROCESSING_DEPOSIT_RESERVE,
    ZonePortalStorage,
    secp256k1::{is_compressed_y_parity, is_valid_x},
};
use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolValue,
};
use tempo_contracts::{
    precompiles::{
        ITIP20, ITIP403Registry, TIP20Error, TIP403_REGISTRY_ADDRESS, ZonePortalError,
        ZonePortalEvent, ZonePortalRole,
    },
    zones::{Deposit, DepositPayload, DepositType, WithdrawalBounceBackDeposit, ZonePortal},
};

/// `ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE`: required ciphertext length of an encrypted deposit.
const ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE: usize = 64;

impl ZonePortalStorage {
    /// Solidity `calculateBouncebackFee`: `ceil(bouncebackGas * block.basefee / 1e12)`.
    pub fn calculate_bounceback_fee(
        &self,
        _call: ZonePortal::calculateBouncebackFeeCall,
    ) -> Result<u128> {
        let basefee = self.storage.with_block_env(|block| block.basefee);
        let gas_fee = U256::from(self.bounceback_gas.read()?)
            .checked_mul(basefee)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let scale = U256::from(TEMPO_BASE_FEE_SCALE);
        let fee = gas_fee
            .checked_add(scale - U256::ONE)
            .ok_or_else(TempoPrecompileError::under_overflow)?
            / scale;
        // Solidity's explicit `uint128(...)` conversion truncates.
        Ok(fee.wrapping_to::<u128>())
    }

    /// Solidity `calculateDepositFee`: `FIXED_DEPOSIT_GAS * zoneGasRate`.
    pub fn calculate_deposit_fee(
        &self,
        _call: ZonePortal::calculateDepositFeeCall,
    ) -> Result<u128> {
        u128::from(FIXED_DEPOSIT_GAS)
            .checked_mul(self.zone_gas_rate.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    /// Solidity `deposit`, an alias for `depositEncrypted`.
    pub fn deposit(&mut self, sender: Address, call: ZonePortal::depositCall) -> Result<B256> {
        self.when_not_paused()?;
        self.deposit_internal(
            sender,
            call.token,
            call.amount,
            call.keyIndex,
            call.encrypted,
            call.tempoRefundRecipient,
        )
    }

    /// Solidity `depositEncrypted`.
    pub fn deposit_encrypted(
        &mut self,
        sender: Address,
        call: ZonePortal::depositEncryptedCall,
    ) -> Result<B256> {
        self.when_not_paused()?;
        self.deposit_internal(
            sender,
            call.token,
            call.amount,
            call.keyIndex,
            call.encrypted,
            call.tempoRefundRecipient,
        )
    }

    /// Solidity `_enqueueBounceBack`: queues a bounce-back deposit for a failed withdrawal.
    pub(crate) fn enqueue_bounce_back(
        &mut self,
        token: Address,
        amount: u128,
        fallback_nonce: u64,
    ) -> Result<()> {
        let deposit = WithdrawalBounceBackDeposit {
            token,
            to: Address::left_padding_from(&fallback_nonce.to_be_bytes()),
            amount,
        };
        let new_hash = self.deposit_queue_hash(DepositType::WithdrawalBounceBack, deposit)?;
        let this_deposit = self.record_deposit(new_hash, MAX_UNPROCESSED_DEPOSITS)?;

        self.emit(ZonePortalEvent::withdrawal_bounce_back(
            new_hash,
            fallback_nonce,
            token,
            amount,
            this_deposit,
        ))
    }

    /// Solidity `_deposit`.
    fn deposit_internal(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        key_index: U256,
        encrypted: DepositPayload,
        tempo_refund_recipient: Address,
    ) -> Result<B256> {
        if tempo_refund_recipient.is_zero() {
            return Err(ZonePortalError::invalid_bounceback_recipient().into());
        }
        self.require_allowed_depositor(sender)?;
        self.require_allowed(tempo_refund_recipient)?;

        // _validateDepositsActive
        if !self.token_configs[token].enabled.read()? {
            return Err(ZonePortalError::token_not_enabled().into());
        }
        if !self.token_configs[token].deposits_active.read()? {
            return Err(ZonePortalError::deposits_not_active().into());
        }

        let policy_id = self.external_static_call(token, &ITIP20::transferPolicyIdCall {})?;
        let authorized = self.external_static_call(
            TIP403_REGISTRY_ADDRESS,
            &ITIP403Registry::isAuthorizedRecipientCall {
                policyId: policy_id,
                user: tempo_refund_recipient,
            },
        )?;
        if !authorized {
            return Err(TIP20Error::policy_forbids().into());
        }

        if !is_compressed_y_parity(encrypted.ephemeralPubkeyYParity)
            || !is_valid_x(encrypted.ephemeralPubkeyX)
        {
            return Err(ZonePortalError::invalid_ephemeral_pubkey().into());
        }

        if encrypted.ciphertext.len() != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE {
            return Err(ZonePortalError::invalid_ciphertext_length(
                U256::from(encrypted.ciphertext.len()),
                U256::from(ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE),
            )
            .into());
        }

        let key_validity = self.is_encryption_key_valid(ZonePortal::isEncryptionKeyValidCall {
            keyIndex: key_index,
        })?;
        if !key_validity.valid {
            let key_count = self.encryption_keys.len()?;
            if key_index >= U256::from(key_count) {
                return Err(ZonePortalError::invalid_encryption_key_index(key_index).into());
            }
            // `key_index < key_count`, and an invalid key is never the latest, so `index + 1`
            // is in bounds too.
            let index: usize = key_index.to();
            let activation_block = self.encryption_keys[index].activation_block.read()?;
            let superseded_at_block = self.encryption_keys[index + 1].activation_block.read()?;
            return Err(ZonePortalError::encryption_key_expired(
                key_index,
                activation_block,
                superseded_at_block,
            )
            .into());
        }

        let (fee, net_amount) = self.collect_deposit_funds(sender, token, amount)?;

        let deposit = Deposit {
            token,
            sender,
            amount: net_amount,
            tempoRefundRecipient: tempo_refund_recipient,
            keyIndex: key_index,
            encrypted,
        };
        let new_hash = self.deposit_queue_hash(DepositType::Deposit, deposit.clone())?;

        // A withdrawal callback may return one deposit through the capacity reserved from
        // public deposits. Further deposits remain subject to the public cap.
        let mut maximum = MAX_UNPROCESSED_DEPOSITS - WITHDRAWAL_PROCESSING_DEPOSIT_RESERVE;
        if self.withdrawal_reentrancy_status.read()? == CALLBACK_DEPOSIT_AVAILABLE {
            self.withdrawal_reentrancy_status
                .write(CALLBACK_DEPOSIT_CONSUMED)?;
            maximum = MAX_UNPROCESSED_DEPOSITS;
        }

        let this_deposit = self.record_deposit(new_hash, maximum)?;

        let Deposit { encrypted, .. } = deposit;
        self.emit(ZonePortalEvent::deposit_made(
            new_hash,
            sender,
            token,
            net_amount,
            fee,
            key_index,
            encrypted.ephemeralPubkeyX,
            encrypted.ephemeralPubkeyYParity,
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.tag,
            tempo_refund_recipient,
            this_deposit,
        ))?;

        Ok(new_hash)
    }

    /// Solidity `_requireAllowedDepositor`: enforced gateways may deposit without the
    /// `Account` role.
    fn require_allowed_depositor(&self, account: Address) -> Result<()> {
        if !self.is_access_enforced.read()? {
            return Ok(());
        }
        if self.is_gateway_enforced.read()?
            && self.has_role_of(account, ZonePortalRole::CallbackGateway)?
        {
            return Ok(());
        }
        if !self.has_role_of(account, ZonePortalRole::Account)? {
            return Err(ZonePortalError::account_not_allowed(account).into());
        }
        Ok(())
    }

    /// Solidity `_collectDepositFunds`: pulls `amount` from `sender` and pays the deposit fee
    /// to the admin. Returns `(fee, netAmount)`.
    fn collect_deposit_funds(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
    ) -> Result<(u128, u128)> {
        let fee = self.calculate_deposit_fee(ZonePortal::calculateDepositFeeCall {})?;
        let bounceback_fee =
            self.calculate_bounceback_fee(ZonePortal::calculateBouncebackFeeCall {})?;
        let minimum = fee
            .checked_add(bounceback_fee)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if amount < minimum {
            return Err(ZonePortalError::deposit_too_small().into());
        }
        // `amount >= fee + bounceback_fee`, so this cannot underflow.
        let net_amount = amount - fee;

        self.external_call(
            token,
            &ITIP20::transferFromCall {
                from: sender,
                to: self.address,
                amount: U256::from(amount),
            },
        )?;
        if fee > 0 {
            let admin = self.admin.read()?;
            self.external_call(
                token,
                &ITIP20::transferCall {
                    to: admin,
                    amount: U256::from(fee),
                },
            )?;
        }
        Ok((fee, net_amount))
    }

    /// `DepositQueueLib.enqueue` / `enqueueDeposit`: the queue head after appending `deposit`,
    /// `keccak256(abi.encode(depositType, deposit, currentDepositQueueHash))`.
    fn deposit_queue_hash<T: SolValue>(
        &self,
        deposit_type: DepositType,
        deposit: T,
    ) -> Result<B256> {
        let previous = self.current_deposit_queue_hash.read()?;
        self.storage
            .keccak256(&(deposit_type, deposit, previous).abi_encode_params())
    }

    /// Solidity `_recordDeposit`: stores the new queue head and returns the deposit number.
    fn record_deposit(&mut self, new_hash: B256, maximum: u64) -> Result<u64> {
        let deposit_count = self.deposit_count.read()?;
        let unprocessed = deposit_count
            .checked_sub(self.last_processed_deposit_number.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if unprocessed >= maximum {
            return Err(ZonePortalError::deposit_block_capacity_exceeded(maximum).into());
        }

        self.current_deposit_queue_hash.write(new_hash)?;
        let this_deposit = deposit_count
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.deposit_count.write(this_deposit)?;
        Ok(this_deposit)
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
    use alloy::primitives::{Bytes, FixedBytes, IntoLogData, address, b256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::IZoneFactory;

    const OWNER: Address = Address::with_last_byte(0x11);
    const ADMIN: Address = Address::with_last_byte(0x22);
    const SEQUENCER: Address = Address::with_last_byte(0x33);
    const ALLOWED: Address = Address::with_last_byte(0x55);
    const GATEWAY: Address = Address::with_last_byte(0x66);
    const OUTSIDER: Address = Address::with_last_byte(0x77);
    const PREVIOUS_HASH: B256 =
        b256!("0x4444444444444444444444444444444444444444444444444444444444444444");
    /// X coordinate of the secp256k1 generator.
    const GENERATOR_X: B256 =
        b256!("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    /// Runs `f` on a freshly created zone whose portal enforces access and gateway modes.
    fn with_portal(f: impl FnOnce(&mut ZonePortalStorage) -> eyre::Result<()>) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
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
                        allowedAccounts: vec![ALLOWED],
                        zoneGateways: vec![GATEWAY],
                        admin: ADMIN,
                        sequencers: vec![SEQUENCER],
                        threshold: 1,
                        rpcUrl: "https://zone.example".to_string(),
                    },
                },
            )?;
            f(&mut ZonePortalStorage::new(created.portal))
        })
    }

    fn payload() -> DepositPayload {
        DepositPayload {
            ephemeralPubkeyX: GENERATOR_X,
            ephemeralPubkeyYParity: 2,
            ciphertext: Bytes::from(vec![0xab; ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE]),
            nonce: FixedBytes::repeat_byte(0x0c),
            tag: FixedBytes::repeat_byte(0x16),
        }
    }

    fn deposit_call(token: Address, tempo_refund_recipient: Address) -> ZonePortal::depositCall {
        ZonePortal::depositCall {
            token,
            amount: 1_000_000,
            keyIndex: U256::ZERO,
            encrypted: payload(),
            tempoRefundRecipient: tempo_refund_recipient,
        }
    }

    #[test]
    fn deposit_queue_hash_matches_solidity() -> eyre::Result<()> {
        with_portal(|portal| {
            portal.current_deposit_queue_hash.write(PREVIOUS_HASH)?;
            let deposit = Deposit {
                token: address!("0x1111111111111111111111111111111111111111"),
                sender: address!("0x2222222222222222222222222222222222222222"),
                amount: 1_000_000,
                tempoRefundRecipient: address!("0x3333333333333333333333333333333333333333"),
                keyIndex: U256::ONE,
                encrypted: payload(),
            };
            // DepositQueueLib.enqueueDeposit(PREVIOUS_HASH, deposit), computed with forge.
            assert_eq!(
                portal.deposit_queue_hash(DepositType::Deposit, deposit)?,
                b256!("0xa80d7568cabefa0a63abf552282c8f6b7b08c425adc7ec117cf6f1009b154dbf")
            );
            Ok(())
        })
    }

    #[test]
    fn enqueue_bounce_back_matches_solidity_and_emits() -> eyre::Result<()> {
        with_portal(|portal| {
            let token = address!("0x1111111111111111111111111111111111111111");
            portal.current_deposit_queue_hash.write(PREVIOUS_HASH)?;

            portal.enqueue_bounce_back(token, 5, 7)?;

            // DepositQueueLib.enqueue(PREVIOUS_HASH, (token, address(7), 5)), computed with forge.
            let expected =
                b256!("0x8a97036af8e051eb7e28a1c3e193435053b0c558a5262d9b3762fcc9f9cdb059");
            assert_eq!(portal.current_deposit_queue_hash.read()?, expected);
            assert_eq!(portal.deposit_count.read()?, 1);
            assert_eq!(
                StorageCtx.get_events(portal.address).last(),
                Some(
                    &ZonePortalEvent::withdrawal_bounce_back(expected, 7, token, 5, 1)
                        .into_log_data()
                )
            );
            Ok(())
        })
    }

    #[test]
    fn enqueue_bounce_back_enforces_unprocessed_cap() -> eyre::Result<()> {
        with_portal(|portal| {
            portal.deposit_count.write(MAX_UNPROCESSED_DEPOSITS + 3)?;
            portal.last_processed_deposit_number.write(3)?;
            assert_eq!(
                portal.enqueue_bounce_back(PATH_USD_ADDRESS, 1, 1),
                Err(
                    ZonePortalError::deposit_block_capacity_exceeded(MAX_UNPROCESSED_DEPOSITS)
                        .into()
                )
            );

            portal.last_processed_deposit_number.write(4)?;
            portal.enqueue_bounce_back(PATH_USD_ADDRESS, 1, 1)?;
            assert_eq!(portal.deposit_count.read()?, MAX_UNPROCESSED_DEPOSITS + 4);
            Ok(())
        })
    }

    #[test]
    fn calculate_deposit_fee_multiplies_and_checks_overflow() -> eyre::Result<()> {
        with_portal(|portal| {
            portal.zone_gas_rate.write(7)?;
            assert_eq!(
                portal.calculate_deposit_fee(ZonePortal::calculateDepositFeeCall {})?,
                700_000
            );

            portal.zone_gas_rate.write(u128::MAX)?;
            assert_eq!(
                portal.calculate_deposit_fee(ZonePortal::calculateDepositFeeCall {}),
                Err(TempoPrecompileError::under_overflow())
            );
            Ok(())
        })
    }

    #[test]
    fn deposits_revert_while_paused() -> eyre::Result<()> {
        with_portal(|portal| {
            let expiry = portal.storage.timestamp().to::<u64>() + 100;
            portal.pause_expiry.write(expiry)?;
            assert_eq!(
                portal.deposit(ALLOWED, deposit_call(PATH_USD_ADDRESS, ALLOWED)),
                Err(ZonePortalError::portal_is_paused().into())
            );
            let call = deposit_call(PATH_USD_ADDRESS, ALLOWED);
            assert_eq!(
                portal.deposit_encrypted(
                    ALLOWED,
                    ZonePortal::depositEncryptedCall {
                        token: call.token,
                        amount: call.amount,
                        keyIndex: call.keyIndex,
                        encrypted: call.encrypted,
                        tempoRefundRecipient: call.tempoRefundRecipient,
                    }
                ),
                Err(ZonePortalError::portal_is_paused().into())
            );
            Ok(())
        })
    }

    #[test]
    fn deposit_checks_recipient_and_access_in_order() -> eyre::Result<()> {
        with_portal(|portal| {
            assert_eq!(
                portal.deposit(OUTSIDER, deposit_call(PATH_USD_ADDRESS, Address::ZERO)),
                Err(ZonePortalError::invalid_bounceback_recipient().into())
            );
            assert_eq!(
                portal.deposit(OUTSIDER, deposit_call(PATH_USD_ADDRESS, ALLOWED)),
                Err(ZonePortalError::account_not_allowed(OUTSIDER).into())
            );
            // An enforced gateway passes the depositor check; the refund recipient must still be
            // an allowed account.
            assert_eq!(
                portal.deposit(GATEWAY, deposit_call(PATH_USD_ADDRESS, OUTSIDER)),
                Err(ZonePortalError::account_not_allowed(OUTSIDER).into())
            );

            portal.is_gateway_enforced.write(false)?;
            assert_eq!(
                portal.deposit(GATEWAY, deposit_call(PATH_USD_ADDRESS, ALLOWED)),
                Err(ZonePortalError::account_not_allowed(GATEWAY).into())
            );
            Ok(())
        })
    }

    #[test]
    fn deposit_requires_enabled_token_with_active_deposits() -> eyre::Result<()> {
        with_portal(|portal| {
            assert_eq!(
                portal.deposit(ALLOWED, deposit_call(OUTSIDER, ALLOWED)),
                Err(ZonePortalError::token_not_enabled().into())
            );

            portal.token_configs[PATH_USD_ADDRESS]
                .deposits_active
                .write(false)?;
            assert_eq!(
                portal.deposit(ALLOWED, deposit_call(PATH_USD_ADDRESS, ALLOWED)),
                Err(ZonePortalError::deposits_not_active().into())
            );
            Ok(())
        })
    }

    #[test]
    fn secp256k1_checks_match_solidity() {
        // Expected values from Secp256k1Lib.isValidX, computed with forge.
        assert!(is_valid_x(GENERATOR_X));
        assert!(is_valid_x(B256::from(U256::from(6))));
        assert!(!is_valid_x(B256::from(U256::from(5))));
        assert!(!is_valid_x(B256::from(U256::from(7))));
        assert!(!is_valid_x(B256::ZERO));
        assert!(!is_valid_x(B256::from(SECP256K1_P)));

        assert!(is_compressed_y_parity(0x02));
        assert!(is_compressed_y_parity(0x03));
        assert!(!is_compressed_y_parity(0x00));
        assert!(!is_compressed_y_parity(0x04));
    }
}
