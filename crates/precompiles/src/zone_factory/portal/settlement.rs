//! Batch submission and settlement verification.

use super::{MAX_UNPROCESSED_TOKEN_ENABLEMENTS, ZonePortalStorage};
use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::{EIP712_DOMAIN_TYPEHASH, VERSION_HASH},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256, address},
    sol_types::SolValue,
};
use keccak_const::Keccak256;
use tempo_contracts::{
    precompiles::{
        ISignatureVerifier, IZoneVerifier, SIGNATURE_VERIFIER_ADDRESS, ZonePortalError,
        ZonePortalEvent,
    },
    zones::ZonePortal,
};

/// EIP-2935 block hash history contract, as in `BlockHashHistory.sol`.
const EIP2935_ADDRESS: Address = address!("0x0000F90827F1C53a10cb7A02335B175320002935");

/// EIP-712 domain name hash: `keccak256("ZonePortal")`.
const NAME_HASH: B256 = B256::new(Keccak256::new().update(b"ZonePortal").finalize());

/// EIP-712 typehash of the settlement attestation sequencers sign.
const SETTLEMENT_ATTESTATION_TYPEHASH: B256 = B256::new(
    Keccak256::new()
        .update(
            b"SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)",
        )
        .finalize(),
);

/// `NO_QUEUE_INDEX`: queue index emitted for a batch without withdrawals.
const NO_QUEUE_INDEX: U256 = U256::MAX;

impl ZonePortalStorage {
    /// Solidity `submitBatch` (the overload with the token enablement transition).
    pub fn submit_batch(
        &mut self,
        sender: Address,
        call: ZonePortal::submitBatch_1Call,
    ) -> Result<()> {
        self.only_sequencer(sender)?;

        if call.blockTransition.prevBlockHash != self.block_hash.read()? {
            return Err(ZonePortalError::invalid_proof().into());
        }

        let block_number = self.storage.block_number();
        let anchor_block_number = if call.recentTempoBlockNumber == 0 {
            if call.tempoBlockNumber > block_number {
                return Err(ZonePortalError::invalid_tempo_block_number().into());
            }
            call.tempoBlockNumber
        } else {
            if call.recentTempoBlockNumber <= call.tempoBlockNumber
                || call.recentTempoBlockNumber > block_number
            {
                return Err(ZonePortalError::invalid_tempo_block_number().into());
            }
            call.recentTempoBlockNumber
        };
        let anchor_block_hash = self.historical_block_hash(anchor_block_number)?;
        if anchor_block_hash.is_zero() {
            return Err(ZonePortalError::invalid_tempo_block_number().into());
        }

        if !self.verify_settlement(&call, anchor_block_number, anchor_block_hash)? {
            return Err(ZonePortalError::invalid_quorum_certificate().into());
        }

        let ZonePortal::submitBatch_1Call {
            tempoBlockNumber: tempo_block_number,
            blockTransition: block_transition,
            depositQueueTransition: deposits,
            tokenEnablementTransition: tokens,
            withdrawalQueueHash: withdrawal_queue_hash,
            verifierConfig: verifier_config,
            proof,
            nextZoneHeight: next_zone_height,
            ..
        } = call;

        if deposits.prevDepositNumber != self.last_processed_deposit_number.read()?
            || deposits.nextDepositNumber < deposits.prevDepositNumber
            || deposits.nextDepositNumber > self.deposit_count.read()?
        {
            return Err(ZonePortalError::invalid_deposit_transition().into());
        }

        let enabled_count = self.enabled_tokens.len()? as u64;
        let cursor_initialized = self.token_enablement_cursor_initialized.read()?;
        let expected_prev = if cursor_initialized {
            self.last_processed_enabled_token_count.read()?
        } else {
            0
        };
        if tokens.prevProcessedTokenCount != expected_prev
            || tokens.nextProcessedTokenCount < tokens.prevProcessedTokenCount
            || tokens.nextProcessedTokenCount > enabled_count
        {
            return Err(ZonePortalError::invalid_token_enablement_transition().into());
        }
        // `nextProcessedTokenCount <= enabled_count` was checked above.
        if !cursor_initialized
            && tokens.nextProcessedTokenCount != 0
            && enabled_count - tokens.nextProcessedTokenCount > MAX_UNPROCESSED_TOKEN_ENABLEMENTS
        {
            return Err(ZonePortalError::invalid_token_enablement_transition().into());
        }

        let verifier = self.verifier.read()?;
        let verify = IZoneVerifier::verifyCall {
            zoneId: self.zone_id.read()?,
            tempoBlockNumber: tempo_block_number,
            anchorBlockNumber: anchor_block_number,
            anchorBlockHash: anchor_block_hash,
            expectedWithdrawalBatchIndex: self.next_withdrawal_batch_index()?,
            nextZoneHeight: next_zone_height,
            blockTransition: block_transition.clone(),
            depositQueueTransition: deposits.clone(),
            tokenEnablementTransition: tokens.clone(),
            withdrawalQueueHash: withdrawal_queue_hash,
            verifierConfig: verifier_config,
            proof,
        };
        if !self.external_static_call(verifier, &verify)? {
            return Err(ZonePortalError::invalid_proof().into());
        }

        let withdrawal_batch_index = self.next_withdrawal_batch_index()?;
        self.withdrawal_batch_index.write(withdrawal_batch_index)?;
        let block_hash = block_transition.nextBlockHash;
        self.block_hash.write(block_hash)?;
        self.last_synced_tempo_block_number
            .write(tempo_block_number)?;
        let last_processed_deposit_number = deposits.nextDepositNumber;
        self.last_processed_deposit_number
            .write(last_processed_deposit_number)?;
        if cursor_initialized || tokens.nextProcessedTokenCount != 0 {
            self.last_processed_enabled_token_count
                .write(tokens.nextProcessedTokenCount)?;
            self.token_enablement_cursor_initialized.write(true)?;
        }
        self.zone_height.write(next_zone_height)?;

        // WithdrawalQueueLib.enqueue
        let assigned_queue_index = if withdrawal_queue_hash.is_zero() {
            NO_QUEUE_INDEX
        } else {
            let tail = self.withdrawal_queue.tail.read()?;
            self.withdrawal_queue.slots[tail].write(withdrawal_queue_hash)?;
            self.withdrawal_queue.tail.write(
                tail.checked_add(U256::ONE)
                    .ok_or_else(TempoPrecompileError::under_overflow)?,
            )?;
            tail
        };

        let last_processed_enabled_token_count = self.last_processed_enabled_token_count.read()?;
        self.emit(ZonePortalEvent::batch_submitted_1(
            withdrawal_batch_index,
            assigned_queue_index,
            deposits.nextProcessedHash,
            block_hash,
            withdrawal_queue_hash,
            last_processed_deposit_number,
            last_processed_enabled_token_count,
        ))
    }

    /// Solidity `_verifySettlement`: whether `signatures` form a quorum certificate of distinct
    /// current sequencers over the settlement attestation.
    fn verify_settlement(
        &mut self,
        call: &ZonePortal::submitBatch_1Call,
        anchor_block_number: u64,
        anchor_block_hash: B256,
    ) -> Result<bool> {
        let threshold = usize::from(self.sequencer_threshold.read()?);
        let signatures = &call.signatures;
        if call.nextZoneHeight <= self.zone_height.read()?
            || signatures.len() < threshold
            || signatures.len() > self.sequencers.len()?
        {
            return Ok(false);
        }

        let struct_hash = self.storage.keccak256(
            &(
                SETTLEMENT_ATTESTATION_TYPEHASH,
                self.zone_id.read()?,
                self.sequencer_set_version.read()?,
                call.nextZoneHeight,
                self.next_withdrawal_batch_index()?,
                self.verifier.read()?,
                call.tempoBlockNumber,
                anchor_block_number,
                anchor_block_hash,
                self.storage.keccak256(&call.blockTransition.abi_encode())?,
                self.storage
                    .keccak256(&call.depositQueueTransition.abi_encode())?,
                self.storage
                    .keccak256(&call.tokenEnablementTransition.abi_encode())?,
                call.withdrawalQueueHash,
                self.storage.keccak256(&call.verifierConfig)?,
            )
                .abi_encode(),
        )?;
        let mut digest_input = [0u8; 66];
        digest_input[..2].copy_from_slice(b"\x19\x01");
        digest_input[2..34].copy_from_slice(self.domain_separator()?.as_slice());
        digest_input[34..].copy_from_slice(struct_hash.as_slice());
        let digest = self.storage.keccak256(&digest_input)?;

        let mut recovered = Vec::new();
        for signature in signatures {
            // A call to a `view` function compiles to STATICCALL; its reverts become `false`.
            let Some(signer) = self.try_external_call(
                SIGNATURE_VERIFIER_ADDRESS,
                &ISignatureVerifier::recoverCall {
                    hash: digest,
                    signature: signature.clone(),
                },
                true,
            )?
            else {
                return Ok(false);
            };
            if signer.is_zero()
                || !self.is_sequencer_account(signer)?
                || recovered.contains(&signer)
            {
                return Ok(false);
            }
            recovered.push(signer);
        }

        Ok(signatures.len() >= threshold)
    }

    /// Solidity `_domainSeparator`.
    fn domain_separator(&self) -> Result<B256> {
        self.storage.keccak256(
            &(
                EIP712_DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                U256::from(self.storage.chain_id()),
                self.address,
            )
                .abi_encode(),
        )
    }

    /// `withdrawalBatchIndex + 1` with Solidity's checked `uint64` arithmetic.
    fn next_withdrawal_batch_index(&self) -> Result<u64> {
        self.withdrawal_batch_index
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    /// `BlockHashHistory.getBlockHash`: the EIP-2935 history contract's hash for `block_number`,
    /// zero when the lookup fails or returns fewer than 32 bytes.
    fn historical_block_hash(&mut self, block_number: u64) -> Result<B256> {
        let input = Bytes::from(U256::from(block_number).to_be_bytes::<32>());
        let result = self.raw_call(EIP2935_ADDRESS, input, true)?;
        Ok(if result.success && result.output.len() >= 32 {
            B256::from_slice(&result.output[..32])
        } else {
            B256::ZERO
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        zone_factory::{ZoneFactory, portal_address},
    };
    use alloy::primitives::{b256, keccak256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::IZoneFactory;

    const OWNER: Address = Address::with_last_byte(0x11);
    const ADMIN: Address = Address::with_last_byte(0x22);
    const SEQUENCER_A: Address = Address::with_last_byte(0x33);
    const SEQUENCER_B: Address = Address::with_last_byte(0x44);
    const BLOCK_NUMBER: u64 = 100;

    /// Creates zone 1 with two sequencers and threshold 2, returning its portal.
    fn create_portal() -> eyre::Result<ZonePortalStorage> {
        TIP20Setup::path_usd(ADMIN).apply()?;
        let mut factory = ZoneFactory::new();
        factory.next_zone_id.write(1)?;
        factory.owner.write(OWNER)?;
        let created = factory.create_zone(
            OWNER,
            IZoneFactory::createZoneCall {
                params: IZoneFactory::CreateZoneParams {
                    initialToken: PATH_USD_ADDRESS,
                    accessMode: false,
                    gatewayMode: false,
                    allowedAccounts: vec![],
                    zoneGateways: vec![],
                    admin: ADMIN,
                    sequencers: vec![SEQUENCER_A, SEQUENCER_B],
                    threshold: 2,
                    rpcUrl: "https://zone.example".to_string(),
                },
            },
        )?;
        Ok(ZonePortalStorage::new(created.portal))
    }

    fn batch(signatures: usize) -> ZonePortal::submitBatch_1Call {
        ZonePortal::submitBatch_1Call {
            tempoBlockNumber: BLOCK_NUMBER - 1,
            recentTempoBlockNumber: 0,
            blockTransition: ZonePortal::BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::repeat_byte(0xbb),
            },
            depositQueueTransition: ZonePortal::DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: ZonePortal::TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 1,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::new(),
            proof: Bytes::new(),
            nextZoneHeight: U256::ONE,
            signatures: vec![Bytes::from_static(&[0; 65]); signatures],
        }
    }

    #[test]
    fn settlement_typehash_and_domain_separator_match_solidity() -> eyre::Result<()> {
        assert_eq!(
            SETTLEMENT_ATTESTATION_TYPEHASH,
            b256!("0xb155d32b4b347a555165cab364d500d1c10bb3b9c50d31d54c220e98ce920258")
        );
        assert_eq!(NAME_HASH, keccak256("ZonePortal"));

        // cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address)" \
        //   <EIP712Domain typehash> $(cast keccak ZonePortal) $(cast keccak 1) 4217 <portal 1>)
        let mut storage = HashMapStorageProvider::new(4217);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            assert_eq!(
                ZonePortalStorage::new(portal_address(1)).domain_separator()?,
                b256!("0x71014200821e14e6eb58be4d8764529eeefc214a8ad8cce652420b614483180d")
            );
            Ok(())
        })
    }

    #[test]
    fn transition_structs_encode_as_static_tuples() {
        let call = batch(0);
        let deposits = &call.depositQueueTransition;
        assert_eq!(
            deposits.abi_encode(),
            (
                deposits.prevProcessedHash,
                deposits.nextProcessedHash,
                deposits.prevDepositNumber,
                deposits.nextDepositNumber,
            )
                .abi_encode()
        );
        assert_eq!(call.blockTransition.abi_encode().len(), 64);
        assert_eq!(call.tokenEnablementTransition.abi_encode().len(), 64);
    }

    #[test]
    fn submit_batch_rejects_before_block_hash_lookup() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        storage.set_block_number(BLOCK_NUMBER);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut portal = create_portal()?;

            assert_eq!(
                portal.submit_batch(ADMIN, batch(2)),
                Err(ZonePortalError::not_sequencer().into())
            );

            let mut call = batch(2);
            call.blockTransition.prevBlockHash = B256::repeat_byte(1);
            assert_eq!(
                portal.submit_batch(SEQUENCER_A, call),
                Err(ZonePortalError::invalid_proof().into())
            );

            for (tempo, recent) in [
                (BLOCK_NUMBER + 1, 0),
                (BLOCK_NUMBER - 1, BLOCK_NUMBER - 1),
                (BLOCK_NUMBER - 1, BLOCK_NUMBER - 2),
                (BLOCK_NUMBER - 1, BLOCK_NUMBER + 1),
            ] {
                let mut call = batch(2);
                call.tempoBlockNumber = tempo;
                call.recentTempoBlockNumber = recent;
                assert_eq!(
                    portal.submit_batch(SEQUENCER_A, call),
                    Err(ZonePortalError::invalid_tempo_block_number().into())
                );
            }
            Ok(())
        })
    }

    #[test]
    fn verify_settlement_rejects_bad_height_and_signature_counts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        storage.set_block_number(BLOCK_NUMBER);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut portal = create_portal()?;
            let anchor_hash = B256::repeat_byte(0xaa);

            let mut stale_height = batch(2);
            stale_height.nextZoneHeight = U256::ZERO;
            for call in [stale_height, batch(1), batch(3)] {
                assert!(!portal.verify_settlement(&call, BLOCK_NUMBER - 1, anchor_hash)?);
            }
            Ok(())
        })
    }
}
