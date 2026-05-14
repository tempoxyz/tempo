//! [TIP-1028] precompile for blocked inbound TIP-20 transfers and mints.

pub mod dispatch;

pub use tempo_contracts::precompiles::ITIP1028BlockedTransfers::{self, InboundKind};
use tempo_contracts::precompiles::{
    BlockTransferError, BlockTransferEvent,
    ITIP403Registry::{self, BlockedReason},
};

use crate::{
    BLOCKED_TRANSFERS_ADDRESS,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{Recipient, TIP20Token},
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolValue,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;

/// Version tag for the v1 [`ITIP1028BlockedTransfers::ProofV1`] layout.
pub const BLOCKED_PROOF_VERSION: u8 = 1;

/// Recovery-authority sentinel: originator/sender is authorized to claim (`address(0)`).
pub const RECOVERY_ORIGINATOR: Address = Address::ZERO;

/// Recovery-authority sentinel: receiver is authorized to claim (`address(1)`).
pub const RECOVERY_RECEIVER: Address = Address::with_last_byte(1);

/// TIP-1028 precompile holding blocked inbound transfers and mints until claimed.
#[contract(addr = BLOCKED_TRANSFERS_ADDRESS)]
pub struct TIP1028BlockedTransfers {
    nonce: u64,
    balances: Mapping<B256, U256>,
}

impl TIP1028BlockedTransfers {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the unclaimed amount for a proof, or zero if unknown or already claimed.
    pub fn balance_of(&self, call: ITIP1028BlockedTransfers::balanceOfCall) -> Result<U256> {
        if !call.token.is_tip20() {
            return Err(BlockTransferError::invalid_token().into());
        }

        let proof = Self::decode_v1(call.proofVersion, &call.proof)?;
        self.balances[self.proof(
            call.proofVersion,
            call.token,
            call.recoveryAuthority,
            &proof,
        )?]
        .read()
    }

    /// Records a blocked inbound transfer or mint and emits `TransferBlocked` event.
    /// Caller must send the funds into this address, which are claimable with a valid proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_blocked(
        &mut self,
        token: Address,
        originator: Address,
        to: &Recipient,
        recovery_address: Address,
        amount: U256,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> Result<(u64, u64)> {
        if !token.is_tip20() {
            return Err(BlockTransferError::invalid_token().into());
        }

        if matches!(
            blocked_reason,
            ITIP403Registry::BlockedReason::NONE | ITIP403Registry::BlockedReason::__Invalid
        ) || kind == ITIP1028BlockedTransfers::InboundKind::__Invalid
        {
            return Err(BlockTransferError::invalid_proof().into());
        }

        let receiver = to.target;
        let recipient = to.virtual_addr.unwrap_or(to.target);

        let blocked_nonce = self.next_proof_nonce()?;
        let blocked_at = self.storage.timestamp().saturating_to::<u64>();
        let proof = ITIP1028BlockedTransfers::ClaimProofV1 {
            originator,
            recipient,
            blockedAt: blocked_at,
            blockedNonce: blocked_nonce,
            blockedReason: blocked_reason as u8,
            kind,
            memo,
        };
        let key = self.proof(BLOCKED_PROOF_VERSION, token, recovery_address, &proof)?;
        self.balances[key].write(amount)?;

        self.emit_event(BlockTransferEvent::TransferBlocked(
            ITIP1028BlockedTransfers::TransferBlocked {
                token,
                from: originator,
                receiver,
                proofVersion: BLOCKED_PROOF_VERSION,
                blockedNonce: blocked_nonce,
                blockedAt: blocked_at,
                recipient,
                amount,
                blockedReason: blocked_reason as u8,
                recoveryAuthority: recovery_address,
                memo,
            },
        ))?;

        Ok((blocked_nonce, blocked_at))
    }

    /// Given a valid proof, releases blocked funds to the authorized recipient.
    pub fn claim(
        &mut self,
        msg_sender: Address,
        call: ITIP1028BlockedTransfers::claimCall,
    ) -> Result<()> {
        if !call.token.is_tip20() {
            return Err(BlockTransferError::invalid_token().into());
        }

        if call.to == BLOCKED_TRANSFERS_ADDRESS {
            return Err(BlockTransferError::invalid_claim_address().into());
        }

        let proof = Self::decode_v1(call.proofVersion, &call.proof)?;
        let receiver = AddressRegistry::new()
            .resolve_recipient(proof.recipient)
            .map_err(|_| BlockTransferError::invalid_claim_address())?;

        let recovery_address = call.recoveryAuthority;
        let recovery_authority =
            RecoveryAuthority::from_address(recovery_address, receiver, proof.originator);
        recovery_authority.validate_auth(msg_sender)?;

        let key = self.proof(call.proofVersion, call.token, recovery_address, &proof)?;
        let amount = self.balances[key].read()?;
        if amount.is_zero() {
            return Err(BlockTransferError::invalid_proof().into());
        }

        let guard = self.storage.checkpoint();
        self.balances[key].write(U256::ZERO)?;

        let reroute = match recovery_authority {
            RecoveryAuthority::Originator(_) => true,
            RecoveryAuthority::Receiver(_) | RecoveryAuthority::Contract(_) => call.to != receiver,
        };
        let recovery_addr = match recovery_authority {
            RecoveryAuthority::Receiver(addr) | RecoveryAuthority::Originator(addr) => Some(addr),
            RecoveryAuthority::Contract(_) => None,
        };
        TIP20Token::from_address(call.token)?.release_blocked_funds(
            proof.originator,
            call.to,
            amount,
            reroute,
            recovery_addr,
        )?;

        self.emit_event(BlockTransferEvent::ProofClaimed(
            ITIP1028BlockedTransfers::ProofClaimed {
                token: call.token,
                receiver,
                proofVersion: call.proofVersion,
                blockedNonce: proof.blockedNonce,
                blockedAt: proof.blockedAt,
                originator: proof.originator,
                recipient: proof.recipient,
                recoveryAuthority: recovery_address,
                caller: msg_sender,
                to: call.to,
                amount,
            },
        ))?;

        guard.commit();
        Ok(())
    }

    /// Allocates the next nonzero proof nonce.
    fn next_proof_nonce(&mut self) -> Result<u64> {
        let nonce = self.nonce.read()?.max(1);
        self.nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    /// ABI-decodes a v1 proof.
    fn decode_v1(
        proof_version: u8,
        proof: &[u8],
    ) -> Result<ITIP1028BlockedTransfers::ClaimProofV1> {
        if proof_version != BLOCKED_PROOF_VERSION {
            return Err(BlockTransferError::invalid_proof().into());
        }
        ITIP1028BlockedTransfers::ClaimProofV1::abi_decode(proof)
            .map_err(|_| BlockTransferError::invalid_proof().into())
    }

    /// Content hash over every proof field. Any mutation yields a different empty slot.
    fn proof(
        &self,
        proof_version: u8,
        token: Address,
        recovery_address: Address,
        proof: &ITIP1028BlockedTransfers::ClaimProofV1,
    ) -> Result<B256> {
        self.storage.keccak256(
            (
                U256::from(proof_version),
                token,
                proof.originator,
                proof.recipient,
                recovery_address,
                U256::from(proof.blockedReason),
                proof.kind,
                proof.memo,
                U256::from(proof.blockedAt),
                U256::from(proof.blockedNonce),
            )
                .abi_encode()
                .as_ref(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryAuthority {
    Originator(Address),
    Receiver(Address),
    Contract(Address),
}

impl RecoveryAuthority {
    fn from_address(address: Address, receiver: Address, originator: Address) -> Self {
        if address == RECOVERY_ORIGINATOR {
            Self::Originator(originator)
        } else if address == RECOVERY_RECEIVER {
            Self::Receiver(receiver)
        } else {
            Self::Contract(address)
        }
    }

    fn validate_auth(self, msg_sender: Address) -> Result<()> {
        let authorized_claimer = match self {
            Self::Receiver(claimer) | Self::Originator(claimer) | Self::Contract(claimer) => {
                claimer
            }
        };
        if msg_sender != authorized_claimer {
            return Err(BlockTransferError::unauthorized_claimer().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address_registry::AddressRegistry,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, VIRTUAL_MASTER, register_virtual_master},
        tip20::ITIP20,
        tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID, TIP403Registry},
    };
    use alloy::sol_types::SolValue;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    impl RecoveryAuthority {
        fn claimer(&self) -> Address {
            match self {
                Self::Originator(addr) => *addr,
                Self::Receiver(addr) => *addr,
                Self::Contract(addr) => *addr,
            }
        }

        fn address(&self) -> Address {
            match self {
                Self::Originator(_) => RECOVERY_ORIGINATOR,
                Self::Receiver(_) => RECOVERY_RECEIVER,
                Self::Contract(addr) => *addr,
            }
        }
    }

    fn proof_v1(
        originator: Address,
        recipient: Address,
        blocked_at: u64,
        blocked_nonce: u64,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> ITIP1028BlockedTransfers::ClaimProofV1 {
        ITIP1028BlockedTransfers::ClaimProofV1 {
            originator,
            recipient,
            blockedAt: blocked_at,
            blockedNonce: blocked_nonce,
            blockedReason: blocked_reason as u8,
            kind,
            memo,
        }
    }

    fn block_all_senders(receiver: Address, recovery_authority: Address) -> Result<()> {
        TIP403Registry::new().set_receive_policy(
            receiver,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: REJECT_ALL_POLICY_ID,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: recovery_authority,
            },
        )
    }

    fn proof_balance(
        precompile: &TIP1028BlockedTransfers,
        token: Address,
        recovery_contract: Address,
        proof: &ITIP1028BlockedTransfers::ClaimProofV1,
    ) -> Result<U256> {
        precompile.balance_of(ITIP1028BlockedTransfers::balanceOfCall {
            token,
            recoveryAuthority: recovery_contract,
            proofVersion: BLOCKED_PROOF_VERSION,
            proof: proof.abi_encode().into(),
        })
    }

    fn claim_call(
        token: Address,
        recovery_contract: Address,
        proof: &ITIP1028BlockedTransfers::ClaimProofV1,
        to: Address,
    ) -> ITIP1028BlockedTransfers::claimCall {
        ITIP1028BlockedTransfers::claimCall {
            token,
            recoveryAuthority: recovery_contract,
            proofVersion: BLOCKED_PROOF_VERSION,
            proof: proof.abi_encode().into(),
            to,
        }
    }

    fn assert_invalid_proof(result: Result<()>) {
        assert!(matches!(
            result,
            Err(e) if e == BlockTransferError::invalid_proof().into()
        ));
    }

    fn assert_unauthorized(result: Result<()>) {
        assert!(matches!(
            result,
            Err(e) if e == BlockTransferError::unauthorized_claimer().into()
        ));
    }

    #[test]
    fn test_claim_transfer() -> eyre::Result<()> {
        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        let blocked_at = 1_728_000u64;

        for (recovery_auth, destination) in [
            (RecoveryAuthority::Originator(originator), originator),
            (RecoveryAuthority::Receiver(receiver), receiver),
            (RecoveryAuthority::Contract(Address::random()), receiver),
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
            storage.set_timestamp(U256::from(blocked_at));

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("T", "T", admin)
                    .with_issuer(admin)
                    .with_mint(originator, amount)
                    .apply()?;
                block_all_senders(receiver, recovery_auth.address())?;

                let unknown = proof_v1(
                    originator,
                    receiver,
                    blocked_at,
                    99,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    B256::ZERO,
                );
                let precompile = TIP1028BlockedTransfers::new();
                assert_eq!(
                    proof_balance(
                        &precompile,
                        token.address(),
                        recovery_auth.address(),
                        &unknown
                    )?,
                    U256::ZERO
                );

                token.transfer(
                    originator,
                    ITIP20::transferCall {
                        to: receiver,
                        amount,
                    },
                )?;

                let proof = proof_v1(
                    originator,
                    receiver,
                    blocked_at,
                    1,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    B256::ZERO,
                );
                assert_eq!(
                    proof_balance(
                        &precompile,
                        token.address(),
                        recovery_auth.address(),
                        &proof
                    )?,
                    amount
                );

                TIP1028BlockedTransfers::new().claim(
                    recovery_auth.claimer(),
                    claim_call(
                        token.address(),
                        recovery_auth.address(),
                        &proof,
                        destination,
                    ),
                )?;

                assert_eq!(
                    proof_balance(
                        &precompile,
                        token.address(),
                        recovery_auth.address(),
                        &proof
                    )?,
                    U256::ZERO
                );
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall {
                        account: BLOCKED_TRANSFERS_ADDRESS
                    })?,
                    U256::ZERO
                );
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall {
                        account: destination
                    })?,
                    amount
                );

                Ok::<(), TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_claim_rejects_when_token_paused() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let blocked_at = 1_728_000u64;
        storage.set_timestamp(U256::from(blocked_at));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_role(admin, TIP20Token::pause_role())
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, RECOVERY_RECEIVER)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            token.pause(admin, ITIP20::pauseCall {})?;

            let proof = proof_v1(
                originator,
                receiver,
                blocked_at,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut precompile = TIP1028BlockedTransfers::new();
            let result = precompile.claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, receiver),
            );
            assert_eq!(result.unwrap_err(), TIP20Error::contract_paused().into());
            assert_eq!(
                proof_balance(&precompile, token.address(), RECOVERY_RECEIVER, &proof)?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_tip1028_precompile_balance_matches_open_proofs() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_001u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver_a = Address::random();
        let receiver_b = Address::random();
        let receiver_c = Address::random();
        let recovery = Address::random();
        let amount_a = U256::from(30u64);
        let amount_b = U256::from(45u64);
        let amount_c = U256::from(70u64);

        StorageCtx::enter(&mut storage, || {
            let mut token_a = TIP20Setup::create("A", "A", admin)
                .with_issuer(admin)
                .with_mint(originator, amount_a + amount_b)
                .apply()?;
            let mut token_b = TIP20Setup::create("B", "B", admin)
                .with_issuer(admin)
                .with_mint(originator, amount_c)
                .apply()?;

            block_all_senders(receiver_a, RECOVERY_RECEIVER)?;
            block_all_senders(receiver_b, recovery)?;
            block_all_senders(receiver_c, RECOVERY_RECEIVER)?;

            token_a.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_a,
                    amount: amount_a,
                },
            )?;
            token_a.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_b,
                    amount: amount_b,
                },
            )?;
            token_b.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver_c,
                    amount: amount_c,
                },
            )?;

            let proof_a = proof_v1(
                originator,
                receiver_a,
                1_728_001,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let proof_b = proof_v1(
                originator,
                receiver_b,
                1_728_001,
                2,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let proof_c = proof_v1(
                originator,
                receiver_c,
                1_728_001,
                3,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let precompile = TIP1028BlockedTransfers::new();
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                proof_balance(&precompile, token_a.address(), RECOVERY_RECEIVER, &proof_a)?
                    + proof_balance(&precompile, token_a.address(), recovery, &proof_b)?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                proof_balance(&precompile, token_b.address(), RECOVERY_RECEIVER, &proof_c)?
            );

            TIP1028BlockedTransfers::new().claim(
                receiver_a,
                claim_call(token_a.address(), RECOVERY_RECEIVER, &proof_a, receiver_a),
            )?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                proof_balance(&precompile, token_a.address(), recovery, &proof_b)?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                proof_balance(&precompile, token_b.address(), RECOVERY_RECEIVER, &proof_c)?
            );

            TIP1028BlockedTransfers::new().claim(
                recovery,
                claim_call(token_a.address(), recovery, &proof_b, receiver_b),
            )?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                U256::ZERO
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                proof_balance(&precompile, token_b.address(), RECOVERY_RECEIVER, &proof_c)?
            );

            Ok(())
        })
    }

    #[test]
    fn test_proof_rejects_bad_encoding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("T", "T", admin).apply()?;
            let precompile = TIP1028BlockedTransfers::new();
            let proof = proof_v1(
                Address::random(),
                Address::random(),
                1,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            for (proof_version, proof_bytes) in [
                (BLOCKED_PROOF_VERSION + 1, proof.abi_encode().into()),
                (BLOCKED_PROOF_VERSION, vec![0xde, 0xad, 0xbe, 0xef].into()),
            ] {
                let result = precompile.balance_of(ITIP1028BlockedTransfers::balanceOfCall {
                    token: token.address(),
                    recoveryAuthority: Address::ZERO,
                    proofVersion: proof_version,
                    proof: proof_bytes,
                });
                assert!(matches!(
                    result,
                    Err(e) if e == BlockTransferError::invalid_proof().into()
                ));
            }

            Ok(())
        })
    }

    #[test]
    fn test_store_rejects_invalid_metadata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("T", "T", admin).apply()?;

            for (blocked_reason, kind) in [
                (BlockedReason::NONE, InboundKind::TRANSFER),
                (BlockedReason::__Invalid, InboundKind::TRANSFER),
                (BlockedReason::RECEIVE_POLICY, InboundKind::__Invalid),
            ] {
                let result = TIP1028BlockedTransfers::new().store_blocked(
                    token.address(),
                    Address::random(),
                    &Recipient::direct(Address::random()),
                    Address::ZERO,
                    U256::from(1u64),
                    blocked_reason,
                    kind,
                    B256::ZERO,
                );
                assert!(matches!(
                    result,
                    Err(e) if e == BlockTransferError::invalid_proof().into()
                ));
            }

            Ok(())
        })
    }

    #[test]
    fn test_proof_key_binds_proof_fields() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_002u64));

        let admin = Address::random();
        let originator_a = Address::random();
        let originator_b = Address::random();
        let recipient = Address::random();
        let recovery = Address::random();
        let memo = B256::repeat_byte(0x11);
        let amount_a = U256::from(10u64);
        let amount_b = U256::from(20u64);

        StorageCtx::enter(&mut storage, || {
            let token_a = TIP20Setup::create("A", "A", admin).apply()?;
            let token_b = TIP20Setup::create("B", "B", admin).apply()?;
            let mut precompile = TIP1028BlockedTransfers::new();

            let (nonce_a, blocked_at_a) = precompile.store_blocked(
                token_a.address(),
                originator_a,
                &Recipient::direct(recipient),
                recovery,
                amount_a,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            )?;
            let (nonce_b, blocked_at_b) = precompile.store_blocked(
                token_a.address(),
                originator_b,
                &Recipient::direct(recipient),
                recovery,
                amount_b,
                BlockedReason::TOKEN_FILTER,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            )?;

            let proof_a = proof_v1(
                originator_a,
                recipient,
                blocked_at_a,
                nonce_a,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            );
            let proof_b = proof_v1(
                originator_b,
                recipient,
                blocked_at_b,
                nonce_b,
                BlockedReason::TOKEN_FILTER,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            );

            assert_eq!(
                proof_balance(&precompile, token_a.address(), recovery, &proof_a)?,
                amount_a
            );
            assert_eq!(
                proof_balance(&precompile, token_a.address(), recovery, &proof_b)?,
                amount_b
            );

            let mutated_proofs = [
                proof_v1(
                    Address::random(),
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    Address::random(),
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    recipient,
                    blocked_at_a + 1,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a + 1,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::TOKEN_FILTER,
                    InboundKind::TRANSFER,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::MINT,
                    memo,
                ),
                proof_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    B256::repeat_byte(0x33),
                ),
            ];

            for mutated in mutated_proofs {
                assert_eq!(
                    proof_balance(&precompile, token_a.address(), recovery, &mutated)?,
                    U256::ZERO
                );
            }
            assert_eq!(
                proof_balance(&precompile, token_a.address(), Address::random(), &proof_a)?,
                U256::ZERO
            );
            assert_eq!(
                proof_balance(&precompile, token_b.address(), recovery, &proof_a)?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_rejects_missing_proof() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_003u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        let proof = proof_v1(
            originator,
            receiver,
            1_728_003,
            1,
            BlockedReason::RECEIVE_POLICY,
            InboundKind::TRANSFER,
            B256::ZERO,
        );

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;

            assert_invalid_proof(TIP1028BlockedTransfers::new().claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, receiver),
            ));

            block_all_senders(receiver, RECOVERY_RECEIVER)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            TIP1028BlockedTransfers::new().claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, receiver),
            )?;
            assert_invalid_proof(TIP1028BlockedTransfers::new().claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, receiver),
            ));

            Ok(())
        })
    }

    #[test]
    fn test_claim_requires_authorized_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_004u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let recovery_receiver = Address::random();
        let recovery = Address::random();
        let stranger = Address::random();
        let amount = U256::from(50u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount * U256::from(2u64))
                .apply()?;
            block_all_senders(receiver, RECOVERY_RECEIVER)?;
            block_all_senders(recovery_receiver, recovery)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: recovery_receiver,
                    amount,
                },
            )?;

            let self_proof = proof_v1(
                originator,
                receiver,
                1_728_004,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let recovery_proof = proof_v1(
                originator,
                recovery_receiver,
                1_728_004,
                2,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            assert_unauthorized(TIP1028BlockedTransfers::new().claim(
                stranger,
                claim_call(token.address(), RECOVERY_RECEIVER, &self_proof, receiver),
            ));
            for caller in [recovery_receiver, stranger] {
                assert_unauthorized(TIP1028BlockedTransfers::new().claim(
                    caller,
                    claim_call(
                        token.address(),
                        recovery,
                        &recovery_proof,
                        recovery_receiver,
                    ),
                ));
            }

            assert_eq!(
                proof_balance(
                    &TIP1028BlockedTransfers::new(),
                    token.address(),
                    RECOVERY_RECEIVER,
                    &self_proof
                )?,
                amount
            );
            assert_eq!(
                proof_balance(
                    &TIP1028BlockedTransfers::new(),
                    token.address(),
                    recovery,
                    &recovery_proof
                )?,
                amount
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_self_recovery() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_005u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(125u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, RECOVERY_RECEIVER)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let proof = proof_v1(
                originator,
                receiver,
                1_728_005,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut precompile = TIP1028BlockedTransfers::new();
            precompile.clear_emitted_events();
            precompile.claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, receiver),
            )?;

            precompile.assert_emitted_events(vec![BlockTransferEvent::ProofClaimed(
                ITIP1028BlockedTransfers::ProofClaimed {
                    token: token.address(),
                    receiver,
                    proofVersion: BLOCKED_PROOF_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_005,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: RECOVERY_RECEIVER,
                    caller: receiver,
                    to: receiver,
                    amount,
                },
            )]);
            assert_eq!(
                proof_balance(&precompile, token.address(), RECOVERY_RECEIVER, &proof)?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                amount
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_via_recovery_contract() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_006u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let recovery = Address::random();
        let destination = Address::random();
        let amount = U256::from(75u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, recovery)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let proof = proof_v1(
                originator,
                receiver,
                1_728_006,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut precompile = TIP1028BlockedTransfers::new();
            precompile.clear_emitted_events();
            precompile.claim(
                recovery,
                claim_call(token.address(), recovery, &proof, destination),
            )?;

            precompile.assert_emitted_events(vec![BlockTransferEvent::ProofClaimed(
                ITIP1028BlockedTransfers::ProofClaimed {
                    token: token.address(),
                    receiver,
                    proofVersion: BLOCKED_PROOF_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_006,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: recovery,
                    caller: recovery,
                    to: destination,
                    amount,
                },
            )]);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: destination
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_rolls_back_on_release_error() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_007u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let destination = Address::random();
        let amount = U256::from(64u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, RECOVERY_RECEIVER)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            block_all_senders(destination, RECOVERY_RECEIVER)?;

            let proof = proof_v1(
                originator,
                receiver,
                1_728_007,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let precompile = TIP1028BlockedTransfers::new();
            let result = TIP1028BlockedTransfers::new().claim(
                receiver,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, destination),
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));

            assert_eq!(
                proof_balance(&precompile, token.address(), RECOVERY_RECEIVER, &proof)?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: BLOCKED_TRANSFERS_ADDRESS
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: destination
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_binds_recovery_contract() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_008u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let recovery = Address::random();
        let other_recovery = Address::random();
        let amount = U256::from(88u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, recovery)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let proof = proof_v1(
                originator,
                receiver,
                1_728_008,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let precompile = TIP1028BlockedTransfers::new();
            assert_eq!(
                proof_balance(&precompile, token.address(), recovery, &proof)?,
                amount
            );
            assert_eq!(
                proof_balance(&precompile, token.address(), Address::ZERO, &proof)?,
                U256::ZERO
            );
            assert_eq!(
                proof_balance(&precompile, token.address(), other_recovery, &proof)?,
                U256::ZERO
            );

            assert_unauthorized(TIP1028BlockedTransfers::new().claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &proof, receiver),
            ));
            assert_invalid_proof(TIP1028BlockedTransfers::new().claim(
                other_recovery,
                claim_call(token.address(), other_recovery, &proof, receiver),
            ));
            TIP1028BlockedTransfers::new().claim(
                recovery,
                claim_call(token.address(), recovery, &proof, receiver),
            )?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                amount
            );
            Ok(())
        })
    }

    #[test]
    fn test_claim_virtual_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_009u64));

        let admin = Address::random();
        let originator = Address::random();
        let amount = U256::from(123u64);

        StorageCtx::enter(&mut storage, || {
            let (_, virtual_addr) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(VIRTUAL_MASTER, RECOVERY_RECEIVER)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: virtual_addr,
                    amount,
                },
            )?;

            let proof = proof_v1(
                originator,
                virtual_addr,
                1_728_009,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut precompile = TIP1028BlockedTransfers::new();
            precompile.clear_emitted_events();
            precompile.claim(
                VIRTUAL_MASTER,
                claim_call(token.address(), RECOVERY_RECEIVER, &proof, VIRTUAL_MASTER),
            )?;

            precompile.assert_emitted_events(vec![BlockTransferEvent::ProofClaimed(
                ITIP1028BlockedTransfers::ProofClaimed {
                    token: token.address(),
                    receiver: VIRTUAL_MASTER,
                    proofVersion: BLOCKED_PROOF_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_009,
                    originator,
                    recipient: virtual_addr,
                    recoveryAuthority: RECOVERY_RECEIVER,
                    caller: VIRTUAL_MASTER,
                    to: VIRTUAL_MASTER,
                    amount,
                },
            )]);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: VIRTUAL_MASTER
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: virtual_addr
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_mint() -> eyre::Result<()> {
        let admin = Address::random();
        let receiver = Address::random();
        let amount = U256::from(144u64);
        let timestamp = 1_728_010u64;

        for (recovery_auth, destination) in [
            (RecoveryAuthority::Originator(admin), admin),
            (RecoveryAuthority::Receiver(receiver), receiver),
            (RecoveryAuthority::Contract(Address::random()), receiver),
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
            storage.set_timestamp(U256::from(timestamp));

            StorageCtx::enter(&mut storage, || {
                let mut token = TIP20Setup::create("T", "T", admin)
                    .with_issuer(admin)
                    .apply()?;
                block_all_senders(receiver, recovery_auth.address())?;

                let mut precompile = TIP1028BlockedTransfers::new();
                precompile.clear_emitted_events();
                token.mint(
                    admin,
                    ITIP20::mintCall {
                        to: receiver,
                        amount,
                    },
                )?;
                precompile.assert_emitted_events(vec![BlockTransferEvent::TransferBlocked(
                    ITIP1028BlockedTransfers::TransferBlocked {
                        token: token.address(),
                        from: admin,
                        receiver,
                        proofVersion: BLOCKED_PROOF_VERSION,
                        blockedNonce: 1,
                        blockedAt: timestamp,
                        recipient: receiver,
                        amount,
                        blockedReason: BlockedReason::RECEIVE_POLICY as u8,
                        recoveryAuthority: recovery_auth.address(),
                        memo: B256::ZERO,
                    },
                )]);
                assert_eq!(token.total_supply()?, amount);
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall {
                        account: BLOCKED_TRANSFERS_ADDRESS
                    })?,
                    amount
                );
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                    U256::ZERO
                );

                let proof = proof_v1(
                    admin,
                    receiver,
                    timestamp,
                    1,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::MINT,
                    B256::ZERO,
                );
                assert_eq!(
                    proof_balance(
                        &precompile,
                        token.address(),
                        recovery_auth.address(),
                        &proof
                    )?,
                    amount
                );

                precompile.claim(
                    recovery_auth.claimer(),
                    claim_call(
                        token.address(),
                        recovery_auth.address(),
                        &proof,
                        destination,
                    ),
                )?;

                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall {
                        account: BLOCKED_TRANSFERS_ADDRESS
                    })?,
                    U256::ZERO
                );
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall {
                        account: destination
                    })?,
                    amount
                );
                assert_eq!(
                    proof_balance(
                        &precompile,
                        token.address(),
                        recovery_auth.address(),
                        &proof
                    )?,
                    U256::ZERO
                );

                Ok::<(), TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }
}
