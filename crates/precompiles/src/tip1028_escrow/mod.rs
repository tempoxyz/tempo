//! [TIP-1028] escrow precompile for blocked inbound TIP-20 transfers and mints.

pub mod dispatch;

pub use tempo_contracts::precompiles::ITIP1028Escrow::{self, InboundKind};
use tempo_contracts::precompiles::{
    ITIP403Registry::{self, BlockedReason},
    TIP1028EscrowError, TIP1028EscrowEvent,
};

use crate::{
    ESCROW_ADDRESS,
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::TIP20Token,
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolValue,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;

/// Version tag for the v1 [`ITIP1028Escrow::ClaimReceiptV1`] layout.
pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

/// Recovery-authority sentinel: receiver is authorized to claim (`address(0)`).
pub const RECOVERY_RECEIVER: Address = Address::ZERO;

/// Recovery-authority sentinel: originator/sender is authorized to claim (`address(1)`).
pub const RECOVERY_SENDER: Address = Address::with_last_byte(1);

/// TIP-1028 escrow holding blocked inbound transfers and mints until claimed.
#[contract(addr = ESCROW_ADDRESS)]
pub struct TIP1028Escrow {
    blocked_receipt_nonce: u64,
    blocked_receipt_amount: Mapping<B256, U256>,
}

impl TIP1028Escrow {
    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the unclaimed amount for a receipt, or zero if unknown or already claimed.
    pub fn blocked_receipt_balance(
        &self,
        call: ITIP1028Escrow::blockedReceiptBalanceCall,
    ) -> Result<U256> {
        if !call.token.is_tip20() {
            return Err(TIP1028EscrowError::invalid_token().into());
        }

        let receipt = Self::decode_v1(call.receiptVersion, &call.receipt)?;
        self.blocked_receipt_amount[self.receipt_key(
            call.receiptVersion,
            call.token,
            call.recoveryAuthority,
            &receipt,
        )?]
        .read()
    }

    /// Records a blocked inbound transfer or mint and emits `TransferBlocked` for
    /// transfers. Caller moves the funds into escrow in the same checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_blocked(
        &mut self,
        token: Address,
        originator: Address,
        receiver: Address,
        recipient: Address,
        recovery_address: Address,
        amount: U256,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> Result<(u64, u64)> {
        if !token.is_tip20() {
            return Err(TIP1028EscrowError::invalid_token().into());
        }

        if matches!(
            blocked_reason,
            ITIP403Registry::BlockedReason::NONE | ITIP403Registry::BlockedReason::__Invalid
        ) || kind == ITIP1028Escrow::InboundKind::__Invalid
        {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }

        let blocked_nonce = self.next_blocked_receipt_nonce()?;
        let blocked_at = self.storage.timestamp().saturating_to::<u64>();
        let receipt = ITIP1028Escrow::ClaimReceiptV1 {
            originator,
            recipient,
            blockedAt: blocked_at,
            blockedNonce: blocked_nonce,
            blockedReason: blocked_reason as u8,
            kind,
            memo,
        };
        let key = self.receipt_key(BLOCKED_RECEIPT_VERSION, token, recovery_address, &receipt)?;
        self.blocked_receipt_amount[key].write(amount)?;

        if kind == ITIP1028Escrow::InboundKind::TRANSFER {
            self.emit_event(TIP1028EscrowEvent::TransferBlocked(
                ITIP1028Escrow::TransferBlocked {
                    token,
                    from: originator,
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: blocked_nonce,
                    blockedAt: blocked_at,
                    recipient,
                    amount,
                    blockedReason: blocked_reason as u8,
                    recoveryAuthority: recovery_address,
                    memo,
                },
            ))?;
        }

        Ok((blocked_nonce, blocked_at))
    }

    /// Releases escrowed receipt funds to the authorized recipient.
    pub fn claim(&mut self, msg_sender: Address, call: ITIP1028Escrow::claimCall) -> Result<()> {
        if !call.token.is_tip20() {
            return Err(TIP1028EscrowError::invalid_token().into());
        }

        let receipt = Self::decode_v1(call.receiptVersion, &call.receipt)?;
        let receiver = AddressRegistry::new()
            .resolve_recipient(receipt.recipient)
            .map_err(|_| TIP1028EscrowError::invalid_claim_address())?;

        let recovery_address = call.recoveryAuthority;
        let recovery_authority =
            RecoveryAuthority::from_address(recovery_address, receiver, receipt.originator);
        recovery_authority.validate_auth(msg_sender)?;
        let claim_target = recovery_authority.claim_target();

        let key = self.receipt_key(call.receiptVersion, call.token, recovery_address, &receipt)?;
        let amount = self.blocked_receipt_amount[key].read()?;
        if amount.is_zero() {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }

        let guard = self.storage.checkpoint();
        self.blocked_receipt_amount[key].write(U256::ZERO)?;

        TIP20Token::from_address(call.token)?.release_from_escrow(claim_target, amount)?;

        self.emit_event(TIP1028EscrowEvent::BlockedReceiptClaimed(
            ITIP1028Escrow::BlockedReceiptClaimed {
                token: call.token,
                receiver,
                receiptVersion: call.receiptVersion,
                blockedNonce: receipt.blockedNonce,
                blockedAt: receipt.blockedAt,
                originator: receipt.originator,
                recipient: receipt.recipient,
                recoveryAuthority: recovery_address,
                caller: msg_sender,
                amount,
            },
        ))?;

        guard.commit();
        Ok(())
    }

    /// Allocates the next nonzero receipt nonce.
    fn next_blocked_receipt_nonce(&mut self) -> Result<u64> {
        let nonce = self.blocked_receipt_nonce.read()?.max(1);
        self.blocked_receipt_nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    /// ABI-decodes a v1 receipt.
    fn decode_v1(receipt_version: u8, receipt: &[u8]) -> Result<ITIP1028Escrow::ClaimReceiptV1> {
        if receipt_version != BLOCKED_RECEIPT_VERSION {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }
        ITIP1028Escrow::ClaimReceiptV1::abi_decode(receipt)
            .map_err(|_| TIP1028EscrowError::invalid_receipt_claim().into())
    }

    /// Content hash over every receipt field. Any mutation yields a different empty slot.
    fn receipt_key(
        &self,
        receipt_version: u8,
        token: Address,
        recovery_address: Address,
        receipt: &ITIP1028Escrow::ClaimReceiptV1,
    ) -> Result<B256> {
        self.storage.keccak256(
            (
                U256::from(receipt_version),
                token,
                receipt.originator,
                receipt.recipient,
                recovery_address,
                U256::from(receipt.blockedReason),
                receipt.kind,
                receipt.memo,
                U256::from(receipt.blockedAt),
                U256::from(receipt.blockedNonce),
            )
                .abi_encode()
                .as_ref(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryAuthority {
    Receiver(Address),
    Originator(Address),
    Contract(Address),
}

impl RecoveryAuthority {
    fn from_address(address: Address, receiver: Address, originator: Address) -> Self {
        if address == RECOVERY_RECEIVER {
            Self::Receiver(receiver)
        } else if address == RECOVERY_SENDER {
            Self::Originator(originator)
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
            return Err(TIP1028EscrowError::unauthorized_claimer().into());
        }
        Ok(())
    }

    fn claim_target(self) -> Address {
        match self {
            Self::Receiver(target) | Self::Originator(target) | Self::Contract(target) => target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address_registry::AddressRegistry,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, VIRTUAL_MASTER, register_virtual_master},
        tip20::ITIP20,
        tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID, TIP403Registry},
    };
    use alloy::sol_types::SolValue;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    fn receipt_v1(
        originator: Address,
        recipient: Address,
        blocked_at: u64,
        blocked_nonce: u64,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> ITIP1028Escrow::ClaimReceiptV1 {
        ITIP1028Escrow::ClaimReceiptV1 {
            originator,
            recipient,
            blockedAt: blocked_at,
            blockedNonce: blocked_nonce,
            blockedReason: blocked_reason as u8,
            kind,
            memo,
        }
    }

    fn block_all_senders(receiver: Address, recovery_address: Address) -> Result<()> {
        TIP403Registry::new().set_receive_policy(
            receiver,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: REJECT_ALL_POLICY_ID,
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: recovery_address,
            },
        )
    }

    fn receipt_balance(
        escrow: &TIP1028Escrow,
        token: Address,
        recovery_contract: Address,
        receipt: &ITIP1028Escrow::ClaimReceiptV1,
    ) -> Result<U256> {
        escrow.blocked_receipt_balance(ITIP1028Escrow::blockedReceiptBalanceCall {
            token,
            recoveryAuthority: recovery_contract,
            receiptVersion: BLOCKED_RECEIPT_VERSION,
            receipt: receipt.abi_encode().into(),
        })
    }

    fn claim_call(
        token: Address,
        recovery_contract: Address,
        receipt: &ITIP1028Escrow::ClaimReceiptV1,
    ) -> ITIP1028Escrow::claimCall {
        ITIP1028Escrow::claimCall {
            token,
            recoveryAuthority: recovery_contract,
            receiptVersion: BLOCKED_RECEIPT_VERSION,
            receipt: receipt.abi_encode().into(),
        }
    }

    fn assert_invalid_receipt(result: Result<()>) {
        assert!(matches!(
            result,
            Err(e) if e == TIP1028EscrowError::invalid_receipt_claim().into()
        ));
    }

    fn assert_unauthorized(result: Result<()>) {
        assert!(matches!(
            result,
            Err(e) if e == TIP1028EscrowError::unauthorized_claimer().into()
        ));
    }

    #[test]
    fn test_receipt_balance_store_and_claim() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_000u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        let blocked_at = 1_728_000u64;

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, Address::ZERO)?;

            let unknown = receipt_v1(
                originator,
                receiver,
                blocked_at,
                99,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let escrow = TIP1028Escrow::new();
            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &unknown)?,
                U256::ZERO
            );

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let receipt = receipt_v1(
                originator,
                receiver,
                blocked_at,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &receipt)?,
                amount
            );

            TIP1028Escrow::new().claim(
                receiver,
                ITIP1028Escrow::claimCall {
                    token: token.address(),
                    recoveryAuthority: Address::ZERO,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    receipt: receipt.abi_encode().into(),
                },
            )?;

            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &receipt)?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
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
            block_all_senders(receiver, Address::ZERO)?;

            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            token.pause(admin, ITIP20::pauseCall {})?;

            let receipt = receipt_v1(
                originator,
                receiver,
                blocked_at,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut escrow = TIP1028Escrow::new();
            let result = escrow.claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            );
            assert_eq!(result.unwrap_err(), TIP20Error::contract_paused().into());
            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &receipt)?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
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
    fn test_escrow_balance_matches_open_receipts() -> eyre::Result<()> {
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

            block_all_senders(receiver_a, Address::ZERO)?;
            block_all_senders(receiver_b, recovery)?;
            block_all_senders(receiver_c, Address::ZERO)?;

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

            let receipt_a = receipt_v1(
                originator,
                receiver_a,
                1_728_001,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let receipt_b = receipt_v1(
                originator,
                receiver_b,
                1_728_001,
                2,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let receipt_c = receipt_v1(
                originator,
                receiver_c,
                1_728_001,
                3,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let escrow = TIP1028Escrow::new();
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                receipt_balance(&escrow, token_a.address(), Address::ZERO, &receipt_a)?
                    + receipt_balance(&escrow, token_a.address(), recovery, &receipt_b)?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                receipt_balance(&escrow, token_b.address(), Address::ZERO, &receipt_c)?
            );

            TIP1028Escrow::new().claim(
                receiver_a,
                claim_call(token_a.address(), Address::ZERO, &receipt_a),
            )?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                receipt_balance(&escrow, token_a.address(), recovery, &receipt_b)?
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                receipt_balance(&escrow, token_b.address(), Address::ZERO, &receipt_c)?
            );

            TIP1028Escrow::new().claim(
                recovery,
                claim_call(token_a.address(), recovery, &receipt_b),
            )?;
            assert_eq!(
                token_a.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                U256::ZERO
            );
            assert_eq!(
                token_b.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                receipt_balance(&escrow, token_b.address(), Address::ZERO, &receipt_c)?
            );

            Ok(())
        })
    }

    #[test]
    fn test_receipt_rejects_bad_encoding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("T", "T", admin).apply()?;
            let escrow = TIP1028Escrow::new();
            let receipt = receipt_v1(
                Address::random(),
                Address::random(),
                1,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            for (receipt_version, receipt_bytes) in [
                (BLOCKED_RECEIPT_VERSION + 1, receipt.abi_encode().into()),
                (BLOCKED_RECEIPT_VERSION, vec![0xde, 0xad, 0xbe, 0xef].into()),
            ] {
                let result =
                    escrow.blocked_receipt_balance(ITIP1028Escrow::blockedReceiptBalanceCall {
                        token: token.address(),
                        recoveryAuthority: Address::ZERO,
                        receiptVersion: receipt_version,
                        receipt: receipt_bytes,
                    });
                assert!(matches!(
                    result,
                    Err(e) if e == TIP1028EscrowError::invalid_receipt_claim().into()
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
                let result = TIP1028Escrow::new().store_blocked(
                    token.address(),
                    Address::random(),
                    Address::random(),
                    Address::random(),
                    Address::ZERO,
                    U256::from(1u64),
                    blocked_reason,
                    kind,
                    B256::ZERO,
                );
                assert!(matches!(
                    result,
                    Err(e) if e == TIP1028EscrowError::invalid_receipt_claim().into()
                ));
            }

            Ok(())
        })
    }

    #[test]
    fn test_store_emits_transfer_blocked_for_transfers() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_001u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let recipient = Address::random();
        let recovery = Address::random();
        let amount = U256::from(42u64);
        let memo = B256::repeat_byte(0x42);

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("T", "T", admin).apply()?;
            let mut escrow = TIP1028Escrow::new();

            let (nonce, blocked_at) = escrow.store_blocked(
                token.address(),
                originator,
                receiver,
                recipient,
                recovery,
                amount,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            )?;

            escrow.assert_emitted_events(vec![TIP1028EscrowEvent::TransferBlocked(
                ITIP1028Escrow::TransferBlocked {
                    token: token.address(),
                    from: originator,
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: nonce,
                    blockedAt: blocked_at,
                    recipient,
                    amount,
                    blockedReason: BlockedReason::RECEIVE_POLICY as u8,
                    recoveryAuthority: recovery,
                    memo,
                },
            )]);

            escrow.clear_emitted_events();
            escrow.store_blocked(
                token.address(),
                Address::ZERO,
                receiver,
                recipient,
                recovery,
                amount,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::MINT,
                memo,
            )?;
            escrow.assert_emitted_events(Vec::<TIP1028EscrowEvent>::new());

            Ok(())
        })
    }

    #[test]
    fn test_receipt_key_binds_receipt_fields() -> eyre::Result<()> {
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
            let mut escrow = TIP1028Escrow::new();

            let (nonce_a, blocked_at_a) = escrow.store_blocked(
                token_a.address(),
                originator_a,
                recipient,
                recipient,
                recovery,
                amount_a,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            )?;
            let (nonce_b, blocked_at_b) = escrow.store_blocked(
                token_a.address(),
                originator_b,
                recipient,
                recipient,
                recovery,
                amount_b,
                BlockedReason::TOKEN_FILTER,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            )?;

            let receipt_a = receipt_v1(
                originator_a,
                recipient,
                blocked_at_a,
                nonce_a,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                memo,
            );
            let receipt_b = receipt_v1(
                originator_b,
                recipient,
                blocked_at_b,
                nonce_b,
                BlockedReason::TOKEN_FILTER,
                InboundKind::MINT,
                B256::repeat_byte(0x22),
            );

            assert_eq!(
                receipt_balance(&escrow, token_a.address(), recovery, &receipt_a)?,
                amount_a
            );
            assert_eq!(
                receipt_balance(&escrow, token_a.address(), recovery, &receipt_b)?,
                amount_b
            );

            let mutated_receipts = [
                receipt_v1(
                    Address::random(),
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    Address::random(),
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    recipient,
                    blocked_at_a + 1,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a + 1,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::TOKEN_FILTER,
                    InboundKind::TRANSFER,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::MINT,
                    memo,
                ),
                receipt_v1(
                    originator_a,
                    recipient,
                    blocked_at_a,
                    nonce_a,
                    BlockedReason::RECEIVE_POLICY,
                    InboundKind::TRANSFER,
                    B256::repeat_byte(0x33),
                ),
            ];

            for mutated in mutated_receipts {
                assert_eq!(
                    receipt_balance(&escrow, token_a.address(), recovery, &mutated)?,
                    U256::ZERO
                );
            }
            assert_eq!(
                receipt_balance(&escrow, token_a.address(), Address::random(), &receipt_a)?,
                U256::ZERO
            );
            assert_eq!(
                receipt_balance(&escrow, token_b.address(), recovery, &receipt_a)?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_rejects_missing_receipt() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_003u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(100u64);
        let receipt = receipt_v1(
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

            assert_invalid_receipt(TIP1028Escrow::new().claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            ));

            block_all_senders(receiver, Address::ZERO)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;
            TIP1028Escrow::new().claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            )?;
            assert_invalid_receipt(TIP1028Escrow::new().claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
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
            block_all_senders(receiver, Address::ZERO)?;
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

            let self_receipt = receipt_v1(
                originator,
                receiver,
                1_728_004,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let recovery_receipt = receipt_v1(
                originator,
                recovery_receiver,
                1_728_004,
                2,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            assert_unauthorized(TIP1028Escrow::new().claim(
                stranger,
                claim_call(token.address(), Address::ZERO, &self_receipt),
            ));
            for caller in [recovery_receiver, stranger] {
                assert_unauthorized(TIP1028Escrow::new().claim(
                    caller,
                    claim_call(token.address(), recovery, &recovery_receipt),
                ));
            }

            assert_eq!(
                receipt_balance(
                    &TIP1028Escrow::new(),
                    token.address(),
                    Address::ZERO,
                    &self_receipt
                )?,
                amount
            );
            assert_eq!(
                receipt_balance(
                    &TIP1028Escrow::new(),
                    token.address(),
                    recovery,
                    &recovery_receipt
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
            block_all_senders(receiver, Address::ZERO)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let receipt = receipt_v1(
                originator,
                receiver,
                1_728_005,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );

            let mut escrow = TIP1028Escrow::new();
            escrow.clear_emitted_events();
            escrow.claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            )?;

            escrow.assert_emitted_events(vec![TIP1028EscrowEvent::BlockedReceiptClaimed(
                ITIP1028Escrow::BlockedReceiptClaimed {
                    token: token.address(),
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_005,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: Address::ZERO,
                    caller: receiver,
                    amount,
                },
            )]);
            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &receipt)?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
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

            let receipt = receipt_v1(
                originator,
                receiver,
                1_728_006,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut escrow = TIP1028Escrow::new();
            escrow.clear_emitted_events();
            escrow.claim(recovery, claim_call(token.address(), recovery, &receipt))?;

            escrow.assert_emitted_events(vec![TIP1028EscrowEvent::BlockedReceiptClaimed(
                ITIP1028Escrow::BlockedReceiptClaimed {
                    token: token.address(),
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_006,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: recovery,
                    caller: recovery,
                    amount,
                },
            )]);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: recovery })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_sender_recovery_claim_releases_to_originator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_007u64));

        let admin = Address::random();
        let originator = Address::random();
        let receiver = Address::random();
        let amount = U256::from(64u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .with_mint(originator, amount)
                .apply()?;
            block_all_senders(receiver, RECOVERY_SENDER)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: receiver,
                    amount,
                },
            )?;

            let receipt = receipt_v1(
                originator,
                receiver,
                1_728_007,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut escrow = TIP1028Escrow::new();
            escrow.clear_emitted_events();
            escrow.claim(
                originator,
                claim_call(token.address(), RECOVERY_SENDER, &receipt),
            )?;

            escrow.assert_emitted_events(vec![TIP1028EscrowEvent::BlockedReceiptClaimed(
                ITIP1028Escrow::BlockedReceiptClaimed {
                    token: token.address(),
                    receiver,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_007,
                    originator,
                    recipient: receiver,
                    recoveryAuthority: RECOVERY_SENDER,
                    caller: originator,
                    amount,
                },
            )]);

            assert_eq!(
                receipt_balance(&escrow, token.address(), RECOVERY_SENDER, &receipt)?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: originator
                })?,
                amount
            );

            Ok(())
        })
    }

    #[test]
    fn test_claim_rolls_back_on_release_error() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_011u64));

        let admin = Address::random();
        let receiver = Address::random();
        let amount = U256::from(64u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .apply()?;
            block_all_senders(receiver, RECOVERY_SENDER)?;
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: receiver,
                    amount,
                },
            )?;

            let receipt = receipt_v1(
                Address::ZERO,
                receiver,
                1_728_011,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::MINT,
                B256::ZERO,
            );
            let escrow = TIP1028Escrow::new();
            let result = TIP1028Escrow::new().claim(
                Address::ZERO,
                claim_call(token.address(), RECOVERY_SENDER, &receipt),
            );
            assert_eq!(result.unwrap_err(), TIP20Error::invalid_recipient().into());

            assert_eq!(
                receipt_balance(&escrow, token.address(), RECOVERY_SENDER, &receipt)?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
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

            let receipt = receipt_v1(
                originator,
                receiver,
                1_728_008,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let escrow = TIP1028Escrow::new();
            assert_eq!(
                receipt_balance(&escrow, token.address(), recovery, &receipt)?,
                amount
            );
            assert_eq!(
                receipt_balance(&escrow, token.address(), Address::ZERO, &receipt)?,
                U256::ZERO
            );
            assert_eq!(
                receipt_balance(&escrow, token.address(), other_recovery, &receipt)?,
                U256::ZERO
            );

            assert_invalid_receipt(TIP1028Escrow::new().claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            ));
            assert_invalid_receipt(TIP1028Escrow::new().claim(
                other_recovery,
                claim_call(token.address(), other_recovery, &receipt),
            ));
            TIP1028Escrow::new()
                .claim(recovery, claim_call(token.address(), recovery, &receipt))?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: recovery })?,
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
            block_all_senders(VIRTUAL_MASTER, Address::ZERO)?;
            token.transfer(
                originator,
                ITIP20::transferCall {
                    to: virtual_addr,
                    amount,
                },
            )?;

            let receipt = receipt_v1(
                originator,
                virtual_addr,
                1_728_009,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::TRANSFER,
                B256::ZERO,
            );
            let mut escrow = TIP1028Escrow::new();
            escrow.clear_emitted_events();
            escrow.claim(
                VIRTUAL_MASTER,
                claim_call(token.address(), Address::ZERO, &receipt),
            )?;

            escrow.assert_emitted_events(vec![TIP1028EscrowEvent::BlockedReceiptClaimed(
                ITIP1028Escrow::BlockedReceiptClaimed {
                    token: token.address(),
                    receiver: VIRTUAL_MASTER,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    blockedNonce: 1,
                    blockedAt: 1_728_009,
                    originator,
                    recipient: virtual_addr,
                    recoveryAuthority: Address::ZERO,
                    caller: VIRTUAL_MASTER,
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        storage.set_timestamp(U256::from(1_728_010u64));

        let admin = Address::random();
        let receiver = Address::random();
        let amount = U256::from(144u64);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("T", "T", admin)
                .with_issuer(admin)
                .apply()?;
            block_all_senders(receiver, Address::ZERO)?;

            let mut escrow = TIP1028Escrow::new();
            escrow.clear_emitted_events();
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: receiver,
                    amount,
                },
            )?;
            escrow.assert_emitted_events(Vec::<TIP1028EscrowEvent>::new());
            assert_eq!(token.total_supply()?, amount);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
                U256::ZERO
            );

            let receipt = receipt_v1(
                Address::ZERO,
                receiver,
                1_728_010,
                1,
                BlockedReason::RECEIVE_POLICY,
                InboundKind::MINT,
                B256::ZERO,
            );
            escrow.claim(
                receiver,
                claim_call(token.address(), Address::ZERO, &receipt),
            )?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ESCROW_ADDRESS
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
}
