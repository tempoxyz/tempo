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
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolValue,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt;

/// Version tag for the v1 [`ITIP1028Escrow::ClaimReceiptV1`] layout.
pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

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
            call.recoveryContract,
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
                    recoveryContract: recovery_address,
                    memo,
                },
            ))?;
        }

        Ok((blocked_nonce, blocked_at))
    }

    /// Releases escrowed receipt funds to the authorized recipient.
    pub fn claim_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP1028Escrow::claimBlockedCall,
    ) -> Result<()> {
        if !call.token.is_tip20() {
            return Err(TIP1028EscrowError::invalid_token().into());
        }

        if call.to == ESCROW_ADDRESS {
            return Err(TIP1028EscrowError::invalid_claim_address().into());
        }

        let receipt = Self::decode_v1(call.receiptVersion, &call.receipt)?;
        let receiver = AddressRegistry::new()
            .resolve_recipient(receipt.recipient)
            .map_err(|_| TIP1028EscrowError::invalid_claim_address())?;

        let recovery_address = call.recoveryContract;
        let authorized = if recovery_address == Address::ZERO {
            msg_sender == receiver
        } else {
            msg_sender == recovery_address
        };
        if !authorized {
            return Err(TIP1028EscrowError::unauthorized_claimer().into());
        }

        let key = self.receipt_key(call.receiptVersion, call.token, recovery_address, &receipt)?;
        let amount = self.blocked_receipt_amount[key].read()?;
        if amount.is_zero() {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }

        let guard = self.storage.checkpoint();
        self.blocked_receipt_amount[key].write(U256::ZERO)?;

        // NOTE: we will update this
        // TIP20Token::from_address(call.token)?.release_from_tip1028_escrow(
        //     receiver,
        //     call.to,
        //     amount,
        //     recovery_address == Address::ZERO,
        // )?;

        self.emit_event(TIP1028EscrowEvent::BlockedReceiptClaimed(
            ITIP1028Escrow::BlockedReceiptClaimed {
                token: call.token,
                receiver,
                receiptVersion: call.receiptVersion,
                blockedNonce: receipt.blockedNonce,
                blockedAt: receipt.blockedAt,
                originator: receipt.originator,
                recipient: receipt.recipient,
                recoveryContract: recovery_address,
                caller: msg_sender,
                to: call.to,
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
