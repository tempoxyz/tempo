//! [TIP-1028] escrow precompile for blocked inbound TIP-20 transfers and mints.

pub mod dispatch;

pub use tempo_contracts::precompiles::ITIP1028Escrow::{self, InboundKind};
use tempo_contracts::precompiles::{
    ITIP403Registry::{self, BlockedReason},
    TIP1028EscrowError, TIP1028EscrowEvent,
};

use crate::{
    TIP1028_ESCROW_ADDRESS,
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

pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

#[contract(addr = TIP1028_ESCROW_ADDRESS)]
pub struct TIP1028Escrow {
    blocked_receipt_nonce: u64,
    blocked_receipt_amount: Mapping<B256, U256>,
}

impl TIP1028Escrow {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

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

    #[allow(clippy::too_many_arguments)]
    pub fn store_blocked(
        &mut self,
        token: Address,
        originator: Address,
        receiver: Address,
        recipient: Address,
        recovery_contract: Address,
        amount: U256,
        blocked_reason: BlockedReason,
        kind: InboundKind,
        memo: B256,
    ) -> Result<(u64, u64)> {
        #[cfg(debug_assertions)]
        // caller (TIP20 precopmile) should validate and enforce these beforehand.
        {
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

            let resolved = AddressRegistry::new()
                .resolve_recipient(recipient)
                .map_err(|_| TIP1028EscrowError::claim_destination_unauthorized())?;
            if resolved != receiver {
                return Err(TIP1028EscrowError::invalid_receipt_claim().into());
            }
        }

        let blocked_nonce = self.next_blocked_receipt_nonce()?;
        let blocked_at = self.storage.timestamp().saturating_to::<u64>();
        let receipt = ITIP1028Escrow::ClaimReceiptV1 {
            originator,
            recipient,
            blockedAt: blocked_at,
            blockedNonce: blocked_nonce,
            blockedReason: blocked_reason.into(),
            kind,
            memo,
        };
        let key = self.receipt_key(BLOCKED_RECEIPT_VERSION, token, recovery_contract, &receipt)?;
        self.blocked_receipt_amount[key].write(amount)?;

        Ok((blocked_nonce, blocked_at))
    }

    pub fn claim_blocked(
        &mut self,
        msg_sender: Address,
        call: ITIP1028Escrow::claimBlockedCall,
    ) -> Result<()> {
        if !call.token.is_tip20() {
            return Err(TIP1028EscrowError::invalid_token().into());
        }
        if call.to == TIP1028_ESCROW_ADDRESS {
            return Err(TIP1028EscrowError::escrow_address_reserved().into());
        }

        let guard = self.storage.checkpoint();
        let receipt = Self::decode_v1(call.receiptVersion, &call.receipt)?;
        let receiver = AddressRegistry::new()
            .resolve_recipient(receipt.recipient)
            .map_err(|_| TIP1028EscrowError::claim_destination_unauthorized())?;

        let authorized = if call.recoveryContract == Address::ZERO {
            msg_sender == receiver
        } else {
            msg_sender == call.recoveryContract
        };
        if !authorized {
            return Err(TIP1028EscrowError::unauthorized_claimer().into());
        }

        let key = self.receipt_key(
            call.receiptVersion,
            call.token,
            call.recoveryContract,
            &receipt,
        )?;
        let amount = self.blocked_receipt_amount[key].read()?;
        if amount.is_zero() {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }
        self.blocked_receipt_amount[key].write(U256::ZERO)?;

        TIP20Token::from_address(call.token)?.release_from_tip1028_escrow(
            receiver,
            receipt.originator,
            call.to,
            amount,
            call.recoveryContract == Address::ZERO,
        )?;

        self.emit_event(TIP1028EscrowEvent::BlockedReceiptClaimed(
            ITIP1028Escrow::BlockedReceiptClaimed {
                token: call.token,
                receiver,
                receiptVersion: call.receiptVersion,
                blockedNonce: receipt.blockedNonce,
                blockedAt: receipt.blockedAt,
                originator: receipt.originator,
                recipient: receipt.recipient,
                recoveryContract: call.recoveryContract,
                caller: msg_sender,
                to: call.to,
                amount,
            },
        ))?;

        guard.commit();
        Ok(())
    }

    fn next_blocked_receipt_nonce(&mut self) -> Result<u64> {
        let nonce = self.blocked_receipt_nonce.read()?.max(1);
        self.blocked_receipt_nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    fn decode_v1(receipt_version: u8, receipt: &[u8]) -> Result<ITIP1028Escrow::ClaimReceiptV1> {
        if receipt_version != BLOCKED_RECEIPT_VERSION {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }
        ITIP1028Escrow::ClaimReceiptV1::abi_decode(receipt)
            .map_err(|_| TIP1028EscrowError::invalid_receipt_claim().into())
    }

    fn receipt_key(
        &self,
        receipt_version: u8,
        token: Address,
        recovery_contract: Address,
        receipt: &ITIP1028Escrow::ClaimReceiptV1,
    ) -> Result<B256> {
        self.storage.keccak256(
            (
                U256::from(receipt_version),
                token,
                receipt.originator,
                receipt.recipient,
                recovery_contract,
                receipt.blockedReason,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::U256;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_store_blocked_rejects_fabricated_or_invalid_receipts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        let originator = Address::random();
        let receiver = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut escrow = TIP1028Escrow::new();

            let err = escrow.store_blocked(
                Address::random(),
                originator,
                receiver,
                receiver,
                Address::ZERO,
                U256::from(100),
                BlockedReason::RECEIVE_POLICY,
                ITIP1028Escrow::InboundKind::TRANSFER,
                B256::ZERO,
            );
            assert_eq!(err.unwrap_err(), TIP1028EscrowError::invalid_token().into());

            let err = escrow.store_blocked(
                PATH_USD_ADDRESS,
                originator,
                receiver,
                receiver,
                Address::ZERO,
                U256::from(100),
                BlockedReason::NONE,
                ITIP1028Escrow::InboundKind::TRANSFER,
                B256::ZERO,
            );
            assert_eq!(
                err.unwrap_err(),
                TIP1028EscrowError::invalid_receipt_claim().into()
            );

            Ok(())
        })
    }
}
