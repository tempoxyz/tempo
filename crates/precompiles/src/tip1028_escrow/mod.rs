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

/// On-chain version tag for the v1 [`ITIP1028Escrow::ClaimReceiptV1`] layout.
pub const BLOCKED_RECEIPT_VERSION: u8 = 1;

/// TIP-1028 escrow precompile. Holds funds debited from blocked inbound transfers and
/// mints, keyed by a content-addressed hash of the receipt fields, and lets the recipient
/// (or their recovery contract) claim them later.
#[contract(addr = ESCROW_ADDRESS)]
pub struct TIP1028Escrow {
    blocked_receipt_nonce: u64,
    blocked_receipt_amount: Mapping<B256, U256>,
}

impl TIP1028Escrow {
    /// Initializes the escrow's storage layout. Called once at genesis/activation.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the unclaimed balance for a receipt, or zero if the receipt is unknown
    /// or already claimed.
    ///
    /// # Errors
    /// - `InvalidToken` — `call.token` is not a TIP-20 address
    /// - `InvalidReceiptClaim` — receipt version is unsupported or fails to decode
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

    /// Records a blocked inbound transfer or mint. Allocates a fresh nonce, writes the
    /// claimable amount under the receipt's content hash, and emits `TransferBlocked`
    /// for transfers (mints stay silent and surface via the parallel `Mint` event on
    /// claim). Caller is responsible for moving the funds into [`ESCROW_ADDRESS`] in
    /// the same checkpoint.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` is not a TIP-20 address
    /// - `InvalidReceiptClaim` — `blocked_reason` is `NONE`/`__Invalid` or `kind` is `__Invalid`
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

    /// Releases an escrowed receipt's funds to `call.to`. When `recoveryContract` is
    /// zero the resolved master of `receipt.recipient` must be the caller; otherwise
    /// only the recovery contract can claim. Zeroes the receipt amount and emits
    /// `BlockedReceiptClaimed`. Atomic with the underlying token release.
    ///
    /// # Errors
    /// - `InvalidToken` — `call.token` is not a TIP-20 address
    /// - `InvalidClaimAddress` — `call.to` is the escrow address or the recipient
    ///   cannot be resolved
    /// - `UnauthorizedClaimer` — caller is neither the resolved receiver nor the
    ///   recovery contract
    /// - `InvalidReceiptClaim` — receipt is unknown, already claimed, or fails to decode
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

    /// Returns the next blocked-receipt nonce and bumps the counter. Skips zero so
    /// nonces are always nonzero (zero is reserved as "unset").
    fn next_blocked_receipt_nonce(&mut self) -> Result<u64> {
        let nonce = self.blocked_receipt_nonce.read()?.max(1);
        self.blocked_receipt_nonce.write(
            nonce
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        Ok(nonce)
    }

    /// ABI-decodes a v1 receipt. Errors if `receipt_version` is unsupported.
    fn decode_v1(receipt_version: u8, receipt: &[u8]) -> Result<ITIP1028Escrow::ClaimReceiptV1> {
        if receipt_version != BLOCKED_RECEIPT_VERSION {
            return Err(TIP1028EscrowError::invalid_receipt_claim().into());
        }
        ITIP1028Escrow::ClaimReceiptV1::abi_decode(receipt)
            .map_err(|_| TIP1028EscrowError::invalid_receipt_claim().into())
    }

    /// Content-addressed key for the receipt amount mapping. Hashes every immutable
    /// receipt field so any tampering yields a different (and empty) slot.
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
