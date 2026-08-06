//! Call builders and event/receipt decoders for TIP-1028 account receive policies.
//!
//! Receive policies are configured on the [`TIP403_REGISTRY_ADDRESS`] precompile via
//! [`set_receive_policy`]. When an inbound TIP-20 transfer or mint is blocked by a
//! receive policy, the funds are redirected to the [`RECEIVE_POLICY_GUARD_ADDRESS`]
//! precompile, which emits a `TransferBlocked` event carrying an ABI-encoded receipt.
//! Blocked funds can later be released with [`claim_blocked_receipt`] or destroyed with
//! [`burn_blocked_receipt`], using the receipt bytes recovered via [`BlockedTransfer`].

use alloy_primitives::{Address, Bytes, Log, TxKind, U256};
use alloy_sol_types::{SolCall, SolEvent};
use tempo_contracts::precompiles::{
    IReceivePolicyGuard::{TransferBlocked, burnBlockedReceiptCall, claimCall},
    ITIP403Registry::setReceivePolicyCall,
    RECEIVE_POLICY_GUARD_ADDRESS, SYSTEM_PRECOMPILES, TIP403_REGISTRY_ADDRESS,
};
use tempo_primitives::{TempoAddressExt, transaction::Call};

/// Type-safe recovery authority selector for TIP-1028 receive policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAuthority {
    /// Encode originator recovery as the TIP-1028 `address(0)` sentinel.
    Originator,
    /// Encode receiver recovery as the receiver account itself.
    Receiver,
    /// Encode an explicit third-party recovery authority.
    ThirdParty(Address),
}

/// Receive-policy call-builder error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivePolicyError {
    /// The encoded recovery authority cannot ever pass `ReceivePolicyGuard.claim()`.
    InvalidRecoveryAuthority(Address),
}

impl core::fmt::Display for ReceivePolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRecoveryAuthority(address) => {
                write!(f, "invalid receive-policy recovery authority: {address}")
            }
        }
    }
}

impl std::error::Error for ReceivePolicyError {}

impl RecoveryAuthority {
    /// Encode this typed authority to the raw address expected by the TIP-403 registry.
    pub fn encode(self, receiver: Address) -> Result<Address, ReceivePolicyError> {
        let authority = match self {
            Self::Originator => Address::ZERO,
            Self::Receiver => receiver,
            Self::ThirdParty(authority) => authority,
        };
        validate_recovery_authority(authority)?;
        Ok(authority)
    }
}

/// Build a `setReceivePolicy(uint64,uint64,address)` call on the TIP-403 registry.
///
/// - `sender_policy_id`: policy applied to inbound senders (`0` to clear).
/// - `token_filter_id`: policy filtering which tokens may be received (`0` to clear).
/// - `recovery_authority`: address allowed to claim funds blocked for this account.
pub fn set_receive_policy(
    sender_policy_id: u64,
    token_filter_id: u64,
    recovery_authority: Address,
) -> Call {
    tip403_registry_call(setReceivePolicyCall {
        senderPolicyId: sender_policy_id,
        tokenFilterId: token_filter_id,
        recoveryAuthority: recovery_authority,
    })
}

/// Build a validated `setReceivePolicy(uint64,uint64,address)` call from a typed authority.
///
/// Use this helper instead of passing raw sentinel addresses in new integrations.
pub fn set_receive_policy_for_receiver(
    sender_policy_id: u64,
    token_filter_id: u64,
    receiver: Address,
    recovery_authority: RecoveryAuthority,
) -> Result<Call, ReceivePolicyError> {
    let recovery_authority = recovery_authority.encode(receiver)?;
    Ok(set_receive_policy(
        sender_policy_id,
        token_filter_id,
        recovery_authority,
    ))
}

/// Return whether `authority` is invalid for receive-policy recovery.
pub fn is_invalid_recovery_authority(authority: Address) -> bool {
    authority.is_virtual()
        || authority.is_tip20()
        || SYSTEM_PRECOMPILES
            .iter()
            .any(|&(precompile, _)| precompile == authority)
}

/// Validate a raw receive-policy recovery authority.
pub fn validate_recovery_authority(authority: Address) -> Result<(), ReceivePolicyError> {
    if authority != Address::ZERO && is_invalid_recovery_authority(authority) {
        return Err(ReceivePolicyError::InvalidRecoveryAuthority(authority));
    }
    Ok(())
}

/// Build a `claim(address,bytes)` call on the ReceivePolicyGuard to release blocked funds.
///
/// `receipt` is the ABI-encoded receipt witness emitted in the `TransferBlocked` event
/// (see [`BlockedTransfer::receipt`]). `to` is where the released funds are sent.
pub fn claim_blocked_receipt(to: Address, receipt: Bytes) -> Call {
    receive_policy_guard_call(claimCall { to, receipt })
}

/// Build a `burnBlockedReceipt(bytes)` call on the ReceivePolicyGuard.
///
/// `receipt` is the ABI-encoded receipt witness emitted in the `TransferBlocked` event
/// (see [`BlockedTransfer::receipt`]).
pub fn burn_blocked_receipt(receipt: Bytes) -> Call {
    receive_policy_guard_call(burnBlockedReceiptCall { receipt })
}

/// A decoded `TransferBlocked` event from the ReceivePolicyGuard.
///
/// Emitted when an inbound TIP-20 transfer or mint is blocked by a receive policy and the
/// funds are redirected to the guard instead of credited to the recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedTransfer {
    /// TIP-20 token whose funds are held by the guard.
    pub token: Address,
    /// Resolved account where the funds would have settled (the master for virtual
    /// recipients).
    pub receiver: Address,
    /// Guard nonce assigned to the blocked operation.
    pub blocked_nonce: u64,
    /// Amount of blocked funds held by the guard.
    pub amount: U256,
    /// Claim receipt layout version.
    pub receipt_version: u8,
    /// ABI-encoded receipt witness; pass to [`claim_blocked_receipt`] or
    /// [`burn_blocked_receipt`].
    pub receipt: Bytes,
}

impl BlockedTransfer {
    /// Decode a single `TransferBlocked` log.
    ///
    /// Returns `None` if the log is not a `TransferBlocked` event from the guard.
    pub fn from_log(log: &Log) -> Option<Self> {
        if log.address != RECEIVE_POLICY_GUARD_ADDRESS {
            return None;
        }

        let event = TransferBlocked::decode_log(log).ok()?.data;
        Some(Self {
            token: event.token,
            receiver: event.receiver,
            blocked_nonce: event.blockedNonce,
            amount: event.amount,
            receipt_version: event.receiptVersion,
            receipt: event.receipt,
        })
    }

    /// Extract every `TransferBlocked` event from a set of logs, e.g. a receipt's logs.
    ///
    /// Use this to detect whether a transfer that mined successfully was actually held by
    /// a receive policy rather than credited to the recipient.
    pub fn from_logs<'a>(logs: impl IntoIterator<Item = &'a Log>) -> Vec<Self> {
        logs.into_iter().filter_map(Self::from_log).collect()
    }
}

fn tip403_registry_call(call: impl SolCall) -> Call {
    Call {
        to: TxKind::Call(TIP403_REGISTRY_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(call.abi_encode()),
    }
}

fn receive_policy_guard_call(call: impl SolCall) -> Call {
    Call {
        to: TxKind::Call(RECEIVE_POLICY_GUARD_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(call.abi_encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, LogData, address, b256, bytes, uint};
    use tempo_contracts::precompiles::IReceivePolicyGuard::TransferBlocked;

    #[test]
    fn set_receive_policy_encodes_registry_call() {
        let recovery = address!("0x1111111111111111111111111111111111111111");
        let call = set_receive_policy(7, 9, recovery);

        assert_eq!(call.to, TxKind::Call(TIP403_REGISTRY_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        let decoded =
            setReceivePolicyCall::abi_decode(&call.input).expect("decode setReceivePolicy");
        assert_eq!(decoded.senderPolicyId, 7);
        assert_eq!(decoded.tokenFilterId, 9);
        assert_eq!(decoded.recoveryAuthority, recovery);
    }

    #[test]
    fn typed_receive_policy_encodes_recovery_authority() {
        let receiver = address!("0x1111111111111111111111111111111111111111");

        let originator =
            set_receive_policy_for_receiver(7, 9, receiver, RecoveryAuthority::Originator)
                .expect("originator recovery is valid");
        let decoded =
            setReceivePolicyCall::abi_decode(&originator.input).expect("decode setReceivePolicy");
        assert_eq!(decoded.recoveryAuthority, Address::ZERO);

        let receiver_recovery =
            set_receive_policy_for_receiver(7, 9, receiver, RecoveryAuthority::Receiver)
                .expect("receiver recovery is valid");
        let decoded = setReceivePolicyCall::abi_decode(&receiver_recovery.input)
            .expect("decode setReceivePolicy");
        assert_eq!(decoded.recoveryAuthority, receiver);

        let third_party = address!("0x2222222222222222222222222222222222222222");
        let third_party_recovery = set_receive_policy_for_receiver(
            7,
            9,
            receiver,
            RecoveryAuthority::ThirdParty(third_party),
        )
        .expect("third-party recovery is valid");
        let decoded = setReceivePolicyCall::abi_decode(&third_party_recovery.input)
            .expect("decode setReceivePolicy");
        assert_eq!(decoded.recoveryAuthority, third_party);
    }

    #[test]
    fn typed_receive_policy_rejects_unclaimable_authorities() {
        let receiver = address!("0x1111111111111111111111111111111111111111");

        for &(authority, _) in SYSTEM_PRECOMPILES {
            let err = set_receive_policy_for_receiver(
                7,
                9,
                receiver,
                RecoveryAuthority::ThirdParty(authority),
            )
            .expect_err("system precompile must be rejected");
            assert_eq!(err, ReceivePolicyError::InvalidRecoveryAuthority(authority));
        }

        let tip20 = address!("0x20c0000000000000000000000000000000000001");
        let err =
            set_receive_policy_for_receiver(7, 9, receiver, RecoveryAuthority::ThirdParty(tip20))
                .expect_err("TIP-20 authority must be rejected");
        assert_eq!(err, ReceivePolicyError::InvalidRecoveryAuthority(tip20));

        let virtual_address = Address::new_virtual(
            tempo_primitives::MasterId::from([0x12, 0x34, 0x56, 0x78]),
            tempo_primitives::UserTag::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]),
        );
        let err = set_receive_policy_for_receiver(
            7,
            9,
            receiver,
            RecoveryAuthority::ThirdParty(virtual_address),
        )
        .expect_err("virtual authority must be rejected");
        assert_eq!(
            err,
            ReceivePolicyError::InvalidRecoveryAuthority(virtual_address)
        );
    }

    #[test]
    fn claim_and_burn_target_the_guard() {
        let to = address!("0x2222222222222222222222222222222222222222");
        let receipt = bytes!("0xdeadbeef");

        let claim = claim_blocked_receipt(to, receipt.clone());
        assert_eq!(claim.to, TxKind::Call(RECEIVE_POLICY_GUARD_ADDRESS));
        let decoded = claimCall::abi_decode(&claim.input).expect("decode claim");
        assert_eq!(decoded.to, to);
        assert_eq!(decoded.receipt, receipt);

        let burn = burn_blocked_receipt(receipt.clone());
        assert_eq!(burn.to, TxKind::Call(RECEIVE_POLICY_GUARD_ADDRESS));
        let decoded = burnBlockedReceiptCall::abi_decode(&burn.input).expect("decode burn");
        assert_eq!(decoded.receipt, receipt);
    }

    #[test]
    fn blocked_transfer_round_trips_from_log() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let receiver = address!("0x3333333333333333333333333333333333333333");
        let receipt = bytes!("0xc0ffee");

        let event = TransferBlocked {
            token,
            receiver,
            blockedNonce: 42,
            amount: uint!(1000_U256),
            receiptVersion: 1,
            receipt: receipt.clone(),
        };

        let log = Log {
            address: RECEIVE_POLICY_GUARD_ADDRESS,
            data: event.encode_log_data(),
        };

        let decoded = BlockedTransfer::from_log(&log).expect("decode TransferBlocked");
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.receiver, receiver);
        assert_eq!(decoded.blocked_nonce, 42);
        assert_eq!(decoded.amount, uint!(1000_U256));
        assert_eq!(decoded.receipt_version, 1);
        assert_eq!(decoded.receipt, receipt);

        // The recovered receipt feeds straight back into the guard call builders.
        let claim = claim_blocked_receipt(receiver, decoded.receipt);
        let decoded_claim = claimCall::abi_decode(&claim.input).expect("decode claim");
        assert_eq!(decoded_claim.receipt, receipt);
    }

    #[test]
    fn from_log_ignores_unrelated_logs() {
        let log = Log {
            address: RECEIVE_POLICY_GUARD_ADDRESS,
            data: LogData::new_unchecked(
                vec![b256!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                )],
                Bytes::new(),
            ),
        };
        assert!(BlockedTransfer::from_log(&log).is_none());
    }

    #[test]
    fn from_log_ignores_transfer_blocked_from_other_address() {
        let event = TransferBlocked {
            token: address!("0x20c0000000000000000000000000000000000001"),
            receiver: address!("0x3333333333333333333333333333333333333333"),
            blockedNonce: 1,
            amount: uint!(5_U256),
            receiptVersion: 1,
            receipt: bytes!("0xabcd"),
        };
        let log = Log {
            address: address!("0x4444444444444444444444444444444444444444"),
            data: event.encode_log_data(),
        };

        assert!(BlockedTransfer::from_log(&log).is_none());
    }

    #[test]
    fn from_logs_collects_only_blocked_transfers() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let receiver = address!("0x3333333333333333333333333333333333333333");
        let event = TransferBlocked {
            token,
            receiver,
            blockedNonce: 1,
            amount: uint!(5_U256),
            receiptVersion: 1,
            receipt: bytes!("0xabcd"),
        };
        let blocked = Log {
            address: RECEIVE_POLICY_GUARD_ADDRESS,
            data: event.encode_log_data(),
        };
        let unrelated = Log {
            address: RECEIVE_POLICY_GUARD_ADDRESS,
            data: LogData::new_unchecked(
                vec![b256!(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                )],
                Bytes::new(),
            ),
        };

        let found = BlockedTransfer::from_logs([&blocked, &unrelated]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, token);
    }
}
