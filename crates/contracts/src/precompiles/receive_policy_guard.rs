pub use IReceivePolicyGuard::{
    IReceivePolicyGuardErrors as ReceivePolicyGuardError,
    IReceivePolicyGuardEvents as ReceivePolicyGuardEvent,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IReceivePolicyGuard {
        enum InboundKind {
            TRANSFER,
            MINT
        }

        /// @notice Claim receipt for one blocked inbound transfer or mint.
        /// @dev `recipient` is the addressed `to` value and may be virtual. The corresponding
        ///      `receiver` emitted in events is the resolved account/master where funds settle.
        struct ClaimReceiptV1 {
            /// @notice Receipt layout version. Must equal `1` for this struct.
            uint8 version;
            /// @notice TIP-20 token whose blocked funds are held by the guard.
            address token;
            /// @notice Address with the authority to claim the blocked funds.
            address recoveryAuthority;
            /// @notice Original sender/originator of the blocked transfer or mint.
            address originator;
            /// @notice Addressed recipient from the inbound operation; may be a virtual address.
            address recipient;
            /// @notice Block timestamp when the inbound operation was blocked.
            uint64 blockedAt;
            /// @notice Guard nonce assigned when the inbound operation was blocked.
            uint64 blockedNonce;
            /// @notice TIP-403 blocked reason encoded as a `BlockedReason` discriminant.
            uint8 blockedReason;
            /// @notice Whether the blocked inbound operation was a transfer or mint.
            InboundKind kind;
            /// @notice Application memo copied from the blocked inbound operation.
            bytes32 memo;
        }

        function balanceOf(bytes calldata receipt) external view returns (uint256 amount);
        function claim(address to, bytes calldata receipt) external;
        function burnBlockedReceipt(bytes calldata receipt) external;

        /// @notice Emitted when an inbound TIP-20 transfer or mint is blocked and funds are redirected.
        /// @param token TIP-20 token whose funds are held by the guard.
        /// @param from Original sender/originator of the blocked operation.
        /// @param receiver Resolved account where funds would settle; for virtual recipients its their master.
        /// @param receiptVersion Claim receipt layout version.
        /// @param blockedNonce Guard nonce assigned to the blocked operation.
        /// @param blockedAt Block timestamp when the operation was blocked.
        /// @param recipient Addressed recipient from the inbound operation; may be virtual.
        /// @param amount Amount of blocked funds held by the guard.
        /// @param blockedReason TIP-403 blocked reason encoded as a `BlockedReason` discriminant.
        /// @param recoveryAuthority Claim authority: originator, receiver, or third-party address.
        /// @param memo Application memo copied from the blocked inbound operation.
        event TransferBlocked(address indexed token, address indexed from, address indexed receiver, uint8 receiptVersion, uint64 blockedNonce, uint64 blockedAt, address recipient, uint256 amount, uint8 blockedReason, address recoveryAuthority, bytes32 memo);

        /// @notice Emitted when blocked funds are claimed with a valid receipt.
        /// @param token TIP-20 token released by the guard.
        /// @param receiver Resolved account where funds would settle; for virtual recipients its their master.
        /// @param receiptVersion Claim receipt layout version.
        /// @param blockedNonce Guard nonce from the claimed receipt.
        /// @param blockedAt Block timestamp from the claimed receipt.
        /// @param originator Original sender/originator from the claimed receipt.
        /// @param recipient Addressed recipient from the claimed receipt; may be virtual.
        /// @param recoveryAuthority Claim authority from the claimed receipt.
        /// @param caller Account that submitted the claim.
        /// @param to Address where released funds were sent.
        /// @param amount Amount of funds released.
        event ReceiptClaimed(address indexed token, address indexed receiver, uint8 receiptVersion, uint64 indexed blockedNonce, uint64 blockedAt, address originator, address recipient, address recoveryAuthority, address caller, address to, uint256 amount);

        error InvalidReceipt();
        error InvalidClaimAddress();
        error UnauthorizedClaimer();
        error AddressReserved();
    }
}

impl IReceivePolicyGuard::ClaimReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: Address,
        recovery_address: Address,
        originator: Address,
        recipient: Address,
        at: u64,
        nonce: u64,
        reason: u8,
        kind: IReceivePolicyGuard::InboundKind,
        memo: B256,
    ) -> Self {
        // Ensure receipt doesn't use the `address(0)` sentinel.
        let recovery_auth = if recovery_address.is_zero() {
            originator
        } else {
            recovery_address
        };

        Self {
            version: 1,
            token,
            recoveryAuthority: recovery_auth,
            originator,
            recipient,
            blockedAt: at,
            blockedNonce: nonce,
            blockedReason: reason,
            kind,
            memo,
        }
    }

    pub fn claimed_event(
        &self,
        receiver: Address,
        caller: Address,
        to: Address,
        amount: U256,
    ) -> ReceivePolicyGuardEvent {
        ReceivePolicyGuardEvent::ReceiptClaimed(IReceivePolicyGuard::ReceiptClaimed {
            token: self.token,
            originator: self.originator,
            receiver,
            receiptVersion: self.version,
            blockedNonce: self.blockedNonce,
            blockedAt: self.blockedAt,
            recipient: self.recipient,
            recoveryAuthority: self.recoveryAuthority,
            caller,
            to,
            amount,
        })
    }

    pub fn blocked_event(&self, receiver: Address, amount: U256) -> ReceivePolicyGuardEvent {
        ReceivePolicyGuardEvent::TransferBlocked(IReceivePolicyGuard::TransferBlocked {
            token: self.token,
            from: self.originator,
            receiver,
            receiptVersion: self.version,
            blockedNonce: self.blockedNonce,
            blockedAt: self.blockedAt,
            recipient: self.recipient,
            amount,
            blockedReason: self.blockedReason,
            recoveryAuthority: self.recoveryAuthority,
            memo: self.memo,
        })
    }
}

impl TryFrom<alloy_primitives::Bytes> for IReceivePolicyGuard::ClaimReceiptV1 {
    type Error = ReceivePolicyGuardError;

    fn try_from(receipt: alloy_primitives::Bytes) -> Result<Self, Self::Error> {
        Self::abi_decode(&receipt).map_err(|_| ReceivePolicyGuardError::invalid_receipt())
    }
}
