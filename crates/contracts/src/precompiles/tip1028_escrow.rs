pub use ITIP1028Escrow::{
    ITIP1028EscrowErrors as TIP1028EscrowError, ITIP1028EscrowEvents as TIP1028EscrowEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP1028Escrow {
        enum BlockedReason {
            NONE,
            TOKEN_FILTER,
            RECEIVE_POLICY
        }

        enum InboundKind {
            TRANSFER,
            MINT
        }

        struct ClaimReceiptV1 {
            address originator;
            address recipient;
            uint64 blockedAt;
            uint64 blockedNonce;
            BlockedReason blockedReason;
            InboundKind kind;
            bytes32 memo;
        }

        function blockedReceiptBalance(address token, address recoveryContract, uint8 receiptVersion, bytes calldata receipt) external view returns (uint256 amount);
        function claimBlocked(address token, address recoveryContract, uint8 receiptVersion, bytes calldata receipt, address to) external;

        event BlockedReceiptClaimed(address indexed token, address indexed receiver, uint8 receiptVersion, uint64 indexed blockedNonce, uint64 blockedAt, address originator, address recipient, address recoveryContract, address caller, address to, uint256 amount);

        error UnauthorizedClaimer();
        error InvalidReceiptClaim();
        error ClaimDestinationUnauthorized();
        error InsufficientEscrowBalance();
        error EscrowAddressReserved();
        error InvalidToken();
    }
}

impl TIP1028EscrowError {
    pub const fn unauthorized_claimer() -> Self {
        Self::UnauthorizedClaimer(ITIP1028Escrow::UnauthorizedClaimer {})
    }

    pub const fn invalid_receipt_claim() -> Self {
        Self::InvalidReceiptClaim(ITIP1028Escrow::InvalidReceiptClaim {})
    }

    pub const fn claim_destination_unauthorized() -> Self {
        Self::ClaimDestinationUnauthorized(ITIP1028Escrow::ClaimDestinationUnauthorized {})
    }

    pub const fn insufficient_escrow_balance() -> Self {
        Self::InsufficientEscrowBalance(ITIP1028Escrow::InsufficientEscrowBalance {})
    }

    pub const fn escrow_address_reserved() -> Self {
        Self::EscrowAddressReserved(ITIP1028Escrow::EscrowAddressReserved {})
    }

    pub const fn invalid_token() -> Self {
        Self::InvalidToken(ITIP1028Escrow::InvalidToken {})
    }
}

// `BlockedReason` conversions between the canonical TIP-403 type and this interface
use super::tip403_registry::ITIP403Registry::BlockedReason as Canonical;

impl From<Canonical> for ITIP1028Escrow::BlockedReason {
    fn from(r: Canonical) -> Self {
        match r {
            Canonical::NONE => Self::NONE,
            Canonical::TOKEN_FILTER => Self::TOKEN_FILTER,
            Canonical::RECEIVE_POLICY => Self::RECEIVE_POLICY,
            Canonical::__Invalid => Self::__Invalid,
        }
    }
}
