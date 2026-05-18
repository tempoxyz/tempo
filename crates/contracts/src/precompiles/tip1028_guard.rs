pub use ITIP1028Guard::{
    ITIP1028GuardErrors as TIP1028GuardError, ITIP1028GuardEvents as BlockTransferEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP1028Guard {
        enum InboundKind {
            TRANSFER,
            MINT
        }

        struct ClaimProofV1 {
            address originator;
            address recipient;
            uint64 blockedAt;
            uint64 blockedNonce;
            uint8 blockedReason;
            InboundKind kind;
            bytes32 memo;
        }

        function balanceOf(address token, address recoveryAuthority, uint8 proofVersion, bytes calldata proof) external view returns (uint256 amount);
        function claim(address token, address recoveryAuthority, uint8 proofVersion, bytes calldata proof, address to) external;

        event TransferBlocked(address indexed token, address indexed from, address indexed receiver, uint8 proofVersion, uint64 blockedNonce, uint64 blockedAt, address recipient, uint256 amount, uint8 blockedReason, address recoveryAuthority, bytes32 memo);
        event ProofClaimed(address indexed token, address indexed receiver, uint8 proofVersion, uint64 indexed blockedNonce, uint64 blockedAt, address originator, address recipient, address recoveryAuthority, address caller, address to, uint256 amount);

        error UnauthorizedClaimer();
        error InvalidProof();
        error InsufficientBalance();
        error BlockAddressReserved();
        error InvalidClaimAddress();
        error InvalidToken();
    }
}

impl TIP1028GuardError {
    pub const fn unauthorized_claimer() -> Self {
        Self::UnauthorizedClaimer(ITIP1028Guard::UnauthorizedClaimer {})
    }

    pub const fn invalid_proof() -> Self {
        Self::InvalidProof(ITIP1028Guard::InvalidProof {})
    }

    pub const fn insufficient_balance() -> Self {
        Self::InsufficientBalance(ITIP1028Guard::InsufficientBalance {})
    }

    pub const fn block_address_reserved() -> Self {
        Self::BlockAddressReserved(ITIP1028Guard::BlockAddressReserved {})
    }

    pub const fn invalid_claim_address() -> Self {
        Self::InvalidClaimAddress(ITIP1028Guard::InvalidClaimAddress {})
    }

    pub const fn invalid_token() -> Self {
        Self::InvalidToken(ITIP1028Guard::InvalidToken {})
    }
}
