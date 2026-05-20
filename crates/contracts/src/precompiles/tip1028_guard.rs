pub use ITIP1028Guard::{
    ITIP1028GuardErrors as TIP1028GuardError, ITIP1028GuardEvents as TIP1028GuardEvent,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP1028Guard {
        enum InboundKind {
            TRANSFER,
            MINT
        }

        struct ClaimProofV1 {
            // Proof metadata
            uint8 version;
            address token;
            address recoveryAuthority;
            // Blocked transfer data
            address originator;
            address recipient;
            uint64 blockedAt;
            uint64 blockedNonce;
            uint8 blockedReason;
            InboundKind kind;
            bytes32 memo;
        }

        function balanceOf(bytes calldata proof) external view returns (uint256 amount);
        function claim(address to, bytes calldata proof) external;

        event TransferBlocked(address indexed token, address indexed from, address indexed receiver, uint8 proofVersion, uint64 blockedNonce, uint64 blockedAt, address recipient, uint256 amount, uint8 blockedReason, address recoveryAuthority, bytes32 memo);
        event ProofClaimed(address indexed token, address indexed receiver, uint8 proofVersion, uint64 indexed blockedNonce, uint64 blockedAt, address originator, address recipient, address recoveryAuthority, address caller, address to, uint256 amount);

        error InvalidProof();
        error InvalidClaimAddress();
        error UnauthorizedClaimer();
        error AddressReserved();
    }
}

impl ITIP1028Guard::ClaimProofV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: Address,
        recovery_auth: Address,
        originator: Address,
        recipient: Address,
        at: u64,
        nonce: u64,
        reason: u8,
        kind: ITIP1028Guard::InboundKind,
        memo: B256,
    ) -> Self {
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
    ) -> TIP1028GuardEvent {
        TIP1028GuardEvent::ProofClaimed(ITIP1028Guard::ProofClaimed {
            token: self.token,
            originator: self.originator,
            receiver,
            proofVersion: self.version,
            blockedNonce: self.blockedNonce,
            blockedAt: self.blockedAt,
            recipient: self.recipient,
            recoveryAuthority: self.recoveryAuthority,
            caller,
            to,
            amount,
        })
    }

    pub fn blocked_event(&self, receiver: Address, amount: U256) -> TIP1028GuardEvent {
        TIP1028GuardEvent::TransferBlocked(ITIP1028Guard::TransferBlocked {
            token: self.token,
            from: self.originator,
            receiver,
            proofVersion: self.version,
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

impl TryFrom<alloy_primitives::Bytes> for ITIP1028Guard::ClaimProofV1 {
    type Error = TIP1028GuardError;

    fn try_from(proof: alloy_primitives::Bytes) -> Result<Self, Self::Error> {
        Self::abi_decode(&proof).map_err(|_| TIP1028GuardError::invalid_proof())
    }
}
