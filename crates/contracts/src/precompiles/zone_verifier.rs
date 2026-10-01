//! ABI for the TIP-1098 native Zone verifier.

pub use IZoneVerifier::IZoneVerifierErrors as ZoneVerifierError;

crate::sol! {
    /// Proof-agnostic Zone verifier ABI retained by TIP-1098.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZoneVerifier {
        struct BlockTransition {
            bytes32 prevBlockHash;
            bytes32 nextBlockHash;
        }

        struct DepositQueueTransition {
            bytes32 prevProcessedHash;
            bytes32 nextProcessedHash;
            uint64 prevDepositNumber;
            uint64 nextDepositNumber;
        }

        struct TokenEnablementTransition {
            uint64 prevProcessedTokenCount;
            uint64 nextProcessedTokenCount;
        }

        /// Approved PCR0/1/2 measurements recorded when a policy entry became active.
        struct PcrEntry {
            uint8 hardfork;
            uint64 activationBlock;
            bytes pcr0;
            bytes pcr1;
            bytes pcr2;
        }

        error Unauthorized();
        error PcrHistoryMismatch(uint256 index);
        error PcrHistoryIndexOutOfBounds(uint256 index);

        function verify(
            uint32 zoneId,
            uint64 tempoBlockNumber,
            uint64 anchorBlockNumber,
            bytes32 anchorBlockHash,
            uint64 expectedWithdrawalBatchIndex,
            uint256 nextZoneHeight,
            BlockTransition calldata blockTransition,
            DepositQueueTransition calldata depositQueueTransition,
            TokenEnablementTransition calldata tokenEnablementTransition,
            bytes32 withdrawalQueueHash,
            bytes calldata verifierConfig,
            bytes calldata proof
        ) external view returns (bool);

        function pcrHistoryLength() external view returns (uint256);

        function pcrHistory(uint256 index) external view returns (PcrEntry memory);

        /// System call that appends newly active PCR policy entries and checks recorded ones.
        function syncPcrHistory() external;
    }

    /// EIP-712 statement committed to a Nitro attestation's `user_data`.
    #[derive(Debug, PartialEq, Eq)]
    struct NitroBatchAttestation {
        uint256 parentChainId;
        address verifier;
        uint32 zoneId;
        uint64 tempoBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        uint64 expectedWithdrawalBatchIndex;
        uint256 nextZoneHeight;
        bytes32 prevBlockHash;
        bytes32 nextBlockHash;
        bytes32 prevProcessedHash;
        bytes32 nextProcessedHash;
        uint64 prevDepositNumber;
        uint64 nextDepositNumber;
        uint64 prevProcessedTokenCount;
        uint64 nextProcessedTokenCount;
        bytes32 withdrawalQueueHash;
        bytes32 verifierConfigHash;
    }
}
