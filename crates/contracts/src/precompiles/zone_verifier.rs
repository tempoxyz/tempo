//! ABI for the TIP-1098 native Zone verifier.

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
