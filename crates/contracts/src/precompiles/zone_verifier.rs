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

        function verify(
            uint32 zoneId,
            uint64 tempoBlockNumber,
            uint64 anchorBlockNumber,
            bytes32 anchorBlockHash,
            uint64 expectedWithdrawalBatchIndex,
            BlockTransition calldata blockTransition,
            DepositQueueTransition calldata depositQueueTransition,
            bytes32 withdrawalQueueHash,
            bytes calldata verifierConfig,
            bytes calldata proof
        ) external view returns (bool);
    }
}
