pub use ICurrentCommittee::ICurrentCommitteeErrors as CurrentCommitteeError;

crate::sol! {
    /// Current effective committee selected by consensus.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ICurrentCommittee {
        error Unauthorized();

        function getCommitteeMembers()
            external
            view
            returns (uint64 epoch, bytes32[] memory publicKeys);

        function setCommitteeMembers(uint64 epoch, bytes32[] calldata publicKeys) external;
    }
}
