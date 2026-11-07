pub use ICurrentCommittee::ICurrentCommitteeErrors as CurrentCommitteeError;

crate::sol! {
    /// Current effective committee selected by consensus.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ICurrentCommittee {
        error Unauthorized();
        error Uninitialized();

        function getCommitteeMembers()
            external
            view
            returns (uint64 epoch, bytes32[] memory publicKeys);

        function setCommitteeMembers(uint64 epoch, bytes32[] calldata publicKeys) external;

        /// The DKG ceremony running during `epoch` (TIP-1123).
        ///
        /// `dealers` is the committee of `epoch`, which deals in the ceremony. `players`
        /// receive shares for `epoch + 1`. Reverts with `Uninitialized` until the first
        /// TIP-1123 boundary block writes the ceremony.
        function getDkgCeremony()
            external
            view
            returns (uint64 epoch, bytes32[] memory dealers, bytes32[] memory players, bool isRotatingNetworkIdentity);
    }
}
