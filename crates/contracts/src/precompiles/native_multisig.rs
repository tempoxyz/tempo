pub use INativeMultisig::{
    INativeMultisigErrors as NativeMultisigError, INativeMultisigEvents as NativeMultisigEvent,
};

crate::sol! {
    /// Native multisig account precompile.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface INativeMultisig {
        struct MultisigOwner {
            address owner;
            uint8 weight;
        }

        struct MultisigConfig {
            bytes32 salt;
            uint64 version;
            uint8 threshold;
            MultisigOwner[] owners;
        }

        event MultisigConfigUpdated(
            address indexed account,
            bytes32 salt,
            uint64 version,
            uint8 threshold,
            MultisigOwner[] owners
        );

        function deriveAccount(bytes32 salt, uint8 threshold, MultisigOwner[] calldata owners)
            external
            pure
            returns (address account);
        function getConfigCommitment(address account) external view returns (bytes32 commitment);
        function updateConfig(
            MultisigConfig calldata current,
            uint8 threshold,
            MultisigOwner[] calldata owners
        ) external;

        error InvalidAccount();
        error InvalidConfig();
        error InvalidThreshold();
        error InvalidMultisigOwner();
        error InvalidWeight();
        error TooManyOwners();
        error DuplicateOwner();
        error InvalidOwnerOrder();
        error UnauthorizedMultisigCaller();
    }
}
