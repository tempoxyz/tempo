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
            uint64 version;
            uint8 threshold;
            MultisigOwner[] owners;
        }

        event MultisigInitialized(address indexed account);
        event MultisigConfigUpdated(
            address indexed account,
            uint8 threshold,
            MultisigOwner[] owners
        );

        function deriveAccount(bytes32 salt, uint8 threshold, MultisigOwner[] calldata owners)
            external
            pure
            returns (address account);
        function isMultisigAccount(address account) external view returns (bool);
        function getConfig(address account) external view returns (MultisigConfig memory);
        function updateConfig(uint8 threshold, MultisigOwner[] calldata owners) external;

        error NotMultisigAccount();
        error InvalidAccount();
        error InvalidConfig();
        error InvalidThreshold();
        error InvalidOwner();
        error InvalidWeight();
        error TooManyOwners();
        error DuplicateOwner();
        error InvalidOwnerOrder();
        error AccountAlreadyInitialized();
        error UnauthorizedCaller();
        error SameTransactionUpdateNotAllowed();
    }
}
