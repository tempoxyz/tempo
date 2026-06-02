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
            uint32 weight;
        }

        struct MultisigConfig {
            uint32 threshold;
            MultisigOwner[] owners;
        }

        event MultisigInitialized(address indexed account, bytes32 indexed configId);
        event MultisigConfigUpdated(
            address indexed account,
            bytes32 indexed configId,
            uint32 threshold,
            MultisigOwner[] owners
        );

        function isMultisigAccount(address account) external view returns (bool);
        function getMultisigConfigId(address account) external view returns (bytes32);
        function getMultisigConfig(address account, bytes32 configId) external view returns (MultisigConfig memory);
        function updateMultisigConfig(bytes32 configId, uint32 threshold, MultisigOwner[] calldata owners) external;

        error NotMultisigAccount();
        error InvalidAccount();
        error InvalidConfig();
        error InvalidConfigId();
        error InvalidThreshold();
        error InvalidOwner();
        error InvalidWeight();
        error TooManyOwners();
        error DuplicateOwner();
        error InvalidOwnerOrder();
        error AccountAlreadyInitialized();
        error ConfigNotFound();
        error UnauthorizedCaller();
        error SameTransactionUpdateNotAllowed();
    }
}
