pub use IConfigurableAccount::{
    IConfigurableAccountErrors as ConfigurableAccountError,
    IConfigurableAccountEvents as ConfigurableAccountEvent,
};

sol! {
    /// Configurable account precompile.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IConfigurableAccount {
        struct ConfigurableAccountOwner {
            address owner;
            uint8 weight;
        }

        struct ConfigurableAccountConfig {
            bytes32 salt;
            uint64 version;
            uint8 threshold;
            ConfigurableAccountOwner[] owners;
        }

        event ConfigurableAccountConfigUpdated(
            address indexed account,
            bytes32 salt,
            uint64 version,
            uint8 threshold,
            ConfigurableAccountOwner[] owners
        );

        event AccountUpgraded(
            address indexed account,
            bytes32 indexed commitment,
            bytes32 salt,
            uint8 threshold,
            ConfigurableAccountOwner[] owners
        );

        function deriveAccount(bytes32 salt, uint8 threshold, ConfigurableAccountOwner[] calldata owners)
            external
            pure
            returns (address account);
        function getConfigCommitment(address account) external view returns (bytes32 commitment);
        function updateConfig(
            ConfigurableAccountConfig calldata current,
            uint8 threshold,
            ConfigurableAccountOwner[] calldata owners
        ) external;
        /// Migrates `msg.sender` using `threshold` and sorted `owners`, returning the stored hash.
        /// Only a direct primitive-root transaction with this call as its sole call may invoke it.
        function upgradeAccount(uint8 threshold, ConfigurableAccountOwner[] calldata owners)
            external
            returns (bytes32 commitment);

        error InvalidAccount();
        error InvalidConfig();
        error InvalidThreshold();
        error InvalidConfigurableAccountOwner();
        error InvalidWeight();
        error TooManyOwners();
        error DuplicateOwner();
        error InvalidOwnerOrder();
        error UnauthorizedConfigurableAccountCaller();
        error PrimitiveRootRequired();
        error UpgradeMustBeOnlyCall();
        error AccountAlreadyConfigurable();
        error AccountHasCode();
    }
}
