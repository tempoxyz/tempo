//! The configurable account precompile's interface (TIP-1107..1114), copied from Tempo main: this
//! release predates the precompile, which activates at T14, so its contracts crate lacks it.

use alloy_primitives::{Address, address};

/// The configurable account precompile.
pub const CONFIGURABLE_ACCOUNT_ADDRESS: Address =
    address!("AACC000000000000000000000000000000000000");

alloy_sol_types::sol! {
    /// Configurable account precompile.
    #[derive(Debug, PartialEq, Eq)]
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
        error UpgradeMustBeDirectCall();
        error AccountAlreadyConfigurable();
        error AccountHasCode();
    }
}
