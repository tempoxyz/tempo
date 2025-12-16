use alloy_sol_types::sol;

pub use ITIP403Registry::{
    ITIP403RegistryErrors as TIP403RegistryError, ITIP403RegistryEvents as TIP403RegistryEvent,
};

sol! {
   #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface ITIP403Registry {
        // Enums
        enum PolicyType {
            WHITELIST,
            BLACKLIST
        }

        // View Functions
        function policyIdCounter() external view returns (uint64);
        function policyData(uint64 policyId) external view returns (PolicyType policyType, address admin);
        function isAuthorized(uint64 policyId, address user) external view returns (bool);

        // State-Changing Functions
        function createPolicy(address admin, PolicyType policyType) external returns (uint64);
        function createPolicyWithAccounts(address admin, PolicyType policyType, address[] calldata accounts) external returns (uint64);
        function setPolicyAdmin(uint64 policyId, address admin) external;
        function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external;
        function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;

        // Events
        event PolicyAdminUpdated(uint64 indexed policyId, address indexed updater, address indexed admin);
        event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);
        event WhitelistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool allowed);
        event BlacklistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool restricted);

        // Errors
        error Unauthorized();
        error IncompatiblePolicyType();
    }
}

impl TIP403RegistryError {
    /// Creates an error for unauthorized calls
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITIP403Registry::Unauthorized {})
    }

    /// Creates an error for incompatible policy types
    pub const fn incompatible_policy_type() -> Self {
        Self::IncompatiblePolicyType(ITIP403Registry::IncompatiblePolicyType {})
    }
}
