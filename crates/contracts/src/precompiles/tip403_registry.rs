pub use ITIP403Registry::{
    ITIP403RegistryErrors as TIP403RegistryError, ITIP403RegistryEvents as TIP403RegistryEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP403Registry {
        // Enums
        enum PolicyType {
            WHITELIST,
            BLACKLIST,
            COMPOUND
        }

        enum BlockedReason {
            NONE,
            TOKEN_FILTER,
            RECEIVE_POLICY
        }

        // View Functions
        function policyIdCounter() external view returns (uint64);
        function policyExists(uint64 policyId) external view returns (bool);
        function policyData(uint64 policyId) external view returns (PolicyType policyType, address admin);
        function isAuthorized(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedSender(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedRecipient(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedMintRecipient(uint64 policyId, address user) external view returns (bool);
        function compoundPolicyData(uint64 policyId) external view returns (uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId);
        function receivePolicy(address account) external view returns (bool hasReceivePolicy, uint64 senderPolicyId, PolicyType senderPolicyType, uint64 tokenFilterId, PolicyType tokenFilterType, address recoveryContract);
        function validateReceivePolicy(address token, address sender, address receiver) external view returns (bool authorized, BlockedReason blockedReason);
        function tokenFilterIdCounter() external view returns (uint64);
        function isTokenAllowed(uint64 tokenFilterId, address token) external view returns (bool);
        function tokenFilterExists(uint64 tokenFilterId) external view returns (bool);
        function tokenFilterData(uint64 tokenFilterId) external view returns (PolicyType filterType, address admin);

        // State-Changing Functions
        function createPolicy(address admin, PolicyType policyType) external returns (uint64);
        function createPolicyWithAccounts(address admin, PolicyType policyType, address[] calldata accounts) external returns (uint64);
        function setPolicyAdmin(uint64 policyId, address admin) external;
        function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external;
        function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;
        function createCompoundPolicy(uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId) external returns (uint64);
        function setReceivePolicy(uint64 senderPolicyId, uint64 tokenFilterId, address recoveryContract) external;
        function createTokenFilter(address admin, PolicyType filterType) external returns (uint64 newTokenFilterId);
        function createTokenFilterWithTokens(address admin, PolicyType filterType, address[] calldata tokens) external returns (uint64 newTokenFilterId);
        function setTokenFilterAdmin(uint64 tokenFilterId, address admin) external;
        function modifyTokenFilterWhitelist(uint64 tokenFilterId, address token, bool allowed) external;
        function modifyTokenFilterBlacklist(uint64 tokenFilterId, address token, bool restricted) external;
        function modifyTokenFilterWhitelistBatch(uint64 tokenFilterId, address[] calldata tokens, bool[] calldata allowed) external;
        function modifyTokenFilterBlacklistBatch(uint64 tokenFilterId, address[] calldata tokens, bool[] calldata restricted) external;

        // Events
        event PolicyAdminUpdated(uint64 indexed policyId, address indexed updater, address indexed admin);
        event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);
        event WhitelistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool allowed);
        event BlacklistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool restricted);
        event CompoundPolicyCreated(uint64 indexed policyId, address indexed creator, uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId);
        event ReceivePolicyUpdated(address indexed account, uint64 senderPolicyId, uint64 tokenFilterId, address recoveryContract);
        event TokenFilterCreated(uint64 indexed tokenFilterId, address indexed creator, PolicyType filterType);
        event TokenFilterAdminUpdated(uint64 indexed tokenFilterId, address indexed updater, address indexed admin);
        event TokenFilterWhitelistUpdated(uint64 indexed tokenFilterId, address indexed updater, address indexed token, bool allowed);
        event TokenFilterBlacklistUpdated(uint64 indexed tokenFilterId, address indexed updater, address indexed token, bool restricted);

        // Errors
        error Unauthorized();
        error PolicyNotFound();
        error PolicyNotSimple();
        error InvalidPolicyType();
        error IncompatiblePolicyType();
        error VirtualAddressNotAllowed();
        error InvalidReceivePolicyType();
        error TokenFilterNotFound();
        error InvalidTokenFilterType();
        error TokenFilterBatchLengthMismatch();
        error EscrowAddressReserved();
    }
}

impl ITIP403Registry::PolicyType {
    /// Returns `true` if this is a whitelist policy.
    pub const fn is_whitelist(&self) -> bool {
        matches!(self, Self::WHITELIST)
    }

    /// Returns `true` if this is a blacklist policy.
    pub const fn is_blacklist(&self) -> bool {
        matches!(self, Self::BLACKLIST)
    }

    /// Returns `true` if this is a compound policy.
    pub const fn is_compound(&self) -> bool {
        matches!(self, Self::COMPOUND)
    }
}

impl TIP403RegistryError {
    /// Creates an error for unauthorized calls
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITIP403Registry::Unauthorized {})
    }

    /// Creates an error for incompatible policy types
    pub const fn invalid_policy_type() -> Self {
        Self::InvalidPolicyType(ITIP403Registry::InvalidPolicyType {})
    }

    /// Creates an error for incompatible policy types
    pub const fn incompatible_policy_type() -> Self {
        Self::IncompatiblePolicyType(ITIP403Registry::IncompatiblePolicyType {})
    }

    /// Creates an error for non-existent policy
    pub const fn policy_not_found() -> Self {
        Self::PolicyNotFound(ITIP403Registry::PolicyNotFound {})
    }

    pub const fn policy_not_simple() -> Self {
        Self::PolicyNotSimple(ITIP403Registry::PolicyNotSimple {})
    }

    /// Virtual addresses are TIP-1022 forwarding aliases and cannot be used as policy members.
    pub const fn virtual_address_not_allowed() -> Self {
        Self::VirtualAddressNotAllowed(ITIP403Registry::VirtualAddressNotAllowed {})
    }

    pub const fn invalid_receive_policy_type() -> Self {
        Self::InvalidReceivePolicyType(ITIP403Registry::InvalidReceivePolicyType {})
    }

    pub const fn token_filter_not_found() -> Self {
        Self::TokenFilterNotFound(ITIP403Registry::TokenFilterNotFound {})
    }

    pub const fn invalid_token_filter_type() -> Self {
        Self::InvalidTokenFilterType(ITIP403Registry::InvalidTokenFilterType {})
    }

    pub const fn token_filter_batch_length_mismatch() -> Self {
        Self::TokenFilterBatchLengthMismatch(ITIP403Registry::TokenFilterBatchLengthMismatch {})
    }

    pub const fn escrow_address_reserved() -> Self {
        Self::EscrowAddressReserved(ITIP403Registry::EscrowAddressReserved {})
    }
}
