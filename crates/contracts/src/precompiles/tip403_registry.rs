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

        /// TIP-1145 flat policy mode.
        enum PolicyMode {
            ALLOW,
            DENY,
            WHITELIST,
            BLACKLIST
        }

        /// TIP-1145 token-specific authorization role selector.
        enum AuthRole {
            SENDER,
            RECIPIENT,
            MINT_RECIPIENT,
            TRANSFER,
            ALL
        }

        /// TIP-1145 membership list kind.
        enum MembershipKind {
            ISSUER,
            RECEIVE_TOKEN,
            RECEIVE_SENDER
        }

        // View Functions
        function policyIdCounter() external view returns (uint64);
        function policyExists(uint64 policyId) external view returns (bool);
        function tokenTransferPolicyId(address token) external view returns (bool isSet, uint64 policyId);
        function policyData(uint64 policyId) external view returns (PolicyType policyType, address admin);
        function isAuthorized(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedSender(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedRecipient(uint64 policyId, address user) external view returns (bool);
        function isAuthorizedMintRecipient(uint64 policyId, address user) external view returns (bool);
        function compoundPolicyData(uint64 policyId) external view returns (uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId);
        function receivePolicy(address account) external view returns (bool hasReceivePolicy, uint64 senderPolicyId, PolicyType senderPolicyType, uint64 tokenFilterId, PolicyType tokenFilterType, address recoveryAuthority);
        function validateReceivePolicy(address token, address sender, address receiver) external view returns (bool authorized, BlockedReason blockedReason);

        // TIP-1145 views
        function tokenPolicy(address token) external view returns (bool isSet, PolicyMode senderMode, PolicyMode recipientMode, PolicyMode mintRecipientMode);
        function tokenUserFlags(address token, address account) external view returns (uint8 flags);
        function isTokenAuthorized(address token, address account, AuthRole role) external view returns (bool authorized);
        function receiveConfig(address receiver) external view returns (bool hasReceivePolicy, PolicyMode tokenMode, PolicyMode senderMode, address recoveryAuthority);
        function receiveSenderMembership(address receiver, address sender) external view returns (bool member);

        // State-Changing Functions
        function createPolicy(address admin, PolicyType policyType) external returns (uint64);
        function createPolicyWithAccounts(address admin, PolicyType policyType, address[] calldata accounts) external returns (uint64);
        function setPolicyAdmin(uint64 policyId, address admin) external;
        function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external;
        function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;
        function createCompoundPolicy(uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId) external returns (uint64);
        function setReceivePolicy(uint64 senderPolicyId, uint64 tokenFilterId, address recoveryAuthority) external;
        function migrateTransferPolicyIds(address[] calldata tokens) external returns (uint256 migrated);

        // TIP-1145 setters
        function setTokenPolicyModes(address token, PolicyMode senderMode, PolicyMode recipientMode, PolicyMode mintRecipientMode) external;
        function addTokenMembers(address token, address[] calldata accounts, AuthRole role) external;
        function removeTokenMembers(address token, address[] calldata accounts, AuthRole role) external;
        function setReceiveConfig(PolicyMode tokenMode, PolicyMode senderMode, address recoveryAuthority) external;
        function addReceiveTokens(address[] calldata tokens) external;
        function removeReceiveTokens(address[] calldata tokens) external;
        function addReceiveSenders(address[] calldata senders) external;
        function removeReceiveSenders(address[] calldata senders) external;

        // Events
        event PolicyAdminUpdated(uint64 indexed policyId, address indexed updater, address indexed admin);
        event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);
        event WhitelistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool allowed);
        event BlacklistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool restricted);
        event CompoundPolicyCreated(uint64 indexed policyId, address indexed creator, uint64 senderPolicyId, uint64 recipientPolicyId, uint64 mintRecipientPolicyId);
        event ReceivePolicyUpdated(address indexed account, uint64 senderPolicyId, uint64 tokenFilterId, address recoveryAuthority);
        event TransferPolicyUpdated(address indexed token, PolicyMode senderMode, PolicyMode recipientMode, PolicyMode mintRecipientMode);
        event ReceivePolicyUpdated(address indexed receiver, PolicyMode tokenMode, PolicyMode senderMode, address recoveryAuthority);
        event PolicyMembershipUpdated(MembershipKind kind, address indexed owner, address indexed account, AuthRole role, bool isMember);

        // Errors
        error Unauthorized();
        error PolicyNotFound();
        error PolicyNotSimple();
        error InvalidPolicyType();
        error IncompatiblePolicyType();
        error VirtualAddressNotAllowed();
        error InvalidReceivePolicyType();
        error InvalidRecoveryAuthority();
        error InvalidToken();
        error InvalidPolicyMode();
        error InvalidAuthRole();
        error AddressReserved();
        error TokenPolicyIdsUnsupported();
        error ReceivePolicyIdsUnsupported();
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
