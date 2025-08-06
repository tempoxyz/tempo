use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface IRolesAuth {
        // Role Management Functions
        function grantRole(bytes32 role, address account) external;
        function revokeRole(bytes32 role, address account) external;
        function renounceRole(bytes32 role) external;
        function setRoleAdmin(bytes32 role, bytes32 adminRole) external;
        function hasRole(address account, bytes32 role) external view returns (bool);
        function getRoleAdmin(bytes32 role) external view returns (bytes32);

        // Events
        event RoleMembershipUpdated(bytes32 indexed role, address indexed account, address indexed sender, bool hasRole);
        event RoleAdminUpdated(bytes32 indexed role, bytes32 indexed newAdminRole, address indexed sender);

        // Errors
        error Unauthorized();
    }

    #[derive(Debug, PartialEq, Eq)]
    interface ITIP20 {
        // Standard token functions
        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);

        // TIP20 Extensions
        function currency() external view returns (string);
        function supplyCap() external view returns (uint256);
        function paused() external view returns (bool);
        function transferPolicyId() external view returns (uint64);
        function nonces(address owner) external view returns (uint256);
        function salts(address owner, bytes4 salt) external view returns (bool);

        // Token Management
        function mint(address to, uint256 amount) external;
        function burn(uint256 amount) external;
        function burnBlocked(address from, uint256 amount) external;
        function transferWithMemo(address to, uint256 amount, bytes32 memo) external;

        // Admin Functions
        function changeTransferPolicyId(uint64 newPolicyId) external;
        function setSupplyCap(uint256 newSupplyCap) external;
        function pause() external;
        function unpause() external;

        // EIP-712 Permit
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
        function DOMAIN_SEPARATOR() external view returns (bytes32);

        // Events
        event Transfer(address indexed from, address indexed to, uint256 amount);
        event Approval(address indexed owner, address indexed spender, uint256 amount);
        event Mint(address indexed to, uint256 amount);
        event Burn(address indexed from, uint256 amount);
        event BurnBlocked(address indexed from, uint256 amount);
        event TransferWithMemo(address indexed from, address indexed to, uint256 amount, bytes32 memo);
        event TransferPolicyUpdate(address indexed updater, uint64 indexed newPolicyId);
        event SupplyCapUpdate(address indexed updater, uint256 indexed newSupplyCap);
        event PauseStateUpdate(address indexed updater, bool isPaused);

        // Errors
        error InsufficientBalance();
        error InsufficientAllowance();
        error SupplyCapExceeded();
        error InvalidSignature();
        error InvalidPayload();
        error InvalidNonce();
        error StringTooLong();
        error PolicyForbids();
        error InvalidRecipient();
        error Expired();
        error SaltAlreadyUsed();
        error ContractPaused();
    }

    #[derive(Debug, PartialEq, Eq)]
    interface ITIP20Factory {
        event TokenCreated(uint256 indexed tokenId, string name, string symbol, uint8 decimals, string currency, address admin);

        function createToken(
            string memory name,
            string memory symbol,
            uint8 decimals,
            string memory currency,
            address admin
        ) external returns (uint256);

        function tokenIdCounter() external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    interface ITIP403Registry {
        // Enums
        enum PolicyType {
            WHITELIST,
            BLACKLIST
        }

        // View Functions
        function policyIdCounter() external view returns (uint64);
        function policyData(uint64 policyId) external view returns (PolicyType policyType, uint64 adminPolicyId);
        function isAuthorized(uint64 policyId, address user) external view returns (bool);

        // State-Changing Functions
        function createPolicy(uint64 adminPolicyId, PolicyType policyType) external returns (uint64);
        function createPolicyWithAccounts(uint64 adminPolicyId, PolicyType policyType, address[] accounts) external returns (uint64);
        function setPolicyAdmin(uint64 policyId, uint64 adminPolicyId) external;
        function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external;
        function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;

        // Events
        event PolicyAdminUpdated(uint64 indexed policyId, address indexed updater, uint64 indexed adminPolicyId);
        event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);
        event WhitelistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool allowed);
        event BlacklistUpdated(uint64 indexed policyId, address indexed updater, address indexed account, bool restricted);

        // Errors
        error Unauthorized();
        error IncompatiblePolicyType();
        error SelfOwnedPolicyMustBeWhitelist();
    }
}

#[macro_export]
macro_rules! tip20_err {
    ($err:ident) => {
        $crate::contracts::types::TIP20Error::$err($crate::contracts::types::ITIP20::$err {})
    };
}

#[macro_export]
macro_rules! tip403_err {
    ($err:ident) => {
        $crate::contracts::types::TIP403RegistryError::$err(
            $crate::contracts::types::ITIP403Registry::$err {},
        )
    };
}

// Use the auto-generated error and event enums
pub use IRolesAuth::{IRolesAuthErrors as RolesAuthError, IRolesAuthEvents as RolesAuthEvent};
pub use ITIP20::{ITIP20Errors as TIP20Error, ITIP20Events as TIP20Event};
pub use ITIP20Factory::ITIP20FactoryEvents as TIP20FactoryEvent;
pub use ITIP403Registry::{
    ITIP403RegistryErrors as TIP403RegistryError, ITIP403RegistryEvents as TIP403RegistryEvent,
};
