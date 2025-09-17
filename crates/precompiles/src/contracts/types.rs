use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
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
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
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
        function mint(address to, uint256 amount) external;
        function burn(uint256 amount) external;

        // TIP20 Extension
        function currency() external view returns (string);
        function supplyCap() external view returns (uint256);
        function paused() external view returns (bool);
        function transferPolicyId() external view returns (uint64);
        function nonces(address owner) external view returns (uint256);
        function salts(address owner, bytes4 salt) external view returns (bool);
        function burnBlocked(address from, uint256 amount) external;
        function mintWithMemo(address to, uint256 amount, bytes32 memo) external;
        function burnWithMemo(uint256 amount, bytes32 memo) external;
        function transferWithMemo(address to, uint256 amount, bytes32 memo) external;
        function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external;

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
        error InvalidCurrency();
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP20Factory {
        event TokenCreated(address indexed token, uint256 indexed tokenId, string name, string symbol, string currency, address admin);

        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address admin
        ) external returns (uint256);

        function tokenIdCounter() external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
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
        function createPolicyWithAccounts(address admin, PolicyType policyType, address[] accounts) external returns (uint64);
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
        error SelfOwnedPolicyMustBeWhitelist();
    }

    #[derive(Debug, PartialEq, Eq)]
    interface ITIP4217Registry {
        function getCurrencyDecimals(string currency) external view returns (uint8);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITipAccountRegistrar {
        function delegateToDefault(bytes32 hash, bytes signature) external returns (address authority);
        function getDelegationMessage() external pure returns (string memory);

        // Errors
        error InvalidSignature();
        error CodeNotEmpty();
        error NonceNotZero();
    }

    /// TIPFeeAMM interface defining the base AMM functionality for stablecoin pools.
    /// This interface provides core liquidity pool management and swap operations.
    ///
    /// NOTE: The FeeManager contract inherits from TIPFeeAMM and shares the same storage layout.
    /// When FeeManager is deployed, it effectively "is" a TIPFeeAMM with additional fee management
    /// capabilities layered on top. Both contracts operate on the same storage slots.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
    interface ITIPFeeAMM {

        // Structs
        struct Pool {
            uint128 reserveUserToken;
            uint128 reserveValidatorToken;
            uint128 pendingFeeSwapIn;
        }

        struct PoolKey {
            address token0;
            address token1;
        }

        // Pool Management
        function createPool(address userToken, address validatorToken) external;
        function getPoolId(address userToken, address validatorToken) external pure returns (bytes32);
        function getPool(address userToken, address validatorToken) external view returns (Pool memory);
        function pools(bytes32 poolId) external view returns (Pool memory);
        function poolExists(bytes32 poolId) external view returns (bool);

        // Liquidity Operations
        function mint(address userToken, address validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, address to) returns (uint256 liquidity);
        function burn(address userToken, address validatorToken, uint256 liquidity, address to) returns (uint256 amountUserToken, uint256 amountValidatorToken);

        // Liquidity Balances
        function totalSupply(bytes32 poolId) external view returns (uint256);
        function liquidityBalances(bytes32 poolId, address user) external view returns (uint256);

        // Events
        event PoolCreated(address indexed userToken, address indexed validatorToken);
        event Mint(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity);
        event Burn(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity, address to);

        // Errors
        error IdenticalAddresses();
        error ZeroAddress();
        error PoolExists();
        error PoolDoesNotExist();
        error InvalidToken();
        error InsufficientLiquidity();
        error InsufficientPoolBalance();
        error InsufficientReserves();
        error InsufficientLiquidityBalance();
        error MustDepositLowerBalanceToken();
        error InvalidAmount();
    }


    /// FeeManager interface for managing gas fee collection and distribution.
    ///
    /// IMPORTANT: FeeManager inherits from TIPFeeAMM and shares the same storage layout.
    /// This means:
    /// - FeeManager has all the functionality of TIPFeeAMM (pool management, swaps, liquidity operations)
    /// - Both contracts use the same storage slots for AMM data (pools, reserves, liquidity balances)
    /// - FeeManager extends TIPFeeAMM with additional storage slots (4-15) for fee-specific data
    /// - When deployed, FeeManager IS a TIPFeeAMM with additional fee management capabilities
    ///
    /// Storage layout:
    /// - Slots 0-3: TIPFeeAMM storage (pools, pool exists, liquidity data)
    /// - Slots 4+: FeeManager-specific storage (validator tokens, user tokens, collected fees, etc.)
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface IFeeManager {
        // Structs
        struct FeeInfo {
            uint128 amount;
            bool hasBeenSet;
        }

        // Constants
        function BASIS_POINTS() external pure returns (uint256);
        function FEE_BPS() external pure returns (uint256);

        // User preferences
        function userTokens(address user) external view returns (address);
        function validatorTokens(address validator) external view returns (address);
        function setUserToken(address token) external;
        function setValidatorToken(address token) external;

        // Fee functions
        function getFeeTokenBalance(address sender, address validator) external view returns (address, uint256);
        function executeBlock(address validator) external;

        // Fee tracking view functions
        function collectedFees(address token) external view returns (uint256);
        function getTokensWithFeesLength() external view returns (uint256);
        function getTokenWithFees(uint256 index) external view returns (address);
        function tokenInFeesArray(address token) external view returns (bool);

        // Events
        event UserTokenSet(address indexed user, address indexed token);
        event ValidatorTokenSet(address indexed validator, address indexed token);

        // Errors
        error OnlyValidator();
        error OnlySystemContract();
        error InvalidToken();
        error PoolDoesNotExist();
        error InsufficientPoolBalance();
        error InsufficientFeeTokenBalance();
    }
}

impl TIP20Error {
    /// Creates an error for insufficient token balance.
    pub const fn insufficient_balance() -> Self {
        Self::InsufficientBalance(ITIP20::InsufficientBalance {})
    }

    /// Creates an error for insufficient spending allowance.
    pub const fn insufficient_allowance() -> Self {
        Self::InsufficientAllowance(ITIP20::InsufficientAllowance {})
    }

    /// Creates an error when minting would exceed supply cap.
    pub const fn supply_cap_exceeded() -> Self {
        Self::SupplyCapExceeded(ITIP20::SupplyCapExceeded {})
    }

    /// Creates an error for invalid cryptographic signature.
    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ITIP20::InvalidSignature {})
    }

    /// Creates an error for invalid payload data.
    pub const fn invalid_payload() -> Self {
        Self::InvalidPayload(ITIP20::InvalidPayload {})
    }

    /// Creates an error for invalid or reused nonce.
    pub const fn invalid_nonce() -> Self {
        Self::InvalidNonce(ITIP20::InvalidNonce {})
    }

    /// Creates an error when string parameter exceeds maximum length.
    pub const fn string_too_long() -> Self {
        Self::StringTooLong(ITIP20::StringTooLong {})
    }

    /// Creates an error when transfer is forbidden by policy.
    pub const fn policy_forbids() -> Self {
        Self::PolicyForbids(ITIP20::PolicyForbids {})
    }

    /// Creates an error for invalid recipient address.
    pub const fn invalid_recipient() -> Self {
        Self::InvalidRecipient(ITIP20::InvalidRecipient {})
    }

    /// Creates an error when operation deadline has expired.
    pub const fn expired() -> Self {
        Self::Expired(ITIP20::Expired {})
    }

    /// Creates an error when salt has already been used.
    pub const fn salt_already_used() -> Self {
        Self::SaltAlreadyUsed(ITIP20::SaltAlreadyUsed {})
    }

    /// Creates an error when contract is paused.
    pub const fn contract_paused() -> Self {
        Self::ContractPaused(ITIP20::ContractPaused {})
    }

    /// Creates an error for invalid currency.
    pub const fn invalid_currency() -> Self {
        Self::InvalidCurrency(ITIP20::InvalidCurrency {})
    }
}

#[macro_export]
macro_rules! tip403_err {
    ($err:ident) => {
        $crate::contracts::types::TIP403RegistryError::$err(
            $crate::contracts::types::ITIP403Registry::$err {},
        )
    };
}

#[macro_export]
macro_rules! fee_manager_err {
    ($err:ident) => {
        $crate::contracts::types::IFeeManager::IFeeManagerErrors::$err(
            $crate::contracts::types::IFeeManager::$err {},
        )
    };
}

#[macro_export]
macro_rules! tip_fee_amm_err {
    ($err:ident) => {
        $crate::contracts::types::ITIPFeeAMM::ITIPFeeAMMErrors::$err(
            $crate::contracts::types::ITIPFeeAMM::$err {},
        )
    };
}

// Use the auto-generated error and event enums
pub use IFeeManager::{IFeeManagerErrors as FeeManagerError, IFeeManagerEvents as FeeManagerEvent};
pub use IRolesAuth::{IRolesAuthErrors as RolesAuthError, IRolesAuthEvents as RolesAuthEvent};
pub use ITIP20::{ITIP20Errors as TIP20Error, ITIP20Events as TIP20Event};
pub use ITIP20Factory::ITIP20FactoryEvents as TIP20FactoryEvent;
pub use ITIP403Registry::{
    ITIP403RegistryErrors as TIP403RegistryError, ITIP403RegistryEvents as TIP403RegistryEvent,
};
pub use ITIPFeeAMM::{ITIPFeeAMMErrors as TIPFeeAMMError, ITIPFeeAMMEvents as TIPFeeAMMEvent};
pub use ITipAccountRegistrar::ITipAccountRegistrarErrors as TipAccountRegistrarError;
