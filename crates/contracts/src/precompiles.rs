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
        function linkingToken() external view returns (address);
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
        function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external bool;

        // Admin Functions
        function changeTransferPolicyId(uint64 newPolicyId) external;
        function setSupplyCap(uint256 newSupplyCap) external;
        function pause() external;
        function unpause() external;

        // EIP-712 Permit
        struct Permit {
            address owner;
            address spender;
            uint256 value;
            uint256 nonce;
            uint256 deadline;
        }
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
        error InvalidLinkingToken();
        error TransfersDisabled();
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP20Factory {
        event TokenCreated(address indexed token, uint256 indexed tokenId, string name, string symbol, string currency, address admin);

        function createToken(
            string memory name,
            string memory symbol,
            string memory currency,
            address linkingToken,
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
        }

        struct PoolKey {
            address token0;
            address token1;
        }

        // Pool Management
        function getPoolId(address userToken, address validatorToken) external pure returns (bytes32);
        function getPool(address userToken, address validatorToken) external view returns (Pool memory);
        function pools(bytes32 poolId) external view returns (Pool memory);

        // Liquidity Operations
        function mint(address userToken, address validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, address to) returns (uint256 liquidity);
        function burn(address userToken, address validatorToken, uint256 liquidity, address to) returns (uint256 amountUserToken, uint256 amountValidatorToken);

        // Liquidity Balances
        function totalSupply(bytes32 poolId) external view returns (uint256);
        function liquidityBalances(bytes32 poolId, address user) external view returns (uint256);

        // TODO: has liquidity

        // Swapping
        function rebalanceSwap(address userToken, address validatorToken, uint256 amountOut, address to) external returns (uint256 amountIn);
        function calculateLiquidity(uint256 x, uint256 y) external pure returns (uint256);

        // Events
        event Mint(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity);
        event Burn(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity, address to);
        event RebalanceSwap(address indexed userToken, address indexed validatorToken, address indexed swapper, uint256 amountIn, uint256 amountOut);
        event FeeSwap(
            address indexed userToken,
            address indexed validatorToken,
            uint256 amountIn,
            uint256 amountOut
        );

        // Errors
        error IdenticalAddresses();
        error ZeroAddress();
        error PoolExists();
        error PoolDoesNotExist();
        error InvalidToken();
        error InsufficientLiquidity();
        error OnlyProtocol();
        error InsufficientPoolBalance();
        error InsufficientReserves();
        error InsufficientLiquidityBalance();
        error MustDepositLowerBalanceToken();
        error InvalidAmount();
        error InvalidRebalanceState();
        error InvalidRebalanceDirection();
        error InvalidNewReserves();
        error CannotSupportPendingSwaps();
        error DivisionByZero();
        error InvalidSwapCalculation();
        error InsufficientLiquidityForPending();
        error TokenTransferFailed();
        error InternalError();
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
        function executeBlock() external;

        // Events
        event UserTokenSet(address indexed user, address indexed token);
        event ValidatorTokenSet(address indexed validator, address indexed token);

        // Errors
        error OnlyValidator();
        error OnlySystemContract();
        error InvalidToken();
        error PoolDoesNotExist();
        error InsufficientLiquidity();
        error InsufficientFeeTokenBalance();
        error InternalError();
        error CannotChangeWithinBlock();
        error TokenPolicyForbids();
    }
}

impl TIPFeeAMMError {
    /// Creates an error for identical token addresses.
    pub const fn identical_addresses() -> Self {
        Self::IdenticalAddresses(ITIPFeeAMM::IdenticalAddresses {})
    }

    /// Creates an error for zero address.
    pub const fn zero_address() -> Self {
        Self::ZeroAddress(ITIPFeeAMM::ZeroAddress {})
    }

    /// Creates an error when pool already exists.
    pub const fn pool_exists() -> Self {
        Self::PoolExists(ITIPFeeAMM::PoolExists {})
    }

    /// Creates an error when pool does not exist.
    pub const fn pool_does_not_exist() -> Self {
        Self::PoolDoesNotExist(ITIPFeeAMM::PoolDoesNotExist {})
    }

    /// Creates an error for invalid token.
    pub const fn invalid_token() -> Self {
        Self::InvalidToken(ITIPFeeAMM::InvalidToken {})
    }

    /// Creates an error for insufficient liquidity.
    pub const fn insufficient_liquidity() -> Self {
        Self::InsufficientLiquidity(ITIPFeeAMM::InsufficientLiquidity {})
    }

    /// Creates an error for insufficient pool balance.
    pub const fn insufficient_pool_balance() -> Self {
        Self::InsufficientPoolBalance(ITIPFeeAMM::InsufficientPoolBalance {})
    }

    /// Creates an error for insufficient reserves.
    pub const fn insufficient_reserves() -> Self {
        Self::InsufficientReserves(ITIPFeeAMM::InsufficientReserves {})
    }

    /// Creates an error for insufficient liquidity balance.
    pub const fn insufficient_liquidity_balance() -> Self {
        Self::InsufficientLiquidityBalance(ITIPFeeAMM::InsufficientLiquidityBalance {})
    }

    /// Creates an error when must deposit lower balance token.
    pub const fn must_deposit_lower_balance_token() -> Self {
        Self::MustDepositLowerBalanceToken(ITIPFeeAMM::MustDepositLowerBalanceToken {})
    }

    /// Creates an error for invalid amount.
    pub const fn invalid_amount() -> Self {
        Self::InvalidAmount(ITIPFeeAMM::InvalidAmount {})
    }

    /// Creates an error for token transfer failure.
    pub const fn token_transfer_failed() -> Self {
        Self::TokenTransferFailed(ITIPFeeAMM::TokenTransferFailed {})
    }

    /// Creates an error for invalid swap calculation.
    pub const fn invalid_swap_calculation() -> Self {
        Self::InvalidSwapCalculation(ITIPFeeAMM::InvalidSwapCalculation {})
    }

    /// Creates an error for insufficient liquidity for pending operations.
    pub const fn insufficient_liquidity_for_pending() -> Self {
        Self::InsufficientLiquidityForPending(ITIPFeeAMM::InsufficientLiquidityForPending {})
    }

    /// Creates an error for division by zero.
    pub const fn division_by_zero() -> Self {
        Self::DivisionByZero(ITIPFeeAMM::DivisionByZero {})
    }

    /// Creates an error for invalid new reserves.
    pub const fn invalid_new_reserves() -> Self {
        Self::InvalidNewReserves(ITIPFeeAMM::InvalidNewReserves {})
    }

    /// Creates an error for internal errors.
    pub const fn internal_error() -> Self {
        Self::InternalError(ITIPFeeAMM::InternalError {})
    }
}

impl FeeManagerError {
    /// Creates an error for invalid token.
    pub const fn invalid_token() -> Self {
        Self::InvalidToken(IFeeManager::InvalidToken {})
    }

    /// Creates an error for internal errors.
    pub const fn internal_error() -> Self {
        Self::InternalError(IFeeManager::InternalError {})
    }

    /// Creates an error for insufficient liquidity.
    pub const fn insufficient_liquidity() -> Self {
        Self::InsufficientLiquidity(IFeeManager::InsufficientLiquidity {})
    }

    /// Creates an error for insufficient fee token balance.
    pub const fn insufficient_fee_token_balance() -> Self {
        Self::InsufficientFeeTokenBalance(IFeeManager::InsufficientFeeTokenBalance {})
    }

    /// Creates an error for only system contract access.
    pub const fn only_system_contract() -> Self {
        Self::OnlySystemContract(IFeeManager::OnlySystemContract {})
    }

    /// Creates an error for beneficiary cannot set its token.
    pub const fn cannot_change_within_block() -> Self {
        Self::CannotChangeWithinBlock(IFeeManager::CannotChangeWithinBlock {})
    }

    /// Creates an error for token policy forbids.
    pub const fn token_policy_forbids() -> Self {
        Self::TokenPolicyForbids(IFeeManager::TokenPolicyForbids {})
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

    /// Creates an error for invalid linking token.
    pub const fn invalid_linking_token() -> Self {
        Self::InvalidLinkingToken(ITIP20::InvalidLinkingToken {})
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

    /// Creates an error for transfers being disabled.
    pub const fn transfers_disabled() -> Self {
        Self::TransfersDisabled(ITIP20::TransfersDisabled {})
    }
}

#[macro_export]
macro_rules! tip403_err {
    ($err:ident) => {
        $crate::precompiles::TIP403RegistryError::$err(
            $crate::precompiles::ITIP403Registry::$err {},
        )
    };
}

#[macro_export]
macro_rules! fee_manager_err {
    ($err:ident) => {
        $crate::precompiles::IFeeManager::IFeeManagerErrors::$err(
            $crate::precompiles::IFeeManager::$err {},
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
