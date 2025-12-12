pub use IFeeManager::{IFeeManagerErrors as FeeManagerError, IFeeManagerEvents as FeeManagerEvent};
pub use ITIPFeeAMM::{ITIPFeeAMMErrors as TIPFeeAMMError, ITIPFeeAMMEvents as TIPFeeAMMEvent};

crate::sol! {
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
    #[sol(abi)]
    interface IFeeManager {
        // Structs
        struct FeeInfo {
            uint128 amount;
            bool hasBeenSet;
        }

        // User preferences
        function userTokens(address user) external view returns (address);
        function validatorTokens(address validator) external view returns (address);
        function setUserToken(address token) external;
        function setValidatorToken(address token) external;

        // Fee functions
        function getFeeTokenBalance(address sender, address validator) external view returns (address, uint256);
        function distributeFees(address validator, address token) external;
        function collectedFees(address validator, address token) external view returns (uint256);
        // NOTE: collectFeePreTx is a protocol-internal function called directly by the
        // execution handler, not exposed via the dispatch interface.

        // Events
        event UserTokenSet(address indexed user, address indexed token);
        event ValidatorTokenSet(address indexed validator, address indexed token);
        event FeesDistributed(address indexed validator, address indexed token, uint256 amount);

        // Errors
        error OnlyValidator();
        error OnlySystemContract();
        error InvalidToken();
        error PoolDoesNotExist();
        error InsufficientFeeTokenBalance();
        error InternalError();
        error CannotChangeWithinBlock();
        error CannotChangeWithPendingFees();
        error TokenPolicyForbids();
    }
}

sol! {
    /// TIPFeeAMM interface defining the base AMM functionality for stablecoin pools.
    /// This interface provides core liquidity pool management and swap operations.
    ///
    /// NOTE: The FeeManager contract inherits from TIPFeeAMM and shares the same storage layout.
    /// When FeeManager is deployed, it effectively "is" a TIPFeeAMM with additional fee management
    /// capabilities layered on top. Both contracts operate on the same storage slots.
    #[derive(Debug, PartialEq, Eq)]
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


        // Constants
        function M() external view returns (uint256);
        function N() external view returns (uint256);
        function SCALE() external view returns (uint256);
        function MIN_LIQUIDITY() external view returns (uint256);

        // Pool Management
        function getPoolId(address userToken, address validatorToken) external pure returns (bytes32);
        function getPool(address userToken, address validatorToken) external view returns (Pool memory);
        function pools(bytes32 poolId) external view returns (Pool memory);

        // Liquidity Operations
        function mint(address userToken, address validatorToken, uint256 amountValidatorToken, address to) external returns (uint256 liquidity);
        function burn(address userToken, address validatorToken, uint256 liquidity, address to) external returns (uint256 amountUserToken, uint256 amountValidatorToken);

        // Liquidity Balances
        function totalSupply(bytes32 poolId) external view returns (uint256);
        function liquidityBalances(bytes32 poolId, address user) external view returns (uint256);

        // Swapping
        function rebalanceSwap(address userToken, address validatorToken, uint256 amountOut, address to) external returns (uint256 amountIn);

        // Events
        event Mint(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity);
        event MintWithValidatorToken(address sender, address indexed to, address indexed userToken, address indexed validatorToken, uint256 amountValidatorToken, uint256 liquidity);
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
}

impl FeeManagerError {
    /// Creates an error for only validator access.
    pub const fn only_validator() -> Self {
        Self::OnlyValidator(IFeeManager::OnlyValidator {})
    }

    /// Creates an error for only system contract access.
    pub const fn only_system_contract() -> Self {
        Self::OnlySystemContract(IFeeManager::OnlySystemContract {})
    }

    /// Creates an error for invalid token.
    pub const fn invalid_token() -> Self {
        Self::InvalidToken(IFeeManager::InvalidToken {})
    }

    /// Creates an error when pool does not exist.
    pub const fn pool_does_not_exist() -> Self {
        Self::PoolDoesNotExist(IFeeManager::PoolDoesNotExist {})
    }

    /// Creates an error for insufficient fee token balance.
    pub const fn insufficient_fee_token_balance() -> Self {
        Self::InsufficientFeeTokenBalance(IFeeManager::InsufficientFeeTokenBalance {})
    }

    /// Creates an error for internal errors.
    pub const fn internal_error() -> Self {
        Self::InternalError(IFeeManager::InternalError {})
    }

    /// Creates an error for cannot change within block.
    pub const fn cannot_change_within_block() -> Self {
        Self::CannotChangeWithinBlock(IFeeManager::CannotChangeWithinBlock {})
    }

    /// Creates an error for cannot change with pending fees.
    pub const fn cannot_change_with_pending_fees() -> Self {
        Self::CannotChangeWithPendingFees(IFeeManager::CannotChangeWithPendingFees {})
    }

    /// Creates an error for token policy forbids.
    pub const fn token_policy_forbids() -> Self {
        Self::TokenPolicyForbids(IFeeManager::TokenPolicyForbids {})
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
