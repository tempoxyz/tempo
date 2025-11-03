pub use IRolesAuth::{IRolesAuthErrors as RolesAuthError, IRolesAuthEvents as RolesAuthEvent};
pub use ITIP20::{ITIP20Errors as TIP20Error, ITIP20Events as TIP20Event};
use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface IRolesAuth {
        function hasRole(address account, bytes32 role) external view returns (bool);
        function getRoleAdmin(bytes32 role) external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function revokeRole(bytes32 role, address account) external;
        function renounceRole(bytes32 role) external;
        function setRoleAdmin(bytes32 role, bytes32 adminRole) external;

        event RoleMembershipUpdated(bytes32 indexed role, address indexed account, address indexed sender, bool hasRole);
        event RoleAdminUpdated(bytes32 indexed role, bytes32 indexed newAdminRole, address indexed sender);

        error Unauthorized();
    }

    /// TIP20 token interface providing standard ERC20 functionality with Tempo-specific extensions.
    ///
    /// TIP20 tokens extend the ERC20 standard with:
    /// - Currency denomination support for real-world asset backing
    /// - Transfer policy enforcement for compliance
    /// - Supply caps for controlled token issuance
    /// - Pause/unpause functionality for emergency controls
    /// - Memo support for transaction context
    /// The interface supports both standard token operations and administrative functions
    /// for managing token behavior and compliance requirements.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20 {
        // Standard token functions
        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function quoteToken() external view returns (address);
        function nextQuoteToken() external view returns (address);
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
        function burnBlocked(address from, uint256 amount) external;
        function mintWithMemo(address to, uint256 amount, bytes32 memo) external;
        function burnWithMemo(uint256 amount, bytes32 memo) external;
        function transferWithMemo(address to, uint256 amount, bytes32 memo) external;
        function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external returns (bool);

        // Admin Functions
        function changeTransferPolicyId(uint64 newPolicyId) external;
        function setSupplyCap(uint256 newSupplyCap) external;
        function pause() external;
        function unpause() external;
        function updateQuoteToken(address newQuoteToken) external;
        function finalizeQuoteTokenUpdate() external;

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



        struct RewardStream {
            address funder;
            uint64 startTime;
            uint64 endTime;
            uint256 ratePerSecondScaled;
            uint256 amountTotal;
        }

        // Reward Functions
        function startReward(uint256 amount, uint128 seconds) external returns (uint64);
        function setRewardRecipient(address recipient) external;
        function cancelReward(uint64 id) external returns (uint256);
        function claimRewards() external returns (uint256);
        function finalizeStreams() external;
        function getStream(uint64 id) external view returns (RewardStream);
        function totalRewardPerSecond() external view returns (uint256);

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
        event UpdateQuoteToken(address indexed updater, address indexed newQuoteToken);
        event QuoteTokenUpdateFinalized(address indexed updater, address indexed newQuoteToken);
        event RewardScheduled(address indexed funder, uint64 indexed id, uint256 amount, uint32 durationSeconds);
        event RewardCanceled(address indexed funder, uint64 indexed id, uint256 refund);
        event RewardRecipientSet(address indexed holder, address indexed recipient);

        // Errors
        error InsufficientBalance();
        error InsufficientAllowance();
        error SupplyCapExceeded();
        error InvalidPayload();
        error StringTooLong();
        error PolicyForbids();
        error InvalidRecipient();
        error ContractPaused();
        error InvalidCurrency();
        error InvalidQuoteToken();
        error TransfersDisabled();
        error InvalidAmount();
        error NotStreamFunder();
        error StreamInactive();
        error NoOptedInSupply();
        error Unauthorized();
    }
}

impl RolesAuthError {
    /// Creates an error for unauthorized access.
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IRolesAuth::Unauthorized {})
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

    /// Creates an error for unauthorized callers
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITIP20::Unauthorized {})
    }

    /// Creates an error when minting would exceed supply cap.
    pub const fn supply_cap_exceeded() -> Self {
        Self::SupplyCapExceeded(ITIP20::SupplyCapExceeded {})
    }

    /// Creates an error for invalid payload data.
    pub const fn invalid_payload() -> Self {
        Self::InvalidPayload(ITIP20::InvalidPayload {})
    }

    /// Creates an error for invalid quote token.
    pub const fn invalid_quote_token() -> Self {
        Self::InvalidQuoteToken(ITIP20::InvalidQuoteToken {})
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

    /// Creates an error for invalid amount.
    pub const fn invalid_amount() -> Self {
        Self::InvalidAmount(ITIP20::InvalidAmount {})
    }

    /// Error for when stream does not exist
    pub const fn stream_inactive() -> Self {
        Self::StreamInactive(ITIP20::StreamInactive {})
    }

    /// Error for when msg.sedner is not stream funder
    pub const fn not_stream_funder() -> Self {
        Self::NotStreamFunder(ITIP20::NotStreamFunder {})
    }

    /// Error for when opted in supply is 0
    pub const fn no_opted_in_supply() -> Self {
        Self::NoOptedInSupply(ITIP20::NoOptedInSupply {})
    }
}
