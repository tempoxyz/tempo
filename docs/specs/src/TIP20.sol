// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20Factory } from "./TIP20Factory.sol";
import { TIP403Registry } from "./TIP403Registry.sol";
import { TIP20RolesAuth } from "./abstracts/TIP20RolesAuth.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract TIP20 is ITIP20, TIP20RolesAuth {

    TIP403Registry internal constant TIP403_REGISTRY =
        TIP403Registry(0x403c000000000000000000000000000000000000);

    address internal constant TIP_FEE_MANAGER_ADDRESS = 0xfeEC000000000000000000000000000000000000;
    address internal constant STABLECOIN_EXCHANGE_ADDRESS =
        0xDEc0000000000000000000000000000000000000;

    address internal constant FACTORY = 0x20Fc000000000000000000000000000000000000;

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    string public name;
    string public symbol;
    string public currency;

    function decimals() public pure returns (uint8) {
        return 6;
    }

    /*//////////////////////////////////////////////////////////////
                             ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    ITIP20 public override quoteToken;
    ITIP20 public override nextQuoteToken;

    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant UNPAUSE_ROLE = keccak256("UNPAUSE_ROLE");
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant BURN_BLOCKED_ROLE = keccak256("BURN_BLOCKED_ROLE");

    uint64 public transferPolicyId = 1; // "Always-allow" policy by default.

    constructor(
        string memory _name,
        string memory _symbol,
        string memory _currency,
        ITIP20 _quoteToken,
        address admin
    ) {
        name = _name;
        symbol = _symbol;
        currency = _currency;
        quoteToken = _quoteToken;
        nextQuoteToken = _quoteToken;
        // No currency registry; all tokens use 6 decimals by default

        hasRole[admin][DEFAULT_ADMIN_ROLE] = true; // Grant admin role to first admin.
    }

    /*//////////////////////////////////////////////////////////////
                              ERC20 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint128 internal _totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /*//////////////////////////////////////////////////////////////
                              TIP20 STORAGE
    //////////////////////////////////////////////////////////////*/

    bool public paused = false;
    uint256 public supplyCap = type(uint128).max; // Default to cap at uint128.max

    /*//////////////////////////////////////////////////////////////
                        REWARD DISTRIBUTION STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant ACC_PRECISION = 1e18;
    uint256 public globalRewardPerToken;
    uint128 public optedInSupply;

    struct UserRewardInfo {
        address rewardRecipient;
        uint256 rewardPerToken;
        uint256 rewardBalance;
    }

    mapping(address => UserRewardInfo) public userRewardInfo;

    /*//////////////////////////////////////////////////////////////
                              POLICY ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function changeTransferPolicyId(uint64 newPolicyId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit TransferPolicyUpdate(msg.sender, transferPolicyId = newPolicyId);
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function setNextQuoteToken(ITIP20 newQuoteToken) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // sets next quote token, to put the DEX for that pair into place-only mode
        // does not check for loops; that is checked in completeQuoteTokenUpdate
        if (!TIP20Factory(FACTORY).isTIP20(address(newQuoteToken))) {
            revert InvalidQuoteToken();
        }

        // If this token represents USD, enforce USD quote token
        if (keccak256(bytes(currency)) == keccak256(bytes("USD"))) {
            if (keccak256(bytes(newQuoteToken.currency())) != keccak256(bytes("USD"))) {
                revert InvalidQuoteToken();
            }
        }

        nextQuoteToken = newQuoteToken;
        emit NextQuoteTokenSet(msg.sender, newQuoteToken);
    }

    function completeQuoteTokenUpdate() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // check that this does not create a loop, by looping through quote token until we reach the root
        ITIP20 current = nextQuoteToken;
        while (address(current) != address(0)) {
            if (current == this) revert InvalidQuoteToken();
            current = current.quoteToken();
        }

        quoteToken = nextQuoteToken;
        emit QuoteTokenUpdate(msg.sender, nextQuoteToken);
    }

    function setSupplyCap(uint256 newSupplyCap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newSupplyCap < _totalSupply) revert InvalidSupplyCap();
        if (newSupplyCap > type(uint128).max) revert SupplyCapExceeded();
        emit SupplyCapUpdate(msg.sender, supplyCap = newSupplyCap);
    }

    function pause() external onlyRole(PAUSE_ROLE) {
        emit PauseStateUpdate(msg.sender, paused = true);
    }

    function unpause() external onlyRole(UNPAUSE_ROLE) {
        emit PauseStateUpdate(msg.sender, paused = false);
    }

    function mint(address to, uint256 amount) external onlyRole(ISSUER_ROLE) {
        _mint(to, amount);
        emit Mint(to, amount);
    }

    function burn(uint256 amount) external onlyRole(ISSUER_ROLE) {
        _transfer(msg.sender, address(0), amount);
        unchecked {
            _totalSupply -= uint128(amount);
        }

        emit Burn(msg.sender, amount);
    }

    function burnBlocked(address from, uint256 amount) external onlyRole(BURN_BLOCKED_ROLE) {
        // Prevent burning from protected precompile addresses
        if (from == TIP_FEE_MANAGER_ADDRESS || from == STABLECOIN_EXCHANGE_ADDRESS) {
            revert ProtectedAddress();
        }

        // Only allow burning from addresses that are blocked from transferring.
        if (TIP403_REGISTRY.isAuthorized(transferPolicyId, from)) {
            revert PolicyForbids();
        }

        _transfer(from, address(0), amount);
        unchecked {
            _totalSupply -= uint128(amount);
        }

        emit BurnBlocked(from, amount);
    }

    function mintWithMemo(address to, uint256 amount, bytes32 memo) external onlyRole(ISSUER_ROLE) {
        _mint(to, amount);
        emit TransferWithMemo(address(0), to, amount, memo);
        emit Mint(to, amount);
    }

    function burnWithMemo(uint256 amount, bytes32 memo) external onlyRole(ISSUER_ROLE) {
        _transfer(msg.sender, address(0), amount);
        unchecked {
            _totalSupply -= uint128(amount);
        }

        emit TransferWithMemo(msg.sender, address(0), amount, memo);
        emit Burn(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                        STANDARD ERC20 FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    modifier notPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier validRecipient(address to) {
        // Don't allow sending to the zero address not other precompiled tokens.
        if (
            to == 0x0000000000000000000000000000000000000000
                || (uint160(to) >> 64) == 0x20c000000000000000000000
        ) revert InvalidRecipient();
        _;
    }

    modifier transferAuthorized(address from, address to) {
        if (
            !TIP403_REGISTRY.isAuthorized(transferPolicyId, from)
                || !TIP403_REGISTRY.isAuthorized(transferPolicyId, to)
        ) revert PolicyForbids();
        _;
    }

    function transfer(address to, uint256 amount)
        public
        virtual
        notPaused
        validRecipient(to)
        transferAuthorized(msg.sender, to)
        returns (bool)
    {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        emit Approval(msg.sender, spender, allowance[msg.sender][spender] = amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        public
        virtual
        notPaused
        validRecipient(to)
        transferAuthorized(from, to)
        returns (bool)
    {
        _transferFrom(from, to, amount);
        return true;
    }

    function _transferFrom(address from, address to, uint256 amount) internal {
        // Allowance check and update.
        uint256 allowed = allowance[from][msg.sender];
        if (amount > allowed) revert InsufficientAllowance();
        unchecked {
            if (allowed != type(uint256).max) {
                allowance[from][msg.sender] = allowed - amount;
            }
        }

        _transfer(from, to, amount);
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (amount > balanceOf[from]) {
            revert InsufficientBalance(balanceOf[from], amount, address(this));
        }

        // Handle reward accounting for opted-in sender
        address fromsRewardRecipient = _updateRewardsAndGetRecipient(from);

        // Handle reward accounting for opted-in receiver (but not when burning)
        address tosRewardRecipient = _updateRewardsAndGetRecipient(to);

        if (fromsRewardRecipient != address(0)) {
            if (tosRewardRecipient == address(0)) {
                optedInSupply -= uint128(amount);
            }
        } else if (tosRewardRecipient != address(0)) {
            optedInSupply += uint128(amount);
        }

        unchecked {
            balanceOf[from] -= amount;
            if (to != address(0)) balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        if (!TIP403_REGISTRY.isAuthorized(transferPolicyId, to)) revert PolicyForbids();
        if (_totalSupply + amount > supplyCap) revert SupplyCapExceeded(); // Catches overflow.

        // Handle reward accounting for opted-in receiver
        address tosRewardRecipient = _updateRewardsAndGetRecipient(to);
        if (tosRewardRecipient != address(0)) {
            optedInSupply += uint128(amount);
        }

        unchecked {
            _totalSupply += uint128(amount);
            balanceOf[to] += amount;
        }

        emit Transfer(address(0), to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                        TIP20 EXTENSION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function transferWithMemo(address to, uint256 amount, bytes32 memo)
        public
        virtual
        notPaused
        validRecipient(to)
        transferAuthorized(msg.sender, to)
    {
        _transfer(msg.sender, to, amount);
        emit TransferWithMemo(msg.sender, to, amount, memo);
    }

    function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo)
        public
        virtual
        notPaused
        validRecipient(to)
        transferAuthorized(from, to)
        returns (bool)
    {
        // Allowance check and update.
        uint256 allowed = allowance[from][msg.sender];
        if (amount > allowed) revert InsufficientAllowance();
        unchecked {
            if (allowed != type(uint256).max) {
                allowance[from][msg.sender] = allowed - amount;
            }
        }

        _transfer(from, to, amount);
        emit TransferWithMemo(from, to, amount, memo);
        return true;
    }

    /// @dev In the Tempo node implementation, this function is not exposed via the TIP20 interface
    /// and is not externally callable. It is only invoked internally by specific precompiles
    /// (like the fee manager precompile), avoiding the need to approve precompiles to spend tokens.
    function systemTransferFrom(address from, address to, uint256 amount)
        external
        virtual
        notPaused
        validRecipient(to)
        transferAuthorized(from, to)
        returns (bool)
    {
        require(msg.sender == TIP_FEE_MANAGER_ADDRESS);
        _transfer(from, to, amount);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                            FEE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function transferFeePreTx(address from, uint256 amount) external {
        require(msg.sender == TIP_FEE_MANAGER_ADDRESS);
        require(from != address(0));

        if (amount > balanceOf[from]) {
            revert InsufficientBalance(balanceOf[from], amount, address(this));
        }

        address fromsRewardRecipient = _updateRewardsAndGetRecipient(from);
        if (fromsRewardRecipient != address(0)) {
            optedInSupply -= uint128(amount);
        }

        unchecked {
            balanceOf[from] -= amount;
            balanceOf[TIP_FEE_MANAGER_ADDRESS] += amount;
        }
    }

    function transferFeePostTx(address to, uint256 refund, uint256 actualUsed) external {
        require(msg.sender == TIP_FEE_MANAGER_ADDRESS);
        require(to != address(0));

        uint256 feeManagerBalance = balanceOf[TIP_FEE_MANAGER_ADDRESS];
        if (refund > feeManagerBalance) {
            revert InsufficientBalance(feeManagerBalance, refund, address(this));
        }

        address tosRewardRecipient = _updateRewardsAndGetRecipient(to);
        if (tosRewardRecipient != address(0)) {
            optedInSupply += uint128(refund);
        }

        unchecked {
            balanceOf[TIP_FEE_MANAGER_ADDRESS] -= refund;
            balanceOf[to] += refund;
        }

        emit Transfer(to, TIP_FEE_MANAGER_ADDRESS, actualUsed);
    }

    /*//////////////////////////////////////////////////////////////
                        REWARD DISTRIBUTION
    //////////////////////////////////////////////////////////////*/

    // Updates the rewards for `user` and their `rewardRecipient`
    function _updateRewardsAndGetRecipient(address user)
        internal
        returns (address rewardRecipient)
    {
        rewardRecipient = userRewardInfo[user].rewardRecipient;
        uint256 cachedGlobalRewardPerToken = globalRewardPerToken;
        uint256 rewardPerTokenDelta =
            cachedGlobalRewardPerToken - userRewardInfo[user].rewardPerToken;

        if (rewardPerTokenDelta != 0) {
            // No rewards to update if not opted-in
            if (rewardRecipient != address(0)) {
                // Balance to update
                uint256 reward = (uint256(balanceOf[user]) * (rewardPerTokenDelta)) / ACC_PRECISION;

                userRewardInfo[rewardRecipient].rewardBalance += reward;
            }
            userRewardInfo[user].rewardPerToken = cachedGlobalRewardPerToken;
        }
    }

    /// @notice Starts a reward distribution. Post-Moderato, only immediate rewards (seconds_ == 0) are allowed.
    /// Scheduled/streaming rewards (seconds_ > 0) are disabled and will revert with ScheduledRewardsDisabled.
    function startReward(uint256 amount, uint32 seconds_)
        external
        virtual
        notPaused
        returns (uint64)
    {
        if (amount == 0) revert InvalidAmount();
        if (!TIP403_REGISTRY.isAuthorized(transferPolicyId, msg.sender)) {
            revert PolicyForbids();
        }

        // Transfer tokens from sender to this contract
        _transfer(msg.sender, address(this), amount);

        if (seconds_ == 0) {
            // Immediate payout
            if (optedInSupply == 0) {
                revert NoOptedInSupply();
            }
            uint256 deltaRPT = (amount * ACC_PRECISION) / optedInSupply;
            globalRewardPerToken += deltaRPT;
            emit RewardScheduled(msg.sender, 0, amount, 0);
            return 0;
        } else {
            // Scheduled/streaming rewards are disabled post-Moderato
            revert ScheduledRewardsDisabled();
        }
    }

    function setRewardRecipient(address newRewardRecipient) external virtual notPaused {
        // Check TIP-403 authorization
        if (newRewardRecipient != address(0)) {
            if (
                !TIP403_REGISTRY.isAuthorized(transferPolicyId, msg.sender)
                    || !TIP403_REGISTRY.isAuthorized(transferPolicyId, newRewardRecipient)
            ) revert PolicyForbids();
        }

        address oldRewardRecipient = _updateRewardsAndGetRecipient(msg.sender);
        if (oldRewardRecipient != address(0)) {
            if (newRewardRecipient == address(0)) {
                optedInSupply -= uint128(balanceOf[msg.sender]);
            }
        } else if (newRewardRecipient != address(0)) {
            optedInSupply += uint128(balanceOf[msg.sender]);
        }
        userRewardInfo[msg.sender].rewardRecipient = newRewardRecipient;

        emit RewardRecipientSet(msg.sender, newRewardRecipient);
    }

    function claimRewards() external virtual notPaused returns (uint256 maxAmount) {
        if (!TIP403_REGISTRY.isAuthorized(transferPolicyId, msg.sender)) revert PolicyForbids();

        _updateRewardsAndGetRecipient(msg.sender);

        uint256 amount = userRewardInfo[msg.sender].rewardBalance;
        uint256 selfBalance = balanceOf[address(this)];
        maxAmount = (selfBalance > amount ? amount : selfBalance);
        userRewardInfo[msg.sender].rewardBalance -= maxAmount;

        balanceOf[address(this)] -= maxAmount;
        if (userRewardInfo[msg.sender].rewardRecipient != address(0)) {
            optedInSupply += uint128(maxAmount);
        }
        balanceOf[msg.sender] += maxAmount;

        emit Transfer(address(this), msg.sender, maxAmount);
    }

    /*//////////////////////////////////////////////////////////////
                        REWARD DISTRIBUTION VIEWS
    //////////////////////////////////////////////////////////////*/


    }
