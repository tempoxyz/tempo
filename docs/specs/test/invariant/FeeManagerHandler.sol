// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";
import { console } from "forge-std/console.sol";

/// @title FeeManagerHandler
/// @notice Handler contract for FeeManager invariant testing
/// @dev Simulates fee collection flows manually since collectFeePreTx/PostTx require msg.sender == address(0)
contract FeeManagerHandler is CommonBase, StdCheats, StdUtils {

    // Storage slot for collectedFees mapping in FeeManager
    // FeeAMM: slot 0 (pools), slot 1 (totalSupply), slot 2 (liquidityBalances)
    // FeeManager: slot 3 (validatorTokens), slot 4 (userTokens), slot 5 (collectedFees)
    uint256 internal constant COLLECTED_FEES_SLOT = 5;

    FeeManager public feeManager;
    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;
    address public admin;

    // Ghost state for invariant tracking
    uint256 public ghost_totalFeesIn;
    uint256 public ghost_totalFeesCollected;
    uint256 public ghost_totalFeesDistributed;
    uint256 public ghost_totalRefunds;

    // Track per-validator collected fees (same token scenario)
    mapping(address => uint256) public ghost_validatorFees;

    address[] public validators;
    address[] public users;

    uint256 public sameTokenFeeCalls;
    uint256 public distributeFeeCalls;

    constructor(FeeManager _feeManager, TIP20 _userToken, TIP20 _validatorToken, address _admin) {
        feeManager = _feeManager;
        userToken = _userToken;
        validatorToken = _validatorToken;
        poolId = feeManager.getPoolId(address(userToken), address(validatorToken));
        admin = _admin;

        // Setup actors
        validators.push(address(0x2001));
        validators.push(address(0x2002));
        users.push(address(0x3001));
        users.push(address(0x3002));
        users.push(address(0x3003));
    }

    /// @notice Simulate fee collection for same token (no swap needed)
    /// @dev Manually simulates what collectFeePreTx + collectFeePostTx would do
    /// @param userSeed Seed to select user
    /// @param validatorSeed Seed to select validator
    /// @param maxAmount Maximum amount to collect
    /// @param actualUsedPct Percentage of maxAmount actually used (0-100)
    function simulateSameTokenFee(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 maxAmount,
        uint256 actualUsedPct
    ) external {
        address user = users[userSeed % users.length];
        address validator = validators[validatorSeed % validators.length];

        // Bound inputs
        maxAmount = bound(maxAmount, 1e6, 1_000_000e18);
        actualUsedPct = bound(actualUsedPct, 0, 100);
        uint256 actualUsed = (maxAmount * actualUsedPct) / 100;
        uint256 refund = maxAmount - actualUsed;

        // Debug: check issuer role
        bytes32 ISSUER_ROLE = keccak256("ISSUER_ROLE");
        bool hasRole = userToken.hasRole(address(this), ISSUER_ROLE);
        console.log("Handler has ISSUER_ROLE:", hasRole);

        // Mint tokens to user (handler has ISSUER_ROLE)
        userToken.mint(user, maxAmount);
        console.log("Minted", maxAmount, "to user");

        // --- Simulate collectFeePreTx ---
        // Transfer max amount from user to FeeManager
        console.log("Transferring from user to feeManager...");
        vm.prank(user);
        userToken.transfer(address(feeManager), maxAmount);
        console.log("Transfer done, updating ghost_totalFeesIn");
        ghost_totalFeesIn += maxAmount;

        // --- Simulate collectFeePostTx ---
        // Refund unused amount to user
        if (refund > 0) {
            console.log("Refunding", refund, "to user");
            vm.prank(address(feeManager));
            userToken.transfer(user, refund);
            ghost_totalRefunds += refund;
        }

        // Same token scenario: fees go directly to collectedFees
        // Use vm.store to write to the actual collectedFees mapping
        _storeCollectedFees(validator, address(userToken), actualUsed);

        // Track in ghost state for invariant checking
        ghost_totalFeesCollected += actualUsed;
        ghost_validatorFees[validator] += actualUsed;

        sameTokenFeeCalls++;
        console.log("sameTokenFeeCalls incremented to:", sameTokenFeeCalls);
    }

    /// @notice Calculate storage slot for collectedFees[validator][token]
    /// @dev collectedFees is mapping(address => mapping(address => uint256)) at slot 5
    function _getCollectedFeesSlot(address validator, address token) internal pure returns (bytes32) {
        // For nested mapping: keccak256(token . keccak256(validator . slot))
        bytes32 innerSlot = keccak256(abi.encode(validator, COLLECTED_FEES_SLOT));
        return keccak256(abi.encode(token, innerSlot));
    }

    /// @notice Store value in collectedFees[validator][token] using vm.store
    function _storeCollectedFees(address validator, address token, uint256 amount) internal {
        bytes32 slot = _getCollectedFeesSlot(validator, token);
        uint256 currentValue = uint256(vm.load(address(feeManager), slot));
        vm.store(address(feeManager), slot, bytes32(currentValue + amount));
    }

    /// @notice Distribute accumulated fees to a validator
    /// @param validatorSeed Seed to select validator
    function distributeFees(uint256 validatorSeed) external {
        address validator = validators[validatorSeed % validators.length];

        // Check if validator has any accumulated fees in ghost state
        uint256 ghostAmount = ghost_validatorFees[validator];
        if (ghostAmount == 0) return;

        // Call the actual feeManager.distributeFees
        feeManager.distributeFees(validator, address(userToken));

        // Update ghost state to track distribution
        ghost_totalFeesDistributed += ghostAmount;
        ghost_validatorFees[validator] = 0;

        distributeFeeCalls++;
    }

    /// @notice Get total ghost fees for a validator
    function getValidatorGhostFees(address validator) external view returns (uint256) {
        return ghost_validatorFees[validator];
    }

    /// @notice Get number of validators
    function validatorCount() external view returns (uint256) {
        return validators.length;
    }

    /// @notice Get validator by index
    function getValidator(uint256 index) external view returns (address) {
        return validators[index];
    }

    /// @notice Get number of users
    function userCount() external view returns (uint256) {
        return users.length;
    }

    /// @notice Get user by index
    function getUser(uint256 index) external view returns (address) {
        return users[index];
    }

}
