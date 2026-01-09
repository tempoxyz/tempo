// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { console } from "forge-std/console.sol";

/// @title FeeManagerInvariantTest
/// @notice Invariant tests for the FeeManager contract
/// @dev Uses inline handler approach - handlers are functions in this contract
contract FeeManagerInvariantTest is StdInvariant, BaseTest {

    // Storage slot for collectedFees mapping in FeeManager
    uint256 internal constant COLLECTED_FEES_SLOT = 5;

    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

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

    function setUp() public override {
        super.setUp();

        // Target this contract - handlers are inline functions here
        targetContract(address(this));

        // Create tokens for testing
        userToken =
            TIP20(factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user")));
        validatorToken = TIP20(
            factory.createToken(
                "ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator")
            )
        );

        // Grant issuer role for minting
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        userToken.grantRole(_ISSUER_ROLE, address(this));
        validatorToken.grantRole(_ISSUER_ROLE, address(this));

        // Setup initial pool liquidity (required for different-token swaps)
        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(admin, initialLiquidity);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, admin);

        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Setup actors
        validators.push(address(0x2001));
        validators.push(address(0x2002));
        users.push(address(0x3001));
        users.push(address(0x3002));
        users.push(address(0x3003));

        // Target specific selectors for fuzzing
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = this.simulateSameTokenFee.selector;
        selectors[1] = this.distributeFees.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Simulate fee collection for same token (no swap needed)
    function simulateSameTokenFee(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 maxAmount,
        uint256 actualUsedPct
    ) external {
        address user = users[userSeed % users.length];
        address validator = validators[validatorSeed % validators.length];

        maxAmount = bound(maxAmount, 1e6, 1_000_000e18);
        actualUsedPct = bound(actualUsedPct, 0, 100);
        uint256 actualUsed = (maxAmount * actualUsedPct) / 100;
        uint256 refund = maxAmount - actualUsed;

        userToken.mint(user, maxAmount);

        vm.prank(user);
        userToken.transfer(address(amm), maxAmount);
        ghost_totalFeesIn += maxAmount;

        if (refund > 0) {
            vm.prank(address(amm));
            userToken.transfer(user, refund);
            ghost_totalRefunds += refund;
        }

        _storeCollectedFees(validator, address(userToken), actualUsed);

        ghost_totalFeesCollected += actualUsed;
        ghost_validatorFees[validator] += actualUsed;

        sameTokenFeeCalls++;
    }

    /// @notice Distribute accumulated fees to a validator
    function distributeFees(uint256 validatorSeed) external {
        address validator = validators[validatorSeed % validators.length];

        uint256 ghostAmount = ghost_validatorFees[validator];
        if (ghostAmount == 0) return;

        amm.distributeFees(validator, address(userToken));

        ghost_totalFeesDistributed += ghostAmount;
        ghost_validatorFees[validator] = 0;

        distributeFeeCalls++;
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _getCollectedFeesSlot(address validator, address token)
        internal
        pure
        returns (bytes32)
    {
        bytes32 innerSlot = keccak256(abi.encode(validator, COLLECTED_FEES_SLOT));
        return keccak256(abi.encode(token, innerSlot));
    }

    function _storeCollectedFees(address validator, address token, uint256 amount) internal {
        bytes32 slot = _getCollectedFeesSlot(validator, token);
        uint256 currentValue = uint256(vm.load(address(amm), slot));
        vm.store(address(amm), slot, bytes32(currentValue + amount));
    }

    function validatorCount() public view returns (uint256) {
        return validators.length;
    }

    function getValidator(uint256 index) public view returns (address) {
        return validators[index];
    }

    function getValidatorGhostFees(address validator) public view returns (uint256) {
        return ghost_validatorFees[validator];
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F1: FEES COLLECTED <= FEES IN
    //////////////////////////////////////////////////////////////*/

    function invariant_feesNeverExceedInput() public view {
        assertLe(ghost_totalFeesCollected, ghost_totalFeesIn, "Collected fees exceed input");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F2: CONSERVATION OF VALUE
    //////////////////////////////////////////////////////////////*/

    function invariant_feeConservation() public view {
        uint256 totalIn = ghost_totalFeesIn;
        uint256 collected = ghost_totalFeesCollected;
        uint256 refunds = ghost_totalRefunds;

        assertEq(totalIn, collected + refunds, "Fee conservation violated");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F3: DISTRIBUTED <= COLLECTED
    //////////////////////////////////////////////////////////////*/

    function invariant_distributionBounded() public view {
        assertLe(
            ghost_totalFeesDistributed, ghost_totalFeesCollected, "Distributed more than collected"
        );
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F4: COLLECTED FEES CLEARED ON DISTRIBUTE
    //////////////////////////////////////////////////////////////*/

    function invariant_collectedFeesClearedOnDistribute() public view {
        uint256 undistributed = ghost_totalFeesCollected - ghost_totalFeesDistributed;

        uint256 sumValidatorFees = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            sumValidatorFees += ghost_validatorFees[validator];
        }

        assertEq(undistributed, sumValidatorFees, "Undistributed fees mismatch");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F5: NON-ZERO FEE ACCUMULATION
    //////////////////////////////////////////////////////////////*/

    function invariant_nonZeroFeeAccumulation() public view {
        if (sameTokenFeeCalls == 0) {
            assertEq(ghost_totalFeesCollected, 0, "Fees collected without any fee calls");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public view {
        console.log("=== FeeManager Invariant Call Summary ===");
        console.log("Same token fee calls:", sameTokenFeeCalls);
        console.log("Distribute fee calls:", distributeFeeCalls);
        console.log("Total fees in:", ghost_totalFeesIn);
        console.log("Total fees collected:", ghost_totalFeesCollected);
        console.log("Total refunds:", ghost_totalRefunds);
        console.log("Total fees distributed:", ghost_totalFeesDistributed);
    }

}
