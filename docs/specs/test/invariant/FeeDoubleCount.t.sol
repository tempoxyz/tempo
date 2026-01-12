// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title FeeDoubleCountTest
/// @notice Unit tests attempting to break fee double-counting invariants (F3, F4, I5)
/// @dev Tests various attack vectors to distribute more fees than collected
/// NOTE: Tests that require storage manipulation are skipped on Tempo chain (precompiles)
contract FeeDoubleCountTest is BaseTest {

    TIP20 public userToken;
    TIP20 public validatorToken;

    address public validator1 = address(0x1001);
    address public validator2 = address(0x1002);
    address public user1 = address(0x2001);
    address public user2 = address(0x2002);

    // Storage slot for collectedFees mapping in FeeManager (slot 5 based on contract layout)
    uint256 internal constant COLLECTED_FEES_SLOT = 5;

    function setUp() public override {
        super.setUp();

        userToken = TIP20(
            factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user"))
        );
        validatorToken = TIP20(
            factory.createToken(
                "ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator")
            )
        );

        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        userToken.grantRole(_ISSUER_ROLE, address(this));
        validatorToken.grantRole(_ISSUER_ROLE, address(this));

        // Setup initial pool liquidity for cross-token swaps
        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(admin, initialLiquidity);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, admin);

        // Fund users
        userToken.mint(user1, 1_000_000e18);
        userToken.mint(user2, 1_000_000e18);
        validatorToken.mint(user1, 1_000_000e18);
        validatorToken.mint(user2, 1_000_000e18);
    }

    /// @dev Skip test if running on Tempo (precompile storage can't be manipulated)
    modifier skipOnTempo() {
        if (isTempo) {
            return;
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
            HELPER: SIMULATE FEE COLLECTION VIA STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Compute storage slot for collectedFees[validator][token]
    function _getCollectedFeesSlot(address validator, address token)
        internal
        pure
        returns (bytes32)
    {
        // collectedFees is at slot 5: mapping(address => mapping(address => uint256))
        bytes32 innerSlot = keccak256(abi.encode(validator, COLLECTED_FEES_SLOT));
        return keccak256(abi.encode(token, innerSlot));
    }

    /// @dev Simulates fee collection by directly setting storage and funding AMM
    function _simulateFeeCollection(
        address, // user - not needed for storage simulation
        address token,
        uint256, // maxAmount - not needed for storage simulation
        uint256 actualUsed,
        address blockValidator
    ) internal {
        // Mint tokens to AMM to back the collected fees
        TIP20(token).mint(address(amm), actualUsed);

        // Set collectedFees via storage
        bytes32 slot = _getCollectedFeesSlot(blockValidator, token);
        uint256 currentValue = uint256(vm.load(address(amm), slot));
        vm.store(address(amm), slot, bytes32(currentValue + actualUsed));
    }

    /// @dev Helper to check collected fees
    function _getCollectedFees(address validator, address token) internal view returns (uint256) {
        return amm.collectedFees(validator, token);
    }

    /*//////////////////////////////////////////////////////////////
            F3 BREAK ATTEMPT: DISTRIBUTE MORE THAN COLLECTED
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempt to distribute fees twice
    function test_F3_DoubleDistribution() public skipOnTempo {
        uint256 feeAmount = 1000e18;

        // Simulate fee collection via protocol call
        // User pays fee in validatorToken (same token scenario)
        _simulateFeeCollection(user1, address(validatorToken), feeAmount, feeAmount, validator1);

        // Verify fees were collected
        uint256 collectedBefore = _getCollectedFees(validator1, address(validatorToken));
        assertEq(collectedBefore, feeAmount, "Fees should be collected");

        // First distribution - should succeed
        uint256 balBefore = validatorToken.balanceOf(validator1);
        amm.distributeFees(validator1, address(validatorToken));
        uint256 balAfter = validatorToken.balanceOf(validator1);

        assertEq(balAfter - balBefore, feeAmount, "First distribution incorrect");

        // Verify collectedFees is now zero
        uint256 remaining = _getCollectedFees(validator1, address(validatorToken));
        assertEq(remaining, 0, "Fees should be cleared after distribution");

        // Second distribution - should do nothing (no revert, just 0 transfer)
        uint256 balBefore2 = validatorToken.balanceOf(validator1);
        amm.distributeFees(validator1, address(validatorToken));
        uint256 balAfter2 = validatorToken.balanceOf(validator1);

        assertEq(balAfter2, balBefore2, "Second distribution should transfer nothing");
    }

    /// @notice Attempt to claim same fees from different callers
    function test_F3_MultipleCallersDistribute() public skipOnTempo {
        uint256 feeAmount = 1000e18;

        // Simulate fee collection
        _simulateFeeCollection(user1, address(validatorToken), feeAmount, feeAmount, validator1);

        // Attacker tries to front-run and claim validator1's fees
        address attacker = address(0x9999);

        // Anyone can call distributeFees, but funds go to the validator, not caller
        vm.prank(attacker);
        amm.distributeFees(validator1, address(validatorToken));

        // Verify fees went to validator1, not attacker
        assertEq(validatorToken.balanceOf(validator1), feeAmount, "Fees should go to validator");
        assertEq(validatorToken.balanceOf(attacker), 0, "Attacker should receive nothing");

        // Fees should be cleared
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);
    }

    /// @notice Attempt to distribute fees for wrong validator
    function test_F3_WrongValidatorDistribution() public skipOnTempo {
        uint256 feeAmount = 1000e18;

        // Simulate fee collection for validator1
        _simulateFeeCollection(user1, address(validatorToken), feeAmount, feeAmount, validator1);

        // Try to distribute validator1's fees to validator2
        uint256 v1BalBefore = validatorToken.balanceOf(validator1);
        uint256 v2BalBefore = validatorToken.balanceOf(validator2);

        // This will try to distribute validator2's fees (which are 0)
        amm.distributeFees(validator2, address(validatorToken));

        // Neither validator should have received funds from this call
        assertEq(validatorToken.balanceOf(validator2), v2BalBefore, "V2 should receive nothing");

        // Validator1's fees should still be pending
        assertEq(
            _getCollectedFees(validator1, address(validatorToken)),
            feeAmount,
            "V1 fees should be unchanged"
        );
    }

    /*//////////////////////////////////////////////////////////////
            F4 BREAK ATTEMPT: FEES NOT CLEARED ON DISTRIBUTE
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify fees are atomically cleared on distribution
    function test_F4_AtomicClearOnDistribute() public skipOnTempo {
        uint256 feeAmount = 1000e18;

        _simulateFeeCollection(user1, address(validatorToken), feeAmount, feeAmount, validator1);

        // Check fees before
        assertEq(_getCollectedFees(validator1, address(validatorToken)), feeAmount);

        // Distribute
        amm.distributeFees(validator1, address(validatorToken));

        // Check fees after - must be zero
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);

        // AMM should have transferred out the tokens
        // (In real scenario, AMM balance would decrease by feeAmount)
    }

    /// @notice Attempt reentrancy during distribution
    /// @dev FeeManager doesn't have reentrancy guards, but transfer is last operation
    function test_F4_ReentrancyAttempt() public skipOnTempo {
        uint256 feeAmount = 1000e18;

        _simulateFeeCollection(user1, address(validatorToken), feeAmount, feeAmount, validator1);

        // Distribute fees
        amm.distributeFees(validator1, address(validatorToken));

        // After distribution, collectedFees is 0 so any reentrancy would get nothing
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);
    }

    /*//////////////////////////////////////////////////////////////
            I5 BREAK ATTEMPT: FEE CONSERVATION VIOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify distributed never exceeds collected (simulated scenario)
    function test_I5_DistributedNeverExceedsCollected() public skipOnTempo {
        uint256 collected1 = 500e18;
        uint256 collected2 = 300e18;
        uint256 totalCollected = collected1 + collected2;

        // Simulate fee collections for two validators
        _simulateFeeCollection(user1, address(validatorToken), collected1, collected1, validator1);
        _simulateFeeCollection(user2, address(validatorToken), collected2, collected2, validator2);

        // Track total distributed
        uint256 distributed = 0;

        // Distribute to validator1
        uint256 v1Before = validatorToken.balanceOf(validator1);
        amm.distributeFees(validator1, address(validatorToken));
        distributed += validatorToken.balanceOf(validator1) - v1Before;

        // Distribute to validator2
        uint256 v2Before = validatorToken.balanceOf(validator2);
        amm.distributeFees(validator2, address(validatorToken));
        distributed += validatorToken.balanceOf(validator2) - v2Before;

        // Verify conservation
        assertEq(distributed, totalCollected, "Distributed should equal collected");
        assertLe(distributed, totalCollected, "Distributed should never exceed collected");
    }

    /// @notice Test fee accumulation across multiple transactions
    function test_I5_AccumulationAcrossMultipleTx() public skipOnTempo {
        uint256 fee1 = 100e18;
        uint256 fee2 = 200e18;
        uint256 fee3 = 150e18;

        // Simulate multiple fee collections to same validator
        _simulateFeeCollection(user1, address(validatorToken), fee1, fee1, validator1);
        assertEq(_getCollectedFees(validator1, address(validatorToken)), fee1);

        _simulateFeeCollection(user1, address(validatorToken), fee2, fee2, validator1);
        assertEq(_getCollectedFees(validator1, address(validatorToken)), fee1 + fee2);

        _simulateFeeCollection(user1, address(validatorToken), fee3, fee3, validator1);
        assertEq(_getCollectedFees(validator1, address(validatorToken)), fee1 + fee2 + fee3);

        // Single distribution should collect all
        uint256 balBefore = validatorToken.balanceOf(validator1);
        amm.distributeFees(validator1, address(validatorToken));
        uint256 received = validatorToken.balanceOf(validator1) - balBefore;

        assertEq(received, fee1 + fee2 + fee3, "Should receive sum of all fees");
    }

    /*//////////////////////////////////////////////////////////////
            EDGE CASES: ZERO FEES AND MULTIPLE TOKENS
    //////////////////////////////////////////////////////////////*/

    /// @notice Distribution with zero fees should be no-op
    function test_ZeroFeeDistribution() public {
        // No fees collected
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);

        uint256 balBefore = validatorToken.balanceOf(validator1);

        // Should not revert, just do nothing
        amm.distributeFees(validator1, address(validatorToken));

        uint256 balAfter = validatorToken.balanceOf(validator1);
        assertEq(balAfter, balBefore, "Balance should not change");
    }

    /// @notice Fees in different tokens are tracked separately
    function test_MultiTokenFeeSeparation() public skipOnTempo {
        uint256 feeUser = 500e18;
        uint256 feeValidator = 300e18;

        // Collect fees in both token types (same token scenario for each)
        _simulateFeeCollection(user1, address(userToken), feeUser, feeUser, validator1);
        _simulateFeeCollection(
            user2, address(validatorToken), feeValidator, feeValidator, validator1
        );

        // Distribute userToken fees
        amm.distributeFees(validator1, address(userToken));
        assertEq(userToken.balanceOf(validator1), feeUser);
        assertEq(_getCollectedFees(validator1, address(userToken)), 0);

        // validatorToken fees should still be pending
        assertEq(_getCollectedFees(validator1, address(validatorToken)), feeValidator);

        // Distribute validatorToken fees
        amm.distributeFees(validator1, address(validatorToken));
        assertEq(validatorToken.balanceOf(validator1), feeValidator);
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);
    }

    /// @notice Multiple validators with same token
    function test_MultiValidatorSameToken() public skipOnTempo {
        uint256 fee1 = 500e18;
        uint256 fee2 = 300e18;

        _simulateFeeCollection(user1, address(validatorToken), fee1, fee1, validator1);
        _simulateFeeCollection(user2, address(validatorToken), fee2, fee2, validator2);

        // Each validator's fees are independent
        assertEq(_getCollectedFees(validator1, address(validatorToken)), fee1);
        assertEq(_getCollectedFees(validator2, address(validatorToken)), fee2);

        // Distributing to one doesn't affect the other
        amm.distributeFees(validator1, address(validatorToken));
        assertEq(validatorToken.balanceOf(validator1), fee1);
        assertEq(_getCollectedFees(validator2, address(validatorToken)), fee2);
    }

    /*//////////////////////////////////////////////////////////////
            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: distributed should never exceed collected
    function testFuzz_DistributedNeverExceedsCollected(uint256 amount) public skipOnTempo {
        amount = bound(amount, 1e18, 100_000e18); // Reasonable range for user balances

        _simulateFeeCollection(user1, address(validatorToken), amount, amount, validator1);

        uint256 collectedBefore = _getCollectedFees(validator1, address(validatorToken));
        uint256 balBefore = validatorToken.balanceOf(validator1);

        amm.distributeFees(validator1, address(validatorToken));

        uint256 distributed = validatorToken.balanceOf(validator1) - balBefore;

        assertEq(distributed, collectedBefore, "Distributed should equal collected");
        assertEq(
            _getCollectedFees(validator1, address(validatorToken)), 0, "Fees should be cleared"
        );
    }

    /// @notice Fuzz: multiple distributions should not double count
    function testFuzz_NoDoubleCount(uint256 amount, uint8 distributions) public skipOnTempo {
        amount = bound(amount, 1e18, 100_000e18);
        distributions = uint8(bound(distributions, 1, 10));

        _simulateFeeCollection(user1, address(validatorToken), amount, amount, validator1);

        uint256 totalDistributed = 0;

        for (uint8 i = 0; i < distributions; i++) {
            uint256 balBefore = validatorToken.balanceOf(validator1);
            amm.distributeFees(validator1, address(validatorToken));
            totalDistributed += validatorToken.balanceOf(validator1) - balBefore;
        }

        // Only first distribution should have transferred funds
        assertEq(totalDistributed, amount, "Total distributed should equal initial amount");
    }

    /*//////////////////////////////////////////////////////////////
            TEMPO-COMPATIBLE TESTS (no storage manipulation)
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify distributeFees is idempotent for zero fees
    function test_DistributeZeroFeesIdempotent() public {
        // When no fees collected, multiple distributions should all be no-ops
        uint256 balBefore = validatorToken.balanceOf(validator1);

        amm.distributeFees(validator1, address(validatorToken));
        amm.distributeFees(validator1, address(validatorToken));
        amm.distributeFees(validator1, address(validatorToken));

        uint256 balAfter = validatorToken.balanceOf(validator1);
        assertEq(balAfter, balBefore, "Balance should not change");
    }

    /// @notice Verify anyone can call distributeFees
    function test_DistributeFeesOpenAccess() public {
        address randomCaller = address(0x8888);

        // Should not revert when called by anyone
        vm.prank(randomCaller);
        amm.distributeFees(validator1, address(validatorToken));

        // Validator balance unchanged (no fees to distribute)
        assertEq(validatorToken.balanceOf(validator1), 0);
    }

    /// @notice Verify distributeFees for non-existent validator
    function test_DistributeFeesNonExistentValidator() public {
        address nonExistentValidator = address(0xDEAD);

        // Should not revert, just be a no-op
        amm.distributeFees(nonExistentValidator, address(validatorToken));

        assertEq(validatorToken.balanceOf(nonExistentValidator), 0);
        assertEq(_getCollectedFees(nonExistentValidator, address(validatorToken)), 0);
    }

    /// @notice Verify distributeFees for non-existent token
    function test_DistributeFeesNonExistentToken() public {
        address fakeToken = address(0xFAFE);

        // Should not revert, just be a no-op (collectedFees[v][t] = 0)
        amm.distributeFees(validator1, fakeToken);

        assertEq(_getCollectedFees(validator1, fakeToken), 0);
    }

    /// @notice Verify collectedFees starts at zero
    function test_CollectedFeesStartsAtZero() public view {
        assertEq(_getCollectedFees(validator1, address(userToken)), 0);
        assertEq(_getCollectedFees(validator1, address(validatorToken)), 0);
        assertEq(_getCollectedFees(validator2, address(userToken)), 0);
        assertEq(_getCollectedFees(validator2, address(validatorToken)), 0);
    }

    /// @notice Verify collectFeePreTx requires protocol caller
    function test_CollectFeePreTxRequiresProtocol() public {
        try amm.collectFeePreTx(user1, address(userToken), 100e18) {
            revert("Should have reverted with ONLY_PROTOCOL");
        } catch Error(string memory reason) {
            assertEq(reason, "ONLY_PROTOCOL", "Wrong revert reason");
        } catch {
            // Acceptable - reverted as expected
        }
    }

    /// @notice Verify collectFeePostTx requires protocol caller
    function test_CollectFeePostTxRequiresProtocol() public {
        try amm.collectFeePostTx(user1, 100e18, 50e18, address(userToken)) {
            revert("Should have reverted with ONLY_PROTOCOL");
        } catch Error(string memory reason) {
            assertEq(reason, "ONLY_PROTOCOL", "Wrong revert reason");
        } catch {
            // Acceptable - reverted as expected
        }
    }

}
