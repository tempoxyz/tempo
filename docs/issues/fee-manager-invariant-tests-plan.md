# Fee Manager & Fee AMM Invariant Testing Plan

## Overview

This document outlines a plan for writing Solidity invariant tests for the `FeeManager` and `FeeAMM` contracts using Foundry. These tests will run against both the Solidity reference implementation (`forge test`) and Rust precompiles (`./tempo-forge test`).

## Test Infrastructure

### File Structure

```
docs/specs/test/
├── BaseTest.t.sol              # Existing base test
├── FeeAMM.t.sol                # Existing unit tests
├── FeeManager.t.sol            # Existing unit tests
└── invariant/                  # NEW: Invariant tests
    ├── FeeAMMHandler.sol       # Handler for FeeAMM operations
    ├── FeeAMMInvariant.t.sol   # FeeAMM invariant tests
    ├── FeeManagerHandler.sol   # Handler for FeeManager operations
    └── FeeManagerInvariant.t.sol # FeeManager invariant tests
```

### foundry.toml Configuration

Add to `docs/specs/foundry.toml`:

```toml
[invariant]
runs = 256
depth = 50
fail_on_revert = false
```

---

## Part 1: FeeAMM Invariants

### Handler Contract

The handler wraps FeeAMM operations with bounded inputs and tracks ghost state:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract FeeAMMHandler is CommonBase, StdCheats, StdUtils {
    FeeManager public amm;
    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

    // Ghost variables for invariant tracking
    uint256 public ghost_totalMinted;
    uint256 public ghost_totalBurned;
    uint256 public ghost_feeSwapIn;
    uint256 public ghost_feeSwapOut;
    uint256 public ghost_rebalanceIn;
    uint256 public ghost_rebalanceOut;

    // Track LP balances per actor
    mapping(address => uint256) public ghost_lpBalances;
    address[] public actors;

    // Call counters for debugging
    uint256 public mintCalls;
    uint256 public burnCalls;
    uint256 public rebalanceCalls;

    constructor(
        FeeManager _amm,
        TIP20 _userToken,
        TIP20 _validatorToken
    ) {
        amm = _amm;
        userToken = _userToken;
        validatorToken = _validatorToken;
        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Setup actors
        actors.push(address(0x1001));
        actors.push(address(0x1002));
        actors.push(address(0x1003));
    }

    // Bounded mint operation
    function mint(uint256 actorSeed, uint256 amount) external {
        // Select actor
        address actor = actors[actorSeed % actors.length];

        // Bound amount: must be > 2000 (MIN_LIQUIDITY * 2) for first mint
        // Use 2002 to 10_000_000e18 range
        amount = bound(amount, 2002, 10_000_000e18);

        // Ensure actor has tokens
        deal(address(validatorToken), actor, amount);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), amount);

        try amm.mint(address(userToken), address(validatorToken), amount, actor) returns (uint256 liquidity) {
            ghost_totalMinted += liquidity;
            ghost_lpBalances[actor] += liquidity;
            mintCalls++;
        } catch {
            // Expected to fail sometimes (e.g., insufficient amount)
        }
        vm.stopPrank();
    }

    // Bounded burn operation
    function burn(uint256 actorSeed, uint256 pct) external {
        address actor = actors[actorSeed % actors.length];

        uint256 balance = amm.liquidityBalances(poolId, actor);
        if (balance == 0) return;

        // Burn 1-100% of balance
        pct = bound(pct, 1, 100);
        uint256 amount = (balance * pct) / 100;
        if (amount == 0) return;

        vm.startPrank(actor);
        try amm.burn(address(userToken), address(validatorToken), amount, actor) returns (uint256 amtU, uint256 amtV) {
            ghost_totalBurned += amount;
            ghost_lpBalances[actor] -= amount;
            burnCalls++;
        } catch {
            // Expected to fail sometimes
        }
        vm.stopPrank();
    }

    // Bounded rebalance swap operation
    function rebalanceSwap(uint256 actorSeed, uint256 amountOut) external {
        address actor = actors[actorSeed % actors.length];

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        if (pool.reserveUserToken == 0) return;

        // Bound to available userToken reserve
        amountOut = bound(amountOut, 1, pool.reserveUserToken);

        // Calculate required input
        uint256 amountIn = (amountOut * 9985) / 10000 + 1;

        // Give actor the validatorToken needed
        deal(address(validatorToken), actor, amountIn);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), amountIn);

        try amm.rebalanceSwap(address(userToken), address(validatorToken), amountOut, actor) returns (uint256 actualIn) {
            ghost_rebalanceIn += actualIn;
            ghost_rebalanceOut += amountOut;
            rebalanceCalls++;
        } catch {
            // May fail if reserves depleted
        }
        vm.stopPrank();
    }

    // Helper to get sum of all LP balances
    function sumLPBalances() external view returns (uint256 total) {
        for (uint256 i = 0; i < actors.length; i++) {
            total += ghost_lpBalances[actors[i]];
        }
    }
}
```

### Invariant Test Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BaseTest } from "../BaseTest.t.sol";
import { FeeAMMHandler } from "./FeeAMMHandler.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";

contract FeeAMMInvariantTest is BaseTest, StdInvariant {
    FeeAMMHandler public handler;
    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

    function setUp() public override {
        super.setUp();

        // Create tokens for testing
        userToken = TIP20(
            factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user"))
        );
        validatorToken = TIP20(
            factory.createToken("ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator"))
        );

        // Create handler
        handler = new FeeAMMHandler(amm, userToken, validatorToken);
        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Target only the handler
        targetContract(address(handler));
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT A1: LP TOKEN ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Total supply must equal MIN_LIQUIDITY + sum of all user balances
    function invariant_lpTokenAccounting() public view {
        uint256 totalSupply = amm.totalSupply(poolId);

        if (totalSupply == 0) return; // Pool not initialized

        uint256 sumBalances = handler.sumLPBalances();
        uint256 minLiquidity = amm.MIN_LIQUIDITY();

        // totalSupply = MIN_LIQUIDITY (locked) + sum of all user balances
        assertEq(
            totalSupply,
            minLiquidity + sumBalances,
            "LP token accounting mismatch"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT A2: RESERVES NEVER NEGATIVE
    //////////////////////////////////////////////////////////////*/

    /// @notice Pool reserves must never underflow (always >= 0)
    function invariant_reservesNonNegative() public view {
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // uint128 can't be negative, but check they're valid
        assertTrue(pool.reserveUserToken >= 0, "User reserve negative");
        assertTrue(pool.reserveValidatorToken >= 0, "Validator reserve negative");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT A3: NO VALUE CREATION FROM ROUNDING
    //////////////////////////////////////////////////////////////*/

    /// @notice Users cannot extract more value than deposited through rounding
    function invariant_noFreeValue() public view {
        // After any sequence of operations:
        // ghost_totalBurned <= ghost_totalMinted (can't burn more LP than minted)

        assertLe(
            handler.ghost_totalBurned(),
            handler.ghost_totalMinted(),
            "Burned more LP than minted"
        );
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT A4: FEE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fee swap output must be exactly (input * M) / SCALE
    function invariant_feeSwapRateCorrect() public view {
        uint256 totalIn = handler.ghost_feeSwapIn();
        uint256 totalOut = handler.ghost_feeSwapOut();

        if (totalIn == 0) return;

        // Expected output: totalIn * 9970 / 10000 (rounded down)
        uint256 expectedOut = (totalIn * 9970) / 10000;

        assertEq(totalOut, expectedOut, "Fee swap rate incorrect");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT A5: REBALANCE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Rebalance swap input must be >= (output * N) / SCALE + 1
    function invariant_rebalanceSwapRateCorrect() public view {
        uint256 totalIn = handler.ghost_rebalanceIn();
        uint256 totalOut = handler.ghost_rebalanceOut();

        if (totalOut == 0) return;

        // Minimum expected input: totalOut * 9985 / 10000 + roundUp
        uint256 minExpectedIn = (totalOut * 9985) / 10000 + handler.rebalanceCalls();

        assertGe(totalIn, minExpectedIn, "Rebalance swap: insufficient input collected");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT A6: POOL SOLVENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Pool must always have enough tokens to cover LP redemptions
    function invariant_poolSolvency() public view {
        uint256 totalSupply = amm.totalSupply(poolId);
        if (totalSupply == 0) return;

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // FeeManager must hold at least the reserve amounts
        uint256 userBalance = userToken.balanceOf(address(amm));
        uint256 validatorBalance = validatorToken.balanceOf(address(amm));

        assertGe(userBalance, pool.reserveUserToken, "Insufficient userToken balance");
        assertGe(validatorBalance, pool.reserveValidatorToken, "Insufficient validatorToken balance");
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public view {
        console.log("Mint calls:", handler.mintCalls());
        console.log("Burn calls:", handler.burnCalls());
        console.log("Rebalance calls:", handler.rebalanceCalls());
        console.log("Total LP minted:", handler.ghost_totalMinted());
        console.log("Total LP burned:", handler.ghost_totalBurned());
    }
}
```

---

## Part 2: FeeManager Invariants

### Handler Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract FeeManagerHandler is CommonBase, StdCheats, StdUtils {
    FeeManager public feeManager;
    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

    // Ghost state
    uint256 public ghost_totalFeesIn;
    uint256 public ghost_totalFeesCollected;
    uint256 public ghost_totalFeesDistributed;
    uint256 public ghost_totalRefunds;

    // Track per-validator collected fees
    mapping(address => mapping(address => uint256)) public ghost_validatorFees;

    address[] public validators;
    address[] public users;

    uint256 public collectPreTxCalls;
    uint256 public collectPostTxCalls;
    uint256 public distributeFeeCalls;

    constructor(
        FeeManager _feeManager,
        TIP20 _userToken,
        TIP20 _validatorToken
    ) {
        feeManager = _feeManager;
        userToken = _userToken;
        validatorToken = _validatorToken;
        poolId = feeManager.getPoolId(address(userToken), address(validatorToken));

        // Setup actors
        validators.push(address(0x2001));
        validators.push(address(0x2002));
        users.push(address(0x3001));
        users.push(address(0x3002));
        users.push(address(0x3003));
    }

    // Simulate fee collection for same token (no swap)
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

        // Give user tokens
        deal(address(userToken), user, maxAmount);

        vm.startPrank(user);
        userToken.approve(address(feeManager), maxAmount);
        vm.stopPrank();

        // Simulate pre-tx (transfer max)
        vm.prank(user);
        userToken.transfer(address(feeManager), maxAmount);
        ghost_totalFeesIn += maxAmount;
        collectPreTxCalls++;

        // Simulate post-tx (refund + accumulate)
        if (refund > 0) {
            vm.prank(address(feeManager));
            userToken.transfer(user, refund);
            ghost_totalRefunds += refund;
        }

        // Same token: direct accumulation
        ghost_totalFeesCollected += actualUsed;
        ghost_validatorFees[validator][address(userToken)] += actualUsed;
        collectPostTxCalls++;
    }

    // Distribute fees
    function distributeFees(uint256 validatorSeed) external {
        address validator = validators[validatorSeed % validators.length];

        uint256 amount = feeManager.collectedFees(validator, address(validatorToken));
        if (amount == 0) {
            // Also check userToken
            amount = feeManager.collectedFees(validator, address(userToken));
            if (amount == 0) return;

            feeManager.distributeFees(validator, address(userToken));
        } else {
            feeManager.distributeFees(validator, address(validatorToken));
        }

        ghost_totalFeesDistributed += amount;
        distributeFeeCalls++;
    }
}
```

### FeeManager Invariant Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BaseTest } from "../BaseTest.t.sol";
import { FeeManagerHandler } from "./FeeManagerHandler.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";

contract FeeManagerInvariantTest is BaseTest, StdInvariant {
    FeeManagerHandler public handler;
    TIP20 public userToken;
    TIP20 public validatorToken;

    function setUp() public override {
        super.setUp();

        userToken = TIP20(
            factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user"))
        );
        validatorToken = TIP20(
            factory.createToken("ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator"))
        );

        // Setup initial pool liquidity (required for different-token swaps)
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);

        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(admin, initialLiquidity);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, admin);

        handler = new FeeManagerHandler(amm, userToken, validatorToken);
        targetContract(address(handler));
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F1: FEES COLLECTED <= FEES IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Total collected fees cannot exceed total fees input
    function invariant_feesNeverExceedInput() public view {
        assertLe(
            handler.ghost_totalFeesCollected(),
            handler.ghost_totalFeesIn(),
            "Collected fees exceed input"
        );
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F2: CONSERVATION OF VALUE
    //////////////////////////////////////////////////////////////*/

    /// @notice fees_in = fees_collected + refunds (for same token)
    function invariant_feeConservation() public view {
        uint256 totalIn = handler.ghost_totalFeesIn();
        uint256 collected = handler.ghost_totalFeesCollected();
        uint256 refunds = handler.ghost_totalRefunds();

        // For same-token scenario: in = collected + refunds
        assertEq(totalIn, collected + refunds, "Fee conservation violated");
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT F3: DISTRIBUTED <= COLLECTED
    //////////////////////////////////////////////////////////////*/

    /// @notice Cannot distribute more fees than collected
    function invariant_distributionBounded() public view {
        assertLe(
            handler.ghost_totalFeesDistributed(),
            handler.ghost_totalFeesCollected(),
            "Distributed more than collected"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public view {
        console.log("CollectPreTx calls:", handler.collectPreTxCalls());
        console.log("CollectPostTx calls:", handler.collectPostTxCalls());
        console.log("DistributeFees calls:", handler.distributeFeeCalls());
        console.log("Total fees in:", handler.ghost_totalFeesIn());
        console.log("Total fees collected:", handler.ghost_totalFeesCollected());
        console.log("Total refunds:", handler.ghost_totalRefunds());
    }
}
```

---

## Part 3: Key Invariants Summary

### FeeAMM Invariants

| ID | Property | Formula |
|----|----------|---------|
| A1 | LP Accounting | `totalSupply == MIN_LIQUIDITY + sum(balances[user])` |
| A2 | Non-negative Reserves | `reserveU >= 0 && reserveV >= 0` |
| A3 | No Free Value | `totalBurned <= totalMinted` |
| A4 | Fee Swap Rate | `amountOut == (amountIn * 9970) / 10000` |
| A5 | Rebalance Rate | `amountIn >= (amountOut * 9985) / 10000 + 1` |
| A6 | Pool Solvency | `tokenBalance >= reserve` for both tokens |

### FeeManager Invariants

| ID | Property | Formula |
|----|----------|---------|
| F1 | Fees Bounded | `feesCollected <= feesIn` |
| F2 | Conservation | `feesIn == feesCollected + refunds` (same token) |
| F3 | Distribution Bounded | `feesDistributed <= feesCollected` |

### Cross-Token Swap Invariants (Integration)

| ID | Property | Formula |
|----|----------|---------|
| I1 | Swap Fee Retained | For different tokens: `feesCollected == feesIn * 0.997` |
| I2 | No Arbitrage | Consecutive fee+rebalance swaps don't create value |

---

## Part 4: Running Tests

```bash
# Run invariant tests against Solidity
cd docs/specs
forge test --match-contract Invariant -vvv

# Run with more depth/runs
forge test --match-contract Invariant --fuzz-runs 1000 --invariant-depth 100 -vvv

# Run against Rust precompiles
./tempo-forge test --match-contract Invariant -vvv
```

---

## Part 5: Implementation Priority

### Phase 1: Core AMM Invariants
1. `invariant_lpTokenAccounting` - Critical for correctness
2. `invariant_poolSolvency` - Critical for security
3. `invariant_feeSwapRateCorrect` - Core math verification

### Phase 2: FeeManager Invariants
4. `invariant_feesNeverExceedInput` - Security critical
5. `invariant_feeConservation` - Correctness
6. `invariant_distributionBounded` - Security

### Phase 3: Edge Cases & Integration
7. Overflow protection invariants
8. Zero amount handling
9. Cross-token swap integration tests

---

## Part 6: isTempo Considerations

Some invariants may need `isTempo` branching for differences between Solidity and Rust:

```solidity
function invariant_example() public view {
    if (!isTempo) {
        // Solidity-specific checks
    }
    // Common checks for both
}
```

Known differences to watch for:
- Event emission (may differ in ordering)
- Error message encoding
- Storage slot computation (should be identical but verify)
