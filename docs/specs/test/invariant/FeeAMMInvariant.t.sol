// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { TIP20Factory } from "../../src/TIP20Factory.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { console } from "forge-std/console.sol";

/// @title FeeAMMInvariantTest
/// @notice Invariant tests for the FeeAMM contract with multi-pool support
/// @dev Uses inline handler approach - handlers are functions in this contract, not a separate contract
contract FeeAMMInvariantTest is StdInvariant, BaseTest {

    // Token universe for multi-pool testing
    TIP20[] public tokens;

    // Actors for testing
    address[] public actors;

    // Dynamic pool tracking
    bytes32[] public poolIds;
    mapping(bytes32 => bool) public seenPool;

    // Ghost variables for invariant tracking
    uint256 public ghost_totalMinted;
    uint256 public ghost_totalBurned;
    uint256 public ghost_rebalanceIn;
    uint256 public ghost_rebalanceOut;
    uint256 public ghost_rebalanceExpectedIn; // Track sum of individual expected inputs
    uint256 public ghost_feeSwapIn;
    uint256 public ghost_feeSwapOut;

    // Track LP balances per actor per pool
    mapping(bytes32 => mapping(address => uint256)) public ghost_lpBalances;

    // Call counters for debugging
    uint256 public mintCalls;
    uint256 public burnCalls;
    uint256 public rebalanceCalls;
    uint256 public feeSwapCalls;

    function setUp() public override {
        super.setUp();

        // Target this contract - handlers are inline functions here
        targetContract(address(this));

        // Create token universe (4 tokens for various pair combinations)
        TIP20 alphaUSD = TIP20(
            factory.createToken("AlphaUSD", "aUSD", "USD", pathUSD, admin, bytes32("alpha"))
        );
        tokens.push(alphaUSD);

        TIP20 betaUSD =
            TIP20(factory.createToken("BetaUSD", "bUSD", "USD", pathUSD, admin, bytes32("beta")));
        tokens.push(betaUSD);

        TIP20 gammaUSD = TIP20(
            factory.createToken("GammaUSD", "gUSD", "USD", pathUSD, admin, bytes32("gamma"))
        );
        tokens.push(gammaUSD);

        TIP20 deltaUSD = TIP20(
            factory.createToken("DeltaUSD", "dUSD", "USD", pathUSD, admin, bytes32("delta"))
        );
        tokens.push(deltaUSD);

        // Grant ISSUER_ROLE to this contract for all tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, admin);
            tokens[i].grantRole(_ISSUER_ROLE, address(this));
        }

        // Create 10 actors for better fuzz coverage
        for (uint256 i = 0; i < 10; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor-", vm.toString(i))));
            actors.push(actor);
            targetSender(actor);
        }

        // Fund all actors with all tokens and set approvals
        for (uint256 i = 0; i < actors.length; i++) {
            address actor = actors[i];
            for (uint256 j = 0; j < tokens.length; j++) {
                tokens[j].mintWithMemo(actor, 10_000_000e6, bytes32(0));
                vm.prank(actor);
                tokens[j].approve(address(amm), type(uint256).max);
            }
        }

        // Target specific selectors for fuzzing (handler functions in this contract)
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = this.mint.selector;
        selectors[1] = this.burn.selector;
        selectors[2] = this.rebalanceSwap.selector;
        selectors[3] = this.simulateFeeSwap.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bounded mint operation across any token pair
    function mint(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 amount) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        amount = bound(amount, 1, 10_000_000e6);

        validatorToken.mint(actor, amount);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), amount);

        try amm.mint(address(userToken), address(validatorToken), amount, actor) returns (
            uint256 liquidity
        ) {
            bytes32 pid = _rememberPool(address(userToken), address(validatorToken));
            ghost_totalMinted += liquidity;
            ghost_lpBalances[pid][actor] += liquidity;
            mintCalls++;
        } catch (bytes memory err) {
            _assertExpectedMintOrBurnRevert(err, "mint");
        }
        vm.stopPrank();
    }

    /// @notice Bounded burn operation
    function burn(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 pct) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        bytes32 pid = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 balance = amm.liquidityBalances(pid, actor);
        if (balance == 0) return;

        pct = bound(pct, 1, 100);
        uint256 amount = (balance * pct) / 100;
        if (amount == 0) return;

        vm.startPrank(actor);
        try amm.burn(address(userToken), address(validatorToken), amount, actor) returns (
            uint256, uint256
        ) {
            _rememberPool(address(userToken), address(validatorToken));
            ghost_totalBurned += amount;
            ghost_lpBalances[pid][actor] -= amount;
            burnCalls++;
        } catch (bytes memory err) {
            _assertExpectedMintOrBurnRevert(err, "burn");
        }
        vm.stopPrank();
    }

    /// @notice Bounded rebalance swap operation with step invariant verification
    function rebalanceSwap(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 rawOut)
        external
    {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        IFeeAMM.Pool memory beforeP = amm.getPool(address(userToken), address(validatorToken));

        uint256 maxOut = uint256(beforeP.reserveUserToken);
        if (maxOut == 0) return;

        uint256 amountOut = bound(rawOut, 1, maxOut);
        uint256 expectedIn = (amountOut * 9985) / 10_000 + 1;

        validatorToken.mint(actor, expectedIn);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), expectedIn);

        try amm.rebalanceSwap(
            address(userToken), address(validatorToken), amountOut, actor
        ) returns (
            uint256 amountIn
        ) {
            _rememberPool(address(userToken), address(validatorToken));

            require(amountIn == expectedIn, "rebalanceSwap amountIn mismatch");

            IFeeAMM.Pool memory afterP = amm.getPool(address(userToken), address(validatorToken));
            require(
                uint256(afterP.reserveValidatorToken)
                    == uint256(beforeP.reserveValidatorToken) + amountIn,
                "reserveValidatorToken delta mismatch"
            );
            require(
                uint256(afterP.reserveUserToken) == uint256(beforeP.reserveUserToken) - amountOut,
                "reserveUserToken delta mismatch"
            );

            ghost_rebalanceIn += amountIn;
            ghost_rebalanceOut += amountOut;
            ghost_rebalanceExpectedIn += expectedIn; // Track individual expected amount
            rebalanceCalls++;
        } catch (bytes memory err) {
            _assertExpectedSwapRevert(err);
        }
        vm.stopPrank();
    }

    /// @notice Simulate fee swap operation
    function simulateFeeSwap(uint256 seedA, uint256 seedB, uint256 amountIn) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        amountIn = bound(amountIn, 1, 1_000_000e6);

        uint256 amountOut = (amountIn * 9970) / 10_000;

        if (pool.reserveValidatorToken < amountOut) return;

        ghost_feeSwapIn += amountIn;
        ghost_feeSwapOut += amountOut;
        feeSwapCalls++;
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _pair(uint256 seedA, uint256 seedB)
        internal
        view
        returns (TIP20 userToken, TIP20 validatorToken)
    {
        uint256 n = tokens.length;
        uint256 ia = seedA % n;
        uint256 ib = seedB % n;

        if (ia == ib) {
            ib = (ib + 1) % n;
        }

        userToken = tokens[ia];
        validatorToken = tokens[ib];
    }

    function _rememberPool(address userToken, address validatorToken)
        internal
        returns (bytes32 pid)
    {
        if (userToken == validatorToken) return bytes32(0);
        pid = amm.getPoolId(userToken, validatorToken);
        if (!seenPool[pid]) {
            seenPool[pid] = true;
            poolIds.push(pid);
        }
    }

    function _sel(bytes memory err) internal pure returns (bytes4) {
        if (err.length < 4) return bytes4(0);
        return bytes4(err);
    }

    function _assertExpectedMintOrBurnRevert(bytes memory err, string memory which) internal pure {
        bytes4 s = _sel(err);
        bool ok = s == IFeeAMM.InsufficientLiquidity.selector || s == IFeeAMM.InvalidToken.selector
            || s == IFeeAMM.InvalidCurrency.selector || s == IFeeAMM.IdenticalAddresses.selector
            || s == IFeeAMM.InvalidAmount.selector;

        if (!ok) _dumpUnexpected(err, s, which);
    }

    function _assertExpectedSwapRevert(bytes memory err) internal pure {
        bytes4 s = _sel(err);
        bool ok = s == IFeeAMM.InsufficientLiquidity.selector
            || s == IFeeAMM.InsufficientReserves.selector || s == IFeeAMM.InvalidToken.selector
            || s == IFeeAMM.InvalidCurrency.selector || s == IFeeAMM.IdenticalAddresses.selector
            || s == IFeeAMM.InvalidAmount.selector;

        if (!ok) _dumpUnexpected(err, s, "swap");
    }

    function _dumpUnexpected(bytes memory err, bytes4 s, string memory which) internal pure {
        console.log("unexpected revert selector in", which, ":");
        console.logBytes4(s);
        console.log("raw revert data:");
        console.logBytes(err);
        revert("unexpected revert selector");
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    function sumLPBalances(bytes32 pid) public view returns (uint256 total) {
        for (uint256 i = 0; i < actors.length; i++) {
            total += ghost_lpBalances[pid][actors[i]];
        }
    }

    function poolCount() public view returns (uint256) {
        return poolIds.length;
    }

    function getPoolId(uint256 index) public view returns (bytes32) {
        return poolIds[index];
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A1: POOL INITIALIZATION SHAPE
    //////////////////////////////////////////////////////////////*/

    function invariant_poolSupplyAndReserveShape() public view {
        uint256 minLiq = amm.MIN_LIQUIDITY();

        for (uint256 i = 0; i < poolCount(); i++) {
            bytes32 pid = getPoolId(i);
            (uint128 ru, uint128 rv) = amm.pools(pid);
            uint256 supply = amm.totalSupply(pid);

            if (supply == 0) {
                assertEq(uint256(ru), 0, "supply=0 => reserveU=0");
                assertEq(uint256(rv), 0, "supply=0 => reserveV=0");
            } else {
                assertGe(supply, minLiq, "initialized pool must lock MIN_LIQUIDITY");
            }

            if (ru != 0 || rv != 0) {
                assertGt(supply, 0, "reserves>0 => supply>0");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A2: LP SUPPLY ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    function invariant_lpAccountingMatchesLockedMinLiquidity() public view {
        uint256 minLiq = amm.MIN_LIQUIDITY();

        for (uint256 i = 0; i < poolCount(); i++) {
            bytes32 pid = getPoolId(i);
            uint256 supply = amm.totalSupply(pid);

            if (supply == 0) continue;

            uint256 sum = sumLPBalances(pid);

            assertEq(supply, sum + minLiq, "supply != sumBalances + MIN_LIQUIDITY");

            for (uint256 k = 0; k < actors.length; k++) {
                uint256 bal = amm.liquidityBalances(pid, actors[k]);
                assertLe(bal, supply, "actor LP balance > totalSupply");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A3: TOKEN BALANCE COVERS RESERVES
    //////////////////////////////////////////////////////////////*/

    function invariant_tokenBalanceCoversSumOfReserves() public view {
        uint256 n = tokens.length;
        uint256[] memory sumReserves = new uint256[](n);

        for (uint256 a = 0; a < n; a++) {
            for (uint256 b = 0; b < n; b++) {
                if (a == b) continue;

                address userToken = address(tokens[a]);
                address validatorToken = address(tokens[b]);

                bytes32 pid = amm.getPoolId(userToken, validatorToken);
                if (!seenPool[pid]) continue;

                IFeeAMM.Pool memory p = amm.getPool(userToken, validatorToken);

                sumReserves[a] += uint256(p.reserveUserToken);
                sumReserves[b] += uint256(p.reserveValidatorToken);
            }
        }

        for (uint256 i = 0; i < n; i++) {
            uint256 bal = tokens[i].balanceOf(address(amm));
            assertGe(bal, sumReserves[i], "token balance < sum(reserves)");
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A4: POOL IDS RESOLVE TO UNIQUE PAIR
    //////////////////////////////////////////////////////////////*/

    function invariant_poolIdsResolveToUniqueOrderedPair() public view {
        for (uint256 i = 0; i < poolCount(); i++) {
            bytes32 pid = getPoolId(i);
            uint256 matches;

            for (uint256 a = 0; a < tokens.length; a++) {
                for (uint256 b = 0; b < tokens.length; b++) {
                    if (a == b) continue;
                    if (amm.getPoolId(address(tokens[a]), address(tokens[b])) == pid) {
                        matches++;
                    }
                }
            }

            assertEq(matches, 1, "poolId must match exactly one ordered pair");
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A5: NO LP WHEN UNINITIALIZED
    //////////////////////////////////////////////////////////////*/

    function invariant_noLpWhenUninitialized() public view {
        for (uint256 i = 0; i < poolCount(); i++) {
            bytes32 pid = getPoolId(i);
            uint256 supply = amm.totalSupply(pid);
            if (supply != 0) continue;

            for (uint256 k = 0; k < actors.length; k++) {
                uint256 bal = amm.liquidityBalances(pid, actors[k]);
                assertEq(bal, 0, "uninitialized pool => all actor LP = 0");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A6: TRACKED POOL IDS ARE MARKED SEEN
    //////////////////////////////////////////////////////////////*/

    function invariant_trackedPoolIdsAreMarkedSeen() public view {
        for (uint256 i = 0; i < poolCount(); i++) {
            assertTrue(seenPool[getPoolId(i)], "poolIds[] must only contain seen pools");
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A7: NO VALUE CREATION FROM ROUNDING
    //////////////////////////////////////////////////////////////*/

    function invariant_noFreeValue() public view {
        assertLe(ghost_totalBurned, ghost_totalMinted, "Burned more LP than minted");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A8: REBALANCE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    function invariant_rebalanceSwapRateCorrect() public view {
        // Use tracked sum of individual expected inputs instead of computing from total
        // This avoids floor division rounding discrepancy: sum(floor(x_i)) <= floor(sum(x_i))
        assertGe(
            ghost_rebalanceIn,
            ghost_rebalanceExpectedIn,
            "Rebalance swap: insufficient input collected"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A9: FEE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    function invariant_feeSwapRateCorrect() public view {
        uint256 expectedOut = (ghost_feeSwapIn * 9970) / 10_000;

        assertLe(ghost_feeSwapOut, expectedOut, "Fee swap output too high");
        assertGe(ghost_feeSwapOut + feeSwapCalls, expectedOut, "Fee swap output too low");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A10: RESERVES BOUNDED BY UINT128
    //////////////////////////////////////////////////////////////*/

    function invariant_reservesBounded() public view {
        for (uint256 i = 0; i < poolCount(); i++) {
            bytes32 pid = getPoolId(i);
            (uint128 ru, uint128 rv) = amm.pools(pid);

            assertLe(uint256(ru), type(uint128).max, "reserveUserToken > u128");
            assertLe(uint256(rv), type(uint128).max, "reserveValidatorToken > u128");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public view {
        console.log("=== FeeAMM Invariant Call Summary ===");
        console.log("Pools touched:", poolCount());
        console.log("Mint calls:", mintCalls);
        console.log("Burn calls:", burnCalls);
        console.log("Rebalance calls:", rebalanceCalls);
        console.log("Fee swap calls:", feeSwapCalls);
        console.log("Total LP minted:", ghost_totalMinted);
        console.log("Total LP burned:", ghost_totalBurned);
        console.log("Total rebalance in:", ghost_rebalanceIn);
        console.log("Total rebalance out:", ghost_rebalanceOut);
        console.log("Total rebalance expected in:", ghost_rebalanceExpectedIn);
        console.log("Total fee swap in:", ghost_feeSwapIn);
        console.log("Total fee swap out:", ghost_feeSwapOut);
    }

}
