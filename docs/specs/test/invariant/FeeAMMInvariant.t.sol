// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { FeeAMMHandler } from "./FeeAMMHandler.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { console } from "forge-std/console.sol";

/// @title FeeAMMInvariantTest
/// @notice Invariant tests for the FeeAMM contract with multi-pool support
/// @dev Tests run against both Solidity reference (forge test) and Rust precompiles (tempo-forge test)
contract FeeAMMInvariantTest is StdInvariant, BaseTest {

    FeeAMMHandler public handler;

    // Token universe for multi-pool testing
    TIP20[] public tokens;

    // Actors for testing
    address[] public actors;

    function setUp() public override {
        super.setUp();

        // Create token universe (4 tokens for various pair combinations)
        // Note: We skip pathUSD since it requires special admin setup
        // Instead we create 4 new tokens that we have full control over

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

        // Grant ISSUER_ROLE to admin for all tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, admin);
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

        // Create handler with tokens and actors
        handler = new FeeAMMHandler(amm, factory, tokens, actors, admin);

        // Grant issuer role to handler for all tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, address(handler));
        }

        // Target only the handler
        targetContract(address(handler));

        // Target specific selectors for fuzzing
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = handler.mint.selector;
        selectors[1] = handler.burn.selector;
        selectors[2] = handler.rebalanceSwap.selector;
        selectors[3] = handler.simulateFeeSwap.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A1: POOL INITIALIZATION SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @notice A pool is either completely uninitialized, or properly initialized
    /// @dev If totalSupply == 0, both reserves must be zero
    ///      If totalSupply > 0, pool must have locked at least MIN_LIQUIDITY
    function invariant_poolSupplyAndReserveShape() public view {
        uint256 minLiq = amm.MIN_LIQUIDITY();

        for (uint256 i = 0; i < handler.poolCount(); i++) {
            bytes32 pid = handler.getPoolId(i);
            (uint128 ru, uint128 rv) = amm.pools(pid);
            uint256 supply = amm.totalSupply(pid);

            // If supply is zero, both reserves must be zero
            if (supply == 0) {
                assertEq(uint256(ru), 0, "supply=0 => reserveU=0");
                assertEq(uint256(rv), 0, "supply=0 => reserveV=0");
            } else {
                // If supply > 0, the pool must have at least MIN_LIQUIDITY locked
                assertGe(supply, minLiq, "initialized pool must lock MIN_LIQUIDITY");
            }

            // If either reserve is nonzero, the pool must be initialized
            if (ru != 0 || rv != 0) {
                assertGt(supply, 0, "reserves>0 => supply>0");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A2: LP SUPPLY ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Total LP supply equals sum of all actor LP balances plus locked MIN_LIQUIDITY
    function invariant_lpAccountingMatchesLockedMinLiquidity() public view {
        uint256 minLiq = amm.MIN_LIQUIDITY();

        for (uint256 i = 0; i < handler.poolCount(); i++) {
            bytes32 pid = handler.getPoolId(i);
            uint256 supply = amm.totalSupply(pid);

            // If supply is zero, this pool is considered uninitialized
            if (supply == 0) continue;

            uint256 sum = handler.sumLPBalances(pid);

            // Strong accounting identity: all LP owned by actors + locked MIN_LIQUIDITY == totalSupply
            assertEq(supply, sum + minLiq, "supply != sumBalances + MIN_LIQUIDITY");

            // Local sanity: no single actor can exceed totalSupply
            for (uint256 k = 0; k < actors.length; k++) {
                uint256 bal = amm.liquidityBalances(pid, actors[k]);
                assertLe(bal, supply, "actor LP balance > totalSupply");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A3: TOKEN BALANCE COVERS RESERVES
    //////////////////////////////////////////////////////////////*/

    /// @notice AMM's on-chain token balance must be at least the sum of reserves across all pools
    function invariant_tokenBalanceCoversSumOfReserves() public view {
        uint256 n = tokens.length;
        uint256[] memory sumReserves = new uint256[](n);

        // Accumulate reserves across all seen pools in the token universe
        for (uint256 a = 0; a < n; a++) {
            for (uint256 b = 0; b < n; b++) {
                if (a == b) continue;

                address userToken = address(tokens[a]);
                address validatorToken = address(tokens[b]);

                bytes32 pid = amm.getPoolId(userToken, validatorToken);
                if (!handler.seenPool(pid)) continue;

                IFeeAMM.Pool memory p = amm.getPool(userToken, validatorToken);

                sumReserves[a] += uint256(p.reserveUserToken);
                sumReserves[b] += uint256(p.reserveValidatorToken);
            }
        }

        // Check AMM balances cover aggregate reserves per token
        for (uint256 i = 0; i < n; i++) {
            uint256 bal = tokens[i].balanceOf(address(amm));
            assertGe(bal, sumReserves[i], "token balance < sum(reserves)");
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A4: POOL IDS RESOLVE TO UNIQUE PAIR
    //////////////////////////////////////////////////////////////*/

    /// @notice Every tracked poolId must correspond to exactly one ordered pair
    function invariant_poolIdsResolveToUniqueOrderedPair() public view {
        for (uint256 i = 0; i < handler.poolCount(); i++) {
            bytes32 pid = handler.getPoolId(i);
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

    /// @notice If a pool is uninitialized (totalSupply == 0), no actor may hold LP for it
    function invariant_noLpWhenUninitialized() public view {
        for (uint256 i = 0; i < handler.poolCount(); i++) {
            bytes32 pid = handler.getPoolId(i);
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

    /// @notice Tracked poolIds must correspond to a "seen" pool
    function invariant_trackedPoolIdsAreMarkedSeen() public view {
        for (uint256 i = 0; i < handler.poolCount(); i++) {
            assertTrue(
                handler.seenPool(handler.getPoolId(i)), "poolIds[] must only contain seen pools"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A7: NO VALUE CREATION FROM ROUNDING
    //////////////////////////////////////////////////////////////*/

    /// @notice Users cannot extract more LP tokens than minted through rounding
    function invariant_noFreeValue() public view {
        assertLe(
            handler.ghost_totalBurned(), handler.ghost_totalMinted(), "Burned more LP than minted"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A8: REBALANCE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Rebalance swap input must be >= (output * N) / SCALE + 1
    function invariant_rebalanceSwapRateCorrect() public view {
        uint256 totalIn = handler.ghost_rebalanceIn();
        uint256 totalOut = handler.ghost_rebalanceOut();

        if (totalOut == 0) return;

        // Minimum expected input: totalOut * 9985 / 10000 + roundUp (1 per swap)
        uint256 minExpectedIn = (totalOut * 9985) / 10_000 + handler.rebalanceCalls();

        assertGe(totalIn, minExpectedIn, "Rebalance swap: insufficient input collected");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A9: FEE SWAP RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fee swap output must be exactly (input * M) / SCALE
    function invariant_feeSwapRateCorrect() public view {
        uint256 totalIn = handler.ghost_feeSwapIn();
        uint256 totalOut = handler.ghost_feeSwapOut();

        if (totalIn == 0) return;

        // Expected output with rounding down per swap
        uint256 expectedOut = (totalIn * 9970) / 10_000;

        // Each swap rounds down, so actual can be at most expected
        assertLe(totalOut, expectedOut, "Fee swap output too high");

        // Actual should be close to expected (within one unit per swap due to rounding)
        uint256 maxRoundingError = handler.feeSwapCalls();
        assertGe(totalOut + maxRoundingError, expectedOut, "Fee swap output too low");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT A10: RESERVES BOUNDED BY UINT128
    //////////////////////////////////////////////////////////////*/

    /// @notice Pool reserves must always fit in uint128
    function invariant_reservesBounded() public view {
        for (uint256 i = 0; i < handler.poolCount(); i++) {
            bytes32 pid = handler.getPoolId(i);
            (uint128 ru, uint128 rv) = amm.pools(pid);

            assertLe(uint256(ru), type(uint128).max, "reserveUserToken > u128");
            assertLe(uint256(rv), type(uint128).max, "reserveValidatorToken > u128");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Log call statistics for debugging
    function invariant_callSummary() public view {
        console.log("=== FeeAMM Invariant Call Summary ===");
        console.log("Pools touched:", handler.poolCount());
        console.log("Mint calls:", handler.mintCalls());
        console.log("Burn calls:", handler.burnCalls());
        console.log("Rebalance calls:", handler.rebalanceCalls());
        console.log("Fee swap calls:", handler.feeSwapCalls());
        console.log("Total LP minted:", handler.ghost_totalMinted());
        console.log("Total LP burned:", handler.ghost_totalBurned());
        console.log("Total rebalance in:", handler.ghost_rebalanceIn());
        console.log("Total rebalance out:", handler.ghost_rebalanceOut());
        console.log("Total fee swap in:", handler.ghost_feeSwapIn());
        console.log("Total fee swap out:", handler.ghost_feeSwapOut());
    }

}
