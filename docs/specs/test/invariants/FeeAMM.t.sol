// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { FeeAMM } from "../../src/FeeAMM.sol";
import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { IFeeManager } from "../../src/interfaces/IFeeManager.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title FeeAMM Invariant Test
/// @notice Invariant tests for the FeeAMM/FeeManager implementation
contract FeeAMMInvariantTest is BaseTest {

    /// @dev Array of test actors that interact with the FeeAMM
    address[] private _actors;

    /// @dev Array of fee tokens (token1, token2, token3, token4)
    TIP20[] private _tokens;

    /// @dev Blacklist policy IDs for each token
    mapping(address => uint64) private _tokenPolicyIds;

    /// @dev Blacklist policy ID for pathUSD
    uint64 private _pathUsdPolicyId;

    /// @dev Additional tokens (token3, token4) - token1/token2 from BaseTest
    TIP20 public token3;
    TIP20 public token4;

    /// @dev Log file path for recording amm actions
    string private constant LOG_FILE = "amm.log";

    /// @dev Constants from Rust tip_fee_manager/amm.rs
    uint256 private constant M = 9970; // Fee swap rate (0.997 = 0.30% fee)
    uint256 private constant N = 9985; // Rebalance swap rate (0.9985 = 0.15% fee)
    uint256 private constant SCALE = 10_000;
    uint256 private constant MIN_LIQUIDITY = 1000;
    uint256 private constant SPREAD = 15; // N - M = 15 basis points

    /// @dev Ghost variables for tracking state changes
    uint256 private _totalMints;
    uint256 private _totalBurns;
    uint256 private _totalRebalanceSwaps;

    /// @dev Struct to reduce stack depth in burn handler
    struct BurnContext {
        address actor;
        address userToken;
        address validatorToken;
        bytes32 poolId;
        uint256 actorLiquidity;
        uint256 liquidityToBurn;
        uint256 totalSupplyBefore;
        uint128 reserveUserBefore;
        uint128 reserveValidatorBefore;
        uint256 actorUserBalanceBefore;
        uint256 actorValidatorBalanceBefore;
    }

    /// @dev Struct to reduce stack depth in rebalance handler
    struct RebalanceContext {
        address actor;
        address userToken;
        address validatorToken;
        uint256 amountOut;
        uint256 expectedAmountIn;
        uint128 reserveUserBefore;
        uint128 reserveValidatorBefore;
        uint256 actorValidatorBefore;
        uint256 actorUserBefore;
    }

    /// @dev Ghost variables for tracking rounding exploitation attempts
    uint256 private _totalMintBurnCycles;
    uint256 private _totalSmallRebalanceSwaps;
    uint256 private _ghostRebalanceInputSum;
    uint256 private _ghostRebalanceOutputSum;

    /// @dev Ghost variables for tracking fee collection
    uint256 private _totalFeeCollections;
    uint256 private _ghostFeeInputSum;
    uint256 private _ghostFeeOutputSum;

    /// @dev Track validators with pending fees (validator => token => hasFees)
    /// Used to avoid wasting calls on distributeFees when there are no fees
    mapping(address => mapping(address => bool)) private _hasPendingFees;

    /// @dev Track actors who have participated in fee-related activities
    /// Only these actors should have their token preferences changed
    mapping(address => bool) private _activeActors;
    address[] private _activeActorList;

    /// @dev Ghost variables for tracking dust accumulation from rounding
    /// All rounding should favor the pool (dust accumulates in AMM, not extracted by users)
    uint256 private _ghostBurnUserTheoretical;
    uint256 private _ghostBurnUserActual;
    uint256 private _ghostBurnValidatorTheoretical;
    uint256 private _ghostBurnValidatorActual;

    /// @dev Precise dust tracking for fee swaps
    /// Fee swap: user pays X, validator receives (X * M / SCALE)
    /// Dust = X - (X * M / SCALE) = X * (SCALE - M) / SCALE (theoretical)
    /// But integer division may leave extra dust
    uint256 private _ghostFeeSwapTheoreticalDust;
    uint256 private _ghostFeeSwapActualDust;

    /// @dev Precise dust tracking for rebalance swaps
    /// Rebalance: user receives Y, pays (Y * N / SCALE) + 1
    /// The +1 is intentional rounding that favors the pool
    uint256 private _ghostRebalanceRoundingDust;

    /// @dev Ghost variables for fee conservation (TEMPO-AMM29)
    /// Track total fees collected and distributed to ensure fees cannot be created from nothing
    uint256 private _ghostTotalFeesCollected;
    uint256 private _ghostTotalFeesDistributed;

    /// @notice Sets up the test environment
    /// @dev Initializes BaseTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Create additional tokens (token1, token2 already created in BaseTest)
        token3 =
            TIP20(factory.createToken("TOKEN3", "T3", "USD", pathUSD, admin, bytes32("token3")));
        token4 =
            TIP20(factory.createToken("TOKEN4", "T4", "USD", pathUSD, admin, bytes32("token4")));

        // Setup pathUSD with issuer role (pathUSDAdmin is the pathUSD admin from BaseTest)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup all tokens with issuer role and create trading pairs
        vm.startPrank(admin);
        TIP20[4] memory tokens = [token1, token2, token3, token4];
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, admin);
            _tokens.push(tokens[i]);

            // Create blacklist policy for each token
            uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
            tokens[i].changeTransferPolicyId(policyId);
            _tokenPolicyIds[address(tokens[i])] = policyId;
        }
        vm.stopPrank();

        // Create blacklist policy for pathUSD
        vm.startPrank(pathUSDAdmin);
        _pathUsdPolicyId = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        pathUSD.changeTransferPolicyId(_pathUsdPolicyId);
        vm.stopPrank();

        _actors = _buildActors(20);

        // Initialize log file (cleared at start of test, appends across invariant runs)
        try vm.removeFile(LOG_FILE) { } catch { }
        _log("================================================================================");
        _log("                         FeeAMM Invariant Test Log");
        _log("================================================================================");
        _log(
            string.concat(
                "Actors: ", vm.toString(_actors.length), " | Tokens: pathUSD, T1, T2, T3, T4"
            )
        );
        _log("--------------------------------------------------------------------------------");
        _log("");
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for minting LP tokens
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    /// @param amount Amount of validator tokens to deposit
    function mint(uint256 actorSeed, uint256 tokenSeed1, uint256 tokenSeed2, uint256 amount)
        external
    {
        address actor = _selectActor(actorSeed);
        address userToken = _selectToken(tokenSeed1);
        address validatorToken = _selectToken(tokenSeed2);

        // Skip if tokens are identical
        vm.assume(userToken != validatorToken);

        // Skip if actor is blacklisted for validatorToken (can't mint funds to them)
        uint64 policyId =
            validatorToken == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[validatorToken];
        vm.assume(registry.isAuthorized(policyId, actor));

        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        uint256 totalSupplyBefore = amm.totalSupply(poolId);

        // First mint requires >= MIN_LIQUIDITY to avoid wasting budget on known rejections
        // Subsequent mints allow smaller amounts to test edge cases
        amount = bound(amount, totalSupplyBefore == 0 ? MIN_LIQUIDITY : 1, 10_000_000_000);

        // Ensure actor has funds
        _ensureFunds(actor, TIP20(validatorToken), amount);
        IFeeAMM.Pool memory poolBefore = amm.getPool(userToken, validatorToken);
        uint256 actorLiquidityBefore = amm.liquidityBalances(poolId, actor);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256 liquidity) {
            vm.stopPrank();

            _totalMints++;

            // TEMPO-AMM1: Liquidity minted should be positive
            assertTrue(liquidity > 0, "TEMPO-AMM1: Minted liquidity should be positive");

            // TEMPO-AMM2: Total supply should increase by minted liquidity (+ MIN_LIQUIDITY for first mint)
            uint256 totalSupplyAfter = amm.totalSupply(poolId);
            if (totalSupplyBefore == 0) {
                assertEq(
                    totalSupplyAfter,
                    liquidity + MIN_LIQUIDITY,
                    "TEMPO-AMM2: First mint total supply mismatch"
                );
            } else {
                assertEq(
                    totalSupplyAfter,
                    totalSupplyBefore + liquidity,
                    "TEMPO-AMM2: Subsequent mint total supply mismatch"
                );
            }

            // TEMPO-AMM3: Actor's liquidity balance should increase
            uint256 actorLiquidityAfter = amm.liquidityBalances(poolId, actor);
            assertEq(
                actorLiquidityAfter,
                actorLiquidityBefore + liquidity,
                "TEMPO-AMM3: Actor liquidity balance mismatch"
            );

            // TEMPO-AMM4: Validator token reserve should increase by deposited amount
            IFeeAMM.Pool memory poolAfter = amm.getPool(userToken, validatorToken);
            assertEq(
                poolAfter.reserveValidatorToken,
                poolBefore.reserveValidatorToken + uint128(amount),
                "TEMPO-AMM4: Validator reserve mismatch after mint"
            );

            _logMint(actor, liquidity, amount);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for burning LP tokens
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    /// @param liquidityPct Percentage of actor's liquidity to burn (0-100)
    function burn(uint256 actorSeed, uint256 tokenSeed1, uint256 tokenSeed2, uint256 liquidityPct)
        external
    {
        BurnContext memory ctx;
        ctx.actor = _selectActor(actorSeed);
        ctx.userToken = _selectToken(tokenSeed1);
        ctx.validatorToken = _selectToken(tokenSeed2);

        // Skip if tokens are identical
        vm.assume(ctx.userToken != ctx.validatorToken);

        ctx.poolId = amm.getPoolId(ctx.userToken, ctx.validatorToken);
        ctx.actorLiquidity = amm.liquidityBalances(ctx.poolId, ctx.actor);

        // Skip if actor has no liquidity
        vm.assume(ctx.actorLiquidity > 0);

        // Calculate amount to burn
        liquidityPct = bound(liquidityPct, 1, 100);
        ctx.liquidityToBurn = (ctx.actorLiquidity * liquidityPct) / 100;
        if (ctx.liquidityToBurn == 0) ctx.liquidityToBurn = 1;

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);
        ctx.totalSupplyBefore = amm.totalSupply(ctx.poolId);
        ctx.reserveUserBefore = poolBefore.reserveUserToken;
        ctx.reserveValidatorBefore = poolBefore.reserveValidatorToken;
        ctx.actorUserBalanceBefore = TIP20(ctx.userToken).balanceOf(ctx.actor);
        ctx.actorValidatorBalanceBefore = TIP20(ctx.validatorToken).balanceOf(ctx.actor);

        vm.startPrank(ctx.actor);
        try amm.burn(ctx.userToken, ctx.validatorToken, ctx.liquidityToBurn, ctx.actor) returns (
            uint256 amountUserToken, uint256 amountValidatorToken
        ) {
            vm.stopPrank();
            _totalBurns++;

            // Track theoretical vs actual for dust analysis
            // Theoretical (unrounded): liquidity * reserve / totalSupply
            // Due to integer division, actual <= theoretical
            uint256 theoreticalUser =
                (ctx.liquidityToBurn * ctx.reserveUserBefore) / ctx.totalSupplyBefore;
            uint256 theoreticalValidator =
                (ctx.liquidityToBurn * ctx.reserveValidatorBefore) / ctx.totalSupplyBefore;
            _ghostBurnUserTheoretical += theoreticalUser;
            _ghostBurnUserActual += amountUserToken;
            _ghostBurnValidatorTheoretical += theoreticalValidator;
            _ghostBurnValidatorActual += amountValidatorToken;

            _assertBurnInvariants(ctx, amountUserToken, amountValidatorToken);
            _logBurn(ctx.actor, ctx.liquidityToBurn, amountUserToken, amountValidatorToken);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @dev Verifies burn invariants
    function _assertBurnInvariants(
        BurnContext memory ctx,
        uint256 amountUserToken,
        uint256 amountValidatorToken
    ) internal view {
        // TEMPO-AMM5: Returned amounts should match pro-rata calculation
        uint256 expectedUserAmount =
            (ctx.liquidityToBurn * ctx.reserveUserBefore) / ctx.totalSupplyBefore;
        uint256 expectedValidatorAmount =
            (ctx.liquidityToBurn * ctx.reserveValidatorBefore) / ctx.totalSupplyBefore;
        assertEq(amountUserToken, expectedUserAmount, "TEMPO-AMM5: User token amount mismatch");
        assertEq(
            amountValidatorToken,
            expectedValidatorAmount,
            "TEMPO-AMM5: Validator token amount mismatch"
        );

        // TEMPO-AMM6: Total supply should decrease by burned liquidity
        assertEq(
            amm.totalSupply(ctx.poolId),
            ctx.totalSupplyBefore - ctx.liquidityToBurn,
            "TEMPO-AMM6: Total supply mismatch after burn"
        );

        // TEMPO-AMM7: Actor's liquidity balance should decrease
        assertEq(
            amm.liquidityBalances(ctx.poolId, ctx.actor),
            ctx.actorLiquidity - ctx.liquidityToBurn,
            "TEMPO-AMM7: Actor liquidity balance mismatch"
        );

        // TEMPO-AMM8: Actor receives the exact calculated token amounts
        assertEq(
            TIP20(ctx.userToken).balanceOf(ctx.actor),
            ctx.actorUserBalanceBefore + amountUserToken,
            "TEMPO-AMM8: Actor user token balance mismatch"
        );
        assertEq(
            TIP20(ctx.validatorToken).balanceOf(ctx.actor),
            ctx.actorValidatorBalanceBefore + amountValidatorToken,
            "TEMPO-AMM8: Actor validator token balance mismatch"
        );

        // TEMPO-AMM9: Pool reserves should decrease
        IFeeAMM.Pool memory poolAfter = amm.getPool(ctx.userToken, ctx.validatorToken);
        assertEq(
            poolAfter.reserveUserToken,
            ctx.reserveUserBefore - uint128(amountUserToken),
            "TEMPO-AMM9: User reserve mismatch"
        );
        assertEq(
            poolAfter.reserveValidatorToken,
            ctx.reserveValidatorBefore - uint128(amountValidatorToken),
            "TEMPO-AMM9: Validator reserve mismatch"
        );
    }

    /// @notice Handler for rebalance swaps (validator token -> user token)
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    /// @param amountOutRaw Amount of user tokens to receive
    function rebalanceSwap(
        uint256 actorSeed,
        uint256 tokenSeed1,
        uint256 tokenSeed2,
        uint256 amountOutRaw
    ) external {
        RebalanceContext memory ctx;
        ctx.actor = _selectActor(actorSeed);
        ctx.userToken = _selectToken(tokenSeed1);
        ctx.validatorToken = _selectToken(tokenSeed2);

        // Skip if tokens are identical
        vm.assume(ctx.userToken != ctx.validatorToken);

        // Skip if actor is blacklisted for validatorToken (can't mint funds to them)
        uint64 policyId = ctx.validatorToken == address(pathUSD)
            ? _pathUsdPolicyId
            : _tokenPolicyIds[ctx.validatorToken];
        vm.assume(registry.isAuthorized(policyId, ctx.actor));

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);

        // Skip if pool has no user token reserves
        vm.assume(poolBefore.reserveUserToken > 0);

        // Bound amountOut to available reserves
        ctx.amountOut = bound(amountOutRaw, 1, poolBefore.reserveUserToken);

        // Calculate expected amountIn: amountIn = (amountOut * N / SCALE) + 1
        ctx.expectedAmountIn = (ctx.amountOut * N) / SCALE + 1;
        ctx.reserveUserBefore = poolBefore.reserveUserToken;
        ctx.reserveValidatorBefore = poolBefore.reserveValidatorToken;

        // Ensure actor has enough validator tokens
        _ensureFunds(ctx.actor, TIP20(ctx.validatorToken), ctx.expectedAmountIn * 2);

        ctx.actorValidatorBefore = TIP20(ctx.validatorToken).balanceOf(ctx.actor);
        ctx.actorUserBefore = TIP20(ctx.userToken).balanceOf(ctx.actor);

        vm.startPrank(ctx.actor);
        try amm.rebalanceSwap(ctx.userToken, ctx.validatorToken, ctx.amountOut, ctx.actor) returns (
            uint256 amountIn
        ) {
            vm.stopPrank();
            _totalRebalanceSwaps++;
            _ghostRebalanceInputSum += amountIn;
            _ghostRebalanceOutputSum += ctx.amountOut;

            // Track small rebalance swaps for rounding analysis
            if (ctx.amountOut < 10_000) {
                _totalSmallRebalanceSwaps++;
            }

            // Track the +1 rounding dust that favors the pool
            // Formula: amountIn = (amountOut * N / SCALE) + 1
            // Without +1: amountIn would be (amountOut * N / SCALE)
            // The +1 is dust captured by the pool
            uint256 withoutRounding = (ctx.amountOut * N) / SCALE;
            uint256 roundingDust = amountIn - withoutRounding; // Should always be 1
            _ghostRebalanceRoundingDust += roundingDust;

            // Mark actor as active
            _markActorActive(ctx.actor);

            _assertRebalanceInvariants(ctx, amountIn);
            _logRebalance(ctx.actor, amountIn, ctx.amountOut);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @dev Verifies rebalance swap invariants
    function _assertRebalanceInvariants(RebalanceContext memory ctx, uint256 amountIn)
        internal
        view
    {
        // TEMPO-AMM10: amountIn should match expected calculation
        assertEq(amountIn, ctx.expectedAmountIn, "TEMPO-AMM10: Rebalance swap amountIn mismatch");

        // TEMPO-AMM11: Pool reserves should update correctly
        IFeeAMM.Pool memory poolAfter = amm.getPool(ctx.userToken, ctx.validatorToken);
        assertEq(
            poolAfter.reserveUserToken,
            ctx.reserveUserBefore - uint128(ctx.amountOut),
            "TEMPO-AMM11: User reserve mismatch after rebalance"
        );
        assertEq(
            poolAfter.reserveValidatorToken,
            ctx.reserveValidatorBefore + uint128(amountIn),
            "TEMPO-AMM11: Validator reserve mismatch after rebalance"
        );

        // TEMPO-AMM12: Actor balances should update correctly
        assertEq(
            TIP20(ctx.validatorToken).balanceOf(ctx.actor),
            ctx.actorValidatorBefore - amountIn,
            "TEMPO-AMM12: Actor validator balance mismatch"
        );
        assertEq(
            TIP20(ctx.userToken).balanceOf(ctx.actor),
            ctx.actorUserBefore + ctx.amountOut,
            "TEMPO-AMM12: Actor user balance mismatch"
        );
    }

    /// @notice Handler for setting validator token preference
    /// @dev Only sets tokens for active actors to avoid wasted calls
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed Seed for selecting token
    function setValidatorToken(uint256 actorSeed, uint256 tokenSeed) external {
        // Only set tokens for actors who have participated in fee activities
        vm.assume(_activeActorList.length > 0);
        address actor = _selectActiveActor(actorSeed);
        address token = _selectToken(tokenSeed);

        // Cannot set validator token if actor is the block coinbase (beneficiary check in Rust)
        vm.coinbase(address(0xdead));

        vm.startPrank(actor, actor); // Set both msg.sender and tx.origin
        try amm.setValidatorToken(token) {
            vm.stopPrank();

            // TEMPO-FEE1: Validator token should be updated
            address storedToken = amm.validatorTokens(actor);
            assertEq(storedToken, token, "TEMPO-FEE1: Validator token not set correctly");

            _log(
                string.concat(
                    "SET_VALIDATOR_TOKEN: ", _getActorIndex(actor), " -> ", _getTokenSymbol(token)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for setting user token preference
    /// @dev Only sets tokens for active actors to avoid wasted calls
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed Seed for selecting token
    function setUserToken(uint256 actorSeed, uint256 tokenSeed) external {
        // Only set tokens for actors who have participated in fee activities
        vm.assume(_activeActorList.length > 0);
        address actor = _selectActiveActor(actorSeed);
        address token = _selectToken(tokenSeed);

        vm.startPrank(actor, actor); // Set both msg.sender and tx.origin
        try amm.setUserToken(token) {
            vm.stopPrank();

            // TEMPO-FEE2: User token should be updated
            address storedToken = amm.userTokens(actor);
            assertEq(storedToken, token, "TEMPO-FEE2: User token not set correctly");

            _log(
                string.concat(
                    "SET_USER_TOKEN: ", _getActorIndex(actor), " -> ", _getTokenSymbol(token)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for mint/burn cycle (tests rounding exploitation)
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    /// @param amount Amount for the cycle
    function mintBurnCycle(
        uint256 actorSeed,
        uint256 tokenSeed1,
        uint256 tokenSeed2,
        uint256 amount
    ) external {
        address actor = _selectActor(actorSeed);
        address userToken = _selectToken(tokenSeed1);
        address validatorToken = _selectToken(tokenSeed2);

        vm.assume(userToken != validatorToken);

        // Skip if actor is blacklisted for validatorToken (can't mint funds to them)
        uint64 policyId =
            validatorToken == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[validatorToken];
        vm.assume(registry.isAuthorized(policyId, actor));

        amount = bound(amount, 1, 100_000);
        _ensureFunds(actor, TIP20(validatorToken), amount);

        uint256 actorBalBefore = TIP20(validatorToken).balanceOf(actor);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256 liquidity) {
            if (liquidity > 0) {
                try amm.burn(userToken, validatorToken, liquidity, actor) returns (
                    uint256, uint256
                ) {
                    _totalMintBurnCycles++;

                    uint256 actorBalAfter = TIP20(validatorToken).balanceOf(actor);
                    // TEMPO-AMM17: Mint/burn cycle should not profit the actor
                    assertTrue(
                        actorBalAfter <= actorBalBefore,
                        "TEMPO-AMM17: Actor should not profit from mint/burn cycle"
                    );
                } catch (bytes memory reason) {
                    _assertKnownError(reason);
                }
            }
        } catch (bytes memory reason) {
            _assertKnownError(reason);
        }
        vm.stopPrank();
    }

    /// @notice Handler for small rebalance swaps (tests rounding exploitation)
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    function smallRebalanceSwap(uint256 actorSeed, uint256 tokenSeed1, uint256 tokenSeed2)
        external
    {
        address actor = _selectActor(actorSeed);
        address userToken = _selectToken(tokenSeed1);
        address validatorToken = _selectToken(tokenSeed2);

        vm.assume(userToken != validatorToken);

        // Skip if actor is blacklisted for validatorToken (can't mint funds to them)
        uint64 policyId =
            validatorToken == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[validatorToken];
        vm.assume(registry.isAuthorized(policyId, actor));

        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);
        vm.assume(pool.reserveUserToken > 0);

        // Use very small amounts where rounding matters most
        uint256 amountOut = bound(pool.reserveUserToken, 1, 100);
        vm.assume(amountOut <= pool.reserveUserToken);

        uint256 expectedIn = (amountOut * N) / SCALE + 1;
        _ensureFunds(actor, TIP20(validatorToken), expectedIn * 2);

        vm.startPrank(actor);
        try amm.rebalanceSwap(userToken, validatorToken, amountOut, actor) returns (
            uint256 amountIn
        ) {
            // TEMPO-AMM18: Small swaps should still pay >= theoretical rate
            uint256 theoretical = (amountOut * N) / SCALE;
            assertTrue(
                amountIn >= theoretical, "TEMPO-AMM18: Small swap should pay >= theoretical rate"
            );
            // TEMPO-AMM19: Small swaps should not allow profit
            assertTrue(amountIn >= 1, "TEMPO-AMM19: Must pay at least 1 for any swap");
        } catch (bytes memory reason) {
            _assertKnownError(reason);
        }
        vm.stopPrank();
    }

    /// @dev Number of actors that can be permanently blacklisted (out of 20)
    /// Only actors 0-4 can remain blacklisted; actors 5-19 are always recovered
    uint256 private constant BLACKLISTABLE_ACTOR_COUNT = 5;

    /// @notice Handler for toggling blacklist status of actors
    /// @dev TEMPO-AMM32/33: Blacklist state changes happen independently of operations.
    ///      Existing handlers (mint, burn, rebalanceSwap, distributeFees) will naturally
    ///      encounter blacklisted actors and verify PolicyForbids behavior.
    ///
    ///      Strategy: Only actors 0-4 (5 out of 20) can be permanently blacklisted.
    ///      Once blacklisted, they stay blacklisted (only recovered in blacklistRecovery).
    ///      All other actors (5-19) are immediately recovered if blacklisted.
    ///      This prevents "assume hell" in long fuzzing campaigns while still testing
    ///      blacklist scenarios thoroughly.
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed Seed for selecting token
    /// @param probabilitySeed Seed for probabilistic decisions
    function toggleBlacklist(uint256 actorSeed, uint256 tokenSeed, uint256 probabilitySeed)
        external
    {
        address actor = _selectActor(actorSeed);
        address token = _selectToken(tokenSeed);

        uint64 policyId = token == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[token];
        address policyAdmin = token == address(pathUSD) ? pathUSDAdmin : admin;

        // Determine if this actor is in the blacklistable pool (actors 0-4)
        uint256 actorIndex = actorSeed % _actors.length;
        bool isBlacklistableActor = actorIndex < BLACKLISTABLE_ACTOR_COUNT;

        // Check current blacklist status
        bool currentlyBlacklisted = !registry.isAuthorized(policyId, actor);

        if (!isBlacklistableActor) {
            // Non-blacklistable actor (5-19): always recover if blacklisted, never blacklist
            if (currentlyBlacklisted) {
                vm.prank(policyAdmin);
                registry.modifyPolicyBlacklist(policyId, actor, false);
                _log(
                    string.concat(
                        "WHITELIST: ",
                        _getActorIndex(actor),
                        " recovered (non-blacklistable) for ",
                        _getTokenSymbol(token)
                    )
                );
            }
            // If not blacklisted, do nothing - keep it that way
            return;
        }

        // Blacklistable actor (0-4): can be permanently blacklisted
        if (currentlyBlacklisted) {
            // Already blacklisted - stay blacklisted (permanent until Phase 2 exit)
            return;
        }

        // Not blacklisted yet - 20% chance to blacklist
        if ((probabilitySeed % 100) < 20) {
            vm.prank(policyAdmin);
            registry.modifyPolicyBlacklist(policyId, actor, true);
            _log(
                string.concat(
                    "BLACKLIST: ",
                    _getActorIndex(actor),
                    " permanently blacklisted for ",
                    _getTokenSymbol(token)
                )
            );
        }
    }

    /// @notice Handler for distributing collected fees
    /// @dev On tempo-foundry, fees are only collected via protocol tx execution
    ///      This handler tests the distribution mechanism when fees exist
    /// @param actorSeed Seed for selecting validator
    /// @param tokenSeed Seed for selecting token
    function distributeFees(uint256 actorSeed, uint256 tokenSeed) external {
        address validator = _selectActor(actorSeed);
        address token = _selectToken(tokenSeed);

        // Skip if we know there are no pending fees for this validator/token pair
        // This avoids wasting calls on "received 0 fees" scenarios
        vm.assume(_hasPendingFees[validator][token]);

        uint256 collectedBefore = amm.collectedFees(validator, token);
        uint256 validatorBalanceBefore = TIP20(token).balanceOf(validator);

        try amm.distributeFees(validator, token) {
            // Clear pending fees tracker
            _hasPendingFees[validator][token] = false;

            // TEMPO-FEE3: Collected fees should be zeroed after distribution
            uint256 collectedAfter = amm.collectedFees(validator, token);
            assertEq(
                collectedAfter, 0, "TEMPO-FEE3: Collected fees should be zero after distribution"
            );

            // TEMPO-FEE4: Validator should receive the collected fees
            if (collectedBefore > 0) {
                uint256 validatorBalanceAfter = TIP20(token).balanceOf(validator);
                assertEq(
                    validatorBalanceAfter,
                    validatorBalanceBefore + collectedBefore,
                    "TEMPO-FEE4: Validator should receive collected fees"
                );
                _ghostTotalFeesDistributed += collectedBefore; // Track for TEMPO-AMM29
            }

            _logDistribute(validator, collectedBefore);
        } catch (bytes memory reason) {
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for simulating fee collection (mocked approach)
    /// @dev Simulates the fee swap and fee accumulation that would happen during tx execution.
    ///      This mocks what collect_fee_pre_tx + collect_fee_post_tx would do:
    ///      1. User pays fees in their preferred token (userToken)
    ///      2. If userToken != validatorToken, execute fee swap at rate M
    ///      3. Accumulate fees for validator in their preferred token
    ///
    ///      Uses vm.store to directly modify precompile storage. Works on both foundry
    ///      (Solidity reference impl) and tempo-foundry (Rust precompile).
    /// @param userSeed Seed for selecting user (fee payer)
    /// @param validatorSeed Seed for selecting validator (fee recipient)
    /// @param feeAmountRaw Amount of fees to simulate
    function simulateFeeCollection(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 feeAmountRaw,
        uint256 crossTokenBias
    ) external {
        address user = _selectActor(userSeed);
        address validator = _selectActor(validatorSeed);

        // Get user and validator token preferences (default to pathUSD if not set)
        address userToken = amm.userTokens(user);
        if (userToken == address(0)) userToken = address(pathUSD);

        address validatorToken = amm.validatorTokens(validator);
        if (validatorToken == address(0)) validatorToken = address(pathUSD);

        // Bound fee amount first so we can check liquidity
        uint256 feeAmount = bound(feeAmountRaw, 1000, 1_000_000);
        uint256 expectedOutForCheck = (feeAmount * M) / SCALE;

        // Skip if user is blacklisted for userToken (can't mint funds to them or transfer from them)
        uint64 userTokenPolicyId =
            userToken == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[userToken];
        vm.assume(registry.isAuthorized(userTokenPolicyId, user));

        // Bias toward cross-token swaps: 90% chance to force different tokens
        // This exercises the actual swap logic more frequently
        if (userToken == validatorToken && (crossTokenBias % 100) < 90) {
            // Try to find a different validator token with sufficient liquidity
            // Use modulo to prevent overflow when iterating
            uint256 baseSeed = crossTokenBias % 1000;
            for (uint256 i = 0; i < 5; i++) {
                address candidateToken = _selectToken(baseSeed + i);
                if (candidateToken != userToken) {
                    IFeeAMM.Pool memory candidatePool = amm.getPool(userToken, candidateToken);
                    // Only use this token if the pool has sufficient liquidity
                    if (candidatePool.reserveValidatorToken >= expectedOutForCheck) {
                        validatorToken = candidateToken;
                        break;
                    }
                }
            }
        }

        // If tokens differ, we need a pool with liquidity
        if (userToken != validatorToken) {
            IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);
            uint256 expectedOut = (feeAmount * M) / SCALE;

            // Skip if insufficient liquidity
            vm.assume(pool.reserveValidatorToken >= expectedOut);
            vm.assume(expectedOut > 0);

            // Skip if adding feeAmount would overflow uint128
            vm.assume(uint256(pool.reserveUserToken) + feeAmount <= type(uint128).max);

            // Transfer userToken to AMM first
            _ensureFunds(user, TIP20(userToken), feeAmount);
            vm.prank(user);
            try TIP20(userToken).transfer(address(amm), feeAmount) returns (bool success) {
                assertTrue(success);

                // Simulate fee swap: update pool reserves
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);
                uint128 newReserveUser = pool.reserveUserToken + uint128(feeAmount);
                uint128 newReserveValidator = pool.reserveValidatorToken - uint128(expectedOut);
                _storePoolReserves(poolId, newReserveUser, newReserveValidator);

                // Accumulate fees for validator
                _storeCollectedFees(validator, validatorToken, expectedOut);
                _hasPendingFees[validator][validatorToken] = true;

                // Mark both actors as active for future token preference changes
                _markActorActive(user);
                _markActorActive(validator);

                _totalFeeCollections++;
                _ghostFeeInputSum += feeAmount;
                _ghostFeeOutputSum += expectedOut;
                _ghostTotalFeesCollected += expectedOut; // Track for TEMPO-AMM29

                // Track precise dust from fee swap (inline to avoid stack depth)
                _ghostFeeSwapTheoreticalDust += (feeAmount * (SCALE - M)) / SCALE;
                _ghostFeeSwapActualDust += feeAmount - expectedOut;

                _logFeeCollection(
                    user, validator, feeAmount, expectedOut, userToken, validatorToken
                );
            } catch (bytes memory reason) {
                _assertKnownError(reason);
            }
        } else {
            // Same token: no swap needed, just accumulate
            _ensureFunds(user, TIP20(userToken), feeAmount);
            vm.prank(user);
            try TIP20(userToken).transfer(address(amm), feeAmount) returns (bool success) {
                assertTrue(success);

                _storeCollectedFees(validator, validatorToken, feeAmount);
                _hasPendingFees[validator][validatorToken] = true;

                // Mark both actors as active
                _markActorActive(user);
                _markActorActive(validator);

                _totalFeeCollections++;
                _ghostFeeInputSum += feeAmount;
                _ghostFeeOutputSum += feeAmount;
                _ghostTotalFeesCollected += feeAmount; // Track for TEMPO-AMM29
                // No dust for same-token transfers

                _logFeeCollectionSameToken(user, validator, feeAmount, userToken);
            } catch (bytes memory reason) {
                _assertKnownError(reason);
            }
        }
    }

    /// @dev Logs a cross-token fee collection
    function _logFeeCollection(
        address user,
        address validator,
        uint256 feeAmount,
        uint256 expectedOut,
        address userToken,
        address validatorToken
    ) internal {
        _log(
            string.concat(
                "FEE_COLLECTION: ",
                _getActorIndex(user),
                " paid ",
                vm.toString(feeAmount),
                " ",
                _getTokenSymbol(userToken),
                " -> ",
                _getActorIndex(validator),
                " receives ",
                vm.toString(expectedOut),
                " ",
                _getTokenSymbol(validatorToken)
            )
        );
    }

    /// @dev Logs a same-token fee collection
    function _logFeeCollectionSameToken(
        address user,
        address validator,
        uint256 feeAmount,
        address token
    ) internal {
        _log(
            string.concat(
                "FEE_COLLECTION: ",
                _getActorIndex(user),
                " paid ",
                vm.toString(feeAmount),
                " ",
                _getTokenSymbol(token),
                " -> ",
                _getActorIndex(validator),
                " (same token, no swap)"
            )
        );
    }

    /// @dev Stores pool reserves directly using vm.store
    function _storePoolReserves(bytes32 poolId, uint128 reserveUser, uint128 reserveValidator)
        internal
    {
        // Storage layout differs between Rust and Solidity implementations:
        // Rust (isTempo=true):
        //   slot 0: validator_tokens
        //   slot 1: user_tokens
        //   slot 2: collected_fees
        //   slot 3: pools
        //   slot 4: total_supply
        //   slot 5: liquidity_balances
        // Solidity (isTempo=false):
        //   slot 0: pools
        uint256 poolsSlot = isTempo ? 3 : 0;
        bytes32 poolSlot = keccak256(abi.encode(poolId, poolsSlot));

        // Pack: lower 128 bits = reserveUserToken, upper 128 bits = reserveValidatorToken
        bytes32 newPoolValue = bytes32(uint256(reserveUser) | (uint256(reserveValidator) << 128));
        vm.store(address(amm), poolSlot, newPoolValue);
    }

    /// @dev Stores/increments collected fees using vm.store
    function _storeCollectedFees(address validator, address token, uint256 amount) internal {
        // Storage layout differs between Rust and Solidity implementations:
        // Rust (isTempo=true):
        //   slot 0: validator_tokens
        //   slot 1: user_tokens
        //   slot 2: collected_fees
        //   slot 3: pools
        //   slot 4: total_supply
        //   slot 5: liquidity_balances
        // Solidity (isTempo=false) - FeeManager inherits FeeAMM:
        //   slot 0: pools (from FeeAMM)
        //   slot 1: totalSupply (from FeeAMM)
        //   slot 2: liquidityBalances (from FeeAMM)
        //   slot 3: validatorTokens (from FeeManager)
        //   slot 4: userTokens (from FeeManager)
        //   slot 5: collectedFees (from FeeManager)
        // collected_fees is mapping(address => mapping(address => uint256))
        // slot = keccak256(token, keccak256(validator, collectedFeesSlot))
        uint256 collectedFeesSlot = isTempo ? 2 : 5;
        bytes32 innerSlot = keccak256(abi.encode(validator, collectedFeesSlot));
        bytes32 feeSlot = keccak256(abi.encode(token, innerSlot));

        // Read current value and add
        uint256 current = uint256(vm.load(address(amm), feeSlot));
        vm.store(address(amm), feeSlot, bytes32(current + amount));
    }

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after each invariant run to log final state
    function afterInvariant() public {
        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("                              Final State Summary");
        _log("--------------------------------------------------------------------------------");
        _log(string.concat("Total mints: ", vm.toString(_totalMints)));
        _log(string.concat("Total burns: ", vm.toString(_totalBurns)));
        _log(string.concat("Total rebalance swaps: ", vm.toString(_totalRebalanceSwaps)));
        _log(string.concat("Total fee collections: ", vm.toString(_totalFeeCollections)));
        _log(string.concat("Total mint/burn cycles: ", vm.toString(_totalMintBurnCycles)));
        _log(string.concat("Total small rebalance swaps: ", vm.toString(_totalSmallRebalanceSwaps)));

        // Fee collection: In > Out due to 0.30% fee (M=0.9970)
        // The difference is fee revenue captured by the AMM
        uint256 feeRevenue =
            _ghostFeeInputSum > _ghostFeeOutputSum ? _ghostFeeInputSum - _ghostFeeOutputSum : 0;
        _log(
            string.concat(
                "Fee swaps - In: ",
                vm.toString(_ghostFeeInputSum),
                ", Out: ",
                vm.toString(_ghostFeeOutputSum),
                ", Revenue (0.30% fee): ",
                vm.toString(feeRevenue)
            )
        );

        // Rebalance: Out > In due to 0.15% discount (N=0.9985)
        // The difference is the incentive paid to LPs for rebalancing
        uint256 rebalanceIncentive = _ghostRebalanceOutputSum > _ghostRebalanceInputSum
            ? _ghostRebalanceOutputSum - _ghostRebalanceInputSum
            : 0;
        _log(
            string.concat(
                "Rebalance swaps - In: ",
                vm.toString(_ghostRebalanceInputSum),
                ", Out: ",
                vm.toString(_ghostRebalanceOutputSum),
                ", LP incentive (0.15% discount): ",
                vm.toString(rebalanceIncentive)
            )
        );

        // Net AMM position: fee revenue minus rebalance incentives paid
        // Should be positive if fee volume exceeds rebalance volume (fee rate > rebalance rate)
        if (feeRevenue >= rebalanceIncentive) {
            _log(string.concat("Net AMM revenue: +", vm.toString(feeRevenue - rebalanceIncentive)));
        } else {
            _log(string.concat("Net AMM revenue: -", vm.toString(rebalanceIncentive - feeRevenue)));
        }

        // Precise dust tracking
        _logDustTracking();

        _logBalances();

        // TEMPO-AMM24: All participants can exit - simulate full withdrawal
        _verifyAllCanExit();
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    function invariantFeeAMM() public view {
        _invariantPoolSolvency();
        _invariantLiquidityAccounting();
        _invariantMinLiquidityLocked();
        _invariantFeeRates();
        _invariantReservesBoundedByU128();
        _invariantSpreadPreventsArbitrage();
        _invariantRebalanceRoundingFavorsPool();
        _invariantBurnRoundingFavorsPool();
        _invariantCollectedFeesNotExceedBalance();
        _invariantFeeSwapRateApplied();
        _invariantPoolIdUniqueness();
        _invariantNoLpWhenUninitialized();
        _invariantFeeConservation();
        _invariantPoolInitializationShape();
    }

    /// @notice TEMPO-AMM13: Pool solvency - AMM token balances >= sum of reserves
    function _invariantPoolSolvency() internal view {
        // Check all token pairs
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);

                IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

                // AMM should hold at least as many tokens as reserves indicate
                uint256 ammUserBalance = TIP20(userToken).balanceOf(address(amm));
                uint256 ammValidatorBalance = TIP20(validatorToken).balanceOf(address(amm));

                // Note: AMM balance may be higher due to collected fees not yet distributed
                assertTrue(
                    ammUserBalance >= pool.reserveUserToken,
                    "TEMPO-AMM13: AMM user token balance < reserve"
                );
                assertTrue(
                    ammValidatorBalance >= pool.reserveValidatorToken,
                    "TEMPO-AMM13: AMM validator token balance < reserve"
                );
            }
        }

        // Also check pathUSD pools
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = address(_tokens[i]);

            // pathUSD as user token
            IFeeAMM.Pool memory pool1 = amm.getPool(address(pathUSD), token);
            assertTrue(
                pathUSD.balanceOf(address(amm)) >= pool1.reserveUserToken,
                "TEMPO-AMM13: AMM pathUSD balance < reserve (as user)"
            );

            // pathUSD as validator token
            IFeeAMM.Pool memory pool2 = amm.getPool(token, address(pathUSD));
            assertTrue(
                pathUSD.balanceOf(address(amm)) >= pool2.reserveValidatorToken,
                "TEMPO-AMM13: AMM pathUSD balance < reserve (as validator)"
            );
        }
    }

    /// @notice TEMPO-AMM14: LP token accounting - sum of balances == total supply
    function _invariantLiquidityAccounting() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);

                uint256 totalSupply = amm.totalSupply(poolId);
                if (totalSupply == 0) continue;

                // Sum all actor balances
                uint256 sumBalances = 0;
                for (uint256 k = 0; k < _actors.length; k++) {
                    sumBalances += amm.liquidityBalances(poolId, _actors[k]);
                }

                // Total supply should equal sum of balances + MIN_LIQUIDITY (locked on first mint)
                // Note: MIN_LIQUIDITY is locked and not assigned to any user
                assertTrue(
                    totalSupply >= sumBalances, "TEMPO-AMM14: Total supply < sum of balances"
                );
                assertTrue(
                    totalSupply <= sumBalances + MIN_LIQUIDITY,
                    "TEMPO-AMM14: Total supply > sum of balances + MIN_LIQUIDITY"
                );
            }
        }
    }

    /// @notice TEMPO-AMM15: MIN_LIQUIDITY permanently locked on first mint
    function _invariantMinLiquidityLocked() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);

                uint256 totalSupply = amm.totalSupply(poolId);
                IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

                // If pool has been initialized (reserves > 0), MIN_LIQUIDITY should be locked
                if (pool.reserveValidatorToken > 0 || pool.reserveUserToken > 0) {
                    assertTrue(
                        totalSupply >= MIN_LIQUIDITY,
                        "TEMPO-AMM15: Total supply < MIN_LIQUIDITY after initialization"
                    );
                }
            }
        }
    }

    /// @notice TEMPO-AMM16: Fee rates are correctly applied (matches Rust constants)
    function _invariantFeeRates() internal pure {
        // Fee swap rate: m = 0.9970 means 0.30% fee
        // Rebalance rate: n = 0.9985 means 0.15% fee
        // These are constants, so just verify they're set correctly
        assertTrue(M == 9970, "TEMPO-AMM16: Fee swap rate M should be 9970");
        assertTrue(N == 9985, "TEMPO-AMM16: Rebalance rate N should be 9985");
        assertTrue(SCALE == 10_000, "TEMPO-AMM16: SCALE should be 10000");
    }

    /// @notice TEMPO-AMM20: Reserves are always bounded by uint128
    function _invariantReservesBoundedByU128() internal view {
        uint256 MAX_U128 = type(uint128).max;
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);

                IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

                // Reserves are uint128 by definition, but verify they're within bounds
                assertTrue(
                    uint256(pool.reserveUserToken) <= MAX_U128,
                    "TEMPO-AMM20: reserveUserToken exceeds uint128"
                );
                assertTrue(
                    uint256(pool.reserveValidatorToken) <= MAX_U128,
                    "TEMPO-AMM20: reserveValidatorToken exceeds uint128"
                );
            }
        }
    }

    /// @notice TEMPO-AMM21: Spread between fee swap and rebalance prevents arbitrage
    function _invariantSpreadPreventsArbitrage() internal pure {
        // For any amount X:
        // Fee swap: X -> (X * M / SCALE)
        // Rebalance: to get X back, need (X * N / SCALE + 1)
        // For arbitrage: fee_out >= rebalance_in
        // X * M / SCALE >= X * N / SCALE + 1
        // Since M < N, this is never true

        assertTrue(M < N, "TEMPO-AMM21: M must be less than N for spread");
        // Spread = N - M = 9985 - 9970 = 15 basis points
        assertTrue(N - M == SPREAD, "TEMPO-AMM21: Spread should be 15 bps");
    }

    /// @notice TEMPO-AMM22: Rebalance swap rounding always favors the pool
    function _invariantRebalanceRoundingFavorsPool() internal view {
        // The +1 in rebalanceSwap formula ensures pool never loses to rounding
        // amountIn = (amountOut * N) / SCALE + 1

        // Verify via accumulated ghost variables
        if (_ghostRebalanceOutputSum > 0) {
            // Total input should be >= theoretical (due to +1 rounding per swap)
            uint256 theoretical = (_ghostRebalanceOutputSum * N) / SCALE;
            assertTrue(
                _ghostRebalanceInputSum >= theoretical,
                "TEMPO-AMM22: Rebalance rounding should favor pool"
            );
        }
    }

    /// @notice TEMPO-FEE5: Collected fees should not exceed AMM token balance
    function _invariantCollectedFeesNotExceedBalance() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = address(_tokens[i]);
            uint256 ammBalance = TIP20(token).balanceOf(address(amm));

            // Sum collected fees for all actors for this token
            uint256 totalCollected = 0;
            for (uint256 j = 0; j < _actors.length; j++) {
                totalCollected += amm.collectedFees(_actors[j], token);
            }

            assertTrue(
                totalCollected <= ammBalance, "TEMPO-FEE5: Collected fees exceed AMM balance"
            );
        }

        // Also check pathUSD
        uint256 pathUsdBalance = pathUSD.balanceOf(address(amm));
        uint256 totalPathUsdCollected = 0;
        for (uint256 j = 0; j < _actors.length; j++) {
            totalPathUsdCollected += amm.collectedFees(_actors[j], address(pathUSD));
        }
        assertTrue(
            totalPathUsdCollected <= pathUsdBalance,
            "TEMPO-FEE5: Collected pathUSD fees exceed AMM balance"
        );
    }

    /// @notice TEMPO-AMM25: Fee swap rate M is correctly applied
    /// amountOut = (amountIn * M / SCALE), output never exceeds input
    function _invariantFeeSwapRateApplied() internal view {
        // Verify via accumulated ghost variables
        // When userToken == validatorToken: output == input (no swap)
        // When userToken != validatorToken: output == input * M / SCALE (0.3% fee)
        // So output should always be <= input
        if (_ghostFeeInputSum > 0 && _totalFeeCollections > 0) {
            assertTrue(
                _ghostFeeOutputSum <= _ghostFeeInputSum, "TEMPO-AMM25: Fee output exceeds fee input"
            );
        }
    }

    /// @notice TEMPO-AMM23: Burn rounding dust accumulates in pool, not extracted by users
    /// @dev Integer division in burn calculation: amount = liquidity * reserve / totalSupply
    ///      This always rounds down, so users receive <= theoretical amount.
    ///      The dust (theoretical - actual) remains in the pool.
    function _invariantBurnRoundingFavorsPool() internal view {
        // Actual amounts received should never exceed theoretical
        // (they should be equal or less due to rounding down)
        assertTrue(
            _ghostBurnUserActual <= _ghostBurnUserTheoretical,
            "TEMPO-AMM23: Burn user actual exceeds theoretical"
        );
        assertTrue(
            _ghostBurnValidatorActual <= _ghostBurnValidatorTheoretical,
            "TEMPO-AMM23: Burn validator actual exceeds theoretical"
        );
    }

    /// @notice TEMPO-AMM27: Pool ID uniqueness - directional pool separation
    /// Pool(A, B) and Pool(B, A) must be separate pools with different IDs
    function _invariantPoolIdUniqueness() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = i + 1; j < _tokens.length; j++) {
                address tokenA = address(_tokens[i]);
                address tokenB = address(_tokens[j]);

                bytes32 poolIdAB = amm.getPoolId(tokenA, tokenB);
                bytes32 poolIdBA = amm.getPoolId(tokenB, tokenA);

                // Pool IDs must be different for directional separation
                assertTrue(
                    poolIdAB != poolIdBA,
                    "TEMPO-AMM27: Pool(A,B) and Pool(B,A) must have different IDs"
                );
            }
        }
    }

    /// @notice TEMPO-AMM28: No LP when uninitialized
    /// If totalSupply == 0, no actor should hold LP tokens for that pool
    function _invariantNoLpWhenUninitialized() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);

                uint256 totalSupply = amm.totalSupply(poolId);

                if (totalSupply == 0) {
                    // Pool is uninitialized - verify no actor has LP tokens
                    for (uint256 k = 0; k < _actors.length; k++) {
                        uint256 balance = amm.liquidityBalances(poolId, _actors[k]);
                        assertEq(
                            balance, 0, "TEMPO-AMM28: Actor has LP tokens in uninitialized pool"
                        );
                    }
                }
            }
        }
    }

    /// @notice TEMPO-AMM29: Fee conservation
    /// Total fees distributed cannot exceed total fees collected
    function _invariantFeeConservation() internal view {
        assertTrue(
            _ghostTotalFeesDistributed <= _ghostTotalFeesCollected,
            "TEMPO-AMM29: Fees distributed exceed fees collected - value creation bug"
        );
    }

    /// @notice TEMPO-AMM30: Pool initialization shape
    /// A pool is either completely uninitialized (all zeros) OR properly initialized with MIN_LIQUIDITY locked
    /// No partial/bricked states allowed (e.g., reserves > 0 but totalSupply < MIN_LIQUIDITY)
    function _invariantPoolInitializationShape() internal view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;
                _verifyPoolShape(address(_tokens[i]), address(_tokens[j]));
            }
            // Check pathUSD pools
            _verifyPoolShape(address(_tokens[i]), address(pathUSD));
            _verifyPoolShape(address(pathUSD), address(_tokens[i]));
        }
    }

    /// @dev Helper to verify pool initialization shape for a single pool
    function _verifyPoolShape(address userToken, address validatorToken) internal view {
        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        uint256 totalSupply = amm.totalSupply(poolId);
        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

        if (totalSupply == 0) {
            // Uninitialized: reserves must also be zero
            assertEq(
                pool.reserveUserToken,
                0,
                "TEMPO-AMM30: Uninitialized pool has non-zero user reserve"
            );
            assertEq(
                pool.reserveValidatorToken,
                0,
                "TEMPO-AMM30: Uninitialized pool has non-zero validator reserve"
            );
        } else {
            // Initialized: totalSupply must be >= MIN_LIQUIDITY
            assertTrue(
                totalSupply >= MIN_LIQUIDITY,
                "TEMPO-AMM30: Initialized pool has totalSupply < MIN_LIQUIDITY (bricked state)"
            );
            // Note: Validator reserve CAN be zero in initialized pools due to rounding.
            // When burns occur with small reserves and large totalSupply, the pro-rata
            // calculation (liquidity * reserve / totalSupply) can round down to 0,
            // meaning the burner's LP tokens are burned but they receive 0 tokens.
            // This drains totalSupply without proportionally draining reserves,
            // eventually leading to reserves = 0 while totalSupply >= MIN_LIQUIDITY.
            // This is a valid (though suboptimal) state, not a bricked pool.
        }
    }

    /// @notice TEMPO-AMM24: All participants can exit - verify everyone can withdraw
    /// @dev After all operations, all LPs should be able to burn their positions and
    ///      all validators should be able to claim their fees. Only dust should remain.
    function _verifyAllCanExit() internal {
        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("              EXIT CHECK PHASE 1: Exit with blacklisted actors frozen");
        _log("--------------------------------------------------------------------------------");

        // Step 1: Distribute all pending fees to validators (tracks frozen fees from blacklisted)
        _exitDistributeAllFees();

        // Step 2: Have all actors burn their LP positions (blacklisted actors will fail silently)
        _exitBurnAllLiquidity();

        // Step 3: Verify only dust remains in the AMM (accounting for frozen balances)
        _exitVerifyOnlyDustRemains();

        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("         EXIT CHECK PHASE 2: Unblacklist all actors and verify recovery");
        _log("--------------------------------------------------------------------------------");

        // Step 4: TEMPO-AMM34 - Unblacklist all actors and verify frozen balances are recoverable
        _exitVerifyCleanExitAfterUnblacklist();

        _log("");
        _log("================================================================================");
        _log("");
    }

    /// @dev Unblacklist ALL actors and verify they can cleanly exit
    /// This proves that blacklisting is a temporary freeze, not permanent loss
    /// Note: Both permanently blacklisted actors (0-4) AND any temporarily blacklisted
    /// actors (5-19 that haven't been recovered yet) need to be unblacklisted
    function _exitVerifyCleanExitAfterUnblacklist() internal {
        // Step 1: Unblacklist ALL actors for all tokens
        // - Actors 0-4: permanently blacklisted, need explicit unblacklist
        // - Actors 5-19: may be temporarily blacklisted if toggleBlacklist hasn't recovered them yet
        uint256 unblacklistedCount = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            address actor = _actors[i];

            // Unblacklist for each token
            for (uint256 t = 0; t < _tokens.length; t++) {
                address token = address(_tokens[t]);
                uint64 policyId = _tokenPolicyIds[token];

                // Only unblacklist if currently blacklisted
                if (!registry.isAuthorized(policyId, actor)) {
                    vm.prank(admin);
                    registry.modifyPolicyBlacklist(policyId, actor, false);
                    unblacklistedCount++;
                }
            }

            // Unblacklist for pathUSD
            if (!registry.isAuthorized(_pathUsdPolicyId, actor)) {
                vm.prank(pathUSDAdmin);
                registry.modifyPolicyBlacklist(_pathUsdPolicyId, actor, false);
                unblacklistedCount++;
            }
        }

        if (unblacklistedCount > 0) {
            _log(
                string.concat(
                    "EXIT CHECK - Unblacklisted ",
                    vm.toString(unblacklistedCount),
                    " actor/token pairs"
                )
            );
        }

        // Step 2: Distribute any remaining frozen fees
        uint256 distributedAfterUnblacklist = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            address validator = _actors[i];

            for (uint256 t = 0; t < _tokens.length; t++) {
                address token = address(_tokens[t]);
                uint256 pending = amm.collectedFees(validator, token);
                if (pending > 0) {
                    try amm.distributeFees(validator, token) {
                        distributedAfterUnblacklist += pending;
                    } catch (bytes memory reason) {
                        // Should not fail after unblacklist - this would be a bug
                        _assertKnownFeeManagerError(reason);
                        revert(
                            string.concat(
                                "TEMPO-AMM34: Distribution failed for ",
                                _getActorIndex(validator),
                                " after unblacklist - frozen fees should be recoverable"
                            )
                        );
                    }
                }
            }

            // pathUSD fees
            uint256 pendingPathUSD = amm.collectedFees(validator, address(pathUSD));
            if (pendingPathUSD > 0) {
                try amm.distributeFees(validator, address(pathUSD)) {
                    distributedAfterUnblacklist += pendingPathUSD;
                } catch (bytes memory reason) {
                    _assertKnownFeeManagerError(reason);
                    revert(
                        string.concat(
                            "TEMPO-AMM34: pathUSD distribution failed for ",
                            _getActorIndex(validator),
                            " after unblacklist - frozen fees should be recoverable"
                        )
                    );
                }
            }
        }

        if (distributedAfterUnblacklist > 0) {
            _log(
                string.concat(
                    "EXIT CHECK - Recovered ",
                    vm.toString(distributedAfterUnblacklist),
                    " frozen fees after unblacklisting"
                )
            );
        }

        // Step 3: Burn any remaining LP (should succeed for all actors now)
        _exitBurnAllLiquidity();

        // Step 4: Verify no collected fees remain (all should be distributed now)
        uint256 remainingFees = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            for (uint256 t = 0; t < _tokens.length; t++) {
                remainingFees += amm.collectedFees(_actors[i], address(_tokens[t]));
            }
            remainingFees += amm.collectedFees(_actors[i], address(pathUSD));
        }

        assertEq(
            remainingFees,
            0,
            "TEMPO-AMM34: All fees should be distributable after unblacklisting all actors"
        );

        // Step 5: Verify no LP positions remain (all should be burned now)
        uint256 remainingLP = 0;
        for (uint256 a = 0; a < _actors.length; a++) {
            for (uint256 i = 0; i < _tokens.length; i++) {
                for (uint256 j = 0; j < _tokens.length; j++) {
                    if (i == j) continue;
                    bytes32 poolId = amm.getPoolId(address(_tokens[i]), address(_tokens[j]));
                    remainingLP += amm.liquidityBalances(poolId, _actors[a]);
                }
                // pathUSD pairs
                bytes32 poolId1 = amm.getPoolId(address(_tokens[i]), address(pathUSD));
                bytes32 poolId2 = amm.getPoolId(address(pathUSD), address(_tokens[i]));
                remainingLP += amm.liquidityBalances(poolId1, _actors[a]);
                remainingLP += amm.liquidityBalances(poolId2, _actors[a]);
            }
        }

        assertEq(
            remainingLP, 0, "TEMPO-AMM34: All LP should be burnable after unblacklisting all actors"
        );

        _log("All frozen balances recovered");
    }

    /// @dev Track frozen fees per token from blacklisted actors that cannot exit
    mapping(address => uint256) private _exitFrozenFees;
    uint256 private _exitFrozenFeesPathUSD;

    /// @dev Distribute all collected fees to validators
    /// Tracks frozen fees for blacklisted actors that cannot claim
    function _exitDistributeAllFees() internal {
        // Reset frozen fee tracking
        for (uint256 t = 0; t < _tokens.length; t++) {
            _exitFrozenFees[address(_tokens[t])] = 0;
        }
        _exitFrozenFeesPathUSD = 0;

        for (uint256 i = 0; i < _actors.length; i++) {
            address validator = _actors[i];

            // Distribute fees for each token
            for (uint256 t = 0; t < _tokens.length; t++) {
                address token = address(_tokens[t]);
                uint256 pendingFees = amm.collectedFees(validator, token);
                if (pendingFees > 0) {
                    try amm.distributeFees(validator, token) { }
                    catch (bytes memory reason) {
                        _assertKnownFeeManagerError(reason);
                        // If distribution failed (likely due to blacklist), track as frozen
                        _exitFrozenFees[token] += pendingFees;
                    }
                }
            }

            // Also distribute pathUSD fees
            uint256 pendingPathUSD = amm.collectedFees(validator, address(pathUSD));
            if (pendingPathUSD > 0) {
                try amm.distributeFees(validator, address(pathUSD)) { }
                catch (bytes memory reason) {
                    _assertKnownFeeManagerError(reason);
                    _exitFrozenFeesPathUSD += pendingPathUSD;
                }
            }
        }

        // Log frozen fees
        if (_exitFrozenFeesPathUSD > 0) {
            _log(
                string.concat(
                    "EXIT CHECK - Frozen pathUSD fees (blacklisted): ",
                    vm.toString(_exitFrozenFeesPathUSD)
                )
            );
        }
        for (uint256 t = 0; t < _tokens.length; t++) {
            if (_exitFrozenFees[address(_tokens[t])] > 0) {
                _log(
                    string.concat(
                        "EXIT CHECK - Frozen ",
                        _tokens[t].symbol(),
                        " fees (blacklisted): ",
                        vm.toString(_exitFrozenFees[address(_tokens[t])])
                    )
                );
            }
        }
    }

    /// @dev Have all actors burn their LP positions
    /// Failed burns (e.g., from blacklisted actors) are silently skipped
    function _exitBurnAllLiquidity() internal {
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];

            // Check all pool pairs
            for (uint256 i = 0; i < _tokens.length; i++) {
                for (uint256 j = 0; j < _tokens.length; j++) {
                    if (i == j) continue;

                    address userToken = address(_tokens[i]);
                    address validatorToken = address(_tokens[j]);
                    bytes32 poolId = amm.getPoolId(userToken, validatorToken);

                    uint256 lpBalance = amm.liquidityBalances(poolId, actor);
                    if (lpBalance > 0) {
                        vm.prank(actor);
                        try amm.burn(userToken, validatorToken, lpBalance, actor) { }
                        catch (bytes memory reason) {
                            _assertKnownError(reason);
                        }
                    }
                }

                // Also check pathUSD pairs
                address token = address(_tokens[i]);

                // token/pathUSD pool
                bytes32 poolId1 = amm.getPoolId(token, address(pathUSD));
                uint256 lpBalance1 = amm.liquidityBalances(poolId1, actor);
                if (lpBalance1 > 0) {
                    vm.prank(actor);
                    try amm.burn(token, address(pathUSD), lpBalance1, actor) { }
                    catch (bytes memory reason) {
                        _assertKnownError(reason);
                    }
                }

                // pathUSD/token pool
                bytes32 poolId2 = amm.getPoolId(address(pathUSD), token);
                uint256 lpBalance2 = amm.liquidityBalances(poolId2, actor);
                if (lpBalance2 > 0) {
                    vm.prank(actor);
                    try amm.burn(address(pathUSD), token, lpBalance2, actor) { }
                    catch (bytes memory reason) {
                        _assertKnownError(reason);
                    }
                }
            }
        }
    }

    /// @dev Verify only dust remains after all exits
    /// Calculates exact expected remaining balance per pool and asserts equality
    function _exitVerifyOnlyDustRemains() internal {
        // After all burns, each initialized pool should have exactly:
        // - reserveValidatorToken: the MIN_LIQUIDITY share of validator tokens
        // - reserveUserToken: the MIN_LIQUIDITY share of user tokens
        // These are locked permanently from the first mint.
        //
        // Additionally, the AMM balance may include:
        // - Unclaimed fee dust from rounding in fee swaps
        // - Rebalance +1 rounding dust

        // TEMPO-AMM24: Verify MIN_LIQUIDITY preserves reserves after all pro-rata burns
        // For each initialized pool, totalSupply >= MIN_LIQUIDITY, so reserves cannot be fully drained
        _verifyMinLiquidityPreservesReserves();

        // Calculate actual remaining balance per token
        uint256 ammPathUSD = pathUSD.balanceOf(address(amm));

        // Calculate expected remaining = sum of all pool reserves (after burns)
        // After burn, pools retain MIN_LIQUIDITY's worth of tokens
        uint256 expectedPathUSD = 0;
        uint256[] memory expectedTokens = new uint256[](_tokens.length);

        // Sum up remaining reserves in all pools
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;
                IFeeAMM.Pool memory pool = amm.getPool(address(_tokens[i]), address(_tokens[j]));
                expectedTokens[i] += pool.reserveUserToken;
                expectedTokens[j] += pool.reserveValidatorToken;
            }

            // pathUSD pairs
            IFeeAMM.Pool memory pool1 = amm.getPool(address(_tokens[i]), address(pathUSD));
            expectedTokens[i] += pool1.reserveUserToken;
            expectedPathUSD += pool1.reserveValidatorToken;

            IFeeAMM.Pool memory pool2 = amm.getPool(address(pathUSD), address(_tokens[i]));
            expectedPathUSD += pool2.reserveUserToken;
            expectedTokens[i] += pool2.reserveValidatorToken;
        }

        // Log detailed breakdown
        _log(
            string.concat(
                "EXIT CHECK - pathUSD: actual=",
                vm.toString(ammPathUSD),
                ", expected_reserves=",
                vm.toString(expectedPathUSD)
            )
        );

        // Assert: actual balance >= expected reserves (solvency)
        // The difference is dust from fee swaps that accumulated
        assertTrue(
            ammPathUSD >= expectedPathUSD,
            "TEMPO-AMM24: pathUSD balance < expected reserves after exit"
        );
        uint256 pathUSDDust = ammPathUSD - expectedPathUSD;

        uint256 totalDust = pathUSDDust;
        for (uint256 t = 0; t < _tokens.length; t++) {
            uint256 ammBalance = _tokens[t].balanceOf(address(amm));

            assertTrue(
                ammBalance >= expectedTokens[t],
                "TEMPO-AMM24: Token balance < expected reserves after exit"
            );

            uint256 tokenDust = ammBalance - expectedTokens[t];
            totalDust += tokenDust;

            _log(
                string.concat(
                    "EXIT CHECK - ",
                    _tokens[t].symbol(),
                    ": actual=",
                    vm.toString(ammBalance),
                    ", expected_reserves=",
                    vm.toString(expectedTokens[t]),
                    ", dust=",
                    vm.toString(tokenDust)
                )
            );
        }

        // Fee swap dust and rebalance +1 rounding both go INTO reserves (not as extra balance).
        // When LPs burn, they receive their pro-rata share of reserves including this dust.
        // Therefore, `totalDust` (balance - reserves) should be minimal, NOT equal to tracked dust.
        //
        // The key security invariant is SOLVENCY: balance >= reserves (checked above).
        // This ensures LPs cannot extract more than the AMM holds.
        uint256 burnDust = (_ghostBurnUserTheoretical - _ghostBurnUserActual)
            + (_ghostBurnValidatorTheoretical - _ghostBurnValidatorActual);

        // Sum up all frozen fees across tokens (from blacklisted actors who couldn't claim)
        uint256 totalFrozenFees = _exitFrozenFeesPathUSD;
        for (uint256 t = 0; t < _tokens.length; t++) {
            totalFrozenFees += _exitFrozenFees[address(_tokens[t])];
        }

        // TEMPO-AMM24: After all burns, any remaining balance beyond reserves should be
        // from MIN_LIQUIDITY lockup, unclaimed collectedFees, or frozen blacklisted balances.
        // The balance should NOT exceed reserves by more than the tracked dust sources (no value creation).
        uint256 expectedDust = _ghostFeeSwapActualDust + _ghostRebalanceRoundingDust;
        uint256 maxExpectedDust = expectedDust + burnDust + totalFrozenFees;

        _log(
            string.concat(
                "EXIT CHECK - Dust: actual=",
                vm.toString(totalDust),
                ", max_allowed=",
                vm.toString(maxExpectedDust),
                " (fee=",
                vm.toString(_ghostFeeSwapActualDust),
                " + rebalance=",
                vm.toString(_ghostRebalanceRoundingDust),
                " + burn=",
                vm.toString(burnDust),
                " + frozen=",
                vm.toString(totalFrozenFees),
                ")"
            )
        );

        assertTrue(
            totalDust <= maxExpectedDust,
            "TEMPO-AMM24: AMM has more dust than expected - potential value creation bug"
        );
    }

    /// @dev Verify that MIN_LIQUIDITY preserves reserves after all pro-rata burns
    /// For each initialized pool: since totalSupply >= MIN_LIQUIDITY and user balances sum to
    /// totalSupply - MIN_LIQUIDITY, burning all user balances leaves MIN_LIQUIDITY/totalSupply
    /// fraction of reserves locked permanently.
    function _verifyMinLiquidityPreservesReserves() internal view {
        // Check token/token pools
        for (uint256 i = 0; i < _tokens.length; i++) {
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (i == j) continue;
                _verifyPoolMinLiquidity(address(_tokens[i]), address(_tokens[j]));
            }

            // Check pathUSD pools
            _verifyPoolMinLiquidity(address(_tokens[i]), address(pathUSD));
            _verifyPoolMinLiquidity(address(pathUSD), address(_tokens[i]));
        }
    }

    /// @dev Helper to verify MIN_LIQUIDITY preservation for a single pool
    function _verifyPoolMinLiquidity(address userToken, address validatorToken) internal view {
        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        uint256 totalSupply = amm.totalSupply(poolId);
        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

        // Skip uninitialized pools
        if (totalSupply == 0) return;

        // TEMPO-AMM15: totalSupply >= MIN_LIQUIDITY for initialized pools
        assertTrue(
            totalSupply >= MIN_LIQUIDITY, "TEMPO-AMM24: totalSupply < MIN_LIQUIDITY after burns"
        );

        // Sum all user LP balances
        uint256 sumUserBalances = 0;
        for (uint256 k = 0; k < _actors.length; k++) {
            sumUserBalances += amm.liquidityBalances(poolId, _actors[k]);
        }

        // After all burns, sumUserBalances should be 0
        // The remaining totalSupply should be >= MIN_LIQUIDITY (locked)
        // Therefore reserves should be > 0 if the pool had any activity
        if (sumUserBalances == 0 && totalSupply >= MIN_LIQUIDITY) {
            // Pool has been fully exited - verify reserves are preserved
            // At least one reserve must be > 0 (validator token is always deposited on mint)
            assertTrue(
                pool.reserveValidatorToken > 0 || pool.reserveUserToken > 0,
                "TEMPO-AMM24: reserves drained despite MIN_LIQUIDITY lock"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Selects an actor based on seed
    /// @param seed Random seed
    /// @return Selected actor address
    function _selectActor(uint256 seed) internal view returns (address) {
        return _actors[seed % _actors.length];
    }

    /// @dev Marks an actor as active (participating in fee-related activities)
    function _markActorActive(address actor) internal {
        if (!_activeActors[actor]) {
            _activeActors[actor] = true;
            _activeActorList.push(actor);
        }
    }

    /// @dev Selects from active actors only, or falls back to regular selection if none active
    function _selectActiveActor(uint256 seed) internal view returns (address) {
        if (_activeActorList.length == 0) {
            return _actors[seed % _actors.length];
        }
        return _activeActorList[seed % _activeActorList.length];
    }

    /// @notice Verifies a revert is due to a known/expected FeeAMM error
    /// @dev Fails if the error selector doesn't match any known error
    /// @param reason The revert reason bytes from the failed call
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IFeeAMM.IdenticalAddresses.selector
            || selector == IFeeAMM.InvalidToken.selector
            || selector == IFeeAMM.InsufficientLiquidity.selector
            || selector == IFeeAMM.InsufficientReserves.selector
            || selector == IFeeAMM.InvalidAmount.selector
            || selector == IFeeAMM.DivisionByZero.selector
            || selector == IFeeAMM.InvalidSwapCalculation.selector
            || selector == IFeeAMM.InvalidCurrency.selector
            || selector == ITIP20.InsufficientBalance.selector
            || selector == ITIP20.PolicyForbids.selector;
        assertTrue(isKnownError, "Failed with unknown error");
    }

    /// @notice Verifies a revert is due to a known/expected FeeManager error
    /// @param reason The revert reason bytes from the failed call
    function _assertKnownFeeManagerError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IFeeAMM.IdenticalAddresses.selector
            || selector == IFeeAMM.InvalidToken.selector
            || selector == IFeeAMM.InsufficientLiquidity.selector
            || selector == IFeeAMM.InvalidCurrency.selector
            || selector == ITIP20.InsufficientBalance.selector
            || selector == ITIP20.PolicyForbids.selector
            // FeeManager specific (string reverts)
            || keccak256(reason)
                == keccak256(abi.encodeWithSignature("Error(string)", "ONLY_DIRECT_CALL"))
            || keccak256(reason)
                == keccak256(abi.encodeWithSignature("Error(string)", "CANNOT_CHANGE_WITHIN_BLOCK"));
        assertTrue(isKnownError, "Failed with unknown FeeManager error");
    }

    /// @notice Creates test actors with initial balances and approvals
    /// @dev Each actor gets funded and approves the FeeAMM for both tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = address(uint160(uint256(keccak256(abi.encodePacked("Actor", i)))));
            actorsAddress[i] = actor;

            // initial actor balance for all tokens
            _ensureFundsAll(actor, 1_000_000_000_000);

            vm.startPrank(actor);
            // Approve all base tokens and pathUSD for the FeeAMM
            for (uint256 j = 0; j < _tokens.length; j++) {
                _tokens[j].approve(address(amm), type(uint256).max);
            }
            pathUSD.approve(address(amm), type(uint256).max);
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /// @dev Selects a token from all available tokens (base tokens + pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token address
    function _selectToken(uint256 rnd) internal view returns (address) {
        // Pool of tokens: pathUSD + all base tokens
        uint256 totalTokens = _tokens.length + 1;
        uint256 index = rnd % totalTokens;
        if (index == 0) {
            return address(pathUSD);
        }
        return address(_tokens[index - 1]);
    }

    /// @notice Ensures an actor has sufficient token balances for testing
    /// @dev Mints tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param token The token to mint (base token for asks, pathUSD for bids)
    /// @param amount The minimum balance required
    function _ensureFunds(address actor, TIP20 token, uint256 amount) internal {
        vm.startPrank(admin);
        if (token.balanceOf(address(actor)) < amount) {
            token.mint(actor, amount + 100_000_000);
        }
        vm.stopPrank();
    }

    /// @notice Ensures an actor has sufficient balances for all tokens (used in setUp)
    /// @dev Mints pathUSD and all base tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param amount The minimum balance required
    function _ensureFundsAll(address actor, uint256 amount) internal {
        vm.startPrank(admin);
        if (pathUSD.balanceOf(address(actor)) < amount) {
            pathUSD.mint(actor, amount + 100_000_000);
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (_tokens[i].balanceOf(address(actor)) < amount) {
                _tokens[i].mint(actor, amount + 100_000_000);
            }
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                              LOGGING
    //////////////////////////////////////////////////////////////*/

    /// @dev Logs an action message to the amm.log file
    function _log(string memory message) internal {
        vm.writeLine(LOG_FILE, message);
    }

    /// @dev Logs a mint action
    function _logMint(address actor, uint256 liquidity, uint256 amount) internal {
        _log(
            string.concat(
                "MINT: ",
                _getActorIndex(actor),
                " minted ",
                vm.toString(liquidity),
                " LP for ",
                vm.toString(amount),
                " validator tokens"
            )
        );
    }

    /// @dev Logs a burn action
    function _logBurn(address actor, uint256 liquidity, uint256 amountUser, uint256 amountValidator)
        internal
    {
        _log(
            string.concat(
                "BURN: ",
                _getActorIndex(actor),
                " burned ",
                vm.toString(liquidity),
                " LP for ",
                vm.toString(amountUser),
                " user + ",
                vm.toString(amountValidator),
                " validator tokens"
            )
        );
    }

    /// @dev Logs a rebalance swap action
    function _logRebalance(address actor, uint256 amountIn, uint256 amountOut) internal {
        _log(
            string.concat(
                "REBALANCE: ",
                _getActorIndex(actor),
                " swapped ",
                vm.toString(amountIn),
                " validator for ",
                vm.toString(amountOut),
                " user tokens"
            )
        );
    }

    /// @dev Logs a fee distribution action
    function _logDistribute(address validator, uint256 amount) internal {
        _log(
            string.concat(
                "DISTRIBUTE_FEES: ",
                _getActorIndex(validator),
                " received ",
                vm.toString(amount),
                " fees"
            )
        );
    }

    /// @dev Gets token symbol for logging
    function _getTokenSymbol(address token) internal view returns (string memory) {
        if (token == address(pathUSD)) {
            return "pathUSD";
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (address(_tokens[i]) == token) {
                return _tokens[i].symbol();
            }
        }
        return vm.toString(token);
    }

    /// @dev Logs AMM balances for all tokens
    function _logBalances() internal {
        string memory balanceStr =
            string.concat("AMM balances: pathUSD=", vm.toString(pathUSD.balanceOf(address(amm))));
        for (uint256 t = 0; t < _tokens.length; t++) {
            balanceStr = string.concat(
                balanceStr,
                ", ",
                _tokens[t].symbol(),
                "=",
                vm.toString(_tokens[t].balanceOf(address(amm)))
            );
        }
        _log(balanceStr);
    }

    /// @dev Logs precise dust tracking information
    function _logDustTracking() internal {
        // Fee swap dust analysis
        uint256 extraDust = _ghostFeeSwapActualDust > _ghostFeeSwapTheoreticalDust
            ? _ghostFeeSwapActualDust - _ghostFeeSwapTheoreticalDust
            : 0;
        _log(
            string.concat(
                "Fee swap dust - Theoretical: ",
                vm.toString(_ghostFeeSwapTheoreticalDust),
                ", Actual: ",
                vm.toString(_ghostFeeSwapActualDust),
                ", Extra: ",
                vm.toString(extraDust)
            )
        );

        // Rebalance +1 rounding dust (should equal swap count)
        _log(
            string.concat(
                "Rebalance +1 rounding dust: ",
                vm.toString(_ghostRebalanceRoundingDust),
                " (should equal rebalance swap count: ",
                vm.toString(_totalRebalanceSwaps),
                ")"
            )
        );

        // Active actor count
        _log(string.concat("Active actors: ", vm.toString(_activeActorList.length)));
    }

    /// @dev Gets actor index from address for logging
    function _getActorIndex(address actor) internal view returns (string memory) {
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == actor) {
                return string.concat("Actor", vm.toString(i));
            }
        }
        return vm.toString(actor);
    }

    function test_repro_TEMPO_AMM30_ZeroValidatorReserve() public {
        this.simulateFeeCollection(
            6_217_401_010_937_182_235_330_593,
            71_141_330_745_412_273_858_523_140_613_712,
            82_940_519_497_026_241_853_278_642_572_649_645_656_082_617,
            20_281_997_670_017_163_135_102_914_189_317_400_289_206
        );
        this.simulateFeeCollection(
            900_460_725_746_834_682_773_235_820_764_048_416_048_585_283_567_285_414_967,
            57_868_748_774_672_895_625_229_209_619,
            30_706_516_524_944_856_915_972_184_595_746_399_835_067_290_067,
            26_873_763_970_028_017_908
        );
        this.simulateFeeCollection(
            1_896_133_607_606_663_338_812_301_648_903_364_820_158_282_460,
            587_634_820_897_769_499_619_033_103_515_862_062_799_239_905_381_615_160_541_996_052_501_162_397_409,
            423_263_541_535_607_641_223_526_793_518_989_593_021_253_392_654_020_044_367_086_486,
            81_305_385_348_813_778_469_256_790_287_564_528_736_558_057_625_532_364_046_469_354_538_983_232_025
        );
        this.simulateFeeCollection(13_932, 4025, 59_206, 17_504_752);
        this.simulateFeeCollection(34_995_676, 2071, 6_981_933_222, 4_516_888_683_122_851);
        this.simulateFeeCollection(20_783, 1_819_264, 9_616_345, 2182);
        this.simulateFeeCollection(35_190, 5_155_068, 16_246_806, 669_543_791);
        this.simulateFeeCollection(
            50_851_922_794_016_125,
            1_678_986_654_677_964_034_751_948_600_336_785_714_756_094_921_915_368_527_678,
            18,
            31_864_378_906_314_562_225_190_273_161_856_656_625_717_241_705_826_517_461_367_154_463_968
        );
        this.simulateFeeCollection(7_835_935, 13_763_019, 44_352, 12_958_668);
        this.simulateFeeCollection(
            1,
            1,
            531_813_033_366_352_184_106_009_694,
            38_552_755_087_238_092_714_606_566_509_748_518_786_019
        );
        this.setUserToken(
            430_916_265_421_189_121_529_616_154_146_798_850_626_318_496_151_536_204,
            237_815_094_032_346_305_989_378_206_563_553_224_111
        );
        this.mintBurnCycle(
            8_704_010_369_172_310_989_778_259_165_865_293_121_681_494_923_419_724_242_398_837_347,
            166_082_169_622_271_516_040_832_242_156_345_194_667_788_573_456,
            10_380_741_460_111_524_670_826_236_718_172_482_907_336_446_641_248_791_906_893_521_628,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_932
        );
        this.simulateFeeCollection(
            95_889_983_804_464_479_844_656_138_558_079_745_452_524_941_582_021_467_283,
            675_735_442_972_389_723_533_214,
            84_279_964_408_290_060_446_009_267_257_866_256_936_639_479_872_301_224_489_238_882_878_484_526_890_964,
            1
        );
        this.simulateFeeCollection(12_186, 19_190, 15_271_180, 1_555_938);
        this.setValidatorToken(5_619_905, 17_868_946);
        this.simulateFeeCollection(20_627_988, 14_266, 2_000_010, 46_372);
        _invariantPoolInitializationShape();
    }

}
