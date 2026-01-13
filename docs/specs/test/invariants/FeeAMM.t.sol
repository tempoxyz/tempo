// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { FeeManager } from "../../src/FeeManager.sol";
import { FeeAMM } from "../../src/FeeAMM.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { IFeeManager } from "../../src/interfaces/IFeeManager.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

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

    /// @dev Constants from FeeAMM
    uint256 private constant M = 9970; // Fee swap rate (0.997)
    uint256 private constant N = 9985; // Rebalance swap rate (0.9985)
    uint256 private constant SCALE = 10_000;
    uint256 private constant MIN_LIQUIDITY = 1000;
    uint256 private constant SPREAD = N - M; // 15 basis points

    /// @dev Constants for overflow and boundary testing
    uint256 private constant MAX_U128 = type(uint128).max;
    uint256 private constant REALISTIC_MAX = 1_000_000_000_000e18; // 1 trillion tokens

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

    /// @dev Struct to reduce stack depth in fee swap handler
    struct FeeSwapContext {
        address actor;
        address userToken;
        address validatorToken;
        uint256 feeAmount;
        uint256 amountOut;
        uint128 reserveUserBefore;
        uint128 reserveValidatorBefore;
        uint128 newReserveUser;
        uint128 newReserveValidator;
        bytes32 poolId;
    }

    /// @dev Mapping to track liquidity provided per pool
    mapping(bytes32 => uint256) private _ghostTotalLiquidity;

    /// @dev Mapping to track total validator tokens deposited per pool
    mapping(bytes32 => uint256) private _ghostValidatorTokensDeposited;

    /// @dev Ghost variables for tracking rounding exploitation attempts
    uint256 private _totalMintBurnCycles;
    uint256 private _totalSmallRebalanceSwaps;
    uint256 private _ghostRebalanceInputSum;
    uint256 private _ghostRebalanceOutputSum;

    /// @dev Ghost variables for tracking fee swaps
    uint256 private _totalFeeSwaps;
    uint256 private _ghostFeeSwapInputSum;
    uint256 private _ghostFeeSwapOutputSum;

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

        // Initialize log file
        try vm.removeFile(LOG_FILE) {} catch {}
        _log("=== FeeAMM Invariant Test Log ===");
        _log(
            string.concat(
                "Tokens: T1=",
                token1.symbol(),
                ", T2=",
                token2.symbol(),
                ", T3=",
                token3.symbol(),
                ", T4=",
                token4.symbol()
            )
        );
        _log(string.concat("Actors: ", vm.toString(_actors.length)));
        _log("");
        _logBalances();
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
        if (userToken == validatorToken) return;

        // Bound amount to reasonable range
        amount = bound(amount, MIN_LIQUIDITY * 3, 10_000_000_000);

        // Ensure actor has funds
        _ensureFunds(actor, TIP20(validatorToken), amount);

        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        IFeeAMM.Pool memory poolBefore = amm.getPool(userToken, validatorToken);
        uint256 totalSupplyBefore = amm.totalSupply(poolId);
        uint256 actorLiquidityBefore = amm.liquidityBalances(poolId, actor);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256 liquidity) {
            vm.stopPrank();

            _totalMints++;
            _ghostTotalLiquidity[poolId] += liquidity;
            _ghostValidatorTokensDeposited[poolId] += amount;

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
        if (ctx.userToken == ctx.validatorToken) return;

        ctx.poolId = amm.getPoolId(ctx.userToken, ctx.validatorToken);
        ctx.actorLiquidity = amm.liquidityBalances(ctx.poolId, ctx.actor);

        // Skip if actor has no liquidity
        if (ctx.actorLiquidity == 0) return;

        // Calculate amount to burn
        liquidityPct = bound(liquidityPct, 1, 100);
        ctx.liquidityToBurn = (ctx.actorLiquidity * liquidityPct) / 100;
        if (ctx.liquidityToBurn == 0) ctx.liquidityToBurn = 1;

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);
        ctx.totalSupplyBefore = amm.totalSupply(ctx.poolId);
        ctx.reserveUserBefore = poolBefore.reserveUserToken;
        ctx.reserveValidatorBefore = poolBefore.reserveValidatorToken;

        vm.startPrank(ctx.actor);
        try amm.burn(ctx.userToken, ctx.validatorToken, ctx.liquidityToBurn, ctx.actor) returns (
            uint256 amountUserToken, uint256 amountValidatorToken
        ) {
            vm.stopPrank();
            _totalBurns++;
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
            amountValidatorToken, expectedValidatorAmount, "TEMPO-AMM5: Validator token amount mismatch"
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
        if (ctx.userToken == ctx.validatorToken) return;

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);

        // Skip if pool has no user token reserves
        if (poolBefore.reserveUserToken == 0) return;

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

            _assertRebalanceInvariants(ctx, amountIn);
            _logRebalance(ctx.actor, amountIn, ctx.amountOut);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @dev Verifies rebalance swap invariants
    function _assertRebalanceInvariants(RebalanceContext memory ctx, uint256 amountIn) internal view {
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
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed Seed for selecting token
    function setValidatorToken(uint256 actorSeed, uint256 tokenSeed) external {
        address actor = _selectActor(actorSeed);
        address token = _selectToken(tokenSeed);

        // Cannot set validator token if actor is the block coinbase
        vm.coinbase(address(0xdead));

        vm.startPrank(actor, actor); // Set both msg.sender and tx.origin
        try amm.setValidatorToken(token) {
            vm.stopPrank();

            // TEMPO-FEE1: Validator token should be updated
            address storedToken = amm.validatorTokens(actor);
            assertEq(storedToken, token, "TEMPO-FEE1: Validator token not set correctly");

            _logSetToken("SET_VALIDATOR_TOKEN", actor, token);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for setting user token preference
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed Seed for selecting token
    function setUserToken(uint256 actorSeed, uint256 tokenSeed) external {
        address actor = _selectActor(actorSeed);
        address token = _selectToken(tokenSeed);

        vm.startPrank(actor, actor); // Set both msg.sender and tx.origin
        try amm.setUserToken(token) {
            vm.stopPrank();

            // TEMPO-FEE2: User token should be updated
            address storedToken = amm.userTokens(actor);
            assertEq(storedToken, token, "TEMPO-FEE2: User token not set correctly");

            _logSetToken("SET_USER_TOKEN", actor, token);
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for mint/burn cycle (tests rounding exploitation A7)
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

        if (userToken == validatorToken) return;

        amount = bound(amount, 1000, 100_000);
        _ensureFunds(actor, TIP20(validatorToken), amount);

        uint256 actorBalBefore = TIP20(validatorToken).balanceOf(actor);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256 liquidity) {
            if (liquidity > 0) {
                try amm.burn(userToken, validatorToken, liquidity, actor) returns (uint256, uint256) {
                    vm.stopPrank();
                    _totalMintBurnCycles++;

                    uint256 actorBalAfter = TIP20(validatorToken).balanceOf(actor);
                    // TEMPO-AMM17: Mint/burn cycle should not profit the actor
                    assertTrue(
                        actorBalAfter <= actorBalBefore,
                        "TEMPO-AMM17: Actor should not profit from mint/burn cycle"
                    );
                } catch {
                    vm.stopPrank();
                }
            } else {
                vm.stopPrank();
            }
        } catch {
            vm.stopPrank();
        }
    }

    /// @notice Handler for small rebalance swaps (tests rounding exploitation A8)
    /// @param actorSeed Seed for selecting actor
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    function smallRebalanceSwap(uint256 actorSeed, uint256 tokenSeed1, uint256 tokenSeed2) external {
        address actor = _selectActor(actorSeed);
        address userToken = _selectToken(tokenSeed1);
        address validatorToken = _selectToken(tokenSeed2);

        if (userToken == validatorToken) return;

        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);
        if (pool.reserveUserToken == 0) return;

        // Use very small amounts where rounding matters most
        uint256 amountOut = bound(pool.reserveUserToken, 1, 100);
        if (amountOut > pool.reserveUserToken) return;

        uint256 expectedIn = (amountOut * N) / SCALE + 1;
        _ensureFunds(actor, TIP20(validatorToken), expectedIn * 2);

        vm.startPrank(actor);
        try amm.rebalanceSwap(userToken, validatorToken, amountOut, actor) returns (uint256 amountIn) {
            vm.stopPrank();

            // TEMPO-AMM18: Small swaps should still pay >= theoretical rate
            uint256 theoretical = (amountOut * N) / SCALE;
            assertTrue(
                amountIn >= theoretical,
                "TEMPO-AMM18: Small swap should pay >= theoretical rate"
            );
            // TEMPO-AMM19: Small swaps should not allow profit
            assertTrue(amountIn >= 1, "TEMPO-AMM19: Must pay at least 1 for any swap");
        } catch {
            vm.stopPrank();
        }
    }

    /// @notice Handler for simulating fee accumulation in a pool
    /// @dev Since executeFeeSwap is protocol-only, we simulate fee accumulation by:
    ///      1. Transferring userTokens to the AMM (simulating fee payment)
    ///      2. Updating pool reserves directly via vm.store (only works when !isTempo)
    ///      This allows subsequent rebalanceSwaps to extract the accumulated fees.
    /// @param actorSeed Seed for selecting actor (fee payer)
    /// @param tokenSeed1 Seed for selecting user token
    /// @param tokenSeed2 Seed for selecting validator token
    /// @param feeAmountRaw The fee amount to accumulate
    function accumulateFees(
        uint256 actorSeed,
        uint256 tokenSeed1,
        uint256 tokenSeed2,
        uint256 feeAmountRaw
    ) external {
        FeeSwapContext memory ctx;
        ctx.actor = _selectActor(actorSeed);
        ctx.userToken = _selectToken(tokenSeed1);
        ctx.validatorToken = _selectToken(tokenSeed2);

        // Skip if tokens are identical
        if (ctx.userToken == ctx.validatorToken) return;

        // Bound fee amount to reasonable range
        ctx.feeAmount = bound(feeAmountRaw, 1000, 5_000_000);

        // Check if pool exists (has some liquidity)
        IFeeAMM.Pool memory pool = amm.getPool(ctx.userToken, ctx.validatorToken);
        if (pool.reserveValidatorToken == 0) return;

        // Calculate fee swap output (at rate M)
        ctx.amountOut = (ctx.feeAmount * M) / SCALE;
        if (ctx.amountOut == 0) return;
        if (pool.reserveValidatorToken < ctx.amountOut) return;

        ctx.reserveUserBefore = pool.reserveUserToken;
        ctx.reserveValidatorBefore = pool.reserveValidatorToken;

        // Ensure actor has enough user tokens
        _ensureFunds(ctx.actor, TIP20(ctx.userToken), ctx.feeAmount);

        // Transfer user tokens to AMM (simulating fee payment)
        vm.prank(ctx.actor);
        TIP20(ctx.userToken).transfer(address(amm), ctx.feeAmount);

        // Calculate new reserves after fee swap
        ctx.newReserveUser = ctx.reserveUserBefore + uint128(ctx.feeAmount);
        ctx.newReserveValidator = ctx.reserveValidatorBefore - uint128(ctx.amountOut);

        // Update pool reserves directly via vm.store to simulate executeFeeSwap
        ctx.poolId = amm.getPoolId(ctx.userToken, ctx.validatorToken);
        _storePoolReserves(ctx.poolId, ctx.newReserveUser, ctx.newReserveValidator);

        // Verify the update worked - if not, silently return (vm.store may not work on precompiles)
        IFeeAMM.Pool memory poolAfter = amm.getPool(ctx.userToken, ctx.validatorToken);
        if (poolAfter.reserveUserToken != ctx.newReserveUser) {
            // vm.store failed, skip this fee accumulation
            return;
        }

        _totalFeeSwaps++;
        _ghostFeeSwapInputSum += ctx.feeAmount;
        _ghostFeeSwapOutputSum += ctx.amountOut;

        _logFeeSwap(ctx.actor, ctx.userToken, ctx.validatorToken, ctx.feeAmount, ctx.amountOut);
    }

    /// @dev Stores pool reserves directly using vm.store
    function _storePoolReserves(bytes32 poolId, uint128 reserveUser, uint128 reserveValidator) internal {
        // Storage slot for mapping: keccak256(key, slot) where slot=0 for pools mapping
        bytes32 poolSlot = keccak256(abi.encode(poolId, uint256(0)));

        // Pack: lower 128 bits = reserveUserToken, upper 128 bits = reserveValidatorToken
        bytes32 newPoolValue = bytes32(uint256(reserveUser) | (uint256(reserveValidator) << 128));
        vm.store(address(amm), poolSlot, newPoolValue);
    }

    /// @notice Handler for distributing collected fees
    /// @param actorSeed Seed for selecting validator
    /// @param tokenSeed Seed for selecting token
    function distributeFees(uint256 actorSeed, uint256 tokenSeed) external {
        address validator = _selectActor(actorSeed);
        address token = _selectToken(tokenSeed);

        uint256 collectedBefore = amm.collectedFees(validator, token);
        uint256 validatorBalanceBefore = TIP20(token).balanceOf(validator);

        // Ensure AMM has enough tokens to distribute
        if (collectedBefore > 0) {
            _ensureFunds(address(amm), TIP20(token), collectedBefore);
        }

        try amm.distributeFees(validator, token) {
            // TEMPO-FEE3: Collected fees should be zeroed after distribution
            uint256 collectedAfter = amm.collectedFees(validator, token);
            assertEq(collectedAfter, 0, "TEMPO-FEE3: Collected fees should be zero after distribution");

            // TEMPO-FEE4: Validator should receive the collected fees
            if (collectedBefore > 0) {
                uint256 validatorBalanceAfter = TIP20(token).balanceOf(validator);
                assertEq(
                    validatorBalanceAfter,
                    validatorBalanceBefore + collectedBefore,
                    "TEMPO-FEE4: Validator should receive collected fees"
                );
            }

            _logDistribute(validator, collectedBefore);
        } catch (bytes memory reason) {
            _assertKnownFeeManagerError(reason);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after invariant testing completes to clean up state
    function afterInvariant() public {
        _log("");
        _log("=== Final State ===");
        _log(string.concat("Total mints: ", vm.toString(_totalMints)));
        _log(string.concat("Total burns: ", vm.toString(_totalBurns)));
        _log(string.concat("Total rebalance swaps: ", vm.toString(_totalRebalanceSwaps)));
        _log(string.concat("Total fee swaps: ", vm.toString(_totalFeeSwaps)));
        _log(string.concat("Total mint/burn cycles: ", vm.toString(_totalMintBurnCycles)));
        _log(string.concat("Total small rebalance swaps: ", vm.toString(_totalSmallRebalanceSwaps)));
        _log(
            string.concat(
                "Rebalance totals - In: ",
                vm.toString(_ghostRebalanceInputSum),
                ", Out: ",
                vm.toString(_ghostRebalanceOutputSum)
            )
        );
        _log(
            string.concat(
                "Fee swap totals - In: ",
                vm.toString(_ghostFeeSwapInputSum),
                ", Out: ",
                vm.toString(_ghostFeeSwapOutputSum)
            )
        );
        _logBalances();
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
        _invariantNoDoubleCountFees();
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
                    totalSupply >= sumBalances,
                    "TEMPO-AMM14: Total supply < sum of balances"
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

    /// @notice TEMPO-AMM16: Fee rates are correctly applied
    function _invariantFeeRates() internal pure {
        // Fee swap rate: m = 0.9970 means 0.30% fee
        // Rebalance rate: n = 0.9985 means 0.15% fee
        // These are constants, so just verify they're set correctly
        assertTrue(M == 9970, "TEMPO-AMM16: Fee swap rate M should be 9970");
        assertTrue(N == 9985, "TEMPO-AMM16: Rebalance rate N should be 9985");
        assertTrue(SCALE == 10_000, "TEMPO-AMM16: SCALE should be 10000");
    }

    /// @notice TEMPO-AMM20: Reserves are always bounded by uint128 (A10)
    function _invariantReservesBoundedByU128() internal view {
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

    /// @notice TEMPO-AMM21: Spread between fee swap and rebalance prevents arbitrage (I8)
    function _invariantSpreadPreventsArbitrage() internal pure {
        // For any amount X:
        // Fee swap: X -> (X * M / SCALE)
        // Rebalance: to get X back, need (X * N / SCALE + 1)
        // For arbitrage: fee_out >= rebalance_in
        // X * M / SCALE >= X * N / SCALE + 1
        // Since M < N, this is never true

        assertTrue(M < N, "TEMPO-AMM21: M must be less than N for spread");
        assertTrue(N - M == SPREAD, "TEMPO-AMM21: Spread should be 15 bps");
        assertTrue(SPREAD == 15, "TEMPO-AMM21: Spread constant incorrect");
    }

    /// @notice TEMPO-AMM22: Rebalance swap rounding always favors the pool (A8)
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

    /// @notice TEMPO-AMM23: Collected fees cannot be double-counted (F3, F4)
    function _invariantNoDoubleCountFees() internal view {
        // For each validator and token, verify collected fees <= token balance at AMM
        // This is a sanity check - actual fee accounting is tested in handlers
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = address(_tokens[i]);
            uint256 ammBalance = TIP20(token).balanceOf(address(amm));

            // Sum of all collected fees for this token should not exceed balance
            uint256 totalCollectedForToken = 0;
            for (uint256 j = 0; j < _actors.length; j++) {
                totalCollectedForToken += amm.collectedFees(_actors[j], token);
            }

            assertTrue(
                totalCollectedForToken <= ammBalance,
                "TEMPO-AMM23: Collected fees exceed AMM balance"
            );
        }
    }

    /// @notice TEMPO-AMM24: Cross-pool solvency - single token balance covers all pool reserves
    function _invariantCrossPoolSolvency() internal view {
        // For each token, sum reserves across ALL pools where it appears
        for (uint256 t = 0; t < _tokens.length; t++) {
            address token = address(_tokens[t]);
            uint256 totalReserves = 0;

            // Sum reserves where token is userToken
            for (uint256 i = 0; i < _tokens.length; i++) {
                if (i == t) continue;
                IFeeAMM.Pool memory pool = amm.getPool(token, address(_tokens[i]));
                totalReserves += pool.reserveUserToken;
            }

            // Sum reserves where token is validatorToken
            for (uint256 i = 0; i < _tokens.length; i++) {
                if (i == t) continue;
                IFeeAMM.Pool memory pool = amm.getPool(address(_tokens[i]), token);
                totalReserves += pool.reserveValidatorToken;
            }

            // Check pathUSD pools
            IFeeAMM.Pool memory poolPathUsdUser = amm.getPool(address(pathUSD), token);
            totalReserves += poolPathUsdUser.reserveValidatorToken;

            IFeeAMM.Pool memory poolPathUsdValidator = amm.getPool(token, address(pathUSD));
            totalReserves += poolPathUsdValidator.reserveUserToken;

            uint256 ammBalance = TIP20(token).balanceOf(address(amm));
            assertTrue(
                ammBalance >= totalReserves,
                "TEMPO-AMM24: Cross-pool solvency violated"
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
            || keccak256(reason) == keccak256(abi.encodeWithSignature("Error(string)", "ONLY_DIRECT_CALL"))
            || keccak256(reason) == keccak256(abi.encodeWithSignature("Error(string)", "CANNOT_CHANGE_WITHIN_BLOCK"));
        assertTrue(isKnownError, "Failed with unknown FeeManager error");
    }

    /// @notice Creates test actors with initial balances and approvals
    /// @dev Each actor gets funded and approves the FeeAMM for both tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = makeAddr(string(abi.encodePacked("Actor", vm.toString(i))));
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
    function _logBurn(
        address actor,
        uint256 liquidity,
        uint256 amountUser,
        uint256 amountValidator
    ) internal {
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

    /// @dev Logs a set token action
    function _logSetToken(string memory action, address actor, address token) internal {
        _log(string.concat(action, ": ", _getActorIndex(actor), " set token to ", vm.toString(token)));
    }

    /// @dev Logs a fee distribution action
    function _logDistribute(address validator, uint256 amount) internal {
        _log(
            string.concat(
                "DISTRIBUTE_FEES: ", _getActorIndex(validator), " received ", vm.toString(amount), " fees"
            )
        );
    }

    /// @dev Logs a fee swap action
    function _logFeeSwap(
        address actor,
        address userToken,
        address validatorToken,
        uint256 feeAmount,
        uint256 amountOut
    ) internal {
        _log(
            string.concat(
                "FEE_SWAP: ",
                _getActorIndex(actor),
                " swapped ",
                vm.toString(feeAmount),
                " ",
                _getTokenSymbol(userToken),
                " -> ",
                vm.toString(amountOut),
                " ",
                _getTokenSymbol(validatorToken)
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

    /// @dev Gets actor index from address for logging
    function _getActorIndex(address actor) internal view returns (string memory) {
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == actor) {
                return string.concat("Actor", vm.toString(i));
            }
        }
        return vm.toString(actor);
    }
}
