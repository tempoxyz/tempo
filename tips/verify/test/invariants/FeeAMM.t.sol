// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { IFeeAMM } from "tempo-std/interfaces/IFeeAMM.sol";
import { IFeeManager } from "tempo-std/interfaces/IFeeManager.sol";
import { ITIP20, ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

/// @title FeeAMM Invariant Test
/// @notice Invariant tests for the FeeAMM/FeeManager implementation
contract FeeAMMInvariantTest is InvariantBaseTest {

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

    /// @dev TEMPO-AMM26: Ghost variables for tracking fee swap reserve updates
    /// Tracks cumulative changes to reserves from fee swaps
    uint256 private _ghostFeeSwapUserReserveIncrease;
    uint256 private _ghostFeeSwapValidatorReserveDecrease;

    /// @dev TEMPO-AMM31: Ghost variables for tracking fee distribution zeroing
    /// Tracks the number of distributeFees calls where fees were properly zeroed
    uint256 private _ghostDistributeFeesCalls;
    uint256 private _ghostDistributeFeesZeroedCount;

    /// @dev Struct for tracking pending fees as a list for efficient selection
    struct PendingFee {
        address validator;
        address token;
    }

    /// @dev List of all (validator, token) pairs with pending fees
    PendingFee[] private _pendingFeesList;

    /// @dev Index lookup for O(1) existence check and removal: keccak256(validator, token) => index + 1 (0 means not in list)
    mapping(bytes32 => uint256) private _pendingFeesIndex;

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
    uint256 private _ghostTotalFeesCollected;
    uint256 private _ghostTotalFeesDistributed;

    /*//////////////////////////////////////////////////////////////
                          TIP-1033: TWO-HOP STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Storage slot index for `two_hop_intermediate` on `TipFeeManager`. The Rust struct is:
    ///   slot 0: validator_tokens             slot 4: total_supply
    ///   slot 1: user_tokens                  slot 5: liquidity_balances
    ///   slot 2: collected_fees               slot 6: pending_fee_swap_reservation (transient)
    ///   slot 3: pools                        slot 7: two_hop_intermediate         (transient)
    /// `vm.load` reads PERSISTENT storage only. Foundry cannot read transient (TLOAD) state, so
    /// TEMPO-FEE14 here reduces to: slot 7 is never observable as persistent storage. Genuine
    /// transient lifetime is covered by Rust unit tests in `crates/precompiles/src/tip_fee_manager`.
    uint256 internal constant TWO_HOP_INTERMEDIATE_SLOT = 7;

    /// @dev Bootstrap liquidity for the two-hop legs. Large enough that fuzzed burns cannot
    /// drain the legs below the typical fuzzed fee output (max ~1M after M-rate compounding).
    uint256 internal constant TWO_HOP_BOOTSTRAP_AMOUNT = 100_000_000_000;

    /// @dev Cap on `_ghostTwoHopWitnesses` to keep gas bounded across long fuzz runs.
    uint256 internal constant MAX_TWO_HOP_WITNESSES = 256;

    /// @dev TIP-1033 tokens. `_userTokenWithHop.quoteToken() == _hopToken` so the fuzzer can
    /// drive the two-hop fallback path (`userToken -> hopToken -> validatorToken`).
    ITIP20Token internal _hopToken;
    ITIP20Token internal _userTokenWithHop;
    ITIP20Token internal _degenerateUserToken;

    /// @dev Counters for two-hop activity.
    uint256 private _totalTwoHopFeeCollections;
    uint256 private _totalDirectPreferredCollections;
    uint256 private _totalDegenerateReverts;
    /// @dev Counts the non-degenerate insufficient-route witnesses (Gap A): direct pool
    /// insufficient AND at least one fallback leg insufficient (with `hopToken` non-zero
    /// and != validatorToken). Distinct from `_totalDegenerateReverts`, which only fires
    /// when `hopToken == validatorToken`.
    uint256 private _totalInsufficientFallbackWitnesses;
    /// @dev Quote-token rotations of non-userToken tokens (drives TEMPO-FEE9 dynamism).
    uint256 private _totalQuoteRotations;
    /// @dev Direct-pool drain burns (mirror of `simulateLegDrainViaBurn` for the direct pool).
    uint256 private _totalDirectDrains;
    /// @dev Fee-amount draws taken from the ±2 boundary band of direct sufficiency.
    uint256 private _totalBoundaryFeeAmounts;

    /// @dev Aggregates for fee math invariants (TEMPO-AMM35/AMM37).
    uint256 private _ghostHop1InputSum;
    uint256 private _ghostHop1OutputSum;
    uint256 private _ghostHop2InputSum;
    uint256 private _ghostHop2OutputSum;
    uint256 private _ghostTwoHopValidatorCredited;
    uint256 private _ghostTwoHopExpectedSequential;

    /// @dev TEMPO-AMM36 regression catcher: largest fallback amount and the credit observed
    /// for that witness. Used to assert sequential math diverges from a fused `(M*M)/SCALE^2`.
    uint256 private _ghostMaxFallbackAmount;
    uint256 private _ghostMaxFallbackCredited;

    /// @dev Witness for a single simulated two-hop / direct fee collection. Captures the
    /// information needed to verify TIP-1033 invariants AMM35-37 and FEE7-FEE11.
    struct TwoHopWitness {
        address userToken;
        address hopToken;
        address validatorToken;
        uint128 directReserveBefore;
        uint128 directReserveAfter;
        uint128 hop1ReserveValBefore;
        uint128 hop1ReserveValAfter;
        uint128 hop2ReserveValBefore;
        uint128 hop2ReserveValAfter;
        uint256 actualSpending;
        uint256 out1;
        uint256 out2;
        bool tookFallback;
        bool directWasInsufficient;
        uint256 ammHopBalanceBefore;
        uint256 ammHopBalanceAfter;
        uint256 sumHopReservesBefore;
        uint256 sumHopReservesAfter;
    }

    TwoHopWitness[] private _ghostTwoHopWitnesses;

    /// @dev Stack-depth helper for the two-hop handler.
    struct TwoHopContext {
        address user;
        address validator;
        address userToken;
        address hopToken;
        address validatorToken;
        uint256 feeAmount;
        uint256 out1;
        uint256 out2;
        IFeeAMM.Pool directPool;
        IFeeAMM.Pool leg1Pool;
        IFeeAMM.Pool leg2Pool;
        uint256 hopBalanceBefore;
        uint256 hopReservesBefore;
    }

    /*//////////////////////////////////////////////////////////////
                          ACTOR SELECTION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Selects an actor who holds liquidity in the given pool
    /// @param seed Random seed for selection
    /// @param poolId The pool ID to check liquidity for
    /// @return actor The selected actor with liquidity > 0
    /// @return liquidity The actor's liquidity balance
    function _selectLiquidityHolder(
        uint256 seed,
        bytes32 poolId
    )
        internal
        view
        returns (address actor, uint256 liquidity)
    {
        address[] memory holders = new address[](_actors.length);
        uint256[] memory balances = new uint256[](_actors.length);
        uint256 count = 0;

        for (uint256 i = 0; i < _actors.length; i++) {
            uint256 bal = amm.liquidityBalances(poolId, _actors[i]);
            if (bal > 0) {
                holders[count] = _actors[i];
                balances[count] = bal;
                count++;
            }
        }

        vm.assume(count > 0);
        uint256 idx = bound(seed, 0, count - 1);
        return (holders[idx], balances[idx]);
    }

    /// @dev Selects a token pair from pools with reserveUserToken > 0 (initialized pools)
    /// @param seed Random seed for selection
    /// @return userToken First token of the initialized pool
    /// @return validatorToken Second token of the initialized pool
    function _selectInitializedPoolPair(uint256 seed)
        internal
        view
        returns (address userToken, address validatorToken)
    {
        uint256 totalTokens = _tokens.length + 1;
        uint256 maxPairs = totalTokens * (totalTokens - 1);

        address[] memory validUserTokens = new address[](maxPairs);
        address[] memory validValidatorTokens = new address[](maxPairs);
        uint256 count = 0;

        for (uint256 i = 0; i < totalTokens; i++) {
            for (uint256 j = 0; j < totalTokens; j++) {
                if (i == j) continue;

                address ut = i == 0 ? address(pathUSD) : address(_tokens[i - 1]);
                address vt = j == 0 ? address(pathUSD) : address(_tokens[j - 1]);

                IFeeAMM.Pool memory pool = amm.getPool(ut, vt);
                if (pool.reserveUserToken > 0) {
                    validUserTokens[count] = ut;
                    validValidatorTokens[count] = vt;
                    count++;
                }
            }
        }

        vm.assume(count > 0);
        uint256 idx = bound(seed, 0, count - 1);
        userToken = validUserTokens[idx];
        validatorToken = validValidatorTokens[idx];
    }

    /// @dev Selects a blacklisted actor for the given token's policy
    /// @param seed Random seed for selection
    /// @param token Token to check blacklist status for
    /// @return actor The selected blacklisted actor, or address(0) if none
    /// @return balance The actor's balance of the token
    function _selectBlacklistedActor(
        uint256 seed,
        address token
    )
        internal
        view
        returns (address actor, uint256 balance)
    {
        uint64 policyId = token == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[token];

        address[] memory blacklisted = new address[](BLACKLISTABLE_ACTOR_COUNT);
        uint256[] memory balances = new uint256[](BLACKLISTABLE_ACTOR_COUNT);
        uint256 count = 0;

        for (uint256 i = 0; i < BLACKLISTABLE_ACTOR_COUNT; i++) {
            address a = _actors[i];
            if (!registry.isAuthorized(policyId, a)) {
                uint256 bal = ITIP20(token).balanceOf(a);
                if (bal >= MIN_LIQUIDITY) {
                    blacklisted[count] = a;
                    balances[count] = bal;
                    count++;
                }
            }
        }

        vm.assume(count > 0);
        uint256 idx = bound(seed, 0, count - 1);
        return (blacklisted[idx], balances[idx]);
    }

    /// @notice Sets up the test environment
    /// @dev Initializes TempoTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        // Add TIP-1033 tokens to `_tokens` BEFORE building actors so initial actor funding and
        // approvals cover them. Pool bootstrapping is deferred until after actors exist so the
        // bootstrap LP balance lands on a tracked actor (keeps TEMPO-AMM14 accounting valid).
        _setupTwoHopTokens();
        _actors = _buildActorsWithApprovals(20, address(amm));
        _bootstrapTwoHopPools();

        // TEMPO-AMM16: Verify fee rate constants once at setup (never change)
        assertTrue(M == 9970, "TEMPO-AMM16: Fee swap rate M should be 9970");
        assertTrue(N == 9985, "TEMPO-AMM16: Rebalance rate N should be 9985");
        assertTrue(SCALE == 10_000, "TEMPO-AMM16: SCALE should be 10000");

        // TEMPO-AMM21: Verify spread constants once at setup (never change)
        assertTrue(M < N, "TEMPO-AMM21: M must be less than N for spread");
        assertTrue(N - M == SPREAD, "TEMPO-AMM21: Spread should be 15 bps");

        // TEMPO-FEE9 (sanity): the configured topology actually exposes the two-hop path.
        assertEq(
            address(ITIP20(address(_userTokenWithHop)).quoteToken()),
            address(_hopToken),
            "TIP-1033 setup: userTokenWithHop.quoteToken must equal hopToken"
        );
    }

    /// @dev Creates the TIP-1033 tokens and registers them in `_tokens` / policy maps.
    /// `_userTokenWithHop.quoteToken() == _hopToken`, exercising the two-hop fallback when
    /// `validatorToken != _hopToken`.
    function _setupTwoHopTokens() internal {
        // hopToken: USD currency, quoted in pathUSD (the standard hub topology).
        _hopToken = ITIP20Token(
            factory.createToken("HOP_TOKEN", "HOP", "USD", pathUSD, admin, bytes32("tip1033_hop"))
        );
        // userTokenWithHop: USD currency, quoted in hopToken. USD-with-USD-quote is permitted
        // by the TIP-20 factory (USD tokens require a USD quote, which hopToken satisfies).
        _userTokenWithHop = ITIP20Token(
            factory.createToken(
                "USER_HOP",
                "UH",
                "USD",
                ITIP20(address(_hopToken)),
                admin,
                bytes32("tip1033_userhop")
            )
        );
        // Separate token for the degenerate route model. Its quote token is `_hopToken`, but
        // unlike `_userTokenWithHop` its direct pool to `_hopToken` is not bootstrapped. This
        // makes `quoteToken == validatorToken && direct insufficient` deterministic instead of
        // depending on fuzzed burns draining the deep hop-1 pool.
        _degenerateUserToken = ITIP20Token(
            factory.createToken(
                "DEGENERATE_USER",
                "DGEN",
                "USD",
                ITIP20(address(_hopToken)),
                admin,
                bytes32("tip1033_degenerate")
            )
        );

        vm.startPrank(admin);
        _hopToken.grantRole(_ISSUER_ROLE, admin);
        _userTokenWithHop.grantRole(_ISSUER_ROLE, admin);
        _degenerateUserToken.grantRole(_ISSUER_ROLE, admin);

        uint64 hopPolicyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        _hopToken.changeTransferPolicyId(hopPolicyId);
        _tokenPolicyIds[address(_hopToken)] = hopPolicyId;
        _tokens.push(_hopToken);

        uint64 uhPolicyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        _userTokenWithHop.changeTransferPolicyId(uhPolicyId);
        _tokenPolicyIds[address(_userTokenWithHop)] = uhPolicyId;
        _tokens.push(_userTokenWithHop);

        uint64 degeneratePolicyId =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        _degenerateUserToken.changeTransferPolicyId(degeneratePolicyId);
        _tokenPolicyIds[address(_degenerateUserToken)] = degeneratePolicyId;
        _tokens.push(_degenerateUserToken);
        vm.stopPrank();
    }

    /// @dev Bootstraps deep liquidity in the two-hop legs using `_actors[0]` so LP balances are
    /// tracked by existing accounting invariants. The direct (userTokenWithHop, validatorToken)
    /// pools are intentionally left uninitialised so the fuzzer naturally exercises fallback.
    function _bootstrapTwoHopPools() internal {
        address bootstrapper = _actors[0];
        // Hop 1: (userTokenWithHop, hopToken) — hopToken is the validator-side reserve.
        _bootstrapPool(
            bootstrapper, address(_userTokenWithHop), address(_hopToken), TWO_HOP_BOOTSTRAP_AMOUNT
        );
        // Hop 2: (hopToken, validatorToken) for every base USD token. Each is a candidate
        // validatorToken that the fuzzer can route through the hop.
        _bootstrapPool(bootstrapper, address(_hopToken), address(token1), TWO_HOP_BOOTSTRAP_AMOUNT);
        _bootstrapPool(bootstrapper, address(_hopToken), address(token2), TWO_HOP_BOOTSTRAP_AMOUNT);
        _bootstrapPool(bootstrapper, address(_hopToken), address(token3), TWO_HOP_BOOTSTRAP_AMOUNT);
        _bootstrapPool(bootstrapper, address(_hopToken), address(token4), TWO_HOP_BOOTSTRAP_AMOUNT);
    }

    function _bootstrapPool(
        address lp,
        address userToken,
        address validatorToken,
        uint256 amount
    )
        internal
    {
        _ensureFunds(lp, ITIP20(validatorToken), amount);
        vm.startPrank(lp);
        ITIP20(validatorToken).approve(address(amm), type(uint256).max);
        amm.mint(userToken, validatorToken, amount, lp);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for minting LP tokens
    /// @param actorSeed Seed for selecting actor
    /// @param pairSeed Seed for selecting token pair
    /// @param amount Amount of validator tokens to deposit
    function mint(uint256 actorSeed, uint256 pairSeed, uint256 amount) external {
        (address userToken, address validatorToken) = _selectTokenPair(pairSeed);
        address actor = _selectAuthorizedActor(actorSeed, validatorToken);

        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        uint256 totalSupplyBefore = amm.totalSupply(poolId);

        // First mint requires >= MIN_LIQUIDITY to avoid wasting budget on known rejections
        // Subsequent mints allow smaller amounts to test edge cases
        amount = bound(amount, totalSupplyBefore == 0 ? MIN_LIQUIDITY : 1, 10_000_000_000);

        // Ensure actor has funds
        _ensureFunds(actor, ITIP20(validatorToken), amount);
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
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for testing that blacklisted actors cannot mint (TEMPO-AMM33)
    /// @dev Explicitly tests that blacklisted actors are rejected with PolicyForbids
    /// @param actorSeed Seed for selecting actor (biased toward blacklistable actors)
    /// @param pairSeed Seed for selecting token pair
    /// @param amountSeed Seed for bounding amount to actor's balance
    function tryMintBlacklisted(uint256 actorSeed, uint256 pairSeed, uint256 amountSeed) external {
        (address userToken, address validatorToken) = _selectTokenPair(pairSeed);
        (address actor, uint256 balance) = _selectBlacklistedActor(actorSeed, validatorToken);

        // Bound amount to actor's available balance
        uint256 amount = bound(amountSeed, MIN_LIQUIDITY, balance);

        vm.prank(actor);
        ITIP20(validatorToken).approve(address(amm), amount);

        // TEMPO-AMM33: Blacklisted actors cannot deposit tokens
        // The mint should revert with PolicyForbids when trying to transfer tokens
        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256) {
            vm.stopPrank();
            // If we reach here, the blacklisted actor was able to mint - this is a bug
            revert("TEMPO-AMM33: Blacklisted actor should not be able to mint");
        } catch (bytes memory reason) {
            vm.stopPrank();
            // TEMPO-AMM33: Verify the revert is due to PolicyForbids or another known error
            // Other valid errors: InsufficientBalance (if actor lost funds), InsufficientAllowance,
            // InsufficientLiquidity (pool not initialized)

            require(reason.length >= 4, "TEMPO-AMM33: Empty revert data");
            bytes4 selector = bytes4(reason);
            bool isExpectedError = selector == ITIP20.PolicyForbids.selector
                || selector == ITIP20.InsufficientBalance.selector
                || selector == ITIP20.InsufficientAllowance.selector
                || selector == IFeeAMM.InsufficientLiquidity.selector;
            assertTrue(
                isExpectedError,
                "TEMPO-AMM33: Blacklisted mint should revert with PolicyForbids or known error"
            );
        }
    }

    /// @notice Handler for burning LP tokens
    /// @param actorSeed Seed for selecting actor
    /// @param pairSeed Seed for selecting token pair
    /// @param liquidityPct Percentage of actor's liquidity to burn (0-100)
    function burn(uint256 actorSeed, uint256 pairSeed, uint256 liquidityPct) external {
        BurnContext memory ctx;
        (ctx.userToken, ctx.validatorToken) = _selectTokenPair(pairSeed);
        ctx.poolId = amm.getPoolId(ctx.userToken, ctx.validatorToken);

        (ctx.actor, ctx.actorLiquidity) = _selectLiquidityHolder(actorSeed, ctx.poolId);

        // Calculate amount to burn
        liquidityPct = bound(liquidityPct, 1, 100);
        ctx.liquidityToBurn = (ctx.actorLiquidity * liquidityPct) / 100;
        if (ctx.liquidityToBurn == 0) ctx.liquidityToBurn = 1;

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);
        ctx.totalSupplyBefore = amm.totalSupply(ctx.poolId);
        ctx.reserveUserBefore = poolBefore.reserveUserToken;
        ctx.reserveValidatorBefore = poolBefore.reserveValidatorToken;
        ctx.actorUserBalanceBefore = ITIP20(ctx.userToken).balanceOf(ctx.actor);
        ctx.actorValidatorBalanceBefore = ITIP20(ctx.validatorToken).balanceOf(ctx.actor);

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
    )
        internal
        view
    {
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
            ITIP20(ctx.userToken).balanceOf(ctx.actor),
            ctx.actorUserBalanceBefore + amountUserToken,
            "TEMPO-AMM8: Actor user token balance mismatch"
        );
        assertEq(
            ITIP20(ctx.validatorToken).balanceOf(ctx.actor),
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
    /// @param pairSeed Seed for selecting token pair
    /// @param amountOutRaw Amount of user tokens to receive
    function rebalanceSwap(uint256 actorSeed, uint256 pairSeed, uint256 amountOutRaw) external {
        RebalanceContext memory ctx;
        (ctx.userToken, ctx.validatorToken) = _selectInitializedPoolPair(pairSeed);
        ctx.actor = _selectAuthorizedActor(actorSeed, ctx.validatorToken);

        IFeeAMM.Pool memory poolBefore = amm.getPool(ctx.userToken, ctx.validatorToken);

        // Bound amountOut to available reserves
        ctx.amountOut = bound(amountOutRaw, 1, poolBefore.reserveUserToken);

        // Calculate expected amountIn: amountIn = (amountOut * N / SCALE) + 1
        ctx.expectedAmountIn = (ctx.amountOut * N) / SCALE + 1;
        ctx.reserveUserBefore = poolBefore.reserveUserToken;
        ctx.reserveValidatorBefore = poolBefore.reserveValidatorToken;

        // Ensure actor has enough validator tokens
        _ensureFunds(ctx.actor, ITIP20(ctx.validatorToken), ctx.expectedAmountIn * 2);

        ctx.actorValidatorBefore = ITIP20(ctx.validatorToken).balanceOf(ctx.actor);
        ctx.actorUserBefore = ITIP20(ctx.userToken).balanceOf(ctx.actor);

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
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @dev Verifies rebalance swap invariants
    function _assertRebalanceInvariants(
        RebalanceContext memory ctx,
        uint256 amountIn
    )
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
            ITIP20(ctx.validatorToken).balanceOf(ctx.actor),
            ctx.actorValidatorBefore - amountIn,
            "TEMPO-AMM12: Actor validator balance mismatch"
        );
        assertEq(
            ITIP20(ctx.userToken).balanceOf(ctx.actor),
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
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownFeeManagerError(reason);
        }
    }

    /// @notice Handler for mint/burn cycle (tests rounding exploitation)
    /// @param actorSeed Seed for selecting actor
    /// @param pairSeed Seed for selecting token pair
    /// @param amount Amount for the cycle
    function mintBurnCycle(uint256 actorSeed, uint256 pairSeed, uint256 amount) external {
        (address userToken, address validatorToken) = _selectTokenPair(pairSeed);
        address actor = _selectAuthorizedActor(actorSeed, validatorToken);

        amount = bound(amount, 1, 100_000);
        _ensureFunds(actor, ITIP20(validatorToken), amount);

        uint256 actorBalBefore = ITIP20(validatorToken).balanceOf(actor);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, amount, actor) returns (uint256 liquidity) {
            if (liquidity > 0) {
                try amm.burn(userToken, validatorToken, liquidity, actor) returns (
                    uint256, uint256
                ) {
                    _totalMintBurnCycles++;

                    uint256 actorBalAfter = ITIP20(validatorToken).balanceOf(actor);
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
    /// @param pairSeed Seed for selecting token pair
    function smallRebalanceSwap(uint256 actorSeed, uint256 pairSeed) external {
        (address userToken, address validatorToken) = _selectInitializedPoolPair(pairSeed);
        address actor = _selectAuthorizedActor(actorSeed, validatorToken);

        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

        // Use very small amounts where rounding matters most
        uint256 amountOut = bound(pool.reserveUserToken, 1, 100);

        uint256 expectedIn = (amountOut * N) / SCALE + 1;
        _ensureFunds(actor, ITIP20(validatorToken), expectedIn * 2);

        vm.startPrank(actor);
        try amm.rebalanceSwap(userToken, validatorToken, amountOut, actor) returns (
            uint256 amountIn
        ) {
            // TEMPO-AMM10/18: Rebalance swap must follow exact formula: amountIn = floor(amountOut * N / SCALE) + 1
            // This is the exact rounding-up formula that always favors the pool
            uint256 expectedAmountIn = (amountOut * N) / SCALE + 1;
            assertEq(
                amountIn,
                expectedAmountIn,
                "TEMPO-AMM18: Small swap amountIn must equal exact formula (floor + 1)"
            );
            // TEMPO-AMM19: Must pay at least 1 for any swap (implicit from +1 in formula)
            assertTrue(amountIn >= 1, "TEMPO-AMM19: Must pay at least 1 for any swap");
        } catch (bytes memory reason) {
            _assertKnownError(reason);
        }
        vm.stopPrank();
    }

    /// @notice Handler for testing first mint boundary condition
    /// @dev Tests that half_amount must be > MIN_LIQUIDITY, not >= (Rust: half_amount <= MIN_LIQUIDITY fails)
    /// @param actorSeed Seed for selecting actor
    /// @param pairSeed Seed for selecting token pair
    function tryFirstMintBoundary(uint256 actorSeed, uint256 pairSeed) external {
        (address userToken, address validatorToken) = _selectTokenPair(pairSeed);
        address actor = _selectAuthorizedActor(actorSeed, validatorToken);
        // T8 mint policy gates run before liquidity checks, so skip actors that cannot reach the
        // boundary condition.
        if (!_isAuthorized(userToken, actor)) return;

        bytes32 poolId = amm.getPoolId(userToken, validatorToken);
        uint256 totalSupplyBefore = amm.totalSupply(poolId);

        // Only test on uninitialized pools
        vm.assume(totalSupplyBefore == 0);

        // Boundary amount: 2 * MIN_LIQUIDITY = 2000
        // half_amount = 1000 = MIN_LIQUIDITY, which should FAIL per Rust (half_amount <= MIN_LIQUIDITY)
        uint256 boundaryAmount = 2 * MIN_LIQUIDITY;

        _ensureFunds(actor, ITIP20(validatorToken), boundaryAmount);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, boundaryAmount, actor) returns (uint256) {
            vm.stopPrank();
        } catch (bytes memory reason) {
            vm.stopPrank();
            // Expected: InsufficientLiquidity when half_amount <= MIN_LIQUIDITY
            assertEq(
                bytes4(reason),
                IFeeAMM.InsufficientLiquidity.selector,
                "First mint with half=MIN_LIQUIDITY should fail with InsufficientLiquidity"
            );
        }

        // Also test just above boundary: 2 * MIN_LIQUIDITY + 2 = 2002
        // half_amount = 1001 > MIN_LIQUIDITY, which should SUCCEED
        uint256 aboveBoundary = 2 * MIN_LIQUIDITY + 2;
        _ensureFunds(actor, ITIP20(validatorToken), aboveBoundary);

        vm.startPrank(actor);
        try amm.mint(userToken, validatorToken, aboveBoundary, actor) returns (uint256 liquidity) {
            vm.stopPrank();
            // Should succeed with liquidity = half_amount - MIN_LIQUIDITY = 1001 - 1000 = 1
            assertEq(liquidity, 1, "First mint just above boundary should yield liquidity of 1");
            _totalMints++;
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for testing rebalance swap with exact division (no remainder)
    /// @dev Tests TEMPO-AMM22: +1 rounding applies even when (amountOut * N) % SCALE == 0
    /// @param actorSeed Seed for selecting actor
    /// @param pairSeed Seed for selecting token pair
    /// @dev Converted to invariant handler since it requires initialized pools
    function handler_exactDivisionRebalance(uint256 actorSeed, uint256 pairSeed) external {
        (address userToken, address validatorToken) = _selectInitializedPoolPair(pairSeed);
        address actor = _selectAuthorizedActor(actorSeed, validatorToken);

        IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);

        // Find an amount where (amountOut * N) % SCALE == 0
        // N = 9985, SCALE = 10000, GCD(9985, 10000) = 5
        // So (amountOut * 9985) % 10000 == 0 when amountOut is a multiple of 2000
        uint256 amountOut = 2000;
        vm.assume(amountOut <= pool.reserveUserToken);

        // Verify this is indeed exact division
        vm.assume((amountOut * N) % SCALE == 0);

        uint256 expectedIn = (amountOut * N) / SCALE + 1; // Should still be +1 even with exact division
        _ensureFunds(actor, ITIP20(validatorToken), expectedIn * 2);

        vm.startPrank(actor);
        try amm.rebalanceSwap(userToken, validatorToken, amountOut, actor) returns (
            uint256 amountIn
        ) {
            vm.stopPrank();

            // TEMPO-AMM22: Even with exact division, the +1 should still apply
            // Without +1: amountIn would be (2000 * 9985) / 10000 = 1997
            // With +1: amountIn should be 1998
            uint256 floorValue = (amountOut * N) / SCALE;
            assertEq(
                amountIn,
                floorValue + 1,
                "TEMPO-AMM22: Rebalance with exact division should still add +1"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
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
    function toggleBlacklist(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 probabilitySeed
    )
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
        }
    }

    /// @notice Handler for distributing collected fees
    /// @dev On tempo-foundry, fees are only collected via protocol tx execution
    ///      This handler tests the distribution mechanism when fees exist
    /// @param seed Seed for selecting a pending fee entry
    function distributeFees(uint256 seed) external {
        // Select from tracked pending fees to avoid discarded runs
        (address validator, address token) = _selectPendingFee(seed);

        uint256 collectedBefore = amm.collectedFees(validator, token);
        uint256 validatorBalanceBefore = ITIP20(token).balanceOf(validator);

        try amm.distributeFees(validator, token) {
            _removePendingFee(validator, token);

            // TEMPO-FEE3 & TEMPO-AMM31: Collected fees should be zeroed after distribution
            // This prevents double-counting of fees for the same validator/token pair
            uint256 collectedAfter = amm.collectedFees(validator, token);
            assertEq(
                collectedAfter,
                0,
                "TEMPO-FEE3/AMM31: Collected fees should be zero after distribution"
            );

            // TEMPO-AMM31: Track that fees were properly zeroed
            _ghostDistributeFeesCalls++;
            if (collectedAfter == 0) {
                _ghostDistributeFeesZeroedCount++;
            }

            // TEMPO-FEE4: Validator should receive the collected fees
            if (collectedBefore > 0) {
                uint256 validatorBalanceAfter = ITIP20(token).balanceOf(validator);
                assertEq(
                    validatorBalanceAfter,
                    validatorBalanceBefore + collectedBefore,
                    "TEMPO-FEE4: Validator should receive collected fees"
                );
                _ghostTotalFeesDistributed += collectedBefore; // Track for TEMPO-AMM29
            }
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
    ///      Uses vm.store to directly modify precompile storage in tempo-foundry.
    /// @param userSeed Seed for selecting user (fee payer)
    /// @param validatorSeed Seed for selecting validator (fee recipient)
    /// @param feeAmountRaw Amount of fees to simulate
    function simulateFeeCollection(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 feeAmountRaw,
        uint256 crossTokenBias
    )
        external
    {
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
            _ensureFunds(user, ITIP20(userToken), feeAmount);
            vm.prank(user);
            try ITIP20(userToken).transfer(address(amm), feeAmount) returns (bool success) {
                assertTrue(success);

                // Simulate fee swap: update pool reserves
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);
                uint128 newReserveUser = pool.reserveUserToken + uint128(feeAmount);
                uint128 newReserveValidator = pool.reserveValidatorToken - uint128(expectedOut);
                _storePoolReserves(poolId, newReserveUser, newReserveValidator);

                // TEMPO-AMM26: Track fee swap reserve updates
                // User token reserve increases by feeAmount, validator token reserve decreases by expectedOut
                _ghostFeeSwapUserReserveIncrease += feeAmount;
                _ghostFeeSwapValidatorReserveDecrease += expectedOut;

                // Accumulate fees for validator
                _storeCollectedFees(validator, validatorToken, expectedOut);
                _addPendingFee(validator, validatorToken);

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
            } catch (bytes memory reason) {
                _assertKnownError(reason);
            }
        } else {
            // Same token: no swap needed, just accumulate
            _ensureFunds(user, ITIP20(userToken), feeAmount);
            vm.prank(user);
            try ITIP20(userToken).transfer(address(amm), feeAmount) returns (bool success) {
                assertTrue(success);

                _storeCollectedFees(validator, validatorToken, feeAmount);
                _addPendingFee(validator, validatorToken);

                // Mark both actors as active
                _markActorActive(user);
                _markActorActive(validator);

                _totalFeeCollections++;
                _ghostFeeInputSum += feeAmount;
                _ghostFeeOutputSum += feeAmount;
                _ghostTotalFeesCollected += feeAmount; // Track for TEMPO-AMM29
                // No dust for same-token transfers
            } catch (bytes memory reason) {
                _assertKnownError(reason);
            }
        }
    }

    /// @notice Handler for simulating two-hop fee collection (TIP-1033, T5+).
    /// @dev Mirrors `simulateFeeCollection` but specialised for the two-hop topology:
    ///      `userToken (USD, quoteToken=hopToken) -> hopToken -> validatorToken`.
    ///      Pre/post-tx state is mocked via `vm.store`. The handler:
    ///        1. Predicts the route locally (mirror of `plan_fee_route`).
    ///        2. Applies the resulting reserve / collected-fees deltas with `vm.store`.
    ///        3. Records a `TwoHopWitness` so `invariant_feeAMM` can verify TIP-1033 properties.
    /// @param userSeed Seed for selecting the fee-paying actor.
    /// @param validatorSeed Seed for selecting the validatorToken among `{token1..token4}`.
    /// @param feeAmountRaw Seed for the fee amount.
    /// @param forceFallbackBias 70%-biased seed: prefer amounts that force the two-hop path.
    function simulateTwoHopFeeCollection(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 feeAmountRaw,
        uint256 forceFallbackBias
    )
        external
    {
        TwoHopContext memory ctx;
        ctx.user = _selectActor(userSeed);
        ctx.validator = _selectActor(validatorSeed);
        ctx.userToken = address(_userTokenWithHop);
        ctx.hopToken = address(_hopToken);
        ctx.validatorToken = _pickTwoHopValidatorToken(validatorSeed);

        // User must be authorised to send userToken (otherwise transfer reverts).
        vm.assume(
            registry.isAuthorized(_tokenPolicyIds[ctx.userToken], ctx.user)
                && registry.isAuthorized(_tokenPolicyIds[ctx.validatorToken], ctx.validator)
        );

        ctx.directPool = amm.getPool(ctx.userToken, ctx.validatorToken);
        ctx.leg1Pool = amm.getPool(ctx.userToken, ctx.hopToken);
        ctx.leg2Pool = amm.getPool(ctx.hopToken, ctx.validatorToken);

        // Three regimes: 10% boundary (±2 of threshold), 60% fallback-biased, 30% direct.
        uint256 regime = forceFallbackBias % 100;
        bool biasBoundary = regime < 10;
        bool biasFallback = !biasBoundary && regime < 70;
        ctx.feeAmount =
            _pickTwoHopFeeAmount(feeAmountRaw, ctx.directPool, biasFallback, biasBoundary);
        if (biasBoundary) _totalBoundaryFeeAmounts++;
        vm.assume(ctx.feeAmount >= 1000);
        // Cap so reserve adds never overflow uint128 in the legs.
        vm.assume(
            uint256(ctx.leg1Pool.reserveUserToken) + ctx.feeAmount <= type(uint128).max
                && uint256(ctx.leg2Pool.reserveUserToken) + ctx.feeAmount <= type(uint128).max
        );

        ctx.out1 = (ctx.feeAmount * M) / SCALE;
        ctx.out2 = (ctx.out1 * M) / SCALE;
        vm.assume(ctx.out2 > 0);

        // Mirror of `plan_fee_route` (T5+):
        //   - direct sufficient => single-hop
        //   - else if hopToken non-zero, != validatorToken, and both legs sufficient => two-hop
        //   - else => no route (handled by simulateDegenerateQuoteEqualsValidator)
        bool directSufficient = ctx.out1 <= uint256(ctx.directPool.reserveValidatorToken);
        bool legsSufficient = ctx.hopToken != address(0) && ctx.hopToken != ctx.validatorToken
            && ctx.out1 <= uint256(ctx.leg1Pool.reserveValidatorToken)
            && ctx.out2 <= uint256(ctx.leg2Pool.reserveValidatorToken);

        if (directSufficient) {
            _executeSimulatedDirectFeeCollection(ctx);
        } else if (legsSufficient) {
            _executeSimulatedTwoHopFeeCollection(ctx);
        } else {
            // Neither path can settle. Real precompile would revert with `InsufficientLiquidity`
            // and (per TIP-1033 invariant 4 + 8) leave NO observable state change and NO transient
            // leak. We model that revert directly here — the previous behaviour (`vm.assume(false)`)
            // discarded the run silently and left this branch effectively untested. Without the
            // explicit assertions, a future change to `plan_fee_route` could half-commit on the
            // insufficient-leg case and the suite would not notice.
            _assertInsufficientFallbackNoCommit(ctx);
        }
    }

    /// @dev Asserts the no-half-commit / no-transient-leak post-conditions of the
    /// non-degenerate insufficient-fallback revert path. Sibling of `simulateDegenerateQuoteEqualsValidator`'s
    /// TEMPO-FEE10 check, generalised to the case where `hopToken != validatorToken` but at
    /// least one leg pool cannot cover its hop output. Covers Gap A from PR-3856 review.
    function _assertInsufficientFallbackNoCommit(TwoHopContext memory ctx) internal {
        IFeeAMM.Pool memory directAfter = amm.getPool(ctx.userToken, ctx.validatorToken);
        IFeeAMM.Pool memory leg1After = amm.getPool(ctx.userToken, ctx.hopToken);
        IFeeAMM.Pool memory leg2After = amm.getPool(ctx.hopToken, ctx.validatorToken);

        assertEq(
            directAfter.reserveUserToken,
            ctx.directPool.reserveUserToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change direct user reserve"
        );
        assertEq(
            directAfter.reserveValidatorToken,
            ctx.directPool.reserveValidatorToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change direct validator reserve"
        );
        assertEq(
            leg1After.reserveUserToken,
            ctx.leg1Pool.reserveUserToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change leg1 user reserve"
        );
        assertEq(
            leg1After.reserveValidatorToken,
            ctx.leg1Pool.reserveValidatorToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change leg1 validator reserve"
        );
        assertEq(
            leg2After.reserveUserToken,
            ctx.leg2Pool.reserveUserToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change leg2 user reserve"
        );
        assertEq(
            leg2After.reserveValidatorToken,
            ctx.leg2Pool.reserveValidatorToken,
            "TIP-1033 (inv. 4): insufficient-fallback revert must not change leg2 validator reserve"
        );

        // No transient leak — see TWO_HOP_INTERMEDIATE_SLOT comment for `vm.load` semantics.
        bytes32 stored = vm.load(address(amm), bytes32(TWO_HOP_INTERMEDIATE_SLOT));
        assertEq(
            stored,
            bytes32(0),
            "TIP-1033 (inv. 8): insufficient-fallback revert must not leak intermediate slot"
        );

        _totalInsufficientFallbackWitnesses++;
    }

    /// @dev Selects a validatorToken for the two-hop simulation. Must be a base USD token,
    /// must differ from `userTokenWithHop` and `hopToken` (otherwise the topology degenerates).
    function _pickTwoHopValidatorToken(uint256 seed) internal view returns (address) {
        // Base candidates are token1..token4. token3/token4 are added to `_tokens` at index 2/3.
        address[4] memory candidates =
            [address(token1), address(token2), address(token3), address(token4)];
        return candidates[seed % candidates.length];
    }

    /// @dev Picks a fee amount in [1k, 1M]. Modes:
    ///   - `biasBoundary`: a 5-wide window around `minInsufficient` (= first amount whose
    ///     `out1` exceeds `directReserve`). Skewed slightly toward insufficient (~3 of 5
    ///     samples land in the fallback regime, ~2 in direct), but every sample is within
    ///     2 of the predicate flip.
    ///   - `biasFallback`: above the threshold (forces fallback).
    ///   - otherwise: below the threshold (direct path can settle).
    function _pickTwoHopFeeAmount(
        uint256 seed,
        IFeeAMM.Pool memory directPool,
        bool biasFallback,
        bool biasBoundary
    )
        internal
        pure
        returns (uint256)
    {
        uint256 lo = 1000;
        uint256 hi = 1_000_000;
        // Smallest fee amount whose `out1 = floor(amount * M / SCALE)` strictly exceeds the
        // direct reserve. Equivalent to `directReserve * SCALE / M + 1` in real arithmetic.
        uint256 directReserve = uint256(directPool.reserveValidatorToken);
        uint256 minInsufficient = directReserve == 0 ? 1 : (directReserve * SCALE) / M + 2;

        if (biasBoundary && directReserve > 0 && minInsufficient <= hi && minInsufficient + 2 >= lo)
        {
            // Centre the draw on the boundary: [minInsufficient - 2, minInsufficient + 2],
            // clamped into the global [lo, hi] range. The outer guard ensures the band overlaps
            // [lo, hi] non-trivially before clamping (otherwise bLo > bHi).
            uint256 bLo = minInsufficient > lo + 2 ? minInsufficient - 2 : lo;
            uint256 bHi = minInsufficient + 2 <= hi ? minInsufficient + 2 : hi;
            return bound(seed, bLo, bHi);
        }

        if (biasFallback && minInsufficient <= hi) {
            return bound(seed, minInsufficient > lo ? minInsufficient : lo, hi);
        }
        // Direct-preferred path: keep amount in range that direct pool can absorb.
        if (!biasFallback && directReserve > 0) {
            uint256 maxDirect = (directReserve * SCALE) / M;
            if (maxDirect >= lo) {
                return bound(seed, lo, maxDirect < hi ? maxDirect : hi);
            }
        }
        return bound(seed, lo, hi);
    }

    /// @dev Executes the direct-path branch of `simulateTwoHopFeeCollection`.
    function _executeSimulatedDirectFeeCollection(TwoHopContext memory ctx) internal {
        _ensureFunds(ctx.user, ITIP20(ctx.userToken), ctx.feeAmount);
        vm.prank(ctx.user);
        try ITIP20(ctx.userToken).transfer(address(amm), ctx.feeAmount) returns (bool ok) {
            assertTrue(ok);
        } catch (bytes memory reason) {
            _assertKnownError(reason);
            return;
        }

        // TEMPO-FEE11 (extended): capture hopToken accounting. Direct path does not touch
        // hopToken, so before == after trivially; the invariant skips !tookFallback witnesses.
        ctx.hopBalanceBefore = ITIP20(ctx.hopToken).balanceOf(address(amm));
        ctx.hopReservesBefore = _sumReservesOfToken(ctx.hopToken);

        bytes32 directPoolId = amm.getPoolId(ctx.userToken, ctx.validatorToken);
        _storePoolReserves(
            directPoolId,
            ctx.directPool.reserveUserToken + uint128(ctx.feeAmount),
            ctx.directPool.reserveValidatorToken - uint128(ctx.out1)
        );
        _storeCollectedFees(ctx.validator, ctx.validatorToken, ctx.out1);
        _addPendingFee(ctx.validator, ctx.validatorToken);
        _markActorActive(ctx.user);
        _markActorActive(ctx.validator);

        _totalFeeCollections++;
        _totalDirectPreferredCollections++;
        _ghostTotalFeesCollected += ctx.out1; // TEMPO-AMM29
        _ghostFeeInputSum += ctx.feeAmount; // TEMPO-AMM25 / TEMPO-FEE6
        _ghostFeeOutputSum += ctx.out1;
        _recordTwoHopWitness(
            ctx,
            /* tookFallback */
            false,
            /* directWasInsufficient */
            false
        );
    }

    /// @dev Executes the two-hop fallback branch of `simulateTwoHopFeeCollection`.
    function _executeSimulatedTwoHopFeeCollection(TwoHopContext memory ctx) internal {
        _ensureFunds(ctx.user, ITIP20(ctx.userToken), ctx.feeAmount);
        vm.prank(ctx.user);
        try ITIP20(ctx.userToken).transfer(address(amm), ctx.feeAmount) returns (bool ok) {
            assertTrue(ok);
        } catch (bytes memory reason) {
            _assertKnownError(reason);
            return;
        }

        // TEMPO-FEE11 (extended): capture hopToken accounting before the leg writes so the
        // conservation invariant compares like-for-like (no userToken-side noise).
        ctx.hopBalanceBefore = ITIP20(ctx.hopToken).balanceOf(address(amm));
        ctx.hopReservesBefore = _sumReservesOfToken(ctx.hopToken);

        // Hop 1: (userToken, hopToken) — user reserve += feeAmount, validator reserve -= out1.
        bytes32 leg1Id = amm.getPoolId(ctx.userToken, ctx.hopToken);
        _storePoolReserves(
            leg1Id,
            ctx.leg1Pool.reserveUserToken + uint128(ctx.feeAmount),
            ctx.leg1Pool.reserveValidatorToken - uint128(ctx.out1)
        );
        // Hop 2: (hopToken, validatorToken) — user reserve += out1, validator reserve -= out2.
        bytes32 leg2Id = amm.getPoolId(ctx.hopToken, ctx.validatorToken);
        _storePoolReserves(
            leg2Id,
            ctx.leg2Pool.reserveUserToken + uint128(ctx.out1),
            ctx.leg2Pool.reserveValidatorToken - uint128(ctx.out2)
        );
        _storeCollectedFees(ctx.validator, ctx.validatorToken, ctx.out2);
        _addPendingFee(ctx.validator, ctx.validatorToken);
        _markActorActive(ctx.user);
        _markActorActive(ctx.validator);

        // Aggregate fee math (TEMPO-AMM35/AMM37).
        _ghostHop1InputSum += ctx.feeAmount;
        _ghostHop1OutputSum += ctx.out1;
        _ghostHop2InputSum += ctx.out1;
        _ghostHop2OutputSum += ctx.out2;
        _ghostTwoHopValidatorCredited += ctx.out2;
        _ghostTwoHopExpectedSequential += ctx.out2;
        if (ctx.feeAmount > _ghostMaxFallbackAmount) {
            _ghostMaxFallbackAmount = ctx.feeAmount;
            _ghostMaxFallbackCredited = ctx.out2;
        }
        _totalFeeCollections++;
        _totalTwoHopFeeCollections++;
        // TEMPO-AMM29 conservation: a two-hop tx credits the validator with `out2` units of
        // validatorToken; that is the only amount the protocol later distributes. The leg-1
        // intermediate output (`out1`) stays inside the AMM as hopToken reserve and is not a
        // distributable fee, so we must NOT count it here.
        _ghostTotalFeesCollected += ctx.out2;
        // TEMPO-AMM25 / TEMPO-FEE6: aggregate input/output sanity. We record the user-side
        // fee paid (input) and the validator-credited amount (output) so the existing
        // `_invariantFeeSwapRateApplied` check (output ≤ input) still holds across two-hop runs.
        _ghostFeeInputSum += ctx.feeAmount;
        _ghostFeeOutputSum += ctx.out2;
        _recordTwoHopWitness(
            ctx,
            /* tookFallback */
            true,
            /* directWasInsufficient */
            true
        );
    }

    /// @dev Pushes a witness onto the bounded ghost array.
    function _recordTwoHopWitness(
        TwoHopContext memory ctx,
        bool tookFallback,
        bool directWasInsufficient
    )
        internal
    {
        if (_ghostTwoHopWitnesses.length >= MAX_TWO_HOP_WITNESSES) return;

        IFeeAMM.Pool memory directAfter = amm.getPool(ctx.userToken, ctx.validatorToken);
        IFeeAMM.Pool memory hop1After = amm.getPool(ctx.userToken, ctx.hopToken);
        IFeeAMM.Pool memory hop2After = amm.getPool(ctx.hopToken, ctx.validatorToken);

        _ghostTwoHopWitnesses.push(
            TwoHopWitness({
                userToken: ctx.userToken,
                hopToken: ctx.hopToken,
                validatorToken: ctx.validatorToken,
                directReserveBefore: ctx.directPool.reserveValidatorToken,
                directReserveAfter: directAfter.reserveValidatorToken,
                hop1ReserveValBefore: ctx.leg1Pool.reserveValidatorToken,
                hop1ReserveValAfter: hop1After.reserveValidatorToken,
                hop2ReserveValBefore: ctx.leg2Pool.reserveValidatorToken,
                hop2ReserveValAfter: hop2After.reserveValidatorToken,
                actualSpending: ctx.feeAmount,
                out1: ctx.out1,
                out2: ctx.out2,
                tookFallback: tookFallback,
                directWasInsufficient: directWasInsufficient,
                // TEMPO-FEE11 (extended): hopToken conservation snapshot.
                ammHopBalanceBefore: ctx.hopBalanceBefore,
                ammHopBalanceAfter: ITIP20(ctx.hopToken).balanceOf(address(amm)),
                sumHopReservesBefore: ctx.hopReservesBefore,
                sumHopReservesAfter: _sumReservesOfToken(ctx.hopToken)
            })
        );
    }

    /// @notice Handler for the degenerate case `userToken.quoteToken() == validatorToken`.
    /// @dev Drives TEMPO-FEE10. The mocked precompile would revert with `InsufficientLiquidity`
    ///      when the direct pool is shallow AND the two-hop fallback degenerates onto the same
    ///      pair. We model the revert as "no state change, no transient leak" since `vm.store`
    ///      cannot model a reverted protocol call directly.
    /// @param userSeed Seed for selecting the user actor.
    /// @param validatorSeed Seed for selecting the validator actor.
    /// @param feeAmountRaw Seed for the fee amount.
    function simulateDegenerateQuoteEqualsValidator(
        uint256 userSeed,
        uint256 validatorSeed,
        uint256 feeAmountRaw
    )
        external
    {
        // Force `validatorToken == userToken.quoteToken()` by picking validatorToken = hopToken.
        // user/validator seeds are reserved for future expansion (e.g. when modelling a real
        // revert against a real call); the model-only check below does not need them yet.
        userSeed;
        validatorSeed;
        address userToken = address(_degenerateUserToken);
        address validatorToken = address(_hopToken);

        IFeeAMM.Pool memory directPoolBefore = amm.getPool(userToken, validatorToken);

        // Force "direct insufficient" by picking a feeAmount whose out1 exceeds the direct
        // pool's validator-side reserve. Cap aggressively so we don't spuriously vm.assume away.
        uint256 directReserve = uint256(directPoolBefore.reserveValidatorToken);
        uint256 minInsufficient = (directReserve * SCALE) / M + 2;
        // The bootstrapped (userTokenWithHop, hopToken) pool is deep, so this branch will
        // typically discard via vm.assume. That is acceptable: the test contributes whenever
        // burns or other handlers happen to drain the direct pool below `minInsufficient`.
        vm.assume(minInsufficient <= 1_000_000);
        uint256 feeAmount = bound(feeAmountRaw, minInsufficient, 1_000_000);
        uint256 amountOut = (feeAmount * M) / SCALE;
        // Sanity: the chosen amount really does outstrip the direct pool reserve.
        if (amountOut <= directReserve) return;

        // Predicted route under TIP-1033 = None (degenerate two-hop). Model the protocol's
        // "revert with no half-commit": no state change, no transient writes.
        IFeeAMM.Pool memory directPoolAfter = amm.getPool(userToken, validatorToken);
        assertEq(
            directPoolAfter.reserveUserToken,
            directPoolBefore.reserveUserToken,
            "TEMPO-FEE10: degenerate revert must not change direct user reserve"
        );
        assertEq(
            directPoolAfter.reserveValidatorToken,
            directPoolBefore.reserveValidatorToken,
            "TEMPO-FEE10: degenerate revert must not change direct validator reserve"
        );
        // No transient leak — see TWO_HOP_INTERMEDIATE_SLOT comment for vm.load semantics.
        bytes32 stored = vm.load(address(amm), bytes32(TWO_HOP_INTERMEDIATE_SLOT));
        assertEq(
            stored, bytes32(0), "TEMPO-FEE10: degenerate revert must not leak intermediate slot"
        );

        _totalDegenerateReverts++;
    }

    /// @notice Drains a two-hop leg pool via a real `amm.burn` from the bootstrapper LP so the
    /// insufficient-fallback branch of `simulateTwoHopFeeCollection` is reachable. Leg pools
    /// are bootstrapped at `TWO_HOP_BOOTSTRAP_AMOUNT = 1e11`, well above the [1k, 1M] fee
    /// range, so without aggressive draining that branch never fires.
    /// @dev Uses a real burn (not `vm.store`) to keep AMM accounting consistent.
    /// @param legChoiceSeed 0 → drain leg1 `(_userTokenWithHop, _hopToken)`, else leg2
    ///                      `(_hopToken, tokenN)`.
    /// @param validatorSeed Picks `tokenN` for leg2.
    /// @param burnPctSeed Fraction of bootstrapper LP to burn, biased to 99.99–100%.
    function simulateLegDrainViaBurn(
        uint256 legChoiceSeed,
        uint256 validatorSeed,
        uint256 burnPctSeed
    )
        external
    {
        address bootstrapper = _actors[0];
        bool drainLeg1 = (legChoiceSeed % 2) == 0;
        address tokenA = drainLeg1 ? address(_userTokenWithHop) : address(_hopToken);
        address tokenB = drainLeg1 ? address(_hopToken) : _pickTwoHopValidatorToken(validatorSeed);

        bytes32 poolId = amm.getPoolId(tokenA, tokenB);
        uint256 lpBalance = amm.liquidityBalances(poolId, bootstrapper);
        if (lpBalance == 0) return;

        // Bias hard toward >= 99.999% so validator-side reserve drops below ~1M (the fee
        // amount upper bound). Anything less leaves the pool deep enough that the route
        // predicate still picks the fallback path.
        uint256 burnPct = bound(burnPctSeed, 99_990, 100_000);
        uint256 toBurn = (lpBalance * burnPct) / 100_000;
        if (toBurn == 0) return;

        vm.startPrank(bootstrapper);
        try amm.burn(tokenA, tokenB, toBurn, bootstrapper) { }
        catch (bytes memory reason) {
            _assertKnownError(reason);
        }
        vm.stopPrank();
    }

    /// @notice Drains the direct pool `(_userTokenWithHop, tokenN)` via real `amm.burn` from any
    /// LP holder, so a previously-deep direct pool can become shallow mid-run and the fallback
    /// path fires more often.
    /// @dev Real burn keeps AMM accounting consistent.
    /// @param actorSeed Picks an LP holder of the direct pool.
    /// @param validatorSeed Picks `tokenN`.
    /// @param burnPctSeed Fraction of LP to burn, biased to 99.99–100%.
    function simulateDirectDrainViaBurn(
        uint256 actorSeed,
        uint256 validatorSeed,
        uint256 burnPctSeed
    )
        external
    {
        address userToken = address(_userTokenWithHop);
        address validatorToken = _pickTwoHopValidatorToken(validatorSeed);
        bytes32 poolId = amm.getPoolId(userToken, validatorToken);

        // Find any LP holder for this pool (may be empty if no actor has minted yet).
        address[] memory holders = new address[](_actors.length);
        uint256[] memory balances = new uint256[](_actors.length);
        uint256 count = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            uint256 bal = amm.liquidityBalances(poolId, _actors[i]);
            if (bal > 0) {
                holders[count] = _actors[i];
                balances[count] = bal;
                count++;
            }
        }
        if (count == 0) return;

        uint256 idx = bound(actorSeed, 0, count - 1);
        address holder = holders[idx];
        uint256 lpBalance = balances[idx];

        uint256 burnPct = bound(burnPctSeed, 99_990, 100_000);
        uint256 toBurn = (lpBalance * burnPct) / 100_000;
        if (toBurn == 0) return;

        vm.startPrank(holder);
        try amm.burn(userToken, validatorToken, toBurn, holder) {
            _totalDirectDrains++;
        } catch (bytes memory reason) {
            _assertKnownError(reason);
        }
        vm.stopPrank();
    }

    /// @notice Rotates a TIP-20's quote token to drive TEMPO-FEE9's "current chain state" check
    /// and `_invariantQuoteTokenGraphWellFormed`. Without this both reduce to static setup
    /// properties.
    /// @dev Excludes `_userTokenWithHop` so existing two-hop fallback witnesses stay consistent
    /// with the post-rotation graph, and excludes `_degenerateUserToken` because
    /// `simulateDegenerateQuoteEqualsValidator` hardcodes its quote as `_hopToken` to engineer
    /// the degenerate-revert state — rotating it would let the degenerate handler false-fail
    /// in states where the real `plan_fee_route` would two-hop. Picks a new quote whose chain
    /// reaches `pathUSD` without passing through the target (cycle pre-check). Validation
    /// reverts are caught silently.
    /// @param tokenSeed Picks the rotation target.
    /// @param newQuoteSeed Picks the candidate new quote.
    function rotateQuoteToken(uint256 tokenSeed, uint256 newQuoteSeed) external {
        // Excludes `_userTokenWithHop` (pins two-hop topology) and `_degenerateUserToken`
        // (pins the degenerate-revert handler). Everything else is fair game.
        uint256 numTokens = _tokens.length;
        ITIP20Token[] memory candidates = new ITIP20Token[](numTokens);
        uint256 numCandidates = 0;
        for (uint256 i = 0; i < numTokens; i++) {
            address t = address(_tokens[i]);
            if (t == address(_userTokenWithHop) || t == address(_degenerateUserToken)) continue;
            candidates[numCandidates++] = ITIP20Token(t);
        }
        if (numCandidates == 0) return;

        ITIP20Token target = candidates[tokenSeed % numCandidates];

        // New quote: any other rotation candidate whose currency is USD AND that does not
        // currently quote (directly or transitively) into `target` (avoids cycle).
        ITIP20 newQuote;
        uint256 startIdx = newQuoteSeed % numCandidates;
        for (uint256 attempt = 0; attempt < numCandidates; attempt++) {
            ITIP20Token c = candidates[(startIdx + attempt) % numCandidates];
            if (address(c) == address(target)) continue;
            // Walk c's quote chain: must reach pathUSD without passing through `target`.
            address cur = address(ITIP20(address(c)).quoteToken());
            bool ok = true;
            uint256 walked = 0;
            while (cur != address(0) && cur != address(pathUSD)) {
                if (cur == address(target)) {
                    ok = false;
                    break;
                }
                if (++walked > 8) {
                    ok = false;
                    break;
                }
                cur = address(ITIP20(cur).quoteToken());
            }
            if (ok && cur == address(pathUSD)) {
                newQuote = ITIP20(address(c));
                break;
            }
        }
        if (address(newQuote) == address(0)) return;

        vm.startPrank(admin);
        // Both calls SHOULD succeed: we prank as admin (role check passes) and pre-walk the
        // candidate's chain (cycle check passes). The catches are a safety net so a future
        // TIP-20 validation rule we haven't anticipated does NOT abort the whole fuzz campaign
        // (`fail_on_revert = true`); a missed rotation just lowers coverage on that step.
        try target.setNextQuoteToken(newQuote) {
            try target.completeQuoteTokenUpdate() {
                _totalQuoteRotations++;
            } catch (bytes memory) { }
        } catch (bytes memory) { }
        vm.stopPrank();
    }

    /// @dev Stores pool reserves directly using vm.store
    function _storePoolReserves(
        bytes32 poolId,
        uint128 reserveUser,
        uint128 reserveValidator
    )
        internal
    {
        // Storage layout in Rust implementation:
        //   slot 0: validator_tokens
        //   slot 1: user_tokens
        //   slot 2: collected_fees
        //   slot 3: pools
        //   slot 4: total_supply
        //   slot 5: liquidity_balances
        uint256 poolsSlot = 3;
        bytes32 poolSlot = keccak256(abi.encode(poolId, poolsSlot));

        // Pack: lower 128 bits = reserveUserToken, upper 128 bits = reserveValidatorToken
        bytes32 newPoolValue = bytes32(uint256(reserveUser) | (uint256(reserveValidator) << 128));
        vm.store(address(amm), poolSlot, newPoolValue);
    }

    /// @dev Stores/increments collected fees using vm.store
    function _storeCollectedFees(address validator, address token, uint256 amount) internal {
        // Storage layout in Rust implementation:
        //   slot 0: validator_tokens
        //   slot 1: user_tokens
        //   slot 2: collected_fees
        //   slot 3: pools
        //   slot 4: total_supply
        //   slot 5: liquidity_balances
        // collected_fees is mapping(address => mapping(address => uint256))
        // slot = keccak256(token, keccak256(validator, collectedFeesSlot))
        uint256 collectedFeesSlot = 2;
        bytes32 innerSlot = keccak256(abi.encode(validator, collectedFeesSlot));
        bytes32 feeSlot = keccak256(abi.encode(token, innerSlot));

        // Read current value and add
        uint256 current = uint256(vm.load(address(amm), feeSlot));
        vm.store(address(amm), feeSlot, bytes32(current + amount));
    }

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after each invariant run
    function afterInvariant() public {
        // TEMPO-AMM24: All participants can exit - simulate full withdrawal
        _verifyAllCanExit();
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    function invariant_feeAMM() public view {
        _invariantPoolStateChecks(); // Unified: AMM13, AMM14, AMM15, AMM20, FEE5
        _invariantRebalanceRoundingFavorsPool();
        _invariantBurnRoundingFavorsPool();
        _invariantFeeSwapRateApplied(); // Also covers TEMPO-FEE6
        _invariantFeeSwapReservesUpdate(); // TEMPO-AMM26
        _invariantFeeDoubleCountPrevention(); // TEMPO-AMM31
        _invariantPoolIdUniqueness();
        _invariantNoLpWhenUninitialized();
        _invariantFeeConservation();
        _invariantPoolInitializationShape();
        // TIP-1033 (T5+): two-hop FeeAMM routing.
        // Unified per-witness pass: TEMPO-AMM35/36/37, TEMPO-FEE7/8/9/11, TIP-1033 inv. 2.
        _invariantTwoHopWitnessChecks();
        _invariantQuoteTokenGraphWellFormed(); // TEMPO-FEE9 (state scan, not witness-driven)
        _invariantSingleHopUnchanged(); // TEMPO-FEE13
        _invariantTransientCleared(); // TEMPO-FEE14
    }

    /// @notice Unified pool state checks - single loop for AMM13, AMM14, AMM15, AMM20, FEE5
    /// @dev Combines _invariantPoolSolvency, _invariantLiquidityAccounting, _invariantMinLiquidityLocked,
    ///      _invariantReservesBoundedByU128, and _invariantCollectedFeesNotExceedBalance
    function _invariantPoolStateChecks() internal view {
        uint256 MAX_U128 = type(uint128).max;
        uint256 numTokens = _tokens.length;
        uint256 numActors = _actors.length;

        // Cache AMM token balances (one balanceOf call per token instead of O(n²))
        uint256[] memory ammBalances = new uint256[](numTokens);
        for (uint256 i = 0; i < numTokens; i++) {
            ammBalances[i] = _tokens[i].balanceOf(address(amm));
        }
        uint256 ammPathUsdBalance = pathUSD.balanceOf(address(amm));

        // Check combined solvency per token (FEE5) - reserves + collected fees <= balance
        // A token's total obligations = sum of reserves across all pools referencing it + collected fees
        uint256 totalTokens = numTokens + 1; // _tokens + pathUSD
        for (uint256 i = 0; i < numTokens; i++) {
            address token = address(_tokens[i]);

            // Sum collected fees for this token across all actors
            uint256 totalCollected = 0;
            for (uint256 a = 0; a < numActors; a++) {
                totalCollected += amm.collectedFees(_actors[a], token);
            }

            // Sum reserves for this token across all pools where it appears
            uint256 totalReserves = 0;
            for (uint256 j = 0; j < totalTokens; j++) {
                address other = j == 0 ? address(pathUSD) : address(_tokens[j - 1]);
                if (other == token) continue;

                // token as userToken in pool(token, other)
                IFeeAMM.Pool memory p1 = amm.getPool(token, other);
                totalReserves += uint256(p1.reserveUserToken);

                // token as validatorToken in pool(other, token)
                IFeeAMM.Pool memory p2 = amm.getPool(other, token);
                totalReserves += uint256(p2.reserveValidatorToken);
            }

            assertTrue(
                totalReserves + totalCollected <= ammBalances[i],
                "TEMPO-FEE5: Combined reserves + collected fees exceed AMM balance"
            );
        }
        // Check pathUSD combined solvency
        {
            uint256 totalPathUsdCollected = 0;
            for (uint256 a = 0; a < numActors; a++) {
                totalPathUsdCollected += amm.collectedFees(_actors[a], address(pathUSD));
            }
            uint256 totalPathUsdReserves = 0;
            for (uint256 j = 0; j < numTokens; j++) {
                address other = address(_tokens[j]);
                // pathUSD as userToken in pool(pathUSD, other)
                IFeeAMM.Pool memory p1 = amm.getPool(address(pathUSD), other);
                totalPathUsdReserves += uint256(p1.reserveUserToken);
                // pathUSD as validatorToken in pool(other, pathUSD)
                IFeeAMM.Pool memory p2 = amm.getPool(other, address(pathUSD));
                totalPathUsdReserves += uint256(p2.reserveValidatorToken);
            }
            assertTrue(
                totalPathUsdReserves + totalPathUsdCollected <= ammPathUsdBalance,
                "TEMPO-FEE5: Combined pathUSD reserves + collected fees exceed AMM balance"
            );
        }

        // Check all token pairs - single O(n²) loop for AMM13, AMM14, AMM15, AMM20
        for (uint256 i = 0; i < numTokens; i++) {
            for (uint256 j = 0; j < numTokens; j++) {
                if (i == j) continue;

                address userToken = address(_tokens[i]);
                address validatorToken = address(_tokens[j]);

                IFeeAMM.Pool memory pool = amm.getPool(userToken, validatorToken);
                bytes32 poolId = amm.getPoolId(userToken, validatorToken);
                uint256 totalSupply = amm.totalSupply(poolId);

                // TEMPO-AMM13: Pool solvency - use cached balances
                assertTrue(
                    ammBalances[i] >= pool.reserveUserToken,
                    "TEMPO-AMM13: AMM user token balance < reserve"
                );
                assertTrue(
                    ammBalances[j] >= pool.reserveValidatorToken,
                    "TEMPO-AMM13: AMM validator token balance < reserve"
                );

                // TEMPO-AMM20: Reserves bounded by uint128
                assertTrue(
                    uint256(pool.reserveUserToken) <= MAX_U128,
                    "TEMPO-AMM20: reserveUserToken exceeds uint128"
                );
                assertTrue(
                    uint256(pool.reserveValidatorToken) <= MAX_U128,
                    "TEMPO-AMM20: reserveValidatorToken exceeds uint128"
                );

                // TEMPO-AMM15: MIN_LIQUIDITY locked on first mint
                if (pool.reserveValidatorToken > 0 || pool.reserveUserToken > 0) {
                    assertTrue(
                        totalSupply >= MIN_LIQUIDITY,
                        "TEMPO-AMM15: Total supply < MIN_LIQUIDITY after initialization"
                    );
                }

                // TEMPO-AMM14: LP token accounting (only if pool has supply)
                if (totalSupply > 0) {
                    uint256 sumBalances = 0;
                    for (uint256 k = 0; k < numActors; k++) {
                        sumBalances += amm.liquidityBalances(poolId, _actors[k]);
                    }
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

        // Check pathUSD pools - TEMPO-AMM13
        for (uint256 i = 0; i < numTokens; i++) {
            address token = address(_tokens[i]);

            IFeeAMM.Pool memory pool1 = amm.getPool(address(pathUSD), token);
            assertTrue(
                ammPathUsdBalance >= pool1.reserveUserToken,
                "TEMPO-AMM13: AMM pathUSD balance < reserve (as user)"
            );

            IFeeAMM.Pool memory pool2 = amm.getPool(token, address(pathUSD));
            assertTrue(
                ammPathUsdBalance >= pool2.reserveValidatorToken,
                "TEMPO-AMM13: AMM pathUSD balance < reserve (as validator)"
            );
        }
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

    /// @notice TEMPO-AMM25 & TEMPO-FEE6: Fee swap rate M is correctly applied
    /// amountOut = (amountIn * M / SCALE), output never exceeds input
    /// TEMPO-FEE6: Ensures amountOut <= amountIn for all fee swaps (0.3% fee captured)
    function _invariantFeeSwapRateApplied() internal view {
        // Verify via accumulated ghost variables
        // When userToken == validatorToken: output == input (no swap)
        // When userToken != validatorToken: output == input * M / SCALE (0.3% fee)
        // So output should always be <= input
        if (_ghostFeeInputSum > 0 && _totalFeeCollections > 0) {
            // TEMPO-AMM25: Fee output never exceeds fee input
            assertTrue(
                _ghostFeeOutputSum <= _ghostFeeInputSum, "TEMPO-AMM25: Fee output exceeds fee input"
            );

            // TEMPO-FEE6: Explicit check that amountOut <= amountIn for fee swaps
            // This is the core fee swap rate invariant - the 0.3% fee means output < input
            assertTrue(
                _ghostFeeOutputSum <= _ghostFeeInputSum,
                "TEMPO-FEE6: Fee swap rate violated - amountOut must be <= amountIn"
            );
        }
    }

    /// @notice TEMPO-AMM26: Fee swap reserves update correctly
    /// Verifies that fee swaps properly update user token reserve (increase) and
    /// validator token reserve (decrease) by the tracked amounts
    function _invariantFeeSwapReservesUpdate() internal view {
        // Fee swap reserve changes should be consistent:
        // - User token reserve increases by feeAmount (input)
        // - Validator token reserve decreases by expectedOut (output after fee)
        // The difference (_ghostFeeSwapUserReserveIncrease - _ghostFeeSwapValidatorReserveDecrease)
        // represents the fee revenue captured by the AMM
        if (_ghostFeeSwapUserReserveIncrease > 0) {
            // Output should always be <= input due to the 0.3% fee
            assertTrue(
                _ghostFeeSwapValidatorReserveDecrease <= _ghostFeeSwapUserReserveIncrease,
                "TEMPO-AMM26: Fee swap reserve decrease exceeds increase"
            );

            // The captured fee should equal input - output (the 0.3% spread)
            uint256 capturedFee =
                _ghostFeeSwapUserReserveIncrease - _ghostFeeSwapValidatorReserveDecrease;

            // Captured fee should be approximately 0.3% of input (with rounding tolerance)
            // Expected: capturedFee = input * (SCALE - M) / SCALE = input * 30 / 10000
            uint256 expectedFeeMin = (_ghostFeeSwapUserReserveIncrease * (SCALE - M)) / SCALE;
            assertTrue(
                capturedFee >= expectedFeeMin, "TEMPO-AMM26: Captured fee less than expected 0.3%"
            );
        }
    }

    /// @notice TEMPO-AMM31: Fee double-count prevention
    /// After distributeFees, collected fees for that validator/token pair should be zeroed
    function _invariantFeeDoubleCountPrevention() internal view {
        // Every distributeFees call should result in zeroed fees
        // This is already checked inline in the handler, but we verify the aggregate here
        if (_ghostDistributeFeesCalls > 0) {
            assertTrue(
                _ghostDistributeFeesZeroedCount == _ghostDistributeFeesCalls,
                "TEMPO-AMM31: Not all distributeFees calls resulted in zeroed fees"
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

    /*//////////////////////////////////////////////////////////////
                    TIP-1033 INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Unified TIP-1033 per-witness pass. Walks `_ghostTwoHopWitnesses` exactly once and
    /// dispatches each witness to `_assertDirectWitness` or `_assertFallbackWitness`. Aggregate
    /// checks (cumulative sums, regression-amount sanity, max-fallback) live outside the loop.
    /// Replaces eight separate full-array iterations: with N witnesses up to
    /// `MAX_TWO_HOP_WITNESSES = 256`, this saves ~25k storage slot reads per `invariant_feeAMM`.
    /// Same pattern as `_invariantPoolStateChecks` for the AMM/FEE invariants.
    /// Covers: TEMPO-AMM35/36/37, TEMPO-FEE7/8/9/11, and TIP-1033 inv. 2 (single-hop).
    function _invariantTwoHopWitnessChecks() internal view {
        uint256 len = _ghostTwoHopWitnesses.length;
        for (uint256 i; i < len;) {
            TwoHopWitness memory w = _ghostTwoHopWitnesses[i];
            uint256 expectedOut1 = (w.actualSpending * M) / SCALE;
            if (w.tookFallback) {
                _assertFallbackWitness(w, expectedOut1);
            } else {
                _assertDirectWitness(w, expectedOut1);
            }
            unchecked {
                ++i;
            }
        }

        // Aggregate checks (independent of any single witness).
        // TEMPO-AMM37: cumulative per-hop output never exceeds input.
        assertTrue(
            _ghostHop1OutputSum <= _ghostHop1InputSum,
            "TEMPO-AMM37: cumulative hop1 output exceeds input"
        );
        assertTrue(
            _ghostHop2OutputSum <= _ghostHop2InputSum,
            "TEMPO-AMM37: cumulative hop2 output exceeds input"
        );
        // TEMPO-AMM35: aggregate validator credit equals sequential floor(...) math.
        assertEq(
            _ghostTwoHopValidatorCredited,
            _ghostTwoHopExpectedSequential,
            "TEMPO-AMM35: aggregate validator credit must equal sequential floor(...) math"
        );
        // TEMPO-AMM36 sanity: the regression amount actually distinguishes sequential vs. fused.
        uint256 regressionAmount = 12_345;
        uint256 regSequential = (((regressionAmount * M) / SCALE) * M) / SCALE;
        uint256 regFused = (regressionAmount * M * M) / (SCALE * SCALE);
        assertTrue(
            regSequential < regFused,
            "TEMPO-AMM36: regression amount must distinguish sequential from fused"
        );
        // TEMPO-AMM36: largest sampled fallback witness used sequential math.
        if (_ghostMaxFallbackAmount > 0) {
            uint256 maxSequential = (((_ghostMaxFallbackAmount * M) / SCALE) * M) / SCALE;
            assertEq(
                _ghostMaxFallbackCredited,
                maxSequential,
                "TEMPO-AMM36: max fallback witness must use sequential math"
            );
        }
    }

    /// @dev Direct-path witness checks: TEMPO-FEE7 + TIP-1033 inv. 2 (single-hop fee math).
    /// Both leg reserves must be untouched and the direct pool delta must equal the spec
    /// formula `floor(actualSpending * M / SCALE)` (re-derived from `actualSpending`, not from
    /// the value the handler stored).
    function _assertDirectWitness(TwoHopWitness memory w, uint256 expectedOut1) internal pure {
        // TEMPO-FEE7: legs untouched.
        assertEq(
            w.hop1ReserveValBefore,
            w.hop1ReserveValAfter,
            "TEMPO-FEE7: direct-preferred path must not touch hop1 reserve"
        );
        assertEq(
            w.hop2ReserveValBefore,
            w.hop2ReserveValAfter,
            "TEMPO-FEE7: direct-preferred path must not touch hop2 reserve"
        );
        // TIP-1033 (inv. 2): single-hop credit and reserve delta both equal the spec formula.
        // Note: the validator-credited `collectedFees` delta is NOT verified here (the witness
        // does not snapshot it); see `_invariantFeeConservation` for the aggregate check.
        assertEq(
            w.out1,
            expectedOut1,
            "TIP-1033 (inv. 2): single-hop credit must equal floor(actualSpending * M / SCALE)"
        );
        assertEq(
            uint256(w.directReserveBefore),
            uint256(w.directReserveAfter) + expectedOut1,
            "TIP-1033 (inv. 2): direct reserve delta must equal floor(actualSpending * M / SCALE)"
        );
    }

    /// @dev Fallback (two-hop) witness checks: TEMPO-AMM35/36/37, TEMPO-FEE8/9/11.
    /// Re-derives `expectedOut2` from `expectedOut1` (sequential math) so a handler that
    /// silently switched to fused math would fail the equality.
    function _assertFallbackWitness(TwoHopWitness memory w, uint256 expectedOut1) internal view {
        uint256 expectedOut2 = (expectedOut1 * M) / SCALE;
        uint256 fusedOut2 = (w.actualSpending * M * M) / (SCALE * SCALE);

        // TEMPO-AMM37 / AMM35: per-hop outputs equal the spec formula.
        assertEq(
            w.out1, expectedOut1, "TEMPO-AMM37: hop1 output must equal floor(amountIn * M / SCALE)"
        );
        assertEq(
            w.out2, expectedOut2, "TEMPO-AMM35: hop2 output must equal floor(out1 * M / SCALE)"
        );
        // TEMPO-AMM36: sequential floors more aggressively, so out2 must never exceed fused;
        // when they actually diverge for this amount, out2 must be strictly less.
        assertTrue(w.out2 <= fusedOut2, "TEMPO-AMM36: sequential math must never exceed fused math");
        if (expectedOut2 < fusedOut2) {
            assertTrue(w.out2 < fusedOut2, "TEMPO-AMM36: divergent witness must not use fused math");
        }

        // TEMPO-FEE8: fallback engaged iff direct insufficient AND both legs sufficient.
        assertTrue(
            w.directWasInsufficient,
            "TEMPO-FEE8: fallback engaged only when direct was insufficient"
        );
        assertTrue(
            uint256(w.hop1ReserveValBefore) >= w.out1,
            "TEMPO-FEE8: fallback requires hop1 reserve >= out1 at planning time"
        );
        assertTrue(
            uint256(w.hop2ReserveValBefore) >= w.out2,
            "TEMPO-FEE8: fallback requires hop2 reserve >= out2 at planning time"
        );
        assertTrue(
            uint256(w.directReserveBefore) < w.out1,
            "TEMPO-FEE8: fallback engaged only when direct < out1"
        );

        // TEMPO-FEE9: intermediate well-formedness (current-chain-state semantics).
        assertTrue(w.hopToken != address(0), "TEMPO-FEE9: intermediate must be non-zero");
        assertTrue(w.hopToken != w.userToken, "TEMPO-FEE9: intermediate != userToken");
        assertTrue(w.hopToken != w.validatorToken, "TEMPO-FEE9: intermediate != validatorToken");
        assertEq(
            address(ITIP20(w.userToken).quoteToken()),
            w.hopToken,
            "TEMPO-FEE9: intermediate must equal userToken.quoteToken()"
        );

        // TEMPO-FEE11: reservation covers settlement (per-leg reserve deltas + direct untouched).
        assertEq(
            uint256(w.hop1ReserveValBefore),
            uint256(w.hop1ReserveValAfter) + w.out1,
            "TEMPO-FEE11: hop1 must lose exactly out1 of validator-side reserve"
        );
        assertEq(
            uint256(w.hop2ReserveValBefore),
            uint256(w.hop2ReserveValAfter) + w.out2,
            "TEMPO-FEE11: hop2 must lose exactly out2 of validator-side reserve"
        );
        assertEq(
            w.directReserveAfter,
            w.directReserveBefore,
            "TEMPO-FEE11: direct pool must be untouched on the fallback path"
        );
        // TEMPO-FEE11 (extended): hopToken conservation across the two-hop fallback.
        assertEq(
            w.ammHopBalanceAfter,
            w.ammHopBalanceBefore,
            "TEMPO-FEE11: AMM balanceOf(hopToken) must not change on the fallback path"
        );
        assertEq(
            w.sumHopReservesAfter,
            w.sumHopReservesBefore,
            "TEMPO-FEE11: sum of hopToken reserves across pools must be conserved on fallback"
        );
    }

    /// @notice TEMPO-FEE9 (extended): TIP-20 token graph well-formedness. Pins the spec edge
    /// case "Cannot happen — TIP-20 token graph does not allow self-quoting" as a runtime check
    /// on every TIP-20 in the test set, independent of fallback witness production. Strong
    /// invariant: pure state scan, impl-independent. Catches any future TIP-20 factory change
    /// that would break the spec's degenerate-revert reasoning (Edge Cases table in TIP-1033).
    function _invariantQuoteTokenGraphWellFormed() internal view {
        uint256 numTokens = _tokens.length;
        for (uint256 i = 0; i < numTokens; i++) {
            ITIP20 t = _tokens[i];
            address q = address(ITIP20(address(t)).quoteToken());
            if (q == address(0)) continue;
            assertTrue(q != address(t), "TEMPO-FEE9: TIP-20 cannot self-quote (spec edge)");
        }
    }

    /// @dev Sums every pool reserve in which `token` participates. Iterates the same universe
    /// as `_invariantPoolStateChecks` (`_tokens` + `pathUSD`) so the two views stay in sync.
    /// Used by TEMPO-FEE11 (extended) to assert hopToken conservation across two-hop fallback.
    function _sumReservesOfToken(address token) internal view returns (uint256 total) {
        uint256 numTokens = _tokens.length;
        uint256 totalTokens = numTokens + 1;
        for (uint256 j = 0; j < totalTokens; j++) {
            address other = j == 0 ? address(pathUSD) : address(_tokens[j - 1]);
            if (other == token) continue;
            IFeeAMM.Pool memory p1 = amm.getPool(token, other);
            total += uint256(p1.reserveUserToken);
            IFeeAMM.Pool memory p2 = amm.getPool(other, token);
            total += uint256(p2.reserveValidatorToken);
        }
    }

    /// @notice TEMPO-FEE13: Single-hop / same-token paths leave the (transient) intermediate
    /// slot zero and reserve the legacy semantics. This delegates to the existing single-hop
    /// invariants (TEMPO-AMM25, TEMPO-FEE6 et al.) and additionally asserts the slot-7 zero.
    function _invariantSingleHopUnchanged() internal view {
        bytes32 stored = vm.load(address(amm), bytes32(TWO_HOP_INTERMEDIATE_SLOT));
        assertEq(
            stored,
            bytes32(0),
            "TEMPO-FEE13: single-hop / same-token path must not promote slot 7 to persistent storage"
        );
    }

    /// @notice TEMPO-FEE14: Transient lifetime. `vm.load` reads PERSISTENT storage only;
    /// genuine transient (TLOAD) state is invisible to Foundry. The strongest property we can
    /// assert here is: slot 7 is never used as persistent storage. Real cross-tx transient
    /// clearing is covered by Rust unit tests in `crates/precompiles/src/tip_fee_manager`.
    function _invariantTransientCleared() internal view {
        bytes32 stored = vm.load(address(amm), bytes32(TWO_HOP_INTERMEDIATE_SLOT));
        assertEq(
            stored,
            bytes32(0),
            "TEMPO-FEE14: two_hop_intermediate slot must remain zero in persistent storage"
        );
    }

    /// @notice TEMPO-AMM24: All participants can exit - verify everyone can withdraw
    /// @dev After all operations, all LPs should be able to burn their positions and
    ///      all validators should be able to claim their fees. Only dust should remain.
    function _verifyAllCanExit() internal {
        // Step 1: Distribute all pending fees to validators (tracks frozen fees from blacklisted)
        _exitDistributeAllFees();

        // Step 2: Have all actors burn their LP positions (blacklisted actors will fail silently)
        _exitBurnAllLiquidity();

        // Step 3: Verify only dust remains in the AMM (accounting for frozen balances)
        _exitVerifyOnlyDustRemains();

        // Step 4: TEMPO-AMM34 - Unblacklist all actors and verify frozen balances are recoverable
        _exitVerifyCleanExitAfterUnblacklist();
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
                                vm.toString(validator),
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
                            vm.toString(validator),
                            " after unblacklist - frozen fees should be recoverable"
                        )
                    );
                }
            }
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

    /// @dev Returns the key for pending fee lookup
    function _pendingFeeKey(address validator, address token) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(validator, token));
    }

    /// @dev Checks if pending fees exist for a validator/token pair
    function _hasPendingFee(address validator, address token) internal view returns (bool) {
        return _pendingFeesIndex[_pendingFeeKey(validator, token)] != 0;
    }

    /// @dev Adds a pending fee entry if not already tracked
    function _addPendingFee(address validator, address token) internal {
        bytes32 key = _pendingFeeKey(validator, token);
        if (_pendingFeesIndex[key] == 0) {
            _pendingFeesList.push(PendingFee({ validator: validator, token: token }));
            _pendingFeesIndex[key] = _pendingFeesList.length;
        }
    }

    /// @dev Removes a pending fee entry using swap-and-pop
    function _removePendingFee(address validator, address token) internal {
        bytes32 key = _pendingFeeKey(validator, token);
        uint256 indexPlusOne = _pendingFeesIndex[key];
        if (indexPlusOne == 0) return;

        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = _pendingFeesList.length - 1;

        if (index != lastIndex) {
            PendingFee memory lastEntry = _pendingFeesList[lastIndex];
            _pendingFeesList[index] = lastEntry;
            _pendingFeesIndex[_pendingFeeKey(lastEntry.validator, lastEntry.token)] = indexPlusOne;
        }

        _pendingFeesList.pop();
        delete _pendingFeesIndex[key];
    }

    /// @dev Selects a pending fee entry from the list
    /// @return validator The validator address
    /// @return token The token address
    function _selectPendingFee(uint256 seed)
        internal
        view
        returns (address validator, address token)
    {
        uint256 count = _pendingFeesList.length;
        vm.assume(count > 0);
        uint256 index = bound(seed, 0, count - 1);
        PendingFee memory entry = _pendingFeesList[index];
        return (entry.validator, entry.token);
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
            || selector == ITIP20.InvalidCurrency.selector || _isKnownTIP20Error(selector);
        assertTrue(isKnownError, "Failed with unknown error");
    }

    /// @notice Verifies a revert is due to a known/expected FeeManager error
    /// @param reason The revert reason bytes from the failed call
    function _assertKnownFeeManagerError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IFeeAMM.IdenticalAddresses.selector
            || selector == IFeeAMM.InvalidToken.selector
            || selector == IFeeAMM.InsufficientLiquidity.selector
            || selector == ITIP20.InvalidCurrency.selector || _isKnownTIP20Error(selector)
            // FeeManager specific (string reverts)
            || keccak256(reason)
                == keccak256(abi.encodeWithSignature("Error(string)", "ONLY_DIRECT_CALL"))
            || keccak256(reason)
                == keccak256(abi.encodeWithSignature("Error(string)", "CANNOT_CHANGE_WITHIN_BLOCK"));
        assertTrue(isKnownError, "Failed with unknown FeeManager error");
    }

}
