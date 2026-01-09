// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { TIP20Factory } from "../../src/TIP20Factory.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";
import { console } from "forge-std/console.sol";

/// @title FeeAMMHandler
/// @notice Handler contract for FeeAMM invariant testing with multi-pool support
/// @dev Wraps FeeAMM operations with bounded inputs and tracks ghost state across multiple pools
contract FeeAMMHandler is CommonBase, StdCheats, StdUtils {

    FeeManager public amm;
    TIP20Factory public factory;
    address public admin;

    // Token universe for multi-pool testing
    TIP20[] public tokens;

    // Dynamic pool tracking
    bytes32[] public poolIds;
    mapping(bytes32 => bool) public seenPool;

    // Ghost variables for invariant tracking
    uint256 public ghost_totalMinted;
    uint256 public ghost_totalBurned;
    uint256 public ghost_rebalanceIn;
    uint256 public ghost_rebalanceOut;
    uint256 public ghost_feeSwapIn;
    uint256 public ghost_feeSwapOut;

    // Track LP balances per actor per pool
    mapping(bytes32 => mapping(address => uint256)) public ghost_lpBalances;
    address[] public actors;

    // Call counters for debugging
    uint256 public mintCalls;
    uint256 public burnCalls;
    uint256 public rebalanceCalls;
    uint256 public feeSwapCalls;

    constructor(
        FeeManager _amm,
        TIP20Factory _factory,
        TIP20[] memory _tokens,
        address[] memory _actors,
        address _admin
    ) {
        amm = _amm;
        factory = _factory;
        admin = _admin;

        // Copy tokens array
        for (uint256 i = 0; i < _tokens.length; i++) {
            tokens.push(_tokens[i]);
        }

        // Copy actors array
        for (uint256 i = 0; i < _actors.length; i++) {
            actors.push(_actors[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                               ACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bounded mint operation across any token pair
    /// @param seedA Seed to select first token
    /// @param seedB Seed to select second token
    /// @param actorSeed Seed to select actor
    /// @param amount Amount of validatorToken to deposit (will be bounded)
    function mint(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 amount) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        // Bound amount to reasonable range, let InsufficientLiquidity revert naturally for small amounts
        amount = bound(amount, 1, 10_000_000e6);

        // Mint tokens to actor (handler has ISSUER_ROLE)
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
            _assertExpectedMintRevert(err);
        }
        vm.stopPrank();
    }

    /// @notice Bounded burn operation
    /// @param seedA Seed to select first token
    /// @param seedB Seed to select second token
    /// @param actorSeed Seed to select actor
    /// @param pct Percentage of balance to burn (1-100)
    function burn(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 pct) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        bytes32 pid = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 balance = amm.liquidityBalances(pid, actor);
        if (balance == 0) return;

        // Burn 1-100% of balance
        pct = bound(pct, 1, 100);
        uint256 amount = (balance * pct) / 100;
        if (amount == 0) return;

        vm.startPrank(actor);
        try amm.burn(address(userToken), address(validatorToken), amount, actor) returns (
            uint256,
            uint256
        ) {
            _rememberPool(address(userToken), address(validatorToken));
            ghost_totalBurned += amount;
            ghost_lpBalances[pid][actor] -= amount;
            burnCalls++;
        } catch (bytes memory err) {
            _assertExpectedBurnRevert(err);
        }
        vm.stopPrank();
    }

    /// @notice Bounded rebalance swap operation with step invariant verification
    /// @param seedA Seed to select first token
    /// @param seedB Seed to select second token
    /// @param actorSeed Seed to select actor
    /// @param rawOut Amount of userToken to receive (will be bounded)
    function rebalanceSwap(uint256 seedA, uint256 seedB, uint256 actorSeed, uint256 rawOut) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);
        address actor = _actor(actorSeed);

        // Snapshot state for step checks
        IFeeAMM.Pool memory beforeP = amm.getPool(address(userToken), address(validatorToken));

        // If no user-token liquidity exists, skip
        uint256 maxOut = uint256(beforeP.reserveUserToken);
        if (maxOut == 0) return;

        // Force amountOut to be strictly positive to avoid zero-amount edge case
        uint256 amountOut = bound(rawOut, 1, maxOut);

        // Expected amountIn = floor(amountOut * N / SCALE) + 1
        uint256 expectedIn = (amountOut * 9985) / 10_000 + 1;

        // Mint tokens to actor
        validatorToken.mint(actor, expectedIn);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), expectedIn);

        try amm.rebalanceSwap(address(userToken), address(validatorToken), amountOut, actor)
        returns (uint256 amountIn) {
            _rememberPool(address(userToken), address(validatorToken));

            // Step invariant: returned amountIn matches formula
            require(amountIn == expectedIn, "rebalanceSwap amountIn mismatch");

            // Step invariant: reserves update exactly
            IFeeAMM.Pool memory afterP = amm.getPool(address(userToken), address(validatorToken));
            require(
                uint256(afterP.reserveValidatorToken) == uint256(beforeP.reserveValidatorToken) + amountIn,
                "reserveValidatorToken delta mismatch"
            );
            require(
                uint256(afterP.reserveUserToken) == uint256(beforeP.reserveUserToken) - amountOut,
                "reserveUserToken delta mismatch"
            );

            ghost_rebalanceIn += amountIn;
            ghost_rebalanceOut += amountOut;
            rebalanceCalls++;
        } catch (bytes memory err) {
            _assertExpectedSwapRevert(err);
        }
        vm.stopPrank();
    }

    /// @notice Simulate fee swap operation
    /// @dev Fee swaps are internal and only called by protocol, so we simulate the math
    /// @param seedA Seed to select first token
    /// @param seedB Seed to select second token
    /// @param amountIn Amount of userToken to swap
    function simulateFeeSwap(uint256 seedA, uint256 seedB, uint256 amountIn) external {
        (TIP20 userToken, TIP20 validatorToken) = _pair(seedA, seedB);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Bound amount to ensure we have liquidity
        amountIn = bound(amountIn, 1, 1_000_000e6);

        // Calculate expected output
        uint256 amountOut = (amountIn * 9970) / 10_000;

        // Skip if insufficient liquidity
        if (pool.reserveValidatorToken < amountOut) return;

        // Track the simulated swap (we can't actually call executeFeeSwap as it's internal)
        ghost_feeSwapIn += amountIn;
        ghost_feeSwapOut += amountOut;
        feeSwapCalls++;
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Get an actor address from a seed
    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    /// @dev Get a token from a seed
    function _token(uint256 seed) internal view returns (TIP20) {
        return tokens[seed % tokens.length];
    }

    /// @dev Get a unique ordered token pair from two seeds
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

    /// @dev Remember a poolId for later invariant checks
    function _rememberPool(address userToken, address validatorToken) internal returns (bytes32 pid) {
        if (userToken == validatorToken) return bytes32(0);
        pid = amm.getPoolId(userToken, validatorToken);
        if (!seenPool[pid]) {
            seenPool[pid] = true;
            poolIds.push(pid);
        }
    }

    /// @dev Extract the selector from a revert error bytes blob
    function _sel(bytes memory err) internal pure returns (bytes4) {
        if (err.length < 4) return bytes4(0);
        return bytes4(err);
    }

    function _assertExpectedMintRevert(bytes memory err) internal pure {
        bytes4 s = _sel(err);
        bool ok = s == IFeeAMM.InsufficientLiquidity.selector
            || s == IFeeAMM.InvalidToken.selector
            || s == IFeeAMM.InvalidCurrency.selector
            || s == IFeeAMM.IdenticalAddresses.selector
            || s == IFeeAMM.InvalidAmount.selector;

        if (!ok) _dumpUnexpected(err, s, "mint");
    }

    function _assertExpectedBurnRevert(bytes memory err) internal pure {
        bytes4 s = _sel(err);
        bool ok = s == IFeeAMM.InsufficientLiquidity.selector
            || s == IFeeAMM.InvalidToken.selector
            || s == IFeeAMM.InvalidCurrency.selector
            || s == IFeeAMM.IdenticalAddresses.selector
            || s == IFeeAMM.InvalidAmount.selector;

        if (!ok) _dumpUnexpected(err, s, "burn");
    }

    function _assertExpectedSwapRevert(bytes memory err) internal pure {
        bytes4 s = _sel(err);
        bool ok = s == IFeeAMM.InsufficientLiquidity.selector
            || s == IFeeAMM.InsufficientReserves.selector
            || s == IFeeAMM.InvalidToken.selector
            || s == IFeeAMM.InvalidCurrency.selector
            || s == IFeeAMM.IdenticalAddresses.selector
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

    /// @notice Helper to get sum of all LP balances for a specific pool
    function sumLPBalances(bytes32 pid) external view returns (uint256 total) {
        for (uint256 i = 0; i < actors.length; i++) {
            total += ghost_lpBalances[pid][actors[i]];
        }
    }

    /// @notice Get number of actors
    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    /// @notice Get actor by index
    function getActor(uint256 index) external view returns (address) {
        return actors[index];
    }

    /// @notice Get number of tokens
    function tokenCount() external view returns (uint256) {
        return tokens.length;
    }

    /// @notice Get token by index
    function getToken(uint256 index) external view returns (TIP20) {
        return tokens[index];
    }

    /// @notice Get number of tracked pools
    function poolCount() external view returns (uint256) {
        return poolIds.length;
    }

    /// @notice Get poolId by index
    function getPoolId(uint256 index) external view returns (bytes32) {
        return poolIds[index];
    }

    /// @notice Get LP balance for actor in pool
    function getLPBalance(bytes32 pid, address actor) external view returns (uint256) {
        return ghost_lpBalances[pid][actor];
    }

}
