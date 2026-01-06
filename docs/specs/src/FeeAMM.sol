// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20Factory } from "./TIP20Factory.sol";
import { TempoUtilities } from "./TempoUtilities.sol";
import { IERC20 } from "./interfaces/IERC20.sol";
import { IFeeAMM } from "./interfaces/IFeeAMM.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract FeeAMM is IFeeAMM {

    uint256 public constant M = 9970; // m = 0.9970 (scaled by 10000)
    uint256 public constant N = 9985;
    uint256 public constant SCALE = 10_000;
    uint256 public constant MIN_LIQUIDITY = 1000;

    TIP20Factory internal constant TIP20_FACTORY =
        TIP20Factory(0x20Fc000000000000000000000000000000000000);

    mapping(bytes32 => Pool) public pools;
    mapping(bytes32 => uint256) public totalSupply;
    mapping(bytes32 => mapping(address => uint256)) public liquidityBalances;

    function _requireUSDTIP20(address token) internal view {
        // Check that the token is a deployed TIP20 (prefix + tokenIdCounter check)
        if (!TempoUtilities.isTIP20(token)) revert InvalidToken();
        if (keccak256(bytes(ITIP20(token).currency())) != keccak256(bytes("USD"))) {
            revert InvalidCurrency();
        }
    }

    function getPoolId(address userToken, address validatorToken) public pure returns (bytes32) {
        // Each ordered pair has its own pool (userToken→validatorToken is different from validatorToken→userToken)
        return keccak256(abi.encode(userToken, validatorToken));
    }

    function getPool(address userToken, address validatorToken)
        external
        view
        returns (Pool memory)
    {
        bytes32 poolId = getPoolId(userToken, validatorToken);
        return pools[poolId];
    }

    function checkSufficientLiquidity(address userToken, address validatorToken, uint256 maxAmount)
        internal
        view
    {
        bytes32 poolId = getPoolId(userToken, validatorToken);
        uint256 amountOutNeeded = (maxAmount * M) / SCALE;
        require(
            pools[poolId].reserveValidatorToken >= amountOutNeeded,
            "INSUFFICIENT_LIQUIDITY_FOR_FEE_SWAP"
        );
    }

    function executeFeeSwap(address userToken, address validatorToken, uint256 amountIn)
        internal
        returns (uint256 amountOut)
    {
        bytes32 poolId = getPoolId(userToken, validatorToken);
        Pool storage pool = pools[poolId];

        amountOut = (amountIn * M) / SCALE;

        require(pool.reserveValidatorToken >= amountOut, "INSUFFICIENT_LIQUIDITY_FOR_FEE_SWAP");

        pool.reserveUserToken += uint128(amountIn);
        pool.reserveValidatorToken -= uint128(amountOut);
    }

    function rebalanceSwap(address userToken, address validatorToken, uint256 amountOut, address to)
        external
        returns (uint256 amountIn)
    {
        bytes32 poolId = getPoolId(userToken, validatorToken);

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        // Round up
        amountIn = (amountOut * N) / SCALE + 1;

        Pool storage pool = pools[poolId];

        pool.reserveValidatorToken += uint128(amountIn);
        pool.reserveUserToken -= uint128(amountOut);

        // Transfer tokens
        ITIP20(validatorToken).systemTransferFrom(msg.sender, address(this), amountIn);
        IERC20(userToken).transfer(to, amountOut);

        emit RebalanceSwap(userToken, validatorToken, msg.sender, amountIn, amountOut);
    }

    /// Single-sided liquidity provision.
    function mint(
        address userToken,
        address validatorToken,
        uint256 amountValidatorToken,
        address to
    ) external returns (uint256 liquidity) {
        if (userToken == validatorToken) revert IdenticalAddresses();

        _requireUSDTIP20(userToken);
        _requireUSDTIP20(validatorToken);
        bytes32 poolId = getPoolId(userToken, validatorToken);

        Pool storage pool = pools[poolId];
        uint256 _totalSupply = totalSupply[poolId];

        if (pool.reserveUserToken == 0 && pool.reserveValidatorToken == 0) {
            // First liquidity provider with validator token only
            if (amountValidatorToken / 2 <= MIN_LIQUIDITY) {
                revert InsufficientLiquidity();
            }
            liquidity = amountValidatorToken / 2 - MIN_LIQUIDITY;
            totalSupply[poolId] += MIN_LIQUIDITY; // Permanently lock MIN_LIQUIDITY
        } else {
            // Subsequent deposits: mint as if user called rebalanceSwap then minted with both
            // which works out to the formula:
            // liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
            uint256 denom =
                uint256(pool.reserveValidatorToken) + (N * uint256(pool.reserveUserToken)) / SCALE;
            liquidity = (amountValidatorToken * _totalSupply) / denom; // rounds down
        }

        if (liquidity == 0) {
            revert InsufficientLiquidity();
        }

        // Transfer validator tokens from user
        ITIP20(validatorToken).systemTransferFrom(msg.sender, address(this), amountValidatorToken);

        // Update reserves (validator token only)
        pool.reserveValidatorToken += uint128(amountValidatorToken);

        // Mint LP tokens
        totalSupply[poolId] += liquidity;
        liquidityBalances[poolId][to] += liquidity;

        emit Mint(msg.sender, to, userToken, validatorToken, amountValidatorToken, liquidity);
    }

    function burn(address userToken, address validatorToken, uint256 liquidity, address to)
        external
        returns (uint256 amountUserToken, uint256 amountValidatorToken)
    {
        bytes32 poolId = getPoolId(userToken, validatorToken);

        Pool storage pool = pools[poolId];

        if (liquidityBalances[poolId][msg.sender] < liquidity) {
            revert InsufficientLiquidity();
        }

        // Calculate amounts
        (amountUserToken, amountValidatorToken) = _calculateBurnAmounts(pool, poolId, liquidity);

        // Burn LP tokens
        liquidityBalances[poolId][msg.sender] -= liquidity;
        totalSupply[poolId] -= liquidity;

        // Update reserves
        pool.reserveUserToken -= uint128(amountUserToken);
        pool.reserveValidatorToken -= uint128(amountValidatorToken);

        // Transfer tokens to user
        IERC20(userToken).transfer(to, amountUserToken);
        IERC20(validatorToken).transfer(to, amountValidatorToken);

        emit Burn(
            msg.sender,
            userToken,
            validatorToken,
            amountUserToken,
            amountValidatorToken,
            liquidity,
            to
        );
    }

    function _calculateBurnAmounts(Pool storage pool, bytes32 poolId, uint256 liquidity)
        private
        view
        returns (uint256 amountUserToken, uint256 amountValidatorToken)
    {
        uint256 _totalSupply = totalSupply[poolId];

        // Calculate pro-rata share of reserves
        amountUserToken = (liquidity * pool.reserveUserToken) / _totalSupply;
        amountValidatorToken = (liquidity * pool.reserveValidatorToken) / _totalSupply;
    }

    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

}
