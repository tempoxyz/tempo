// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {FeeAMM} from "./FeeAMM.sol";
import {TIP20Factory} from "./TIP20Factory.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {IFeeManager} from "./interfaces/IFeeManager.sol";
import {ITIP20} from "./interfaces/ITIP20.sol";

contract FeeManager is IFeeManager, FeeAMM {
    address internal constant LINKING_USD =
        0x20C0000000000000000000000000000000000000;

    // Validator token preferences
    mapping(address => address) public validatorTokens;

    // User token preferences
    mapping(address => address) public userTokens;

    // Fee collection tracking
    uint256 private collectedFees;

    // Track tokens that have collected fees
    address[] private tokensWithFees;
    mapping(address => bool) private tokenInFeesArray;

    modifier onlyDirectCall() {
        // In the real implementation, the protocol does a check that this is the top frame,
        // which is no longer possible in the EVM due to 7702
        require(msg.sender == tx.origin, "ONLY_DIRECT_CALL");
        _;
    }

    // TODO: could just call this on the TIP20Factory contract
    function isTIP20(address token) internal pure returns (bool) {
        return bytes14(bytes20(token)) == 0x20c0000000000000000000000000;
    }

    function setValidatorToken(address token) external onlyDirectCall {
        // prevent changing within the validator's own block to avoid edge cases
        require(msg.sender != block.coinbase, "CANNOT_CHANGE_WITHIN_BLOCK");
        require(isTIP20(token), "INVALID_TOKEN");
        require(
            keccak256(bytes(ITIP20(token).currency())) ==
                keccak256(bytes("USD")),
            "INVALID_TOKEN"
        );
        validatorTokens[msg.sender] = token;
        emit ValidatorTokenSet(msg.sender, token);
    }

    function setUserToken(address token) external onlyDirectCall {
        require(isTIP20(token), "INVALID_TOKEN");
        // forbid setting linkingUSD as the user's fee token
        require(token != LINKING_USD, "CANNOT_SET_LINKINGUSD");
        require(
            keccak256(bytes(ITIP20(token).currency())) ==
                keccak256(bytes("USD")),
            "INVALID_TOKEN"
        );
        userTokens[msg.sender] = token;
        emit UserTokenSet(msg.sender, token);
    }

    // This function is called by the protocol before any transaction is executed.
    // If it reverts, the transaction is invalid
    function collectFeePreTx(
        address user,
        address txToAddress,
        uint256 maxAmount
    ) external returns (address userToken) {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Get validator's preferred token
        address validatorToken = validatorTokens[block.coinbase];
        require(validatorToken != address(0), "VALIDATOR_TOKEN_NOT_SET");

        // Get user's preferred token
        // Logic is: transaction > account > contract > validator
        // TODO: once transactions can set their preferred fee token, add this to the logic
        // TODO: special-case the logic for when txToAddress is this contract, as per the spec
        userToken = userTokens[user];
        if (userToken == address(0)) {
            if (isTIP20(txToAddress)) {
                userToken = txToAddress;
            } else {
                userToken = validatorToken;
            }
        }

        // If user token is different from validator token, verify pool exists and has liquidity
        if (userToken != validatorToken) {
            require(
                hasLiquidity(userToken, validatorToken, maxAmount),
                "INSUFFICIENT_LIQUIDITY_FOR_FEE_SWAP"
            );
        }

        ITIP20(userToken).systemTransferFrom(user, address(this), maxAmount);
    }

    // This function is called by the protocol after a transaction is executed.
    // It should never revert. If it does, there is a design flaw in the protocol.
    function collectFeePostTx(
        address user,
        uint256 maxAmount,
        uint256 actualUsed,
        address userToken,
        address validatorToken
    ) external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Calculate refund amount
        uint256 refundAmount = maxAmount - actualUsed;

        // Refund unused tokens to user
        if (refundAmount > 0) {
            IERC20(userToken).transfer(user, refundAmount);
        }

        feeSwap(userToken, validatorToken, actualUsed);

        // Track collected fees (only the actual used amount)
        if (actualUsed > 0) {
            if (userToken == validatorToken) {
                collectedFees += actualUsed;
            } else if (!tokenInFeesArray[userToken]) {
                tokensWithFees.push(userToken);
                tokenInFeesArray[userToken] = true;
            }
        }
    }

    // This function is called once in a special transaction required by the protocol at the end of each block.
    // It should never revert. If it does, there is a design flaw in the protocol.
    function executeBlock() external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Get current validator's preferred token
        address validatorToken = validatorTokens[block.coinbase];
        require(validatorToken != address(0), "VALIDATOR_TOKEN_NOT_SET");

        // Process all collected fees and execute pending swaps
        for (uint256 i = 0; i < tokensWithFees.length; i++) {
            address token = tokensWithFees[i];

            if (token != validatorToken) {
                // Check if pool exists
                FeeAMM.Pool memory pool = this.getPool(token, validatorToken);
                if (
                    pool.reserveUserToken > 0 || pool.reserveValidatorToken > 0
                ) {
                    // Execute pending swaps to update reserves and get output amount
                    collectedFees += executePendingFeeSwaps(
                        token,
                        validatorToken
                    );
                }
            }

            // Clear tracking for this token
            tokenInFeesArray[token] = false;
            delete tokensWithFees[i];
        }

        delete tokensWithFees;

        // Transfer all validator tokens to the validator
        if (collectedFees > 0) {
            IERC20(validatorToken).transfer(block.coinbase, collectedFees);
            collectedFees = 0;
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC20} from "./interfaces/IERC20.sol";
import {IFeeAMM} from "./interfaces/IFeeAMM.sol";
import {ITIP20} from "./interfaces/ITIP20.sol";

contract FeeAMM is IFeeAMM {
    uint256 public constant M = 9970; // m = 0.9970 (scaled by 10000)
    uint256 public constant N = 9985;
    uint256 public constant SCALE = 10_000;
    uint256 public constant MIN_LIQUIDITY = 1000;

    mapping(bytes32 => Pool) public pools;
    mapping(bytes32 => uint128) internal pendingFeeSwapIn; // Amount of userToken to be added from fee swaps
    mapping(bytes32 => uint256) public totalSupply; // Total LP tokens for each pool
    mapping(bytes32 => mapping(address => uint256)) public liquidityBalances; // LP token balances

    function _requireUSD(address token) private view {
        require(
            keccak256(bytes(ITIP20(token).currency())) ==
                keccak256(bytes("USD")),
            "ONLY_USD_TOKENS"
        );
    }

    function getPoolId(
        address userToken,
        address validatorToken
    ) public pure returns (bytes32) {
        // Each ordered pair has its own pool (userToken→validatorToken is different from validatorToken→userToken)
        return keccak256(abi.encodePacked(userToken, validatorToken));
    }

    function getPool(
        address userToken,
        address validatorToken
    ) external view returns (Pool memory) {
        bytes32 poolId = getPoolId(userToken, validatorToken);
        return pools[poolId];
    }

    function hasLiquidity(
        address userToken,
        address validatorToken,
        uint256 amountIn
    ) internal view returns (bool) {
        bytes32 poolId = getPoolId(userToken, validatorToken);

        // Calculate output at fixed price m = 0.9970
        uint256 amountOut = (amountIn * M) / SCALE;

        // Check if there's enough validatorToken available (accounting for pending swaps)
        uint256 availableValidatorToken = _getEffectiveValidatorReserve(poolId);
        return amountOut <= availableValidatorToken;
    }

    function feeSwap(
        address userToken,
        address validatorToken,
        uint256 amountIn
    ) internal returns (uint256 amountOut) {
        require(
            hasLiquidity(userToken, validatorToken, amountIn),
            "INSUFFICIENT_LIQUIDITY_FOR_FEE_SWAP"
        );

        bytes32 poolId = getPoolId(userToken, validatorToken);

        // Track pending swap input
        pendingFeeSwapIn[poolId] += uint128(amountIn);

        amountOut = (amountIn * M) / SCALE;
    }

    function rebalanceSwap(
        address userToken,
        address validatorToken,
        uint256 amountOut,
        address to
    ) external returns (uint256 amountIn) {
        bytes32 poolId = getPoolId(userToken, validatorToken);

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        // Round up
        amountIn = (amountOut * N) / SCALE + 1;

        Pool storage pool = pools[poolId];

        pool.reserveValidatorToken += uint128(amountIn);
        pool.reserveUserToken -= uint128(amountOut);

        // Transfer tokens
        ITIP20(validatorToken).systemTransferFrom(
            msg.sender,
            address(this),
            amountIn
        );
        IERC20(userToken).transfer(to, amountOut);

        emit RebalanceSwap(
            userToken,
            validatorToken,
            msg.sender,
            amountIn,
            amountOut
        );
    }

    function mint(
        address userToken,
        address validatorToken,
        uint256 amountUserToken,
        uint256 amountValidatorToken,
        address to
    ) external returns (uint256 liquidity) {
        _requireUSD(userToken);
        _requireUSD(validatorToken);
        bytes32 poolId = getPoolId(userToken, validatorToken);

        Pool storage pool = pools[poolId];
        uint256 _totalSupply = totalSupply[poolId];

        if (pool.reserveUserToken == 0 && pool.reserveValidatorToken == 0) {
            // First liquidity provider
            if ((amountUserToken + amountValidatorToken) / 2 <= MIN_LIQUIDITY) {
                revert InsufficientLiquidity();
            }
            liquidity =
                (amountUserToken + amountValidatorToken) /
                2 -
                MIN_LIQUIDITY;
            totalSupply[poolId] += MIN_LIQUIDITY; // Permanently lock MIN_LIQUIDITY
        } else {
            // Subsequent liquidity providers - must provide proportional amounts
            uint256 liquidityUser = pool.reserveUserToken > 0
                ? (amountUserToken * _totalSupply) / pool.reserveUserToken
                : type(uint256).max;
            uint256 liquidityValidator = pool.reserveValidatorToken > 0
                ? (amountValidatorToken * _totalSupply) /
                    pool.reserveValidatorToken
                : type(uint256).max;
            liquidity = liquidityUser < liquidityValidator
                ? liquidityUser
                : liquidityValidator;
        }

        if (liquidity == 0) {
            revert InsufficientLiquidity();
        }

        // Transfer tokens from user
        ITIP20(userToken).systemTransferFrom(
            msg.sender,
            address(this),
            amountUserToken
        );
        ITIP20(validatorToken).systemTransferFrom(
            msg.sender,
            address(this),
            amountValidatorToken
        );

        // Update reserves
        pool.reserveUserToken += uint128(amountUserToken);
        pool.reserveValidatorToken += uint128(amountValidatorToken);

        // Mint LP tokens
        totalSupply[poolId] += liquidity;
        liquidityBalances[poolId][to] += liquidity;

        emit Mint(
            msg.sender,
            userToken,
            validatorToken,
            amountUserToken,
            amountValidatorToken,
            liquidity
        );
    }

    function mintWithValidatorToken(
        address userToken,
        address validatorToken,
        uint256 amountValidatorToken,
        address to
    ) external returns (uint256 liquidity) {
        _requireUSD(userToken);
        _requireUSD(validatorToken);
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
            uint256 denom = uint256(pool.reserveValidatorToken) +
                (N * uint256(pool.reserveUserToken)) /
                SCALE;
            liquidity = (amountValidatorToken * _totalSupply) / denom; // rounds down
        }

        if (liquidity == 0) {
            revert InsufficientLiquidity();
        }

        // Transfer validator tokens from user
        ITIP20(validatorToken).systemTransferFrom(
            msg.sender,
            address(this),
            amountValidatorToken
        );

        // Update reserves (validator token only)
        pool.reserveValidatorToken += uint128(amountValidatorToken);

        // Mint LP tokens
        totalSupply[poolId] += liquidity;
        liquidityBalances[poolId][to] += liquidity;

        emit Mint(
            msg.sender,
            userToken,
            validatorToken,
            0,
            amountValidatorToken,
            liquidity
        );
    }

    function burn(
        address userToken,
        address validatorToken,
        uint256 liquidity,
        address to
    ) external returns (uint256 amountUserToken, uint256 amountValidatorToken) {
        bytes32 poolId = getPoolId(userToken, validatorToken);

        Pool storage pool = pools[poolId];

        require(
            liquidityBalances[poolId][msg.sender] >= liquidity,
            "INSUFFICIENT_LIQUIDITY"
        );

        // Calculate amounts
        (amountUserToken, amountValidatorToken) = _calculateBurnAmounts(
            pool,
            poolId,
            liquidity
        );

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

    function _calculateBurnAmounts(
        Pool storage pool,
        bytes32 poolId,
        uint256 liquidity
    )
        private
        view
        returns (uint256 amountUserToken, uint256 amountValidatorToken)
    {
        uint256 _totalSupply = totalSupply[poolId];

        // Calculate pro-rata share of reserves
        amountUserToken = (liquidity * pool.reserveUserToken) / _totalSupply;
        amountValidatorToken =
            (liquidity * pool.reserveValidatorToken) /
            _totalSupply;

        require(
            amountUserToken >= 0 && amountValidatorToken >= 0,
            "INSUFFICIENT_LIQUIDITY_BURNED"
        );

        // Check that withdrawal doesn't violate pending swaps
        // Don't need to check userToken since it only increases during the block
        uint256 availableValidatorToken = _getEffectiveValidatorReserve(poolId);

        require(
            amountValidatorToken <= availableValidatorToken,
            "WITHDRAWAL_EXCEEDS_AVAILABLE_VALIDATOR_TOKEN"
        );
    }

    function executePendingFeeSwaps(
        address userToken,
        address validatorToken
    ) internal returns (uint256 amountOut) {
        bytes32 poolId = getPoolId(userToken, validatorToken);
        Pool storage pool = pools[poolId];

        // Store the input amount to return
        uint256 amountIn = pendingFeeSwapIn[poolId];

        // Calculate output from input
        amountOut = (amountIn * M) / SCALE;

        // Apply pending fee swap to reserves
        // Add userToken input, subtract validatorToken output
        pool.reserveUserToken = uint128(
            uint256(pool.reserveUserToken) + amountIn
        );
        pool.reserveValidatorToken = uint128(
            uint256(pool.reserveValidatorToken) - amountOut
        );

        // Clear pending swap
        pendingFeeSwapIn[poolId] = 0;

        emit FeeSwap(userToken, validatorToken, amountIn, amountOut);
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

    // Helper functions for pending reserve calculations

    function _getEffectiveValidatorReserve(
        bytes32 poolId
    ) private view returns (uint256) {
        // Effective validatorToken reserve = current - pendingOut
        uint256 pendingOut = (pendingFeeSwapIn[poolId] * M) / SCALE;
        return uint256(pools[poolId].reserveValidatorToken) - pendingOut;
    }
}
