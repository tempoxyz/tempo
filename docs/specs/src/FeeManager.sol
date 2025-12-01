// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "./FeeAMM.sol";
import { TIP20Factory } from "./TIP20Factory.sol";
import { IERC20 } from "./interfaces/IERC20.sol";
import { IFeeManager } from "./interfaces/IFeeManager.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract FeeManager is IFeeManager, FeeAMM {

    address internal constant LINKING_USD = 0x20C0000000000000000000000000000000000000;

    // Validator token preferences
    mapping(address => address) public validatorTokens;

    // User token preferences
    mapping(address => address) public userTokens;

    // Fee collection tracking per validator (amount in validator's preferred token)
    mapping(address => uint256) private collectedFeesByValidator;

    // Track validators that have collected fees
    address[] private validatorsWithFees;
    mapping(address => bool) private validatorInFeesArray;

    // Track pools that have pending swaps (for reserve updates)
    // We track token pairs since we need both tokens to execute swaps
    struct TokenPair {
        address userToken;
        address validatorToken;
    }
    TokenPair[] private poolsWithFees;
    mapping(bytes32 => bool) private poolInFeesArray;

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
        // prevent changing if validator already has collected fees in this block
        require(collectedFeesByValidator[msg.sender] == 0, "CANNOT_CHANGE_WITH_PENDING_FEES");
        require(isTIP20(token), "INVALID_TOKEN");
        require(
            keccak256(bytes(ITIP20(token).currency())) == keccak256(bytes("USD")), "INVALID_TOKEN"
        );
        validatorTokens[msg.sender] = token;
        emit ValidatorTokenSet(msg.sender, token);
    }

    function setUserToken(address token) external onlyDirectCall {
        require(isTIP20(token), "INVALID_TOKEN");
        // forbid setting linkingUSD as the user's fee token
        require(token != LINKING_USD, "CANNOT_SET_LINKINGUSD");
        require(
            keccak256(bytes(ITIP20(token).currency())) == keccak256(bytes("USD")), "INVALID_TOKEN"
        );
        userTokens[msg.sender] = token;
        emit UserTokenSet(msg.sender, token);
    }

    // This function is called by the protocol before any transaction is executed.
    // If it reverts, the transaction is invalid
    function collectFeePreTx(
        address user,
        address txToAddress,
        uint256 maxAmount,
        address feeRecipient
    ) external returns (address userToken) {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Get fee recipient's preferred token (fallback to linkingUSD if not set)
        address validatorToken = validatorTokens[feeRecipient];
        if (validatorToken == address(0)) {
            validatorToken = LINKING_USD;
        }

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

        // If user token is different from validator token, reserve AMM liquidity
        if (userToken != validatorToken) {
            reserveLiquidity(userToken, validatorToken, maxAmount);
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
        address validatorToken,
        address feeRecipient
    ) external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Calculate refund amount
        uint256 refundAmount = maxAmount - actualUsed;

        // Refund unused tokens to user
        if (refundAmount > 0) {
            IERC20(userToken).transfer(user, refundAmount);
        }

        releaseLiquidityPostTx(userToken, validatorToken, refundAmount);

        // Track collected fees (only the actual used amount)
        if (actualUsed > 0) {
            // Track validator for fee distribution
            if (!validatorInFeesArray[feeRecipient]) {
                validatorsWithFees.push(feeRecipient);
                validatorInFeesArray[feeRecipient] = true;
            }

            if (userToken == validatorToken) {
                // Direct fee in validator's preferred token
                collectedFeesByValidator[feeRecipient] += actualUsed;
            } else {
                // Compute expected output immediately (simplified approach)
                uint256 expectedOut = (actualUsed * M) / SCALE;
                collectedFeesByValidator[feeRecipient] += expectedOut;

                // Track pool for swap execution (to update reserves)
                bytes32 poolId = getPoolId(userToken, validatorToken);
                if (!poolInFeesArray[poolId]) {
                    poolsWithFees.push(TokenPair(userToken, validatorToken));
                    poolInFeesArray[poolId] = true;
                }
            }
        }
    }

    // This function is called once in a special transaction required by the protocol at the end of each block.
    // It should never revert. If it does, there is a design flaw in the protocol.
    function executeBlock() external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Execute pending swaps for all pools (to update reserves)
        // Note: We execute swaps per pool, not per validator, since pools are shared
        for (uint256 i = 0; i < poolsWithFees.length; i++) {
            TokenPair memory pair = poolsWithFees[i];
            
            // Check if pool exists and has pending swaps
            FeeAMM.Pool memory pool = this.getPool(pair.userToken, pair.validatorToken);
            bytes32 poolId = getPoolId(pair.userToken, pair.validatorToken);
            
            // Execute swap if there are pending swaps (updates reserves)
            // Note: We don't use the return value since we've already computed expectedOut
            if (pendingFeeSwapIn[poolId] > 0) {
                executePendingFeeSwaps(pair.userToken, pair.validatorToken);
            }

            // Clear tracking
            poolInFeesArray[poolId] = false;
        }
        delete poolsWithFees;

        // Distribute fees to all validators
        for (uint256 i = 0; i < validatorsWithFees.length; i++) {
            address validator = validatorsWithFees[i];
            uint256 amount = collectedFeesByValidator[validator];
            
            if (amount > 0) {
                address validatorToken = validatorTokens[validator];
                // Fallback to linkingUSD if validator hasn't set one
                if (validatorToken == address(0)) {
                    validatorToken = LINKING_USD;
                }
                
                IERC20(validatorToken).transfer(validator, amount);
                collectedFeesByValidator[validator] = 0;
            }

            // Clear tracking
            validatorInFeesArray[validator] = false;
        }
        delete validatorsWithFees;
    }

}
