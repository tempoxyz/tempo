// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "./FeeAMM.sol";
import { TIP20Factory } from "./TIP20Factory.sol";
import { IERC20 } from "./interfaces/IERC20.sol";
import { IFeeManager } from "./interfaces/IFeeManager.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract FeeManager is IFeeManager, FeeAMM {

    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;

    // Validator token preferences
    mapping(address => address) public validatorTokens;

    // User token preferences
    mapping(address => address) public userTokens;

    // Fee collection tracking per validator (amount in validator's preferred token)
    mapping(address => uint256) public collectedFeesByValidator;

    modifier onlyDirectCall() {
        // In the real implementation, the protocol does a check that this is the top frame,
        // which is no longer possible in the EVM due to 7702
        require(msg.sender == tx.origin, "ONLY_DIRECT_CALL");
        _;
    }

    function setValidatorToken(address token) external onlyDirectCall {
        // prevent changing within the validator's own block to avoid edge cases
        require(msg.sender != block.coinbase, "CANNOT_CHANGE_WITHIN_BLOCK");
        // prevent changing if validator has uncollected fees
        require(collectedFeesByValidator[msg.sender] == 0, "CANNOT_CHANGE_WITH_COLLECTED_FEES");
        _requireUSDTIP20(token);
        validatorTokens[msg.sender] = token;
        emit ValidatorTokenSet(msg.sender, token);
    }

    function setUserToken(address token) external onlyDirectCall {
        _requireUSDTIP20(token);
        userTokens[msg.sender] = token;
        emit UserTokenSet(msg.sender, token);
    }

    // This function is called by the protocol before any transaction is executed.
    // If it reverts, the transaction is invalid.
    // NOTE: The fee token (userToken) is determined by the protocol before calling this function
    // using logic that considers: tx.feeToken, setUserToken calls, userTokens storage, tx.to if TIP-20.
    function collectFeePreTx(address user, address userToken, uint256 maxAmount) external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        // Get fee recipient and their preferred token (fallback to PATH_USD if not set)
        address feeRecipient = block.coinbase;
        address validatorToken = validatorTokens[feeRecipient];
        if (validatorToken == address(0)) {
            validatorToken = PATH_USD;
        }

        // Collect the maximum fee up front from the user
        ITIP20(userToken).transferFeePreTx(user, maxAmount);

        if (userToken == validatorToken) {
            // Direct fee in validator's preferred token
            collectedFeesByValidator[feeRecipient] += maxAmount;
        } else {
            // Execute fee swap via the AMM
            uint256 amountOut = executeFeeSwap(userToken, validatorToken, maxAmount);
            collectedFeesByValidator[feeRecipient] += amountOut;
        }
    }

    /// @notice Allows a validator to receive their accumulated fees
    /// @dev Can be called by anyone, but fees are always sent to the validator
    /// @param validator The validator address to distribute fees to
    function distributeFees(address validator) external {
        uint256 amount = collectedFeesByValidator[validator];
        if (amount == 0) return;

        address validatorToken = validatorTokens[validator];
        if (validatorToken == address(0)) {
            validatorToken = PATH_USD;
        }

        collectedFeesByValidator[validator] = 0;
        IERC20(validatorToken).transfer(validator, amount);

        emit FeesDistributed(validator, validatorToken, amount);
    }

}
