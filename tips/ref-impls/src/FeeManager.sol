// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { FeeAMM } from "./FeeAMM.sol";
import { TIP403Registry } from "./TIP403Registry.sol";
import { IERC20 } from "./interfaces/IERC20.sol";
import { IFeeManager } from "./interfaces/IFeeManager.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract FeeManager is IFeeManager, FeeAMM {

    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;
    TIP403Registry internal constant TIP403_REGISTRY =
        TIP403Registry(0x403c000000000000000000000000000000000000);

    mapping(address => address) public validatorTokens;
    mapping(address => address) public userTokens;
    mapping(address => mapping(address => uint256)) public collectedFees;

    modifier onlyDirectCall() {
        require(msg.sender == tx.origin, "ONLY_DIRECT_CALL");
        _;
    }

    function setValidatorToken(address token) external onlyDirectCall {
        require(msg.sender != block.coinbase, "CANNOT_CHANGE_WITHIN_BLOCK");
        _requireUSDTIP20(token);
        validatorTokens[msg.sender] = token;
        emit ValidatorTokenSet(msg.sender, token);
    }

    function setUserToken(address token) external onlyDirectCall {
        _requireUSDTIP20(token);
        userTokens[msg.sender] = token;
        emit UserTokenSet(msg.sender, token);
    }

    function collectFeePreTx(address user, address userToken, uint256 maxAmount) external {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        address validatorToken = validatorTokens[block.coinbase];
        if (validatorToken == address(0)) {
            validatorToken = PATH_USD;
        }

        // Ensure fee payer can send the fee token and FeeManager can receive it.
        uint64 policyId = ITIP20(userToken).transferPolicyId();
        if (
            !TIP403_REGISTRY.isAuthorizedSender(policyId, user)
                || !TIP403_REGISTRY.isAuthorizedRecipient(policyId, address(this))
        ) {
            revert ITIP20.PolicyForbids();
        }

        ITIP20(userToken).transferFeePreTx(user, maxAmount);

        if (userToken != validatorToken) {
            checkSufficientLiquidity(userToken, validatorToken, maxAmount);
        }
    }

    function collectFeePostTx(
        address user,
        uint256 maxAmount,
        uint256 actualUsed,
        address userToken
    )
        external
    {
        require(msg.sender == address(0), "ONLY_PROTOCOL");

        address feeRecipient = block.coinbase;
        address validatorToken = validatorTokens[feeRecipient];
        if (validatorToken == address(0)) {
            validatorToken = PATH_USD;
        }

        uint256 refundAmount = maxAmount - actualUsed;
        ITIP20(userToken).transferFeePostTx(user, refundAmount, actualUsed);

        if (userToken != validatorToken && actualUsed > 0) {
            uint256 amountOut = executeFeeSwap(userToken, validatorToken, actualUsed);
            collectedFees[feeRecipient][validatorToken] += amountOut;
        } else if (userToken == validatorToken && actualUsed > 0) {
            collectedFees[feeRecipient][validatorToken] += actualUsed;
        }
    }

    function getFeeToken() external view returns (address) {
        address token;
        // NOTE: The slot used here (0) is specific to this reference implementation.
        // The production Rust precompile uses a different transient slot determined
        // by the `contract` macro's layout (currently slot 7).
        assembly {
            token := tload(0)
        }
        return token;
    }

    function distributeFees(address validator, address token) external {
        uint256 amount = collectedFees[validator][token];
        if (amount == 0) {
            return;
        }

        collectedFees[validator][token] = 0;

        IERC20(token).transfer(validator, amount);

        emit FeesDistributed(validator, token, amount);
    }

}
