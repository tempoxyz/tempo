// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IFeeAMM } from "./IFeeAMM.sol";

interface IFeeManager is IFeeAMM {

    event UserTokenSet(address indexed user, address indexed token);
    event ValidatorTokenSet(address indexed validator, address indexed token);

    function collectFeePostTx(
        address user,
        uint256 maxAmount,
        uint256 actualUsed,
        address userToken,
        address validatorToken,
        address feeRecipient
    ) external;

    function collectFeePreTx(
        address user,
        address txToAddress,
        uint256 maxAmount,
        address feeRecipient
    ) external returns (address userToken);

    function executeBlock() external;

    function setUserToken(address token) external;

    function setValidatorToken(address token) external;

    function userTokens(address) external view returns (address);

    function validatorTokens(address) external view returns (address);

}
