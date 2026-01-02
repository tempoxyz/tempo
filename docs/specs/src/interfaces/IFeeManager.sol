// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IFeeAMM } from "./IFeeAMM.sol";

interface IFeeManager is IFeeAMM {

    event UserTokenSet(address indexed user, address indexed token);
    event ValidatorTokenSet(address indexed validator, address indexed token);
    event FeesDistributed(address indexed validator, address indexed token, uint256 amount);

    function distributeFees(address validator, address token) external;

    function collectedFees(address validator, address token) external view returns (uint256);

    function setUserToken(address token) external;

    function setValidatorToken(address token) external;

    function userTokens(address) external view returns (address);

    function validatorTokens(address) external view returns (address);

}
