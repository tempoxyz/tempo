// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IFeeAMM } from "./IFeeAMM.sol";

interface IFeeManager is IFeeAMM {

    event UserTokenSet(address indexed user, address indexed token);
    event ValidatorTokenSet(address indexed validator, address indexed token);

    // NOTE: collectFeePreTx and collectFeePostTx are protocol-internal functions
    // called directly by the execution handler, not exposed via the public interface.
    // TODO: Design fuzz tests for collectFeePreTx/collectFeePostTx to test against the precompile implementation.

    function executeBlock() external;

    function setUserToken(address token) external;

    function setValidatorToken(address token) external;

    function userTokens(address) external view returns (address);

    function validatorTokens(address) external view returns (address);

}
