// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IFeeAMM } from "./IFeeAMM.sol";

interface IFeeManager is IFeeAMM {

    event UserTokenSet(address indexed user, address indexed token);
    event ValidatorTokenSet(address indexed validator, address indexed token);
    event FeesDistributed(address indexed validator, address indexed token, uint256 amount);

    // NOTE: collectFeePreTx is a protocol-internal function called directly by the
    // execution handler, not exposed via the public interface.
    // TODO: Design fuzz tests for collectFeePreTx to test against the precompile implementation.

    function distributeFees(address validator) external;

    function collectedFeesByValidator(address validator) external view returns (uint256);

    function setUserToken(address token) external;

    function setValidatorToken(address token) external;

    function userTokens(address) external view returns (address);

    function validatorTokens(address) external view returns (address);

}
