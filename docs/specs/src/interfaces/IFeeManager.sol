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

    /// @notice Total uncollected issuer fees for a given token currently held by the FeeManager.
    /// @dev Denominated in the token itself. Increased on same-token fee payments, decreased on claims.
    function collectedFeesByToken(address token) external view returns (uint256);

    /// @notice Claims all uncollected issuer fees for `token`, sending them to `recipient`.
    /// @dev Caller must hold `FEE_CLAIM_ROLE` on the given token.
    function claimTokenFees(address token, address recipient) external;

}
