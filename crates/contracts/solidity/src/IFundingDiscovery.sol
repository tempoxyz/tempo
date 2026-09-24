// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IFundingPolicy} from "./IFundingPolicy.sol";

/// @notice Discover funding candidates without moving funds or granting spending authority.
interface IFundingDiscovery {
    struct Source {
        address target;
        bytes data;
        uint256 availableAmount;
    }

    struct Discovery {
        address token;
        uint256 amount;
        uint16 slippageBps;
        Source[] sources;
    }

    error InvalidCandidate(address source);
    error InvalidSlippage();

    /// @notice Discover using ordered source configurations without a stored policy.
    /// @param amount Target account balance in token base units, not the shortfall.
    /// @param slippageBps Aggregate slippage tolerance, at most 10,000 basis points.
    /// @param sources Ordered source targets and configuration data.
    function discover(
        address account,
        address token,
        uint256 amount,
        uint16 slippageBps,
        IFundingPolicy.Source[] calldata sources
    ) external view returns (Discovery memory);

    /// @notice Discover sources and verify complete rules against the policy's current commitment.
    /// @param amount Target account balance in token base units, not the shortfall.
    /// @param policyId Existing funding policy; checked even when the balance already suffices.
    /// @param rules Complete canonical ABI-encoded IFundingPolicy.Rules, not a rules hash.
    function discover(
        address account,
        address token,
        uint256 amount,
        uint64 policyId,
        bytes calldata rules
    ) external view returns (Discovery memory);
}
