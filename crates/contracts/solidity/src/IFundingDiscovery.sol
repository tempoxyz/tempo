// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

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

    function discover(
        uint64 policyId,
        address account,
        address token,
        uint256 amount,
        bytes calldata policyRules
    ) external view returns (Discovery memory);
}
