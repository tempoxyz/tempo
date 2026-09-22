// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IFundingDiscovery {
    struct SourceCandidate {
        address target;
        bytes data;
        uint256 availableAmount;
    }

    struct Discovery {
        address token;
        uint256 amount;
        uint16 slippageBps;
        SourceCandidate[] sources;
    }

    error InvalidCandidate(address source);
    error InvalidSlippage();

    function discover(uint64 policyId, address account, address token, uint256 amount)
        external
        view
        returns (Discovery memory);
}
