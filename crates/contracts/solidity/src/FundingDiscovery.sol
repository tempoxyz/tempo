// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IFundingPolicy} from "./IFundingPolicy.sol";
import {IFundingDiscovery} from "./IFundingDiscovery.sol";

interface IDiscoverySource {
    struct Candidate {
        bytes requestData;
        uint256 availableAmount;
    }

    function discover(
        address account,
        address assetOut,
        uint256 amountOut,
        uint256 maxCost,
        bytes calldata policyData
    ) external view returns (Candidate[] memory);
}

interface IDiscoveryToken {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Estimates candidates under a stored policy without granting spending authority.
contract FundingDiscovery is IFundingDiscovery {
    IFundingPolicy public immutable fundingPolicy;

    constructor(IFundingPolicy policy) {
        fundingPolicy = policy;
    }

    function discover(uint64 policyId, address account, address token, uint256 amount)
        external
        view
        returns (Discovery memory result)
    {
        IFundingPolicy.Policy memory policy = fundingPolicy.getPolicy(policyId);
        uint256 routeIndex;
        while (routeIndex < policy.routes.length && policy.routes[routeIndex].token != token) {
            ++routeIndex;
        }
        if (routeIndex == policy.routes.length) revert IFundingPolicy.TokenNotAllowed(token);
        if (policy.slippageBps > 10_000) revert InvalidSlippage();
        result.token = token;
        result.amount = amount;
        result.slippageBps = policy.slippageBps;
        result.sources = new SourceCandidate[](0);
        uint256 balance = IDiscoveryToken(token).balanceOf(account);
        if (balance >= amount) return result;

        uint256 shortfall = amount - balance;
        // Divide first to avoid intermediate overflow; an unrepresentable final budget still reverts.
        uint256 budget = shortfall + (shortfall / 10_000) * policy.slippageBps
            + ((shortfall % 10_000) * policy.slippageBps) / 10_000;
        IFundingPolicy.Source[] memory sources = policy.routes[routeIndex].sources;
        IDiscoverySource.Candidate[][] memory candidates =
            new IDiscoverySource.Candidate[][](sources.length);
        uint256 count;
        for (uint256 i; i < sources.length; ++i) {
            candidates[i] = IDiscoverySource(sources[i].target)
                .discover(account, token, shortfall, budget, sources[i].data);
            for (uint256 j; j < candidates[i].length; ++j) {
                IDiscoverySource.Candidate memory candidate = candidates[i][j];
                if (
                    candidate.requestData.length == 0 || candidate.availableAmount == 0
                        || candidate.availableAmount > shortfall
                ) {
                    revert InvalidCandidate(sources[i].target);
                }
            }
            count += candidates[i].length;
        }

        result.sources = new SourceCandidate[](count);
        uint256 index;
        for (uint256 i; i < sources.length; ++i) {
            for (uint256 j; j < candidates[i].length; ++j) {
                result.sources[index++] = SourceCandidate({
                    target: sources[i].target,
                    data: candidates[i][j].requestData,
                    availableAmount: candidates[i][j].availableAmount
                });
            }
        }
    }
}
