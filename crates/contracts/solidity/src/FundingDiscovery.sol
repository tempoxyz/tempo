// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IFundingPolicy} from "./IFundingPolicy.sol";
import {IFundingDiscovery} from "./IFundingDiscovery.sol";

interface IDiscoverySource {
    struct Candidate {
        bytes requestData;
        uint256 availableAmount;
    }

    function verify(bytes calldata requestData, bytes calldata policyData)
        external
        view
        returns (bool);

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
    IFundingPolicy public constant fundingPolicy =
        IFundingPolicy(0x1120000000000000000000000000000000000002);

    function discover(
        uint64 policyId,
        address account,
        address token,
        uint256 amount,
        bytes calldata policyRules
    ) external view returns (Discovery memory result) {
        IFundingPolicy.Policy memory policy = fundingPolicy.getPolicy(policyId);
        bytes32 domain = keccak256("tempo.funding-policy.rules.v1");
        if (
            policyRules.length == 0
                || keccak256(abi.encode(domain, policyRules)) != policy.rulesHash
        ) {
            revert IFundingPolicy.InvalidPolicyData();
        }
        IFundingPolicy.Rules memory rules = abi.decode(policyRules, (IFundingPolicy.Rules));
        if (keccak256(abi.encode(rules)) != keccak256(policyRules)) {
            revert IFundingPolicy.InvalidPolicyData();
        }
        uint256 routeIndex;
        while (routeIndex < rules.routes.length && rules.routes[routeIndex].token != token) {
            ++routeIndex;
        }
        if (routeIndex == rules.routes.length) revert IFundingPolicy.TokenNotAllowed(token);
        if (rules.maxSlippageBps > 10_000) revert InvalidSlippage();
        result.token = token;
        result.amount = amount;
        result.slippageBps = rules.maxSlippageBps;
        result.sources = new Source[](0);
        uint256 balance = IDiscoveryToken(token).balanceOf(account);
        if (balance >= amount) return result;

        uint256 shortfall = amount - balance;
        // Divide first to avoid intermediate overflow; an unrepresentable final budget still reverts.
        uint256 budget = shortfall + (shortfall / 10_000) * rules.maxSlippageBps
            + ((shortfall % 10_000) * rules.maxSlippageBps) / 10_000;
        IFundingPolicy.Source[] memory sources = rules.routes[routeIndex].sources;
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
                        || !IDiscoverySource(sources[i].target)
                            .verify(candidate.requestData, sources[i].data)
                ) {
                    revert InvalidCandidate(sources[i].target);
                }
            }
            count += candidates[i].length;
        }

        result.sources = new Source[](count);
        uint256 index;
        for (uint256 i; i < sources.length; ++i) {
            for (uint256 j; j < candidates[i].length; ++j) {
                result.sources[index++] = Source({
                    target: sources[i].target,
                    data: candidates[i][j].requestData,
                    availableAmount: candidates[i][j].availableAmount
                });
            }
        }
    }
}
