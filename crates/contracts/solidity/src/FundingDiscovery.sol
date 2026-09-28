// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IFundingPolicy} from "./IFundingPolicy.sol";
import {IFundingDiscovery} from "./IFundingDiscovery.sol";

interface IDiscoverySource {
    struct Candidate {
        bytes executionData;
        uint256 availableAmount;
    }

    function verify(bytes calldata executionData, bytes calldata configData)
        external
        view
        returns (bool);

    function discover(
        address account,
        address assetOut,
        uint256 amountOut,
        uint256 maxCost,
        bytes calldata configData
    ) external view returns (Candidate[] memory);
}

interface IDiscoveryToken {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Estimates candidates under supplied rules without granting spending authority.
contract FundingDiscovery is IFundingDiscovery {
    IFundingPolicy public constant fundingPolicy =
        IFundingPolicy(0x1120000000000000000000000000000000000002);

    function discover(
        address account,
        address token,
        uint256 amount,
        uint16 slippageBps,
        IFundingPolicy.Source[] calldata sources
    ) external view returns (Discovery memory) {
        return discoverSources(account, token, amount, slippageBps, sources);
    }

    function discover(
        address account,
        address token,
        uint256 amount,
        uint64 policyId,
        bytes calldata rules
    ) external view returns (Discovery memory) {
        IFundingPolicy.Policy memory policy = fundingPolicy.getPolicy(policyId);
        bytes32 domain = keccak256("tempo.funding-policy.rules.v1");
        if (keccak256(abi.encode(domain, rules)) != policy.rulesHash) {
            revert IFundingPolicy.InvalidPolicyData();
        }
        return discoverRules(account, token, amount, rules);
    }

    function discoverRules(address account, address token, uint256 amount, bytes calldata encoded)
        private
        view
        returns (Discovery memory result)
    {
        IFundingPolicy.Rules memory rules;
        try this.decodeRules(encoded) returns (IFundingPolicy.Rules memory decoded) {
            rules = decoded;
        } catch {
            revert IFundingPolicy.InvalidPolicyData();
        }
        uint256 routeIndex;
        while (routeIndex < rules.routes.length && rules.routes[routeIndex].token != token) {
            ++routeIndex;
        }
        if (routeIndex == rules.routes.length) revert IFundingPolicy.TokenNotAllowed(token);
        return discoverSources(
            account, token, amount, rules.maxSlippageBps, rules.routes[routeIndex].sources
        );
    }

    function discoverSources(
        address account,
        address token,
        uint256 amount,
        uint16 slippageBps,
        IFundingPolicy.Source[] memory sources
    ) private view returns (Discovery memory result) {
        if (slippageBps > 10_000) revert InvalidSlippage();
        result.token = token;
        result.amount = amount;
        result.slippageBps = slippageBps;
        result.sources = new Source[](0);
        uint256 balance = IDiscoveryToken(token).balanceOf(account);
        if (balance >= amount) return result;

        uint256 shortfall = amount - balance;
        // Divide first to avoid intermediate overflow; an unrepresentable final budget still reverts.
        uint256 budget = shortfall + (shortfall / 10_000) * slippageBps
            + ((shortfall % 10_000) * slippageBps) / 10_000;
        IDiscoverySource.Candidate[][] memory candidates =
            new IDiscoverySource.Candidate[][](sources.length);
        uint256 count;
        for (uint256 i; i < sources.length; ++i) {
            candidates[i] = IDiscoverySource(sources[i].target)
                .discover(account, token, shortfall, budget, sources[i].data);
            for (uint256 j; j < candidates[i].length; ++j) {
                IDiscoverySource.Candidate memory candidate = candidates[i][j];
                if (
                    candidate.executionData.length == 0 || candidate.availableAmount == 0
                        || candidate.availableAmount > shortfall
                        || !IDiscoverySource(sources[i].target)
                            .verify(candidate.executionData, sources[i].data)
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
                    data: candidates[i][j].executionData,
                    availableAmount: candidates[i][j].availableAmount
                });
            }
        }
    }

    /// @dev An external decoder lets discovery normalize malformed ABI errors before reading balances.
    function decodeRules(bytes calldata encoded)
        external
        pure
        returns (IFundingPolicy.Rules memory rules)
    {
        rules = abi.decode(encoded, (IFundingPolicy.Rules));
        if (keccak256(abi.encode(rules)) != keccak256(encoded)) {
            revert IFundingPolicy.InvalidPolicyData();
        }
    }
}
