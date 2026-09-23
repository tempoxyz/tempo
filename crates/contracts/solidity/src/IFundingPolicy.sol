// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IFundingPolicy {
    struct Source {
        address target;
        bytes data;
    }

    struct Route {
        address token;
        Source[] sources;
    }

    struct Rules {
        uint16 maxSlippageBps;
        Route[] routes;
    }

    struct Policy {
        address[] admins;
        bytes32 rulesHash;
    }

    error TokenNotAllowed(address token);
    error PolicyNotFound();
    error Unauthorized();
    error InvalidPolicy();
    error InvalidPolicyData();

    function policyIdCounter() external view returns (uint64);
    function policyExists(uint64 policyId) external view returns (bool);
    function createPolicy(address[] calldata admins, Rules calldata rules)
        external
        returns (uint64 policyId);
    function getPolicy(uint64 policyId) external view returns (Policy memory policy);
    function setRules(uint64 policyId, Rules calldata rules) external;
    function setAdmins(uint64 policyId, address[] calldata admins) external;

    event PolicyCreated(
        uint64 indexed policyId, address indexed updater, bytes32 rulesHash, Rules rules
    );
    event PolicyRulesUpdated(
        uint64 indexed policyId, address indexed updater, bytes32 rulesHash, Rules rules
    );
    event PolicyAdminsUpdated(uint64 indexed policyId, address indexed updater, address[] admins);
}
