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

    struct Policy {
        address[] admins;
        uint16 slippageBps;
        Route[] routes;
    }

    error TokenNotAllowed(address token);
    error PolicyNotFound();
    error Unauthorized();
    error InvalidPolicy();

    function policyIdCounter() external view returns (uint64);
    function policyExists(uint64 policyId) external view returns (bool);
    function createPolicy(Policy calldata policy) external returns (uint64 policyId);
    function getPolicy(uint64 policyId) external view returns (Policy memory policy);
    function modifyPolicy(uint64 policyId, uint16 slippageBps, Route[] calldata routes) external;
    function setAdmins(uint64 policyId, address[] calldata admins) external;

    event PolicyCreated(uint64 indexed policyId, address indexed updater);
    /// @dev policyHash is keccak256(abi.encode(policy)) after the rule update.
    event PolicyUpdated(uint64 indexed policyId, address indexed updater, bytes32 policyHash);
    event PolicyAdminsUpdated(uint64 indexed policyId, address indexed updater, address[] admins);
}
