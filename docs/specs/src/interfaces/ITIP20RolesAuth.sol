// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface ITIP20RolesAuth {

    error Unauthorized();

    event RoleMembershipUpdated(
        bytes32 indexed role, address indexed account, address indexed sender, bool hasRole
    );
    event RoleAdminUpdated(
        bytes32 indexed role, bytes32 indexed newAdminRole, address indexed sender
    );

    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;

    function renounceRole(bytes32 role) external;

    function setRoleAdmin(bytes32 role, bytes32 adminRole) external;

}
