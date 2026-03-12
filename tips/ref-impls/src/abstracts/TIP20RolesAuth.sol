// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { ITIP20RolesAuth } from "../interfaces/ITIP20RolesAuth.sol";

abstract contract TIP20RolesAuth is ITIP20RolesAuth {

    mapping(address account => mapping(bytes32 role => bool)) public hasRole;
    mapping(bytes32 role => bytes32 adminRole) internal roleAdmin;

    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0; // Roles with unset admins will yield this role as admin.
    bytes32 internal constant UNGRANTABLE_ROLE = bytes32(type(uint256).max); // Can never be granted to anyone.

    constructor() {
        // Prevent granting this role by making it self-administered.
        roleAdmin[UNGRANTABLE_ROLE] = UNGRANTABLE_ROLE;
    }

    modifier onlyRole(bytes32 role) {
        if (!hasRole[msg.sender][role]) revert Unauthorized();
        _;
    }

    function grantRole(bytes32 role, address account) external onlyRole(roleAdmin[role]) {
        hasRole[account][role] = true;
        emit RoleMembershipUpdated(role, account, msg.sender, true);
    }

    function revokeRole(bytes32 role, address account) external virtual onlyRole(roleAdmin[role]) {
        hasRole[account][role] = false;
        emit RoleMembershipUpdated(role, account, msg.sender, false);
    }

    function renounceRole(bytes32 role) external virtual onlyRole(role) {
        hasRole[msg.sender][role] = false;
        emit RoleMembershipUpdated(role, msg.sender, msg.sender, false);
    }

    function setRoleAdmin(
        bytes32 role,
        bytes32 adminRole
    )
        external
        virtual
        onlyRole(roleAdmin[role])
    {
        roleAdmin[role] = adminRole;
        emit RoleAdminUpdated(role, adminRole, msg.sender);
    }

}
