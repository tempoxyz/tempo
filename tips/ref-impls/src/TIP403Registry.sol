// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { ITIP403Registry } from "./interfaces/ITIP403Registry.sol";

contract TIP403Registry is ITIP403Registry {

    uint64 public policyIdCounter = 2; // Skip special policies (documented in isAuthorized).

    mapping(uint64 => PolicyData) internal _policyData;

    /*//////////////////////////////////////////////////////////////
                      POLICY TYPE-SPECIFIC STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint64 => mapping(address => bool)) internal policySet;

    /*//////////////////////////////////////////////////////////////
                      GENERAL POLICY ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function createPolicy(address admin, PolicyType policyType)
        public
        returns (uint64 newPolicyId)
    {
        _policyData[newPolicyId = policyIdCounter++] =
            PolicyData({ policyType: policyType, admin: admin });

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
    }

    function createPolicyWithAccounts(
        address admin,
        PolicyType policyType,
        address[] calldata accounts
    ) public returns (uint64 newPolicyId) {
        newPolicyId = policyIdCounter++;

        _policyData[newPolicyId] = PolicyData({ policyType: policyType, admin: admin });

        // Set the initial policy set.
        for (uint256 i = 0; i < accounts.length; i++) {
            policySet[newPolicyId][accounts[i]] = true;

            if (policyType == PolicyType.WHITELIST) {
                emit WhitelistUpdated(newPolicyId, msg.sender, accounts[i], true);
            } else {
                emit BlacklistUpdated(newPolicyId, msg.sender, accounts[i], true);
            }
        }

        emit PolicyCreated(newPolicyId, msg.sender, policyType);
        emit PolicyAdminUpdated(newPolicyId, msg.sender, admin);
    }

    function setPolicyAdmin(uint64 policyId, address admin) external {
        require(_policyData[policyId].admin == msg.sender, Unauthorized());

        _policyData[policyId].admin = admin;

        emit PolicyAdminUpdated(policyId, msg.sender, admin);
    }

    /*//////////////////////////////////////////////////////////////
                   POLICY TYPE-SPECIFIC ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external {
        PolicyData memory data = _policyData[policyId];

        require(data.admin == msg.sender, Unauthorized());
        require(data.policyType == PolicyType.WHITELIST, IncompatiblePolicyType());

        policySet[policyId][account] = allowed;

        emit WhitelistUpdated(policyId, msg.sender, account, allowed);
    }

    function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external {
        PolicyData memory data = _policyData[policyId];

        require(data.admin == msg.sender, Unauthorized());
        require(data.policyType == PolicyType.BLACKLIST, IncompatiblePolicyType());

        policySet[policyId][account] = restricted;

        emit BlacklistUpdated(policyId, msg.sender, account, restricted);
    }

    /*//////////////////////////////////////////////////////////////
                        GENERAL POLICY QUERYING
    //////////////////////////////////////////////////////////////*/

    function policyExists(uint64 policyId) public view returns (bool) {
        // Special policies 0 and 1 always exist
        if (policyId < 2) {
            return true;
        }

        // Check if policy ID is within the range of created policies
        return policyId < policyIdCounter;
    }

    function isAuthorized(uint64 policyId, address user) public view returns (bool) {
        // Special case for the "always-allow" and "always-reject" policies.
        if (policyId < 2) {
            // policyId == 0 is the "always-reject" policy.
            // policyId == 1 is the "always-allow" policy.
            return policyId == 1;
        }

        PolicyData memory data = _policyData[policyId];

        return data.policyType == PolicyType.WHITELIST
            ? policySet[policyId][user]
            : !policySet[policyId][user];
    }

    function policyData(uint64 policyId)
        public
        view
        returns (PolicyType policyType, address admin)
    {
        require(policyExists(policyId), PolicyNotFound(policyId));

        PolicyData memory data = _policyData[policyId];
        return (data.policyType, data.admin);
    }

}
