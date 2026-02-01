// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title The interface for TIP-403 transfer policy registry
/// @notice Registry for managing transfer policies that control which addresses can send or receive tokens
interface ITIP403Registry {

    /// @notice Policy types available for transfer restrictions
    /// @param WHITELIST Only addresses on the whitelist are authorized for transfers
    /// @param BLACKLIST All addresses except those on the blacklist are authorized for transfers
    enum PolicyType {
        WHITELIST,
        BLACKLIST
    }

    /// @notice Data structure containing policy configuration
    /// @param policyType The type of policy (whitelist or blacklist)
    /// @param admin The address authorized to modify this policy
    struct PolicyData {
        PolicyType policyType;
        address admin;
    }

    /// @notice Error when caller lacks authorization to perform the requested action
    error Unauthorized();

    /// @notice Error when attempting to operate on a policy with incompatible type
    error IncompatiblePolicyType();

    /// @notice Error when querying a policy that does not exist
    error PolicyNotFound();

    /// @notice Emitted when a policy's admin is updated
    /// @param policyId The ID of the policy that was updated
    /// @param updater The address that performed the update
    /// @param admin The new admin address for the policy
    event PolicyAdminUpdated(
        uint64 indexed policyId, address indexed updater, address indexed admin
    );

    /// @notice Emitted when a new policy is created
    /// @param policyId The ID of the newly created policy
    /// @param updater The address that created the policy
    /// @param policyType The type of policy that was created
    event PolicyCreated(uint64 indexed policyId, address indexed updater, PolicyType policyType);

    /// @notice Emitted when a whitelist policy is modified
    /// @param policyId The ID of the whitelist policy that was updated
    /// @param updater The address that performed the update
    /// @param account The account whose whitelist status was changed
    /// @param allowed Whether the account is now allowed (true) or not (false)
    event WhitelistUpdated(
        uint64 indexed policyId, address indexed updater, address indexed account, bool allowed
    );

    /// @notice Emitted when a blacklist policy is modified
    /// @param policyId The ID of the blacklist policy that was updated
    /// @param updater The address that performed the update
    /// @param account The account whose blacklist status was changed
    /// @param restricted Whether the account is now restricted (true) or not (false)
    event BlacklistUpdated(
        uint64 indexed policyId, address indexed updater, address indexed account, bool restricted
    );

    /// @notice Returns the current policy ID counter
    /// @return The next policy ID that will be assigned to a newly created policy
    function policyIdCounter() external view returns (uint64);

    /// @notice Returns whether a policy exists
    /// @param policyId The ID of the policy to check
    /// @return True if the policy exists, false otherwise
    function policyExists(uint64 policyId) external view returns (bool);

    /// @notice Returns the policy data for a given policy ID
    /// @param policyId The ID of the policy to query
    /// @return policyType The type of the policy (whitelist or blacklist)
    /// @return admin The admin address of the policy
    function policyData(uint64 policyId)
        external
        view
        returns (PolicyType policyType, address admin);

    /// @notice Creates a new transfer policy without initial accounts
    /// @param admin The address to be assigned as the admin of the new policy
    /// @param policyType The type of policy to create (whitelist or blacklist)
    /// @return newPolicyId The ID of the newly created policy
    function createPolicy(address admin, PolicyType policyType)
        external
        returns (uint64 newPolicyId);

    /// @notice Creates a new transfer policy with initial accounts
    /// @param admin The address to be assigned as the admin of the new policy
    /// @param policyType The type of policy to create (whitelist or blacklist)
    /// @param accounts The initial accounts to add to the policy list
    /// @return newPolicyId The ID of the newly created policy
    function createPolicyWithAccounts(
        address admin,
        PolicyType policyType,
        address[] calldata accounts
    ) external returns (uint64 newPolicyId);

    /// @notice Updates the admin address for an existing policy
    /// @param policyId The ID of the policy to update
    /// @param admin The new admin address for the policy
    function setPolicyAdmin(uint64 policyId, address admin) external;

    /// @notice Modifies the whitelist status of an account for a whitelist policy
    /// @param policyId The ID of the whitelist policy to modify
    /// @param account The account to update
    /// @param allowed Whether to allow (true) or disallow (false) the account
    function modifyPolicyWhitelist(uint64 policyId, address account, bool allowed) external;

    /// @notice Modifies the blacklist status of an account for a blacklist policy
    /// @param policyId The ID of the blacklist policy to modify
    /// @param account The account to update
    /// @param restricted Whether to restrict (true) or unrestrict (false) the account
    function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;

    /// @notice Checks if a user is authorized under a specific policy
    /// @param policyId The ID of the policy to check against
    /// @param user The address to check authorization for
    /// @return True if the user is authorized, false otherwise
    function isAuthorized(uint64 policyId, address user) external view returns (bool);

}
