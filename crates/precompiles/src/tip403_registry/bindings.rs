use alloy::sol;

sol! {
    /// TIP403Registry interface for managing authorization policies and permissions.
    ///
    /// TIP403 provides a comprehensive authorization framework supporting:
    /// - Policy-based access control with whitelists and blacklists
    /// - Admin role management and delegation
    /// - Flexible policy composition and inheritance
    /// - Integration with token transfer restrictions
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP403Registry {
        /// Policy types for authorization control
        enum PolicyType {
            None,        // No restrictions
            Whitelist,   // Only allow listed addresses
            Blacklist    // Deny listed addresses
        }

        /// Create a new authorization policy
        /// @param policyType The type of policy (whitelist/blacklist)
        /// @param admin The admin address for the policy
        /// @return policyId The created policy ID
        function createPolicy(PolicyType policyType, address admin) external returns (uint64 policyId);

        /// Add addresses to a policy's list
        /// @param policyId The policy ID
        /// @param addresses The addresses to add
        function addToPolicy(uint64 policyId, address[] calldata addresses) external;

        /// Remove addresses from a policy's list  
        /// @param policyId The policy ID
        /// @param addresses The addresses to remove
        function removeFromPolicy(uint64 policyId, address[] calldata addresses) external;

        /// Check if an address is authorized under a policy
        /// @param policyId The policy ID
        /// @param account The address to check
        /// @return authorized Whether the address is authorized
        function isAuthorized(uint64 policyId, address account) external view returns (bool authorized);

        /// Check if an address is in a policy's list
        /// @param policyId The policy ID  
        /// @param account The address to check
        /// @return inList Whether the address is in the policy list
        function isInPolicy(uint64 policyId, address account) external view returns (bool inList);

        /// Get policy information
        /// @param policyId The policy ID
        /// @return policyType The policy type
        /// @return admin The policy admin
        /// @return listSize The number of addresses in the policy list
        function getPolicyInfo(uint64 policyId) external view returns (
            PolicyType policyType,
            address admin,
            uint256 listSize
        );

        /// Grant admin rights to another address
        /// @param policyId The policy ID
        /// @param newAdmin The new admin address
        function grantAdmin(uint64 policyId, address newAdmin) external;

        /// Revoke admin rights from an address
        /// @param policyId The policy ID
        /// @param admin The admin address to revoke
        function revokeAdmin(uint64 policyId, address admin) external;

        /// Check if an address is an admin for a policy
        /// @param policyId The policy ID
        /// @param account The address to check
        /// @return isAdmin Whether the address is an admin
        function isPolicyAdmin(uint64 policyId, address account) external view returns (bool isAdmin);

        // Events
        event PolicyCreated(uint64 indexed policyId, PolicyType policyType, address indexed admin);
        event AddressAddedToPolicy(uint64 indexed policyId, address indexed account);
        event AddressRemovedFromPolicy(uint64 indexed policyId, address indexed account);
        event AdminGranted(uint64 indexed policyId, address indexed admin, address indexed grantedBy);
        event AdminRevoked(uint64 indexed policyId, address indexed admin, address indexed revokedBy);

        // Errors
        error PolicyDoesNotExist();
        error Unauthorized();
        error AddressAlreadyInPolicy();
        error AddressNotInPolicy();
        error InvalidPolicyType();
        error CannotRemoveLastAdmin();
    }
}