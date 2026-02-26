pub use IFeatureRegistry::IFeatureRegistryErrors as FeatureRegistryError;

crate::sol! {
    /// Feature Registry interface for managing protocol feature flags.
    ///
    /// Stores a bitmap of active features and allows the admin to activate,
    /// deactivate, or schedule features for timestamp-based activation.
    /// The admin can also killswitch (cancel) scheduled features.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFeatureRegistry {
        // =====================================================================
        // View functions
        // =====================================================================

        /// Get a single 256-bit word of the feature bitmap at `index`.
        function featureWord(uint64 index) external view returns (uint256);

        /// Check whether a feature is currently active.
        function isActive(uint32 featureId) external view returns (bool);

        /// Get the scheduled activation timestamp for a feature (0 = not scheduled).
        function scheduledActivation(uint32 featureId) external view returns (uint64);

        /// Get the contract owner / admin.
        function owner() external view returns (address);

        // =====================================================================
        // Mutate functions (owner only)
        // =====================================================================

        /// Immediately activate a feature.
        function activate(uint32 featureId) external;

        /// Immediately deactivate a feature (killswitch).
        function deactivate(uint32 featureId) external;

        /// Schedule a feature to activate at a future timestamp.
        function scheduleActivation(uint32 featureId, uint64 activateAt) external;

        /// Cancel a scheduled activation (killswitch for scheduled features).
        function cancelScheduledActivation(uint32 featureId) external;

        /// Transfer admin ownership.
        function transferOwnership(address newOwner) external;

        // =====================================================================
        // Errors
        // =====================================================================

        error Unauthorized();
        error FeatureAlreadyActive(uint32 featureId);
        error FeatureNotActive(uint32 featureId);
        error FeatureNotScheduled(uint32 featureId);
        error FeatureAlreadyScheduled(uint32 featureId);
        error InvalidActivationTime();
        error InvalidOwner();
    }
}

impl FeatureRegistryError {
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IFeatureRegistry::Unauthorized {})
    }

    pub const fn feature_already_active(feature_id: u32) -> Self {
        Self::FeatureAlreadyActive(IFeatureRegistry::FeatureAlreadyActive { featureId: feature_id })
    }

    pub const fn feature_not_active(feature_id: u32) -> Self {
        Self::FeatureNotActive(IFeatureRegistry::FeatureNotActive { featureId: feature_id })
    }

    pub const fn feature_not_scheduled(feature_id: u32) -> Self {
        Self::FeatureNotScheduled(IFeatureRegistry::FeatureNotScheduled { featureId: feature_id })
    }

    pub const fn feature_already_scheduled(feature_id: u32) -> Self {
        Self::FeatureAlreadyScheduled(IFeatureRegistry::FeatureAlreadyScheduled {
            featureId: feature_id,
        })
    }

    pub const fn invalid_activation_time() -> Self {
        Self::InvalidActivationTime(IFeatureRegistry::InvalidActivationTime {})
    }

    pub const fn invalid_owner() -> Self {
        Self::InvalidOwner(IFeatureRegistry::InvalidOwner {})
    }
}
