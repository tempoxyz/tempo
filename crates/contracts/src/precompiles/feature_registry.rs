pub use IFeatureRegistry::{
    IFeatureRegistryErrors as FeatureRegistryError, IFeatureRegistryEvents as FeatureRegistryEvent,
};

crate::sol! {
    /// Registry for Tempo protocol feature activation.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFeatureRegistry {
        enum FeatureStatus {
            Pending,
            Active
        }

        struct Feature {
            uint64 minimumSupportedVersionKey;
            FeatureStatus status;
            uint64 activationEpoch;
        }

        struct MinimumVersionCheckpoint {
            uint64 minimumVersionKey;
            uint256 supportCount;
        }

        /// @notice Returns the registry owner authorized to register features and schedule activation.
        function owner() external view returns (address);

        /// @notice Returns the fixed global activation quorum threshold: 4/5, or 80%.
        function activationQuorum() external view returns (uint256 numerator, uint256 denominator);

        /// @notice Registers a new pending feature.
        function registerFeature(
            uint64 featureId,
            uint64 minimumSupportedVersionKey
        ) external;

        /// @notice Registers a minimum version checkpoint that can be used for feature activation.
        function minimum_required_version(uint64 minimumVersionKey) external;

        /// @notice Reports that an active validator is running at least the checkpoint version.
        function reportMinimumVersionSupport(
            address validator,
            uint64 minimumVersionKey,
            uint64 validatorVersionKey
        ) external;

        /// @notice Schedules activation for a pending feature.
        function scheduleActivation(uint64 featureId, uint64 activationEpoch) external;

        /// @notice Activates a scheduled feature at or after its activation epoch if all checks pass.
        function activateFeature(uint64 featureId) external;

        /// @notice Replaces the activation epoch for a scheduled pending feature.
        function rescheduleActivation(uint64 featureId, uint64 activationEpoch) external;

        /// @notice Cancels a scheduled activation before the feature becomes active.
        function cancelScheduledActivation(uint64 featureId) external;

        /// @notice Returns the registered feature metadata and current status.
        function getFeature(uint64 featureId) external view returns (Feature memory);

        /// @notice Returns whether a feature is registered.
        function isFeatureRegistered(uint64 featureId) external view returns (bool);

        /// @notice Returns whether a feature is active at the current block.
        function isFeatureActive(uint64 featureId) external view returns (bool);

        /// @notice Returns one word from the active feature bitmap.
        function activeFeatureBitmapWord(uint256 wordIndex) external view returns (uint256);

        /// @notice Returns the number of active features recorded in activation order.
        function activeFeatureCount() external view returns (uint256);

        /// @notice Returns the active feature ID at a zero-based activation-order index.
        function activeFeatureAt(uint256 index) external view returns (uint64);

        /// @notice Returns the number of features scheduled for a given activation epoch.
        function scheduledFeatureCount(uint64 activationEpoch) external view returns (uint256);

        /// @notice Returns the scheduled feature ID at a zero-based index for an activation epoch.
        function scheduledFeatureAt(uint64 activationEpoch, uint256 index) external view returns (uint64);

        /// @notice Returns the latest Tempo version key reported by a validator.
        function validatorVersionKey(address validator) external view returns (uint64);

        /// @notice Returns a registered minimum version checkpoint.
        function minimumVersionCheckpoint(uint64 minimumVersionKey) external view returns (MinimumVersionCheckpoint memory);

        /// @notice Returns whether a minimum version checkpoint is registered.
        function isMinimumVersionCheckpointRegistered(uint64 minimumVersionKey) external view returns (bool);

        /// @notice Returns whether a validator has reported support for a minimum version.
        function validatorSupportsMinimumVersion(address validator, uint64 minimumVersionKey) external view returns (bool);

        /// @notice Returns current support for a minimum version.
        function minimumVersionSupportCount(uint64 minimumVersionKey) external view returns (uint256 support, uint256 required);

        /// @notice Returns whether a minimum version has quorum support.
        function hasMinimumVersionQuorum(uint64 minimumVersionKey) external view returns (bool);

        /// @notice Returns whether a validator's reported version supports a feature.
        function validatorSupportsFeature(address validator, uint64 featureId) external view returns (bool);

        /// @notice Returns current active-validator support for a feature.
        function featureSupportCount(uint64 featureId) external view returns (uint256 support, uint256 required);

        /// @notice Returns whether a feature has quorum support from the active validator set.
        function hasQuorum(uint64 featureId) external view returns (bool);

        /// @notice Emitted when a feature is registered.
        event FeatureRegistered(uint64 featureId, uint64 minimumSupportedVersionKey);

        /// @notice Emitted when a minimum version checkpoint is registered.
        event MinimumVersionCheckpointRegistered(uint64 minimumVersionKey);

        /// @notice Emitted when a validator reports support for a minimum version.
        event MinimumVersionSupportReported(address indexed validator, uint64 minimumVersionKey, uint256 supportCount);

        /// @notice Emitted when a pending feature is scheduled for activation.
        event FeatureScheduled(uint64 featureId, uint64 activationEpoch);

        /// @notice Emitted when a pending feature's activation epoch is replaced.
        event FeatureRescheduled(uint64 featureId, uint64 activationEpoch);

        /// @notice Emitted when a scheduled feature is cancelled.
        event FeatureScheduleCancelled(uint64 featureId);

        /// @notice Emitted when a scheduled feature becomes active.
        event FeatureActivated(uint64 featureId, uint64 activationEpoch);

        /// @notice Emitted when a scheduled feature remains pending after an activation attempt fails.
        event FeatureActivationFailed(
            uint64 featureId,
            uint64 activationEpoch,
            bool quorumSatisfied
        );

        /// @notice Emitted when the active validator support count changes.
        event FeatureSupportUpdated(uint64 featureId, uint256 support, uint256 required);

        /// @notice Caller is not authorized to update feature registry state.
        error Unauthorized();

        /// @notice Feature ID is invalid or reserved.
        error InvalidFeatureId();

        /// @notice Tempo version is not canonical or cannot be encoded.
        error InvalidVersion();

        /// @notice Minimum version checkpoint is already registered.
        error MinimumVersionCheckpointAlreadyRegistered();

        /// @notice Minimum version checkpoint is not registered.
        error MinimumVersionCheckpointNotRegistered();

        /// @notice Validator has already reported support for this minimum version.
        error MinimumVersionSupportAlreadyReported();

        /// @notice Validator's reported version is below the minimum version.
        error ValidatorVersionBelowMinimum();

        /// @notice Feature is already registered.
        error FeatureAlreadyRegistered();

        /// @notice Feature is not registered.
        error FeatureNotRegistered();

        /// @notice Feature is not pending.
        error FeatureNotPending();

        /// @notice Feature already has a scheduled activation epoch.
        error FeatureAlreadyScheduled();

        /// @notice Feature does not have a scheduled activation epoch.
        error FeatureNotScheduled();

        /// @notice Requested activation epoch is not strictly greater than the current epoch.
        error ActivationEpochNotFuture();

        /// @notice Feature cannot be activated before its scheduled activation epoch.
        error ActivationEpochNotReached();
    }
}
