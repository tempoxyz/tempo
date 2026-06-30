pub use IFeatureRegistry::{
    IFeatureRegistryErrors as FeatureRegistryError, IFeatureRegistryEvents as FeatureRegistryEvent,
};

crate::sol! {
    /// Registry for Tempo feature-head scheduling.
    ///
    /// The feature head is the hash-chain head for the active feature stack.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFeatureRegistry {
        /// @notice Returns the registry owner authorized to schedule feature activation.
        function owner() external view returns (address);

        /// @notice Returns the fixed global activation quorum threshold: 4/5, or 80%.
        function activationQuorum() external view returns (uint256 numerator, uint256 denominator);

        /// @notice Returns the active feature stack head.
        function activeFeatureHead() external view returns (bytes32);

        /// @notice Returns the scheduled feature head and earliest activation epoch.
        function scheduledFeatureHead() external view returns (bytes32 featureHead, uint64 activationEpoch);

        /// @notice Reports whether the proposer validator is ready for the currently scheduled feature head. System caller only.
        function reportFeatureReadiness(bool ready) external;

        /// @notice Schedules a feature head for activation at the target epoch.
        function scheduleFeatureHead(bytes32 featureHead, uint64 activationEpoch) external;

        /// @notice Activates the scheduled feature head during block processing. System caller only.
        function activateScheduledFeatureHead() external;

        /// @notice Cancels the scheduled feature head before activation.
        function cancelScheduledFeatureHead() external;

        /// @notice Returns whether a validator reported readiness for a feature head.
        function validatorConfirmedFeatureHead(address validator, bytes32 featureHead) external view returns (bool);

        /// @notice Returns current active-validator readiness for a feature head.
        function featureHeadSupport(bytes32 featureHead) external view returns (uint256 support, uint256 required);

        /// @notice Returns whether a feature head has quorum readiness from the active validator set.
        function hasFeatureHeadQuorum(bytes32 featureHead) external view returns (bool);

        /// @notice Emitted when a validator reports readiness for a feature head.
        event FeatureReadinessReported(address indexed validator, bytes32 indexed featureHead, bool ready);

        /// @notice Emitted when a feature head is scheduled for activation.
        event FeatureHeadScheduled(bytes32 indexed featureHead, uint64 activationEpoch);

        /// @notice Emitted when the scheduled feature head is cancelled.
        event FeatureHeadScheduleCancelled(bytes32 indexed featureHead);

        /// @notice Emitted when a scheduled feature head becomes active during epoch processing.
        event FeatureHeadActivated(bytes32 indexed previousFeatureHead, bytes32 indexed featureHead, uint64 activationEpoch);

        /// @notice Emitted when active validator readiness for a feature head changes.
        event FeatureHeadSupportUpdated(bytes32 indexed featureHead, uint256 support, uint256 required);

        /// @notice Caller is not authorized to update feature registry state.
        error Unauthorized();

        /// @notice Feature head is invalid or reserved.
        error InvalidFeatureHead();

        /// @notice Feature head is already active.
        error FeatureHeadAlreadyActive();

        /// @notice A feature head is already scheduled for activation.
        error FeatureHeadAlreadyScheduled();

        /// @notice No feature head is scheduled for activation.
        error FeatureHeadNotScheduled();

        /// @notice The block environment does not include a proposer public key.
        error ProposerPublicKeyUnavailable();

        /// @notice Requested activation epoch is not strictly greater than the current epoch.
        error ActivationEpochNotFuture();
    }
}
