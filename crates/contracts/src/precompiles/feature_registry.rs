pub use IFeatureRegistry::{
    IFeatureRegistryErrors as FeatureRegistryError, IFeatureRegistryEvents as FeatureRegistryEvent,
};

crate::sol! {
    /// Registry for Tempo protocol feature tip scheduling.
    ///
    /// The feature tip is the highest active protocol feature ID. A chain with feature tip `N`
    /// treats every feature ID in `1..=N` as active.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFeatureRegistry {
        /// @notice Returns the registry owner authorized to schedule feature tip activation.
        function owner() external view returns (address);

        /// @notice Returns the fixed global activation quorum threshold: 4/5, or 80%.
        function activationQuorum() external view returns (uint256 numerator, uint256 denominator);

        /// @notice Returns the highest active protocol feature ID.
        function featuresTip() external view returns (uint64);

        /// @notice Returns the scheduled feature tip and earliest activation epoch.
        function scheduledFeaturesTip() external view returns (uint64 featuresTip, uint64 activationEpoch);

        /// @notice Records the highest protocol feature tip reported for a validator. System caller only.
        function setSupportedFeaturesTip(address validator, uint64 featuresTip) external;

        /// @notice Schedules a higher feature tip for activation at the target epoch.
        function scheduleFeaturesTip(uint64 featuresTip, uint64 activationEpoch) external;

        /// @notice Activates the scheduled feature tip during block processing. System caller only.
        function activateScheduledFeaturesTip(uint64 currentEpoch) external;

        /// @notice Cancels the scheduled feature tip before activation.
        function cancelScheduledFeaturesTip() external;

        /// @notice Returns the latest feature tip reported by a validator.
        function validatorSupportedFeaturesTip(address validator) external view returns (uint64);

        /// @notice Returns current active-validator support for a feature tip.
        function featuresTipSupport(uint64 featuresTip) external view returns (uint256 support, uint256 required);

        /// @notice Returns whether a feature tip has quorum support from the active validator set.
        function hasFeaturesTipQuorum(uint64 featuresTip) external view returns (bool);

        /// @notice Emitted when a validator reports support for a feature tip.
        event SupportedFeaturesTipSet(address indexed validator, uint64 featuresTip, uint256 supportCount);

        /// @notice Emitted when a higher feature tip is scheduled for activation.
        event FeaturesTipScheduled(uint64 featuresTip, uint64 activationEpoch);

        /// @notice Emitted when the scheduled feature tip is cancelled.
        event FeaturesTipScheduleCancelled(uint64 featuresTip);

        /// @notice Emitted when a scheduled feature tip becomes active during epoch processing.
        event FeaturesTipActivated(uint64 previousFeaturesTip, uint64 featuresTip, uint64 activationEpoch);

        /// @notice Emitted when active validator support for a feature tip changes.
        event FeaturesTipSupportUpdated(uint64 featuresTip, uint256 support, uint256 required);

        /// @notice Caller is not authorized to update feature registry state.
        error Unauthorized();

        /// @notice Feature tip is invalid or reserved.
        error InvalidFeaturesTip();

        /// @notice Feature tip must be higher than the current active feature tip.
        error FeaturesTipNotIncreasing();

        /// @notice Validator cannot lower its reported supported feature tip.
        error SupportedFeaturesTipDecreased();

        /// @notice A feature tip is already scheduled for activation.
        error FeaturesTipAlreadyScheduled();

        /// @notice No feature tip is scheduled for activation.
        error FeaturesTipNotScheduled();

        /// @notice Requested activation epoch is not strictly greater than the current epoch.
        error ActivationEpochNotFuture();
    }
}
