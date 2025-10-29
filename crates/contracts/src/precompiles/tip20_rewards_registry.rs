use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface ITIPRewardsRegistry {
        /// Register a stream end time for a token
        function addStream(address token, uint128 endTime) external;

        /// Get all tokens with streams ending at a given timestamp
        function getTokensEndingAt(uint128 timestamp) external view returns (address[]);

        /// Finalize streams for all tokens ending at the given timestamp (system only)
        function finalizeStreams(uint128 timestamp) external returns (address[]);
    }
}
