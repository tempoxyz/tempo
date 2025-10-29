use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface ITIP20RewardsRegistry {
        /// Register a stream end time for a token
        function addStream(address token, uint128 endTime) external;

        /// Get all tokens with streams ending at a given timestamp
        function getStreamsEndingAtTimestamp(uint128 timestamp) external view returns (address[]);

        /// Finalize streams for all tokens ending at the current timestamp
        function finalizeStreams() external returns (address[]);
    }
}
