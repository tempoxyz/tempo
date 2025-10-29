pub use ITIP20RewardsRegistry::ITIP20RewardsRegistryErrors as TIP20RewardsRegistryError;
use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface ITIP20RewardsRegistry {
        /// Finalize streams for all tokens ending at the current timestamp
        function finalizeStreams() external;

        error Unauthorized();
    }
}

impl TIP20RewardsRegistryError {
    /// Creates an unauthorized access error.
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITIP20RewardsRegistry::Unauthorized {})
    }
}
