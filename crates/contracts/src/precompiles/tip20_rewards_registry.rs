pub use ITIP20RewardsRegistry::ITIP20RewardsRegistryErrors as TIP20RewardsRegistryError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP20RewardsRegistry {
        /// Finalize streams for all tokens ending at the current timestamp
        function finalizeStreams() external;

        error Unauthorized();
        error StreamsAlreadyFinalized();
    }
}

impl TIP20RewardsRegistryError {
    /// Creates an unauthorized access error.
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITIP20RewardsRegistry::Unauthorized {})
    }

    /// Creates an error for streams already finalized
    pub const fn streams_already_finalized() -> Self {
        Self::StreamsAlreadyFinalized(ITIP20RewardsRegistry::StreamsAlreadyFinalized {})
    }
}
