pub use IStorageCredits::IStorageCreditsErrors as StorageCreditsError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IStorageCredits {
        enum Mode {
            Refund,
            Preserve,
            Direct
        }

        error InvalidMode();
        error OnlyDirectCall();

        function balanceOf(address account) external view returns (uint64);
        function modeOf(address account) external view returns (Mode);
        function budgetOf(address account) external view returns (uint64);

        function setMode(Mode newMode) external;
        function setBudget(uint64 credits) external;
    }
}

impl IStorageCredits::Mode {
    /// Returns the lowercase string label for this mode.
    ///
    /// Returns `"unknown"` for Alloy's synthetic invalid variant, which represents an
    /// out-of-range decoded enum value.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Refund => "refund",
            Self::Preserve => "preserve",
            Self::Direct => "direct",
            Self::__Invalid => "unknown",
        }
    }
}
