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
    /// Returns the canonical lowercase label for this storage credit mode.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Refund => "refund",
            Self::Preserve => "preserve",
            Self::Direct => "direct",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IStorageCredits;

    #[test]
    fn mode_as_str() {
        assert_eq!(IStorageCredits::Mode::Refund.as_str(), "refund");
        assert_eq!(IStorageCredits::Mode::Preserve.as_str(), "preserve");
        assert_eq!(IStorageCredits::Mode::Direct.as_str(), "direct");
    }
}
