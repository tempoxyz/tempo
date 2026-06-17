pub use IStorageCredits::{
    IStorageCreditsErrors as StorageCreditsError, IStorageCreditsEvents as StorageCreditsEvent,
};

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

        event ModeUpdated(address indexed account, Mode newMode);

        function balanceOf(address account) external view returns (uint64);
        function modeOf(address account) external view returns (Mode);
        function budgetOf(address account) external view returns (uint64);

        function setMode(Mode newMode) external;
        function setBudget(uint64 creditBudget) external;
    }
}
