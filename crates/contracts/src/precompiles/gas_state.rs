pub use ITIP1060StorageCredits::{
    ITIP1060StorageCreditsErrors as TIP1060StorageCreditsError,
    ITIP1060StorageCreditsEvents as TIP1060StorageCreditsEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP1060StorageCredits {
        enum Mode {
            Refund,
            Preserve,
            Direct
        }

        error InvalidMode();

        event ModeUpdated(address indexed account, Mode newMode);

        function balance() external view returns (uint64);
        function balanceOf(address account) external view returns (uint64);

        function mode() external view returns (Mode);
        function modeOf(address account) external view returns (Mode);

        function setMode(Mode newMode) external;
    }
}
