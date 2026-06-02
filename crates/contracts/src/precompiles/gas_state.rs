pub use ITIP1060StorageGasTokens::{
    ITIP1060StorageGasTokensErrors as TIP1060StorageGasTokensError,
    ITIP1060StorageGasTokensEvents as TIP1060StorageGasTokensEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP1060StorageGasTokens {
        enum Mode {
            RefundTokens,
            PreserveTokens,
            DirectTokens
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
