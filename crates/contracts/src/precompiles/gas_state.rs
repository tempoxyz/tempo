pub use IStorageGasTokens::{
    IStorageGasTokensErrors as StorageGasTokensError,
    IStorageGasTokensEvents as StorageGasTokensEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IStorageGasTokens {
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
