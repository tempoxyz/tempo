use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface ITIP4217Registry {
        function getCurrencyDecimals(string currency) external view returns (uint8);
    }
}
