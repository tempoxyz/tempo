use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP4217Registry {
        function getCurrencyDecimals(string memory currency) external view returns (uint8);
    }
}
