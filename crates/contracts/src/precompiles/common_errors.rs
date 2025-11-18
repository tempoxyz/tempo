use alloy::sol;

sol! {
    /// Error returned when a function selector is not recognized
    #[derive(Debug, PartialEq, Eq)]
    error UnknownFunctionSelector(bytes4 selector);
}
