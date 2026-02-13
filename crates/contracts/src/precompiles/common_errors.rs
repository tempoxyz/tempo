#[allow(unused_imports)]
use alloc::string::String;

crate::sol! {
    /// Error returned when a function selector is not recognized
    #[derive(Debug, PartialEq, Eq)]
    error UnknownFunctionSelector(bytes4 selector);
}
