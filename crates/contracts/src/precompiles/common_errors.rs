pub use ICommonPrecompileErrors::ICommonPrecompileErrorsErrors as CommonPrecompileError;

use alloy::sol;

sol! {
    /// Common errors shared across all precompiles
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ICommonPrecompileErrors {
        /// Error returned when a function selector is not recognized
        error UnknownFunctionSelector(bytes4 selector);
    }
}

impl CommonPrecompileError {
    /// Creates an error for unknown function selector
    pub fn unknown_function_selector(selector: [u8; 4]) -> Self {
        Self::UnknownFunctionSelector(ICommonPrecompileErrors::UnknownFunctionSelector {
            selector: selector.into(),
        })
    }
}
