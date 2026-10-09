pub use crate::precompiles::{IRolesAuth::Unauthorized, IStablecoinDEX::InsufficientBalance};

crate::sol! {
    /// Returned when a nonzero caller accesses the registry through its EVM interface.
    #[derive(Debug, PartialEq, Eq)]
    error OnlyPrecompiles();
}
