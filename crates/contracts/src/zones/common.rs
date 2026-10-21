pub use crate::precompiles::{IRolesAuth::Unauthorized, IStablecoinDEX::InsufficientBalance};

crate::sol! {
    /// Returned when a nonzero caller accesses the registry through its EVM interface.
    #[derive(Debug, PartialEq, Eq)]
    error OnlyPrecompiles();

    /// Returned when a call would update or migrate a configurable account on a Zone.
    #[derive(Debug, PartialEq, Eq)]
    error ConfigurableAccountsNotSupported();
}
