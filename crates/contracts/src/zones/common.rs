crate::sol! {
    /// Generic unauthorized access error used by zone wrapper logic.
    #[derive(Debug)]
    error Unauthorized();

    /// Returned when a nonzero caller accesses the registry through its EVM interface.
    #[derive(Debug, PartialEq, Eq)]
    error OnlyPrecompiles();

    /// Replaces the upstream balance error to hide the user's balance from the spender.
    error InsufficientBalance();
}
