use alloy::primitives::{Address};

pub const MULTICALL_ADDRESS: Address = alloy::providers::MULTICALL3_ADDRESS;

pub mod contracts {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        Multicall,
        "abi/Multicall.json",
    );
}

pub use contracts::Multicall;
