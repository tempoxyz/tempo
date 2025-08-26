use alloy::primitives::{Address, address};

pub const MULTICALL_ADDRESS: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");

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
