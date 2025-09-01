//! Tempo predeployed contracts and bindings.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy::primitives::{Address, address};

pub const MULTICALL_ADDRESS: Address = alloy::providers::MULTICALL3_ADDRESS;
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

pub mod contracts {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        Multicall,
        "abi/Multicall.json",
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        CreateX,
        "abi/CreateX.json",
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        Permit2,
        "abi/Permit2.json"
    );
}

pub use contracts::{CreateX, Multicall, Permit2};
