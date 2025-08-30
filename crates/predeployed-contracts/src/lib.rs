//! Tempo predeployed contracts and bindings.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy::primitives::Address;

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
