//! Tempo predeployed contracts and bindings.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy::primitives::{Address, address};

pub const MULTICALL_ADDRESS: Address = alloy::providers::MULTICALL3_ADDRESS;
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");
pub const DEFAULT_7702_DELEGATE_ADDRESS: Address =
    address!("0x7702c00000000000000000000000000000000000");

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

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IthacaAccount,
        "abi/IthacaAccount.json",
    );
}

pub use contracts::{CreateX, IthacaAccount, Multicall, Permit2};
