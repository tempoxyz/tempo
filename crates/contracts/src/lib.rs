//! Tempo predeployed contracts and bindings.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy::primitives::{Address, address};

pub const MULTICALL_ADDRESS: Address = alloy::providers::MULTICALL3_ADDRESS;
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
pub const SAFE_DEPLOYER_ADDRESS: Address = address!("0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7");
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");
pub const DEFAULT_7702_DELEGATE_ADDRESS: Address =
    address!("0x7702c00000000000000000000000000000000000");
pub const ARACHNID_CREATE2_FACTORY_ADDRESS: Address =
    address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

pub mod contracts {
    use alloy::{
        primitives::{Bytes, bytes},
        sol,
    };

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

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SafeDeployer,
        "abi/SafeDeployer.json",
    );

    pub const ARACHNID_CREATE2_FACTORY_BYTECODE: Bytes = bytes!(
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
    );
}

pub use contracts::{CreateX, IthacaAccount, Multicall, Permit2, SafeDeployer};

pub mod precompiles;
