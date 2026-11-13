//! Tempo predeployed contracts and bindings.

#![no_std]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
// auto-generated sol! builders for events/errors with many fields trigger this
#![allow(clippy::too_many_arguments)]

extern crate alloc;

pub use tempo_hardfork::TempoHardfork;

use alloy_primitives::{Address, B256, address, b256};

pub mod zones;

/// Default address for the Multicall3 contract on most chains. See: <https://github.com/mds1/multicall>
pub const MULTICALL3_ADDRESS: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
pub const SAFE_DEPLOYER_ADDRESS: Address = address!("0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7");
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");
pub const PERMIT2_SALT: B256 =
    b256!("0x0000000000000000000000000000000000000000d3af2663da51c10215000000");
pub const ARACHNID_CREATE2_FACTORY_ADDRESS: Address =
    address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// Helper macro to allow feature-gating rpc and serde implementations.
macro_rules! sol {
    ($($input:tt)*) => {
        #[cfg(all(feature = "rpc", feature = "serde"))]
        alloy_sol_types::sol! {
            #![sol(rpc, extra_derives(serde::Serialize, serde::Deserialize))]
            $($input)*
        }
        #[cfg(all(feature = "rpc", not(feature = "serde")))]
        alloy_sol_types::sol! {
            #![sol(rpc)]
            $($input)*
        }
        #[cfg(all(not(feature = "rpc"), feature = "serde"))]
        alloy_sol_types::sol! {
            #![sol(extra_derives(serde::Serialize, serde::Deserialize))]
            $($input)*
        }
        #[cfg(all(not(feature = "rpc"), not(feature = "serde")))]
        alloy_sol_types::sol! {
            $($input)*
        }
    };
}

pub(crate) use sol;

pub mod contracts {
    use alloy_primitives::{B256, Bytes, b256, bytes};

    sol!(
        #[allow(missing_docs)]
        CreateX,
        "abi/CreateX.json",
    );

    /// Keccak256 hash of CreateX deployed bytecode
    pub const CREATEX_BYTECODE_HASH: B256 =
        b256!("0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f");

    sol!(
        #[allow(missing_docs)]
        Permit2,
        "abi/Permit2.json"
    );

    sol!(
        #[allow(missing_docs)]
        SafeDeployer,
        "abi/SafeDeployer.json",
    );

    pub const ARACHNID_CREATE2_FACTORY_BYTECODE: Bytes = bytes!(
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
    );

    sol!(
        #[allow(missing_docs)]
        Multicall3,
        "abi/Multicall3.json",
    );

    /// Keccak256 hash of Multicall3 deployed bytecode
    pub const MULTICALL3_DEPLOYED_BYTECODE_HASH: B256 =
        b256!("0xd5c15df687b16f2ff992fc8d767b4216323184a2bbc6ee2f9c398c318e770891");
}

pub use contracts::{CreateX, Multicall3, Permit2, SafeDeployer};

pub mod precompiles;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn deployed_bytecode_hashes_match_constants() {
        assert_eq!(
            keccak256(&Multicall3::DEPLOYED_BYTECODE),
            contracts::MULTICALL3_DEPLOYED_BYTECODE_HASH,
            "MULTICALL3_DEPLOYED_BYTECODE_HASH does not match the actual bytecode"
        );
        assert_eq!(
            keccak256(&CreateX::DEPLOYED_BYTECODE),
            contracts::CREATEX_BYTECODE_HASH,
            "CREATEX_BYTECODE_HASH does not match the actual bytecode"
        );
    }
}
