//! Tempo predeployed contracts and bindings.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_primitives::{Address, B256, address, b256};

/// Default address for the Multicall3 contract on most chains. See: <https://github.com/mds1/multicall>
pub const MULTICALL3_ADDRESS: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
pub const SAFE_DEPLOYER_ADDRESS: Address = address!("0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7");
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022d473030f116ddee9f6b43ac78ba3");
pub const PERMIT2_SALT: B256 =
    b256!("0x0000000000000000000000000000000000000000d3af2663da51c10215000000");
pub const ARACHNID_CREATE2_FACTORY_ADDRESS: Address =
    address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// Helper macro to allow feature-gating rpc implementations behind the `rpc` feature.
macro_rules! sol {
    ($($input:tt)*) => {
        #[cfg(feature = "rpc")]
        alloy_sol_types::sol! {
            #[sol(rpc)]
            $($input)*
        }
        #[cfg(not(feature = "rpc"))]
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
    //! Tests to verify that our predeployed contract bytecode matches Ethereum mainnet.
    //!
    //! These tests use alloy to fetch the code hash directly from Ethereum mainnet
    //! and compare against our stored bytecode hashes. This ensures we haven't accidentally
    //! deployed the wrong contract (e.g., Multicall instead of Multicall3).
    //!
    //! Run with:
    //! ```sh
    //! cargo test -p tempo-contracts
    //! ```
    //!
    //! Optionally set `ETH_RPC_URL` to use a custom RPC endpoint.

    use super::*;
    use alloy_primitives::{B256, keccak256};
    use alloy_provider::{Provider, ProviderBuilder};

    /// Default public RPC URL for Ethereum mainnet.
    const DEFAULT_ETH_RPC_URL: &str = "https://eth.llamarpc.com";

    /// Returns the Ethereum mainnet RPC URL from the `ETH_RPC_URL` environment variable,
    /// or falls back to a default public RPC.
    fn get_rpc_url() -> String {
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| DEFAULT_ETH_RPC_URL.to_string())
    }

    /// Fetches the code hash for an address from Ethereum mainnet using alloy provider.
    async fn get_mainnet_code_hash(address: Address) -> B256 {
        let rpc_url = get_rpc_url();
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

        let code = provider
            .get_code_at(address)
            .await
            .expect("Failed to fetch code from mainnet");
        keccak256(&code)
    }

    #[tokio::test]
    #[ignore = "requires mainnet RPC access - not needed after mainnet launch"]
    async fn multicall3_bytecode_matches_mainnet() {
        // Verify our hash constant matches our bytecode
        let computed_hash = keccak256(&Multicall3::DEPLOYED_BYTECODE);
        let stored_hash = contracts::MULTICALL3_DEPLOYED_BYTECODE_HASH;
        assert_eq!(
            computed_hash, stored_hash,
            "MULTICALL3_DEPLOYED_BYTECODE_HASH does not match the actual bytecode!\n\
             Computed: {computed_hash}\n\
             Stored:   {stored_hash}"
        );

        // Verify our bytecode matches mainnet
        let mainnet_hash = get_mainnet_code_hash(MULTICALL3_ADDRESS).await;
        assert_eq!(
            mainnet_hash, stored_hash,
            "Multicall3 bytecode hash mismatch!\n\
             Mainnet: {mainnet_hash}\n\
             Ours:    {stored_hash}\n\
             This likely means we have the wrong bytecode for Multicall3."
        );
    }

    #[tokio::test]
    #[ignore = "requires mainnet RPC access - not needed after mainnet launch"]
    async fn createx_bytecode_matches_mainnet() {
        // Verify our hash constant matches our bytecode
        let computed_hash = keccak256(&CreateX::DEPLOYED_BYTECODE);
        let stored_hash = contracts::CREATEX_BYTECODE_HASH;
        assert_eq!(
            computed_hash, stored_hash,
            "CREATEX_BYTECODE_HASH does not match the actual bytecode!\n\
             Computed: {computed_hash}\n\
             Stored:   {stored_hash}"
        );

        // Verify our bytecode matches mainnet
        let mainnet_hash = get_mainnet_code_hash(CREATEX_ADDRESS).await;
        assert_eq!(
            mainnet_hash, stored_hash,
            "CreateX bytecode hash mismatch!\n\
             Mainnet: {mainnet_hash}\n\
             Ours:    {stored_hash}\n\
             This likely means we have the wrong bytecode for CreateX."
        );
    }

    #[tokio::test]
    #[ignore = "requires mainnet RPC access - not needed after mainnet launch"]
    async fn arachnid_create2_factory_bytecode_matches_mainnet() {
        let mainnet_hash = get_mainnet_code_hash(ARACHNID_CREATE2_FACTORY_ADDRESS).await;
        let our_hash = keccak256(&contracts::ARACHNID_CREATE2_FACTORY_BYTECODE);

        assert_eq!(
            mainnet_hash, our_hash,
            "Arachnid CREATE2 factory bytecode hash mismatch!\n\
             Mainnet: {mainnet_hash}\n\
             Ours:    {our_hash}\n\
             This likely means we have the wrong bytecode for Arachnid CREATE2 factory."
        );
    }

    #[tokio::test]
    #[ignore = "requires mainnet RPC access - not needed after mainnet launch"]
    async fn safe_deployer_bytecode_matches_mainnet() {
        let mainnet_hash = get_mainnet_code_hash(SAFE_DEPLOYER_ADDRESS).await;
        let our_hash = keccak256(&SafeDeployer::DEPLOYED_BYTECODE);

        assert_eq!(
            mainnet_hash, our_hash,
            "SafeDeployer bytecode hash mismatch!\n\
             Mainnet: {mainnet_hash}\n\
             Ours:    {our_hash}\n\
             This likely means we have the wrong bytecode for SafeDeployer."
        );
    }
}
