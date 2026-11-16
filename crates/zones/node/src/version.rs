use std::env;

pub use reth_node_core::version::RethCliVersionConsts;
use reth_node_core::version::{
    try_init_version_metadata, version_metadata as global_version_metadata,
};

/// The globally configured Tempo Zone client identity.
pub fn client_version() -> &'static str {
    global_version_metadata().p2p_client_version.as_ref()
}

/// Sets version information for Tempo Zone globally.
///
/// The version information is read by the CLI and node services. Binaries build it with [`zone_version_metadata!`].
pub fn init_version_metadata(metadata: RethCliVersionConsts) {
    try_init_version_metadata(metadata)
        .expect("version metadata is set once, before anything reads it");
}

/// The version information for Tempo Zone, stamped by the calling binary's build script.
///
/// Version metadata changes with every commit, and the build timestamp with every build. Stamped
/// in this library, it would rebuild every crate that depends on it, so each binary's build script
/// stamps it and the binary expands this macro.
#[macro_export]
macro_rules! zone_version_metadata {
    () => {
        $crate::version::RethCliVersionConsts {
            name_client: ::std::borrow::Cow::Borrowed("Tempo Zone"),
            cargo_pkg_version: ::std::borrow::Cow::Borrowed(env!("CARGO_PKG_VERSION")),
            vergen_git_sha_long: ::std::borrow::Cow::Borrowed(env!("VERGEN_GIT_SHA")),
            vergen_git_sha: ::std::borrow::Cow::Borrowed(env!("VERGEN_GIT_SHA_SHORT")),
            vergen_build_timestamp: ::std::borrow::Cow::Borrowed(env!("VERGEN_BUILD_TIMESTAMP")),
            vergen_cargo_target_triple: ::std::borrow::Cow::Borrowed(env!(
                "VERGEN_CARGO_TARGET_TRIPLE"
            )),
            vergen_cargo_features: ::std::borrow::Cow::Borrowed(env!("VERGEN_CARGO_FEATURES")),
            short_version: ::std::borrow::Cow::Borrowed(env!("RETH_SHORT_VERSION")),
            long_version: ::std::borrow::Cow::Borrowed(concat!(
                env!("RETH_LONG_VERSION_0"),
                "\n",
                env!("RETH_LONG_VERSION_1"),
                "\n",
                env!("RETH_LONG_VERSION_2"),
                "\n",
                env!("RETH_LONG_VERSION_3"),
                "\n",
                env!("RETH_LONG_VERSION_4"),
            )),
            build_profile_name: ::std::borrow::Cow::Borrowed(env!("RETH_BUILD_PROFILE")),
            p2p_client_version: ::std::borrow::Cow::Borrowed(env!("RETH_P2P_CLIENT_VERSION")),
            extra_data: ::std::borrow::Cow::Owned($crate::version::extra_data()),
        }
    };
}

/// The extra data Tempo Zone puts in the blocks it builds.
pub fn extra_data() -> String {
    format!(
        "tempo-zone/v{}/{}",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::OperatorWeb3Api;
    use jsonrpsee::types::{Response, response::Success};
    use reth_rpc_api::Web3ApiServer as _;

    #[tokio::test]
    async fn serves_the_configured_client_version() {
        let p2p_client_version = format!("tempo-zone/v{}-test", env!("CARGO_PKG_VERSION"));
        init_version_metadata(RethCliVersionConsts {
            name_client: "Tempo Zone".into(),
            p2p_client_version: p2p_client_version.clone().into(),
            extra_data: extra_data().into(),
            ..Default::default()
        });

        assert_eq!(
            extra_data(),
            format!(
                "tempo-zone/v{}/{}",
                env!("CARGO_PKG_VERSION"),
                env::consts::OS
            )
        );
        assert_eq!(client_version(), p2p_client_version);

        let (response, _) = OperatorWeb3Api
            .into_rpc()
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}"#,
                1,
            )
            .await
            .expect("operator client version should be available");
        let response = serde_json::from_str::<Response<'_, String>>(&response).unwrap();
        assert_eq!(
            Success::try_from(response).unwrap().result,
            client_version()
        );
    }
}
