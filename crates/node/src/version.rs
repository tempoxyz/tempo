use reth_ethereum::node::core::version::RethCliVersionConsts;
use reth_node_core::version::try_init_version_metadata;
use std::{borrow::Cow, env};

/// Sets version information for Tempo globally.
///
/// The version information is read by the CLI.
pub fn init_version_metadata(build_timestamp: &'static str) {
    try_init_version_metadata(version_metadata(build_timestamp))
        .expect("Version metadata should be generated in `build.rs`");
}

/// The version information for Tempo.
pub fn version_metadata(build_timestamp: &'static str) -> RethCliVersionConsts {
    RethCliVersionConsts {
        name_client: Cow::Borrowed("Tempo"),
        cargo_pkg_version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
        vergen_git_sha_long: Cow::Borrowed(env!("VERGEN_GIT_SHA")),
        vergen_git_sha: Cow::Borrowed(env!("VERGEN_GIT_SHA_SHORT")),
        vergen_build_timestamp: Cow::Borrowed(build_timestamp),
        vergen_cargo_target_triple: Cow::Borrowed(env!("VERGEN_CARGO_TARGET_TRIPLE")),
        vergen_cargo_features: Cow::Borrowed(env!("VERGEN_CARGO_FEATURES")),
        short_version: Cow::Borrowed(env!("RETH_SHORT_VERSION")),
        long_version: Cow::Owned(format!(
            "{}\n{}\nBuild Timestamp: {build_timestamp}\n{}\n{}",
            env!("RETH_LONG_VERSION_0"),
            env!("RETH_LONG_VERSION_1"),
            env!("RETH_LONG_VERSION_2"),
            env!("RETH_LONG_VERSION_3"),
        )),

        build_profile_name: Cow::Borrowed(env!("RETH_BUILD_PROFILE")),
        p2p_client_version: Cow::Borrowed(env!("RETH_P2P_CLIENT_VERSION")),
        extra_data: Cow::Owned(extra_data()),
    }
}

fn extra_data() -> String {
    format!("tempo/v{}/{}", env!("CARGO_PKG_VERSION"), env::consts::OS)
}
