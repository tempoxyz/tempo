pub use reth_node_core::version::RethCliVersionConsts;
use reth_node_core::version::try_init_version_metadata;
use std::env;

/// Sets version information for Tempo globally.
///
/// The version information is read by the CLI. Binaries build it with [`tempo_version_metadata!`](crate::tempo_version_metadata).
pub fn init_version_metadata(metadata: RethCliVersionConsts) {
    try_init_version_metadata(metadata)
        .expect("version metadata is set once, before anything reads it");
}

/// The version information for Tempo, stamped by the calling binary's build script.
///
/// Version metadata changes with every commit, and the build timestamp with every build. Stamped
/// in this library, it would rebuild every crate that depends on it, so each binary's build script
/// stamps it and the binary expands this macro.
#[macro_export]
macro_rules! tempo_version_metadata {
    () => {
        $crate::version::RethCliVersionConsts {
            name_client: ::std::borrow::Cow::Borrowed("Tempo"),
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

/// The extra data Tempo puts in the blocks it builds.
pub fn extra_data() -> String {
    format!("tempo/v{}/{}", env!("CARGO_PKG_VERSION"), env::consts::OS)
}
