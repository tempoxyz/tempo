use reth_ethereum::node::core::version::RethCliVersionConsts;
use std::borrow::Cow;

pub(crate) fn tempo() -> RethCliVersionConsts {
    RethCliVersionConsts {
        name_client: Cow::Borrowed("Reth"),
        cargo_pkg_version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
        vergen_git_sha_long: Cow::Borrowed(env!("VERGEN_GIT_SHA")),
        vergen_git_sha: Cow::Borrowed(env!("VERGEN_GIT_SHA_SHORT")),
        vergen_build_timestamp: Cow::Borrowed(env!("VERGEN_BUILD_TIMESTAMP")),
        vergen_cargo_target_triple: Cow::Borrowed(env!("VERGEN_CARGO_TARGET_TRIPLE")),
        vergen_cargo_features: Cow::Borrowed(env!("VERGEN_CARGO_FEATURES")),
        short_version: Cow::Borrowed(env!("RETH_SHORT_VERSION")),
        long_version: Cow::Owned(format!(
            "{}\n{}\n{}\n{}\n{}",
            env!("RETH_LONG_VERSION_0"),
            env!("RETH_LONG_VERSION_1"),
            env!("RETH_LONG_VERSION_2"),
            env!("RETH_LONG_VERSION_3"),
            env!("RETH_LONG_VERSION_4"),
        )),

        build_profile_name: Cow::Borrowed(env!("RETH_BUILD_PROFILE")),
        p2p_client_version: Cow::Borrowed(env!("RETH_P2P_CLIENT_VERSION")),
        extra_data: Cow::Owned(extra_data()),
    }
}

fn extra_data() -> String {
    format!(
        "reth/v{}/{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    )
}
