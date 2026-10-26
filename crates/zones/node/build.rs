#![allow(missing_docs)]

use std::{env, error::Error};

use smolgen::{Build, Cargo, Emitter, Gitcl};

fn main() -> Result<(), Box<dyn Error>> {
    let mut emitter = Emitter::default();

    let build_builder = Build::builder().build_timestamp(true).build();
    emitter.add_instructions(&build_builder)?;

    let cargo_builder = Cargo::builder().features(true).target_triple(true).build();
    emitter.add_instructions(&cargo_builder)?;

    // Tracking the git HEAD reruns this script, and rebuilds everything above this crate, on every
    // commit and checkout. Debug builds skip it and keep the SHA from the last run of this script.
    // Release profiles keep tracking HEAD, so their version always matches the checkout.
    let git_builder = Gitcl::builder()
        .describe(false, true, Some("zones/v[0-9]*"))
        .dirty(true)
        .sha(false)
        .rerun_on_head_change(env::var("PROFILE")? != "debug")
        .build();
    emitter.add_instructions(&git_builder)?;

    emitter.emit_and_set()?;
    let sha = env::var("VERGEN_GIT_SHA")?;
    let sha_short = &sha[0..7];

    let is_dirty = env::var("VERGEN_GIT_DIRTY").is_ok_and(|dirty| dirty == "true");
    let not_on_tag = env::var("VERGEN_GIT_DESCRIBE")
        .map(|describe| {
            !describe.starts_with("zones/v")
                || describe
                    .rsplit_once("-g")
                    .is_some_and(|(_, hash)| sha.starts_with(hash))
        })
        .unwrap_or(true);
    let version_suffix = if is_dirty || not_on_tag { "-dev" } else { "" };
    println!("cargo:rustc-env=RETH_VERSION_SUFFIX={version_suffix}");

    println!("cargo:rustc-env=VERGEN_GIT_SHA_SHORT={}", &sha[..8]);

    let out_dir = env::var("OUT_DIR")?;
    let profile = out_dir
        .rsplit(std::path::MAIN_SEPARATOR)
        .nth(3)
        .ok_or("build profile missing from OUT_DIR")?;
    println!("cargo:rustc-env=RETH_BUILD_PROFILE={profile}");

    let pkg_version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=RETH_SHORT_VERSION={pkg_version}{version_suffix} ({sha_short})");
    println!("cargo:rustc-env=RETH_LONG_VERSION_0=Version: {pkg_version}{version_suffix}");
    println!("cargo:rustc-env=RETH_LONG_VERSION_1=Commit SHA: {sha}");
    println!(
        "cargo:rustc-env=RETH_LONG_VERSION_2=Build Timestamp: {}",
        env::var("VERGEN_BUILD_TIMESTAMP")?
    );
    println!(
        "cargo:rustc-env=RETH_LONG_VERSION_3=Build Features: {}",
        env::var("VERGEN_CARGO_FEATURES")?
    );
    println!("cargo:rustc-env=RETH_LONG_VERSION_4=Build Profile: {profile}");
    println!(
        "cargo:rustc-env=RETH_P2P_CLIENT_VERSION={}",
        format_args!(
            "tempo-zone/v{pkg_version}-{sha_short}/{}",
            env::var("VERGEN_CARGO_TARGET_TRIPLE")?
        )
    );

    Ok(())
}
