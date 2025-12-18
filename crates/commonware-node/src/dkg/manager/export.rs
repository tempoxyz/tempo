//! Export functions for DKG signing share migration.
//!
//! This module provides functionality to export the signing share at epoch boundaries,
//! enabling coordinated network upgrades with breaking storage changes.

use std::path::Path;

use commonware_cryptography::bls12381::primitives::group::Share;
use eyre::{Result, WrapErr as _};
use tempo_commonware_node_config::SigningShare;
use tracing::info;

/// Write the signing share to a file in hex format.
///
/// The exported file can be used directly as `--consensus.signing-share` for a new node.
/// If the file already exists, it will be overwritten.
pub fn write_share_to_file(share: &Share, path: &Path) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).wrap_err("failed to create parent directories")?;
    }

    // Use SigningShare wrapper which writes hex-encoded with 0x prefix
    let signing_share = SigningShare::from(share.clone());
    signing_share
        .write_to_file(path)
        .wrap_err("failed to write signing share")?;

    info!(
        path = %path.display(),
        "wrote signing share to file"
    );

    Ok(())
}
