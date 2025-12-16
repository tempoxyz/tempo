//! Export types and functions for DKG state migration.
//!
//! This module provides functionality to export DKG state at epoch boundaries,
//! enabling coordinated network upgrades with breaking storage changes.

use std::{fs::OpenOptions, io::Write, path::Path};

use alloy_primitives::hex;
use commonware_codec::Encode as _;
use commonware_runtime::{Clock, Metrics, Storage};
use eyre::{OptionExt as _, Result, WrapErr as _};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::dkg::manager::{
    actor::post_allegretto, read_write_transaction::DkgReadWriteTransaction,
};

/// Exported DKG state for migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgExport {
    /// The block height at which the export was taken.
    pub exported_at_height: u64,

    /// The floor height for the new node (first block of the next epoch).
    pub floor_height: u64,

    /// The epoch state containing DKG outcome.
    pub epoch_state: ExportedEpochState,
}

/// Exported epoch state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedEpochState {
    /// The epoch number.
    pub epoch: u64,

    /// Hex-encoded ed25519 public keys of participants.
    pub participants: Vec<String>,

    /// Hex-encoded BLS12-381 public polynomial.
    pub public_polynomial: String,

    /// Hex-encoded private share (if this node is a signer).
    pub private_share: Option<String>,
}

impl DkgExport {
    /// Export the current DKG state from the database.
    ///
    /// Only supports post-allegretto state.
    pub(crate) async fn from_db<TContext>(
        tx: &DkgReadWriteTransaction<TContext>,
        block_height: u64,
    ) -> Result<Self>
    where
        TContext: Clock + Metrics + Storage,
    {
        let epoch_state: post_allegretto::EpochState = tx
            .get_epoch()
            .await
            .wrap_err("failed to read epoch state")?
            .ok_or_eyre("epoch state not found")?;

        Ok(Self {
            exported_at_height: block_height,
            floor_height: block_height + 1,
            epoch_state: ExportedEpochState {
                epoch: epoch_state.dkg_outcome.epoch,
                participants: epoch_state
                    .dkg_outcome
                    .participants
                    .iter()
                    .map(|pk| hex::encode(pk.encode()))
                    .collect(),
                public_polynomial: hex::encode(epoch_state.dkg_outcome.public.encode()),
                private_share: epoch_state
                    .dkg_outcome
                    .share
                    .as_ref()
                    .map(|share| hex::encode(share.encode())),
            },
        })
    }

    /// Write the export to a file.
    ///
    /// If the file already exists, this is a no-op to prevent accidental overwrites.
    /// Uses atomic file creation to avoid TOCTOU race conditions.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).wrap_err_with(|| {
                format!(
                    "failed to create parent directories for: {}",
                    path.display()
                )
            })?;
        }

        // Use create_new(true) for atomic file creation - fails if file exists
        let file = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                info!(
                    path = %path.display(),
                    "DKG export file already exists; skipping write"
                );
                return Ok(());
            }
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!("failed to create DKG export file: {}", path.display())
                });
            }
        };

        let json = serde_json::to_string_pretty(self)
            .wrap_err("failed to serialize DKG export to JSON")?;

        let mut file = file;
        file.write_all(json.as_bytes())
            .wrap_err_with(|| format!("failed to write DKG export to file: {}", path.display()))?;
        file.sync_all()
            .wrap_err("failed to sync DKG export file to disk")?;

        info!(
            path = %path.display(),
            epoch = self.epoch_state.epoch,
            exported_at_height = self.exported_at_height,
            floor_height = self.floor_height,
            "wrote DKG export to file"
        );

        Ok(())
    }
}
