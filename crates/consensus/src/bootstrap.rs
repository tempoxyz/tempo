//! Consensus bootstrap file layout and helpers.

use std::path::{Path, PathBuf};

use commonware_codec::DecodeExt as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use eyre::WrapErr as _;

use crate::consensus::Digest;

pub(crate) const FINALIZATION_PATH: &str = "bootstrap/finalization.cert";

pub(crate) fn read_bootstrap_finalization(
    consensus_dir: &Path,
) -> eyre::Result<Option<Finalization<Scheme<PublicKey, MinSig>, Digest>>> {
    let path = consensus_dir.join(FINALIZATION_PATH);
    if !std::fs::exists(path.clone()).wrap_err("could not determine file existence")? {
        return Ok(None);
    }

    let bytes = std::fs::read(path).wrap_err("failed to read file")?;
    let finalization = Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(bytes.as_ref())
        .wrap_err("malformed finalization")?;

    Ok(Some(finalization))
}

pub fn write_bootstrap_finalization(
    consensus_dir: &Path,
    finalization: &[u8],
) -> eyre::Result<PathBuf> {
    let path = consensus_dir.join(FINALIZATION_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create dir: {}", parent.display()))?;
    }

    std::fs::write(&path, finalization)
        .wrap_err_with(|| format!("failed to write finalization to {}", path.display()))?;

    Ok(path)
}
