//! Crash-safe checkpoint publication. The filesystem is trusted locally, not rollback-resistant.

use crate::{HeadTracker, config::Network};
use alloy_primitives::{B256, keccak256};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};
use tempo_finality::{CertifiedHeader, NetworkIdentity};

const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Most recent transition. Earlier authenticated identity context is trusted local checkpoint data;
/// this is not a self-contained proof chain back to genesis after arbitrary key rotations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transition {
    pub previous_identity: NetworkIdentity,
    pub boundary: CertifiedHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub network: Network,
    pub identity: NetworkIdentity,
    pub head: CertifiedHeader,
    pub transition: Option<Transition>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEnvelope {
    checkpoint: Checkpoint,
    checksum: B256,
}

/// One writer per datadir. The lock lives for the entire client lifetime, not just publication.
pub struct Store {
    dir: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        let existing = dir
            .ancestors()
            .find(|path| path.exists())
            .map(Path::to_path_buf);
        fs::create_dir_all(&dir).map_err(|_| Error::Io)?;
        if let Some(existing) = existing {
            for parent in dir.ancestors() {
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| Error::Io)?;
                if parent == existing {
                    break;
                }
            }
        }
        let lock = private_file(&dir.join("lock"))?;
        lock.try_lock().map_err(|_| Error::Locked)?;
        Ok(Self { dir, _lock: lock })
    }

    pub fn load(&self, network: &Network) -> Result<Option<Checkpoint>, Error> {
        let path = self.dir.join("checkpoint.json");
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Io),
        };
        if file.metadata().map_err(|_| Error::Io)?.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let envelope: FileEnvelope = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let payload = serde_json::to_vec(&envelope.checkpoint).map_err(|_| Error::Invalid)?;
        if keccak256(payload) != envelope.checksum || envelope.checkpoint.version != 1 {
            return Err(Error::Invalid);
        }
        if &envelope.checkpoint.network != network {
            return Err(Error::NetworkMismatch);
        }
        envelope.checkpoint.restore()?;
        Ok(Some(envelope.checkpoint))
    }

    /// Sync file contents, rename atomically, then sync the containing directory before returning.
    /// A failure after rename is still a failed durable publication; callers must not advertise it.
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<(), Error> {
        let payload = serde_json::to_vec(checkpoint).map_err(|_| Error::Invalid)?;
        let bytes = serde_json::to_vec(&FileEnvelope {
            checkpoint: checkpoint.clone(),
            checksum: keccak256(payload),
        })
        .map_err(|_| Error::Invalid)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let mut file = private_file(&self.dir.join("checkpoint.tmp"))?;
        file.set_len(0).map_err(|_| Error::Io)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Io)?;
        fs::rename(
            self.dir.join("checkpoint.tmp"),
            self.dir.join("checkpoint.json"),
        )
        .map_err(|_| Error::Io)?;
        File::open(&self.dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::Io)
    }
}

impl Checkpoint {
    pub fn restore(&self) -> Result<HeadTracker, Error> {
        self.network.validate().map_err(|_| Error::Invalid)?;
        if self.version != 1 {
            return Err(Error::Invalid);
        }
        let mut rng: rand::rngs::StdRng = rand::make_rng();
        if let Some(transition) = &self.transition {
            let mut verifier = HeadTracker::new(
                transition.previous_identity.clone(),
                self.network.epoch_length,
            );
            verifier
                .authenticate_transition(&mut rng, &transition.boundary)
                .map_err(|_| Error::Invalid)?;
            if verifier.identity() != &self.identity {
                return Err(Error::Invalid);
            }
        } else if self.identity != self.network.anchor {
            return Err(Error::Invalid);
        }
        let mut tracker = HeadTracker::new(self.identity.clone(), self.network.epoch_length);
        tracker
            .accept(&mut rng, self.head.clone())
            .map_err(|_| Error::Invalid)?;
        Ok(tracker)
    }
}

fn private_file(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| Error::Io)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("light checkpoint storage I/O or durability failure")]
    Io,
    #[error("light datadir is already locked by another client")]
    Locked,
    #[error("light checkpoint is corrupt, unverifiable, oversized, or has an unknown format")]
    Invalid,
    #[error("light checkpoint belongs to different configured network/trust/layout parameters")]
    NetworkMismatch,
}
