//! Secret-safe preparation of a node's independent P2P and sequencer identities.

use std::path::PathBuf;

use alloy::signers::local::PrivateKeySigner;
use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_math::algebra::Random as _;
use eyre::{Context as _, ensure};
use serde::Serialize;

use super::secret_file::{WriteSecretOptions, encode_private_key, write_secret_file};

const P2P_KEY_FILE: &str = "p2p.key";
const SEQUENCER_KEY_FILE: &str = "sequencer.key";

#[derive(Debug, clap::Parser)]
pub(crate) struct Identity {
    #[command(subcommand)]
    command: IdentityCommand,
}

#[derive(Debug, clap::Subcommand)]
enum IdentityCommand {
    /// Generate independent P2P and individual sequencer keys for one node.
    Prepare(Prepare),
}

impl Identity {
    pub(crate) fn run(self) -> eyre::Result<()> {
        match self.command {
            IdentityCommand::Prepare(command) => command.run(),
        }
    }
}

#[derive(Debug, clap::Parser)]
struct Prepare {
    /// Directory that receives p2p.key and sequencer.key.
    #[arg(long)]
    rotation_dir: PathBuf,

    /// Node name recorded in the report.
    #[arg(long)]
    node: String,

    /// Replace both generated key files if either already exists.
    #[arg(long)]
    force: bool,

    /// Emit a stable machine-readable report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareReport {
    ok: bool,
    node: String,
    p2p_key_path: String,
    sequencer_key_path: String,
    p2p_public_key: String,
    sequencer_address: alloy::primitives::Address,
}

impl Prepare {
    fn run(self) -> eyre::Result<()> {
        ensure!(!self.node.trim().is_empty(), "--node cannot be empty");

        let p2p_path = self.rotation_dir.join(P2P_KEY_FILE);
        let sequencer_path = self.rotation_dir.join(SEQUENCER_KEY_FILE);
        if !self.force {
            ensure!(
                !p2p_path.exists() && !sequencer_path.exists(),
                "identity output already exists in {}; choose an empty directory or pass --force",
                self.rotation_dir.display()
            );
        }

        std::fs::create_dir_all(&self.rotation_dir).wrap_err_with(|| {
            format!(
                "failed creating rotation directory {}",
                self.rotation_dir.display()
            )
        })?;

        // These keys intentionally come from different algorithms and independent RNG draws.
        let p2p_key = PrivateKey::random(rand::rng());
        let sequencer_key = PrivateKeySigner::random();
        let p2p_encoded = format!(
            "{}\n",
            const_hex::encode_prefixed(p2p_key.encode().as_ref())
        );
        let options = WriteSecretOptions {
            overwrite: self.force,
        };
        write_secret_file(&p2p_path, p2p_encoded.as_bytes(), options)?;
        if let Err(error) = write_secret_file(
            &sequencer_path,
            encode_private_key(&sequencer_key).as_bytes(),
            options,
        ) {
            // With --force the old destination was atomically replaced, so leaving the new P2P
            // key is safer than pretending the operation was transactional. Without --force,
            // the destination preflight guarantees this only handles an unexpected race/error.
            return Err(error).wrap_err("P2P key was written but sequencer key creation failed");
        }

        let report = PrepareReport {
            ok: true,
            node: self.node,
            p2p_key_path: p2p_path.display().to_string(),
            sequencer_key_path: sequencer_path.display().to_string(),
            p2p_public_key: const_hex::encode_prefixed(p2p_key.public_key().as_ref()),
            sequencer_address: sequencer_key.address(),
        };
        if self.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("Prepared replacement identity for {}", report.node);
            println!("  P2P key: {}", report.p2p_key_path);
            println!("  Sequencer key: {}", report.sequencer_key_path);
            println!("  P2P public key: {}", report.p2p_public_key);
            println!("  Sequencer address: {}", report.sequencer_address);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use alloy::signers::local::PrivateKeySigner;

    use super::{P2P_KEY_FILE, Prepare, SEQUENCER_KEY_FILE};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tempo-xtask-identity-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn prepare_writes_distinct_owner_only_key_files_and_refuses_overwrite() {
        let directory = TestDirectory::new();
        let rotation_dir = directory.path().join("node-a");
        Prepare {
            rotation_dir: rotation_dir.clone(),
            node: "node-a".to_owned(),
            force: false,
            json: true,
        }
        .run()
        .unwrap();

        let p2p = fs::read_to_string(rotation_dir.join(P2P_KEY_FILE)).unwrap();
        let sequencer = fs::read_to_string(rotation_dir.join(SEQUENCER_KEY_FILE)).unwrap();
        assert!(p2p.trim().starts_with("0x"));
        assert_eq!(p2p.trim().len(), 66);
        assert!(sequencer.trim().parse::<PrivateKeySigner>().is_ok());
        assert_ne!(p2p, sequencer);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(rotation_dir.join(P2P_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(rotation_dir.join(SEQUENCER_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let error = Prepare {
            rotation_dir,
            node: "node-a".to_owned(),
            force: false,
            json: true,
        }
        .run()
        .unwrap_err();
        assert!(error.to_string().contains("identity output already exists"));
    }
}
