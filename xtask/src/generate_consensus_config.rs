use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use commonware_cryptography::{PrivateKeyExt as _, Signer as _, ed25519::PrivateKey};
use commonware_utils::set::OrderedAssociated;
use eyre::{WrapErr as _, ensure};
use rand::SeedableRng;
use tempo_commonware_node_config::{PeersAndPublicPolynomial, SigningKey, SigningShare};

/// Generates a config file to run a bunch of validators locally.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateConsensusConfig {
    /// The target directory that will be populated with validator configurations.
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,

    #[command(flatten)]
    consensus_args: ConsensusArgs,
}

#[derive(Debug, clap::Args)]
pub(crate) struct ConsensusArgs {
    /// A comma-separated list of <ip>:<port>.
    #[arg(long, value_name = "<ip>:<port>")]
    pub(crate) validators: Vec<SocketAddr>,
    /// A fixed seed to generate all signing keys and group shares. This is
    /// intended for use in development and testing. Use at your own peril.
    #[arg(long)]
    pub(crate) seed: Option<u64>,
}

impl ConsensusArgs {
    pub(crate) fn generate_consensus_config(self) -> eyre::Result<ConsensusConfig> {
        let Self { validators, seed } = self;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
        let mut signers = (0..validators.len())
            .map(|_| PrivateKey::from_rng(&mut rng))
            .collect::<Vec<_>>();
        signers.sort_by_key(|signer| signer.public_key());

        // generate consensus key
        let threshold = commonware_utils::quorum(validators.len() as u32);
        let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
            _,
            commonware_cryptography::bls12381::primitives::variant::MinSig,
        >(&mut rng, None, validators.len() as u32, threshold);

        let peers = validators
            .into_iter()
            .zip(signers.iter())
            .map(|(peer, private_key)| (private_key.public_key(), peer))
            .collect::<OrderedAssociated<_, _>>();

        let mut validators = vec![];
        for (addr, (signer, share)) in peers.values().iter().zip(signers.into_iter().zip(shares)) {
            validators.push(Validator {
                addr: addr.clone(),
                signing_key: SigningKey::from(signer),
                signing_share: SigningShare::from(share),
            });
        }
        Ok(ConsensusConfig {
            peers_and_public_polynomial: PeersAndPublicPolynomial {
                peers,
                public_polynomial: polynomial,
            },
            validators,
        })
    }
}

pub(crate) struct ConsensusConfig {
    pub(crate) peers_and_public_polynomial: PeersAndPublicPolynomial,
    pub(crate) validators: Vec<Validator>,
}

#[derive(Clone, Debug)]
pub(crate) struct Validator {
    pub(crate) addr: SocketAddr,
    pub(crate) signing_key: SigningKey,
    pub(crate) signing_share: SigningShare,
}

impl Validator {
    pub(crate) fn dst_dir(&self, path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(self.addr.to_string())
    }
    pub(crate) fn dst_signing_key(&self, path: impl AsRef<Path>) -> PathBuf {
        self.dst_dir(path).join("signing.key")
    }

    pub(crate) fn dst_signing_share(&self, path: impl AsRef<Path>) -> PathBuf {
        self.dst_dir(path).join("signing.share")
    }
}

impl GenerateConsensusConfig {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            force,
            consensus_args,
        } = self;
        let output = std::path::absolute(&output).wrap_err_with(|| {
            format!(
                "failed determining absolute directory given --output `{}`",
                output.display()
            )
        })?;

        std::fs::create_dir_all(&output).wrap_err_with(|| {
            format!("failed creating target directory at `{}`", output.display())
        })?;

        if force {
            eprintln!(
                "--force was specified: deleting all files in target directory `{}`",
                output.display()
            );
            // XXX: this first removes the directory and then recreates it. Small workaround
            // so that one doesn't have to iterate through the entire thing recursively.
            std::fs::remove_dir_all(&output)
                .and_then(|_| std::fs::create_dir(&output))
                .wrap_err_with(|| {
                    format!("failed clearing target directory at `{}`", output.display())
                })?;
        } else {
            let target_is_empty = std::fs::read_dir(&output)
                .wrap_err_with(|| {
                    format!(
                        "failed reading target directory `{}` to determine if it is empty",
                        output.display()
                    )
                })?
                .next()
                .is_none();
            ensure!(
                target_is_empty,
                "target directory `{}` is not empty; delete all its contents or rerun command with --force",
                output.display(),
            );
        }

        let consensus_config = consensus_args
            .generate_consensus_config()
            .wrap_err("failed generating consensus config")?;

        let peers_and_poly_dst = output.join("peers_and_polynomial.toml");
        consensus_config
            .peers_and_public_polynomial
            .write_to_file(&peers_and_poly_dst)
            .wrap_err_with(|| {
                format!(
                    "failed to write peers and public polynomial to `{}`",
                    peers_and_poly_dst.display(),
                )
            })?;

        for validator in consensus_config.validators {
            std::fs::create_dir(validator.dst_dir(&output)).wrap_err_with(|| {
                format!(
                    "failed creating target directory to store validator specifici keys at `{}`",
                    validator.dst_dir(&output).display()
                )
            })?;
            let signing_key_dst = validator.dst_signing_key(&output);
            validator
                .signing_key
                .write_to_file(&signing_key_dst)
                .wrap_err_with(|| {
                    format!(
                        "failed writing ed25519 signing key to `{}`",
                        signing_key_dst.display()
                    )
                })?;
            let signing_share_dst = validator.dst_signing_share(&output);
            validator
                .signing_share
                .write_to_file(&signing_share_dst)
                .wrap_err_with(|| {
                    format!(
                        "failed writing bls12381 signing share to `{}`",
                        signing_share_dst.display()
                    )
                })?;
        }

        // // Write configuration files
        // for (_, dst, cfg) in &configurations {
        //     let pretty = toml::to_string_pretty(&cfg).wrap_err("failed to convert config to toml")?;
        //     std::fs::write(dst, &pretty)
        //         .wrap_err_with(|| format!("failed writing config to file `{dst}`"))?;
        //     eprintln!("wrote config to file: `{dst}`");
        // }

        // eprintln!("Config files written");
        // eprintln!("To start validators, run:");
        // for (instance, (name, dst, cfg)) in (1u32..).zip(&configurations) {
        //     let eth_dst = cfg.storage_directory.with_file_name("reth_storage");
        //     let command = format!(
        //         "cargo run --release --bin tempo -- \
        //             \\\nnode \
        //             \\\n--consensus-config {dst} \
        //             \\\n--datadir {eth_dst} \
        //             \\\n--chain dev \
        //             \\\n--instance {instance} \
        //             \\\n--http"
        //     );
        //     println!("{name}: {command}");
        // }
        // println!("\nTo view metrics, run:");
        // for (name, _, peer_config) in &configurations {
        //     let cmd = match peer_config.metrics_port {
        //         None => "<metrics port not set>".to_string(),
        //         Some(metrics_port) => format!("curl http://localhost:{metrics_port}/metrics",),
        //     };
        //     println!("{name}: {cmd}");
        // }
        Ok(())
    }
}
