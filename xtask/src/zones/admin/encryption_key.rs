//! Shared sequencer encryption-key preparation and registration.

use std::{collections::HashSet, fmt, path::PathBuf, time::Duration};

use alloy::{
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use eyre::{Context as _, ensure, eyre};
use serde::Serialize;
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::ZonePortal;
use zeroize::Zeroizing;
use zone_sequencer::{encryption_key_identity, prove_encryption_key_possession};

use super::{
    config::{ExpectedEncryptionKey, SharedAdminArgs, format_duration, parse_nonzero_duration},
    invariants::{
        ensure_invariants, evaluate_base_invariants, portal_sequencer_coverage_invariant,
        required_decryption_keys_invariant,
    },
    secret_file::{
        WriteSecretOptions, encode_private_key, read_private_key_file, read_private_keyring_file,
        write_secret_file,
    },
    snapshot::{ClusterView, EncryptionKey as PortalEncryptionKey},
};

const NEW_SHARED_KEY_FILE: &str = "new-shared.key";
const DEPOSIT_DECRYPTION_KEYS_FILE: &str = "deposit-decryption-keys";
const DEFAULT_FINALITY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FINALITY_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, clap::Parser)]
pub(crate) struct EncryptionKey {
    #[command(subcommand)]
    command: EncryptionKeyCommand,
}

#[derive(Debug, clap::Subcommand)]
enum EncryptionKeyCommand {
    /// Generate a replacement shared key and merged decryption keyring.
    Prepare(Prepare),
    /// Verify preloading, then register the replacement key on ZonePortal.
    Register(Register),
}

impl EncryptionKey {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        match self.command {
            EncryptionKeyCommand::Prepare(command) => command.run().await,
            EncryptionKeyCommand::Register(command) => command.run().await,
        }
    }
}

#[derive(Debug, clap::Parser)]
struct Prepare {
    #[command(flatten)]
    shared: SharedAdminArgs,

    /// Current shared sequencer private key file.
    #[arg(long)]
    current_key_file: PathBuf,

    /// Currently deployed deposit-decryption-keys file; its nonblank keys are retained.
    #[arg(long)]
    existing_decryption_keys_file: PathBuf,

    /// Directory that receives new-shared.key and deposit-decryption-keys.
    #[arg(long)]
    rotation_dir: PathBuf,

    /// Replace existing generated key files.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdentity {
    address: Address,
    x: B256,
    y_parity: u8,
}

impl KeyIdentity {
    fn expected(self) -> ExpectedEncryptionKey {
        ExpectedEncryptionKey {
            x: self.x,
            y_parity: self.y_parity,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareReport {
    ok: bool,
    new_key_path: String,
    keyring_path: String,
    old_key: KeyIdentity,
    new_key: KeyIdentity,
}

impl Prepare {
    async fn run(self) -> eyre::Result<()> {
        progress("Loading and checking the Zone...");
        let config = self.shared.load()?;
        let view =
            ClusterView::collect(config, self.shared.rpc_timeout, |message| progress(message))
                .await?;
        ensure_healthy(&view)?;

        let current = read_private_key_file(&self.current_key_file)?;
        let old_key = identity_from_signer(&current)?;
        let active = view
            .portal
            .encryption_key
            .ok_or_else(|| eyre!("Portal has no active encryption key to rotate"))?;
        ensure!(
            key_matches(active, old_key),
            "current key file does not derive the active Portal encryption key {}",
            display_portal_key(active)
        );
        let existing_keyring = read_private_keyring_file(&self.existing_decryption_keys_file)?;
        let existing_identities = existing_keyring
            .iter()
            .map(identity_from_signer)
            .collect::<eyre::Result<HashSet<_>>>()?;
        ensure!(
            existing_identities.contains(&old_key),
            "existing decryption keyring `{}` does not include the current active key",
            self.existing_decryption_keys_file.display()
        );

        let new_signer = distinct_random_key(&current)?;
        let new_key = identity_from_signer(&new_signer)?;
        let new_key_path = self.rotation_dir.join(NEW_SHARED_KEY_FILE);
        let keyring_path = self.rotation_dir.join(DEPOSIT_DECRYPTION_KEYS_FILE);
        if !self.force {
            ensure!(
                !new_key_path.exists() && !keyring_path.exists(),
                "rotation output already exists in {}; choose an empty directory or pass --force",
                self.rotation_dir.display()
            );
        }

        std::fs::create_dir_all(&self.rotation_dir).wrap_err_with(|| {
            format!(
                "failed creating rotation directory {}",
                self.rotation_dir.display()
            )
        })?;
        let options = WriteSecretOptions {
            overwrite: self.force,
        };
        write_secret_file(
            &new_key_path,
            encode_private_key(&new_signer).as_bytes(),
            options,
        )?;
        let keyring = merge_decryption_keyring(existing_keyring, &new_signer)?;
        write_secret_file(&keyring_path, keyring.as_bytes(), options)?;

        let report = PrepareReport {
            ok: true,
            new_key_path: new_key_path.display().to_string(),
            keyring_path: keyring_path.display().to_string(),
            old_key,
            new_key,
        };
        if self.shared.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("Prepared shared sequencer key rotation");
            println!("  New key: {}", report.new_key_path);
            println!("  Keyring: {}", report.keyring_path);
            println!("  Old public key: {}", display_identity(old_key));
            println!("  New public key: {}", display_identity(new_key));
        }
        Ok(())
    }
}

#[derive(Debug, clap::Parser)]
struct Register {
    #[command(flatten)]
    shared: SharedAdminArgs,

    /// Replacement shared private key produced by `prepare`.
    #[arg(long)]
    new_key_file: PathBuf,

    /// Individual sequencer key that submits setSequencerEncryptionKey.
    #[arg(long)]
    transaction_key_file: PathBuf,

    /// Submit the Portal transaction. Without this flag the command is a dry run.
    #[arg(long)]
    execute: bool,

    /// Deadline for finalized postconditions. Defaults to 5m.
    #[arg(long, value_parser = parse_nonzero_duration)]
    timeout: Option<Duration>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterReport {
    ok: bool,
    dry_run: bool,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<B256>,
    portal: Address,
    signer: Address,
    old_key: Option<PortalEncryptionKey>,
    new_key: KeyIdentity,
}

impl Register {
    async fn run(self) -> eyre::Result<()> {
        let new_signer = read_private_key_file(&self.new_key_file)?;
        let new_key = identity_from_signer(&new_signer)?;
        let tx_signer = read_private_key_file(&self.transaction_key_file)?;

        progress("Loading and checking the Zone...");
        let config = self.shared.load()?;
        let view =
            ClusterView::collect(config, self.shared.rpc_timeout, |message| progress(message))
                .await?;

        if view
            .portal
            .encryption_key
            .is_some_and(|key| key_matches(key, new_key))
        {
            ensure_healthy(&view)?;
            ensure_registration_coverage(&view)?;
            return self.print_report(RegisterReport {
                ok: true,
                dry_run: !self.execute,
                submitted: false,
                tx_hash: None,
                portal: view.portal.portal,
                signer: tx_signer.address(),
                old_key: None,
                new_key,
            });
        }

        let old_portal_key = view
            .portal
            .encryption_key
            .ok_or_else(|| eyre!("Portal has no active encryption key to rotate"))?;
        let old_key = old_portal_key;
        let old_expected = ExpectedEncryptionKey {
            x: old_key.x,
            y_parity: old_key.y_parity,
        };
        ensure!(
            old_expected != new_key.expected(),
            "new key is already active"
        );
        ensure_registration_preconditions(&view, old_expected, new_key.expected())?;
        ensure!(
            view.portal.sequencers.contains(&tx_signer.address()),
            "transaction signer {} is not a current Portal sequencer",
            tx_signer.address()
        );

        let proof = prove_encryption_key_possession(view.portal.portal, &new_signer)?;
        let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&view.config.l1_rpc_url)
            .await
            .wrap_err("failed connecting to Tempo L1 RPC")?;
        progress("Simulating setSequencerEncryptionKey...");
        ZonePortal::new(view.portal.portal, &l1)
            .setSequencerEncryptionKey(
                proof.x,
                proof.y_parity,
                proof.pop_v,
                proof.pop_r,
                proof.pop_s,
            )
            .from(tx_signer.address())
            .call()
            .await
            .wrap_err("setSequencerEncryptionKey simulation failed")?;

        if !self.execute {
            return self.print_report(RegisterReport {
                ok: true,
                dry_run: true,
                submitted: false,
                tx_hash: None,
                portal: view.portal.portal,
                signer: tx_signer.address(),
                old_key: Some(old_key),
                new_key,
            });
        }

        progress("Rechecking all preconditions immediately before submission...");
        let finalized =
            ClusterView::collect(view.config.clone(), self.shared.rpc_timeout, |message| {
                progress(message)
            })
            .await?;
        if finalized
            .portal
            .encryption_key
            .is_some_and(|key| key_matches(key, new_key))
        {
            ensure_healthy(&finalized)?;
            ensure_registration_coverage(&finalized)?;
            return self.print_report(RegisterReport {
                ok: true,
                dry_run: false,
                submitted: false,
                tx_hash: None,
                portal: finalized.portal.portal,
                signer: tx_signer.address(),
                old_key: Some(old_key),
                new_key,
            });
        }
        ensure!(
            finalized
                .portal
                .encryption_key
                .is_some_and(|key| key == old_key),
            "active Portal key changed during the dry-run; refusing to submit"
        );
        ensure_registration_preconditions(&finalized, old_expected, new_key.expected())?;
        ensure!(
            finalized.portal.sequencers.contains(&tx_signer.address()),
            "transaction signer is no longer a current Portal sequencer"
        );

        let latest_key = ZonePortal::new(finalized.portal.portal, &l1)
            .sequencerEncryptionKey()
            .call()
            .await
            .wrap_err("failed reading the latest Portal encryption key")?;
        let latest_key = PortalEncryptionKey {
            x: latest_key.x,
            y_parity: latest_key.normalized_y_parity().ok_or_else(|| {
                eyre!(
                    "Portal returned invalid encryption-key yParity {:#x}; expected 0/1 or 0x02/0x03",
                    latest_key.yParity
                )
            })?,
        };

        let (tx_hash, submitted) = match registration_action(old_key, latest_key, new_key)? {
            RegistrationAction::Submit => {
                progress("Submitting setSequencerEncryptionKey...");
                let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                    .wallet(tx_signer.clone())
                    .connect(&finalized.config.l1_rpc_url)
                    .await?;
                let tx_hash = zone_sequencer::register_encryption_key(
                    &provider,
                    finalized.portal.portal,
                    &new_signer,
                )
                .await
                .wrap_err("failed to send setSequencerEncryptionKey")?;
                progress(format!(
                    "Transaction {tx_hash} succeeded; waiting for finalization..."
                ));
                (Some(tx_hash), true)
            }
            RegistrationAction::WaitForFinality => {
                progress(
                    "Replacement key is already included at latest; waiting for finalization without resubmitting...",
                );
                (None, false)
            }
        };

        let timeout = self.timeout.unwrap_or(DEFAULT_FINALITY_TIMEOUT);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let later =
                ClusterView::collect(finalized.config.clone(), self.shared.rpc_timeout, |_| {})
                    .await?;
            if later
                .portal
                .encryption_key
                .is_some_and(|key| key_matches(key, new_key))
            {
                return self.print_report(RegisterReport {
                    ok: true,
                    dry_run: false,
                    submitted,
                    tx_hash,
                    portal: later.portal.portal,
                    signer: tx_signer.address(),
                    old_key: Some(old_key),
                    new_key,
                });
            }
            ensure!(
                later
                    .portal
                    .encryption_key
                    .is_some_and(|key| key == old_key),
                "a different encryption key finalized while waiting for registration"
            );
            if std::time::Instant::now() >= deadline {
                return match tx_hash {
                    Some(tx_hash) => Err(eyre!(
                        "transaction {tx_hash} succeeded but timed out after {} waiting for the new encryption key to finalize; retrying is safe",
                        format_duration(timeout)
                    )),
                    None => Err(eyre!(
                        "timed out after {} waiting for the included encryption key to finalize; no transaction was resubmitted",
                        format_duration(timeout)
                    )),
                };
            }
            tokio::time::sleep(FINALITY_POLL).await;
        }
    }

    fn print_report(&self, report: RegisterReport) -> eyre::Result<()> {
        if self.shared.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "{}",
                if report.dry_run {
                    "Encryption-key registration dry run passed"
                } else if report.submitted {
                    "Encryption-key registration finalized"
                } else {
                    "Encryption key is already active"
                }
            );
            println!("  Portal: {}", report.portal);
            println!("  Signer: {}", report.signer);
            if let Some(old_key) = report.old_key {
                println!("  Old public key: {}", display_portal_key(old_key));
            }
            println!("  New public key: {}", display_identity(report.new_key));
            if let Some(tx_hash) = report.tx_hash {
                println!("  Transaction: {tx_hash}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationAction {
    Submit,
    WaitForFinality,
}

fn registration_action(
    old_key: PortalEncryptionKey,
    latest_key: PortalEncryptionKey,
    new_key: KeyIdentity,
) -> eyre::Result<RegistrationAction> {
    if latest_key == old_key {
        return Ok(RegistrationAction::Submit);
    }
    if key_matches(latest_key, new_key) {
        return Ok(RegistrationAction::WaitForFinality);
    }
    Err(eyre!(
        "active Portal key changed before submission to {}; refusing to submit",
        display_portal_key(latest_key)
    ))
}

fn ensure_healthy(view: &ClusterView) -> eyre::Result<()> {
    let invariants = evaluate_base_invariants(
        &view.config,
        view.manifest.as_ref(),
        &view.portal,
        &view.nodes,
        None,
        None,
        None,
    );
    ensure_invariants("cluster preflight failed", &invariants)
}

fn ensure_registration_preconditions(
    view: &ClusterView,
    old_key: ExpectedEncryptionKey,
    new_key: ExpectedEncryptionKey,
) -> eyre::Result<()> {
    let mut invariants = evaluate_base_invariants(
        &view.config,
        view.manifest.as_ref(),
        &view.portal,
        &view.nodes,
        None,
        None,
        Some(old_key),
    );
    invariants.push(required_decryption_keys_invariant(
        &view.nodes,
        &[old_key, new_key],
    ));
    invariants.push(portal_sequencer_coverage_invariant(
        &view.portal,
        &view.nodes,
    ));
    ensure_invariants("registration preflight failed", &invariants)
}

fn ensure_registration_coverage(view: &ClusterView) -> eyre::Result<()> {
    ensure_invariants(
        "registration preflight failed",
        &[portal_sequencer_coverage_invariant(
            &view.portal,
            &view.nodes,
        )],
    )
}

fn identity_from_signer(signer: &PrivateKeySigner) -> eyre::Result<KeyIdentity> {
    let (x, y_parity, address) = encryption_key_identity(signer)?;
    Ok(KeyIdentity {
        address,
        x,
        y_parity,
    })
}

fn distinct_random_key(current: &PrivateKeySigner) -> eyre::Result<PrivateKeySigner> {
    for _ in 0..8 {
        let candidate = PrivateKeySigner::random();
        if candidate.address() != current.address() {
            return Ok(candidate);
        }
    }
    Err(eyre!("failed to generate a distinct replacement key"))
}

fn merge_decryption_keyring(
    existing: Vec<PrivateKeySigner>,
    new_key: &PrivateKeySigner,
) -> eyre::Result<Zeroizing<String>> {
    let mut identities = HashSet::new();
    let mut keyring = Zeroizing::new(String::new());
    for key in existing.iter().chain(std::iter::once(new_key)) {
        if identities.insert(identity_from_signer(key)?) {
            keyring.push_str(&encode_private_key(key));
        }
    }
    Ok(keyring)
}

fn key_matches(portal: PortalEncryptionKey, identity: KeyIdentity) -> bool {
    portal.x == identity.x && portal.y_parity == identity.y_parity
}

fn display_portal_key(key: PortalEncryptionKey) -> String {
    format!("x={} parity={}", key.x, key.y_parity)
}

fn display_identity(key: KeyIdentity) -> String {
    format!(
        "x={} parity={} address={}",
        key.x, key.y_parity, key.address
    )
}

fn progress(message: impl fmt::Display) {
    eprintln!("[admin encryption-key] {message}");
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::B256, signers::local::PrivateKeySigner};

    use super::{
        PortalEncryptionKey, RegistrationAction, identity_from_signer, merge_decryption_keyring,
        registration_action,
    };

    #[test]
    fn identity_contains_canonical_parity() {
        let signer = PrivateKeySigner::from_slice(&[0x11; 32]).unwrap();
        let identity = identity_from_signer(&signer).unwrap();
        assert!(identity.y_parity == 2 || identity.y_parity == 3);
        assert_eq!(identity.address, signer.address());
    }

    #[test]
    fn merged_keyring_preserves_existing_keys_and_deduplicates_by_identity() {
        let old = PrivateKeySigner::from_slice(&[0x11; 32]).unwrap();
        let historical = PrivateKeySigner::from_slice(&[0x22; 32]).unwrap();
        let new = PrivateKeySigner::from_slice(&[0x33; 32]).unwrap();
        let keyring = merge_decryption_keyring(vec![old.clone(), historical, old], &new).unwrap();
        assert_eq!(keyring.lines().count(), 3);
        assert!(keyring.contains(&super::encode_private_key(&new)));
    }

    #[test]
    fn included_replacement_waits_for_finality_instead_of_resubmitting() {
        let old = PortalEncryptionKey {
            x: B256::repeat_byte(0x11),
            y_parity: 2,
        };
        let new_signer = PrivateKeySigner::from_slice(&[0x33; 32]).unwrap();
        let new = identity_from_signer(&new_signer).unwrap();
        let latest = PortalEncryptionKey {
            x: new.x,
            y_parity: new.y_parity,
        };

        assert_eq!(
            registration_action(old, latest, new).unwrap(),
            RegistrationAction::WaitForFinality
        );
    }
}
