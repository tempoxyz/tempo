//! Generate and refresh Tempo Zone private-RPC authorization-token maps.

use crate::zone_auth::{
    build_token_fields, encode_token_hex, parse_token_fields, sign_token, verify_token,
    MAX_TOKEN_VALIDITY_SECS, SIGNATURE_LEN,
};
use clap::Args;
use eyre::{bail, eyre, Result, WrapErr};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use txgen_core::{EcdsaSigner, WorkloadSpec};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_TTL_SECS: u64 = 600;
const DEFAULT_REFRESH_BEFORE_SECS: u64 = 30;
const INITIAL_RETRY_SECS: u64 = 1;
const MAX_RETRY_SECS: u64 = 30;
const TEMP_FILE_ATTEMPTS: usize = 128;

/// Generate or continuously refresh a Zone private-RPC authorization-token map.
#[derive(Args)]
pub struct AuthTokenMapArgs {
    /// Workload specification file (YAML)
    #[arg(long, value_name = "PATH")]
    pub spec: PathBuf,

    /// Logical/root account pool to authenticate
    #[arg(long, value_name = "NAME")]
    pub pool: String,

    /// Nonzero Tempo Zone identifier
    #[arg(long)]
    pub zone_id: u32,

    /// Zone chain identifier
    #[arg(long)]
    pub chain_id: u64,

    /// Token lifetime in seconds (a server may enforce less than the 30-day maximum)
    #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
    pub ttl_secs: u64,

    /// Seconds before expiry at which watch mode refreshes the complete map
    #[arg(long, default_value_t = DEFAULT_REFRESH_BEFORE_SECS)]
    pub refresh_before_secs: u64,

    /// Keep running and refresh the map before its tokens expire
    #[arg(long)]
    pub watch: bool,

    /// Replace an existing output in one-shot mode
    #[arg(long)]
    pub force: bool,

    /// Secret JSON output path
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
}

struct Config {
    spec: PathBuf,
    pool: String,
    zone_id: u32,
    chain_id: u64,
    ttl_secs: u64,
    refresh_before_secs: u64,
    watch: bool,
    force: bool,
    output: PathBuf,
}

impl TryFrom<AuthTokenMapArgs> for Config {
    type Error = eyre::Report;

    fn try_from(args: AuthTokenMapArgs) -> Result<Self> {
        if args.zone_id == 0 {
            bail!("--zone-id must be nonzero");
        }
        if args.ttl_secs == 0 || args.ttl_secs > MAX_TOKEN_VALIDITY_SECS {
            bail!("--ttl-secs must be between 1 and {MAX_TOKEN_VALIDITY_SECS}");
        }
        if args.refresh_before_secs >= args.ttl_secs {
            bail!("--refresh-before-secs must be less than --ttl-secs");
        }
        if args.pool.is_empty() {
            bail!("--pool must not be empty");
        }
        if args.output.file_name().is_none() {
            bail!("--output must name a file");
        }

        Ok(Self {
            spec: args.spec,
            pool: args.pool,
            zone_id: args.zone_id,
            chain_id: args.chain_id,
            ttl_secs: args.ttl_secs,
            refresh_before_secs: args.refresh_before_secs,
            watch: args.watch,
            force: args.force,
            output: args.output,
        })
    }
}

/// Run the Tempo-specific `auth-token-map` command.
pub async fn run_auth_token_map(args: AuthTokenMapArgs) -> Result<()> {
    let config = Config::try_from(args)?;
    let clock = SystemClock;

    if config.watch {
        // Register before mnemonic derivation so startup SIGINT/SIGTERM cannot take the default
        // process-killing path while a large pool is being derived synchronously.
        let shutdown = shutdown_signal()?;
        let signers = load_pool_signers(&config.spec, &config.pool)?;
        run_watch(&config, &signers, &clock, shutdown).await
    } else {
        let signers = load_pool_signers(&config.spec, &config.pool)?;
        let generated = generate_and_write(&config, &signers, &clock, config.force)?;
        print_summary(&config, &generated, false)?;
        Ok(())
    }
}

fn load_pool_signers(spec_path: &Path, pool_name: &str) -> Result<Vec<EcdsaSigner>> {
    let spec = WorkloadSpec::load(spec_path)
        .wrap_err_with(|| format!("failed to load spec: {}", spec_path.display()))?;
    let pool = spec
        .accounts
        .get(pool_name)
        .ok_or_else(|| eyre!("account pool '{pool_name}' not found"))?;
    let signers = pool
        .derive_signers()
        .map_err(|_| eyre!("failed to derive signers for pool '{pool_name}'"))?;

    if signers.is_empty() {
        bail!("account pool '{pool_name}' is empty");
    }
    Ok(signers)
}

trait Clock {
    fn now_secs(&self) -> Result<u64>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| eyre!("system clock is before the Unix epoch"))
    }
}

struct SecretToken(String);

impl Serialize for SecretToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct GeneratedMap {
    entries: BTreeMap<String, SecretToken>,
    issued_at: u64,
    expires_at: u64,
}

fn generate_map(
    signers: &[EcdsaSigner],
    zone_id: u32,
    chain_id: u64,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<GeneratedMap> {
    let expires_at =
        issued_at.checked_add(ttl_secs).ok_or_else(|| eyre!("token expiry timestamp overflow"))?;
    let fields = build_token_fields(zone_id, chain_id, issued_at, expires_at);
    let expected_fields = parse_token_fields(&fields)?;
    let mut entries = BTreeMap::new();

    for signer in signers {
        let address = signer.address();
        let token = Zeroizing::new(sign_token(signer, &fields)?);
        verify_token(&*token, address)?;

        let parsed = parse_token_fields(&token[SIGNATURE_LEN..])?;
        if parsed != expected_fields {
            bail!("generated Zone authorization-token fields failed local verification");
        }

        let key = format!("0x{}", hex::encode(address.as_slice()));
        let token_hex = SecretToken(encode_token_hex(&token));
        if entries.insert(key, token_hex).is_some() {
            bail!("selected account pool contains duplicate signer addresses");
        }
    }

    if entries.len() != signers.len() {
        bail!("generated token-map entry count does not match the selected account pool");
    }

    Ok(GeneratedMap { entries, issued_at, expires_at })
}

fn generate_and_write<C: Clock>(
    config: &Config,
    signers: &[EcdsaSigner],
    clock: &C,
    replace_existing: bool,
) -> Result<GeneratedMap> {
    let issued_at = clock.now_secs()?;
    let generated =
        generate_map(signers, config.zone_id, config.chain_id, issued_at, config.ttl_secs)?;
    let mut json = serde_json::to_vec(&generated.entries)
        .map_err(|_| eyre!("failed to serialize authorization-token map"))?;
    let write_result = atomic_write_checked(&config.output, &json, replace_existing, || {
        validate_publish_time(clock, generated.issued_at, generated.expires_at)
    });
    json.zeroize();
    write_result?;
    Ok(generated)
}

fn validate_publish_time<C: Clock>(clock: &C, issued_at: u64, expires_at: u64) -> Result<()> {
    let now = clock.now_secs()?;
    if now < issued_at {
        bail!("system clock moved backwards while generating the token map");
    }
    if now >= expires_at {
        bail!(
            "authorization tokens expired before the map could be published; increase --ttl-secs"
        );
    }
    Ok(())
}

async fn run_watch<C: Clock>(
    config: &Config,
    signers: &[EcdsaSigner],
    clock: &C,
    mut shutdown: ShutdownFuture,
) -> Result<()> {
    // If shutdown arrived during signer derivation, stop before generating or publishing a map.
    tokio::select! {
        biased;
        shutdown_result = &mut shutdown => {
            shutdown_result?;
            return Ok(());
        }
        () = std::future::ready(()) => {}
    }

    let mut generated = generate_and_write(config, signers, clock, true)?;
    print_summary(config, &generated, true)?;

    let mut retry_secs = INITIAL_RETRY_SECS;

    loop {
        let refresh_at = generated
            .expires_at
            .checked_sub(config.refresh_before_secs)
            .expect("refresh lead time validated against TTL");
        let now = clock.now_secs()?;
        let wait_secs = refresh_at.saturating_sub(now);

        tokio::select! {
            shutdown_result = &mut shutdown => {
                shutdown_result?;
                return Ok(());
            }
            () = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
        }

        match generate_and_write(config, signers, clock, true) {
            Ok(refreshed) => {
                generated = refreshed;
                retry_secs = INITIAL_RETRY_SECS;
                print_summary(config, &generated, true)?;
            }
            Err(error) => {
                eprintln!(
                    "warning: failed to refresh Zone authorization-token map: {error}; retrying in {retry_secs}s"
                );
                tokio::select! {
                    shutdown_result = &mut shutdown => {
                        shutdown_result?;
                        return Ok(());
                    }
                    () = tokio::time::sleep(Duration::from_secs(retry_secs)) => {}
                }
                retry_secs = retry_secs.saturating_mul(2).min(MAX_RETRY_SECS);
            }
        }
    }
}

fn print_summary(config: &Config, generated: &GeneratedMap, watching: bool) -> Result<()> {
    let mode = if watching { " (watching)" } else { "" };
    println!(
        "wrote {} Zone authorization tokens for zone {} chain {} issued_at={} expires_at={} to {}{}",
        generated.entries.len(),
        config.zone_id,
        config.chain_id,
        generated.issued_at,
        generated.expires_at,
        config.output.display(),
        mode,
    );
    io::stdout().flush().wrap_err("failed to flush the token-map summary")?;
    Ok(())
}

type ShutdownFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

fn shutdown_signal() -> Result<ShutdownFuture> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut interrupt =
            signal(SignalKind::interrupt()).wrap_err("failed to register the SIGINT handler")?;
        let mut terminate =
            signal(SignalKind::terminate()).wrap_err("failed to register the SIGTERM handler")?;
        Ok(Box::pin(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
            Ok(())
        }))
    }

    #[cfg(not(unix))]
    {
        Ok(Box::pin(async {
            tokio::signal::ctrl_c().await.wrap_err("failed to listen for Ctrl-C")?;
            Ok(())
        }))
    }
}

#[cfg(test)]
fn atomic_write(output: &Path, bytes: &[u8], replace_existing: bool) -> Result<()> {
    atomic_write_checked(output, bytes, replace_existing, || Ok(()))
}

fn atomic_write_checked<F>(
    output: &Path,
    bytes: &[u8],
    replace_existing: bool,
    before_publish: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    inspect_destination(output, replace_existing)?;
    let parent =
        output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent_metadata = fs::metadata(parent)
        .wrap_err_with(|| format!("failed to inspect output directory: {}", parent.display()))?;
    if !parent_metadata.is_dir() {
        bail!("output parent is not a directory: {}", parent.display());
    }
    warn_if_unsafe_directory(parent, &parent_metadata);

    let (temporary_path, mut temporary_file) = create_temporary_file(output, parent)?;
    let mut cleanup = TemporaryFileGuard::new(temporary_path.clone());

    temporary_file.write_all(bytes).wrap_err_with(|| {
        format!("failed to write temporary output: {}", temporary_path.display())
    })?;
    temporary_file.flush().wrap_err_with(|| {
        format!("failed to flush temporary output: {}", temporary_path.display())
    })?;
    temporary_file.sync_all().wrap_err_with(|| {
        format!("failed to sync temporary output: {}", temporary_path.display())
    })?;
    drop(temporary_file);

    // Recheck immediately before publishing. A replacement never follows a destination symlink:
    // rename swaps the directory entry itself, and this check rejects a pre-existing one. The
    // no-replace path also uses a kernel-enforced atomic no-clobber operation to close the race
    // between this inspection and publication.
    inspect_destination(output, replace_existing)?;
    before_publish()?;
    publish_temporary(&temporary_path, output, replace_existing).wrap_err_with(|| {
        format!(
            "failed to atomically replace output {} with {}",
            output.display(),
            temporary_path.display()
        )
    })?;
    cleanup.disarm();

    #[cfg(unix)]
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        eprintln!(
            "warning: failed to sync output directory {} after replacement: {error}",
            parent.display()
        );
    }

    Ok(())
}

fn publish_temporary(temporary: &Path, output: &Path, replace_existing: bool) -> io::Result<()> {
    if replace_existing {
        fs::rename(temporary, output)
    } else {
        rename_without_replacement(temporary, output)
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple", target_os = "redox"))]
fn rename_without_replacement(temporary: &Path, output: &Path) -> io::Result<()> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};

    renameat_with(CWD, temporary, CWD, output, RenameFlags::NOREPLACE).map_err(Into::into)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "redox")))]
fn rename_without_replacement(temporary: &Path, output: &Path) -> io::Result<()> {
    // The destination link appears atomically and `hard_link` fails if it already exists. Both
    // paths are in the same directory, so they necessarily reside on the same filesystem.
    fs::hard_link(temporary, output)?;
    fs::remove_file(temporary)
}

fn inspect_destination(output: &Path, replace_existing: bool) -> Result<()> {
    match fs::symlink_metadata(output) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("refusing to use symlink output: {}", output.display());
            }
            if !metadata.is_file() {
                bail!("output exists and is not a regular file: {}", output.display());
            }
            warn_if_unsafe_file(output, &metadata);
            if !replace_existing {
                bail!("output already exists; pass --force to replace it: {}", output.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .wrap_err_with(|| format!("failed to inspect output path: {}", output.display())),
    }
}

fn create_temporary_file(output: &Path, parent: &Path) -> Result<(PathBuf, File)> {
    let file_name = output.file_name().ok_or_else(|| eyre!("--output must name a file"))?;
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(
            ".txgen-{}-{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let temporary_path = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!("failed to create temporary output in {}", parent.display())
                });
            }
        }
    }

    bail!("failed to allocate a unique temporary output file in {}", parent.display());
}

struct TemporaryFileGuard {
    path: Option<PathBuf>,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn warn_if_unsafe_file(path: &Path, metadata: &fs::Metadata) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "warning: existing output {} has permissions {:03o}; replacement will use 600",
            path.display(),
            mode
        );
    }
}

#[cfg(not(unix))]
fn warn_if_unsafe_file(_path: &Path, _metadata: &fs::Metadata) {}

#[cfg(unix)]
fn warn_if_unsafe_directory(path: &Path, metadata: &fs::Metadata) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        eprintln!(
            "warning: output directory {} is group- or world-writable ({:03o})",
            path.display(),
            mode
        );
    }
}

#[cfg(not(unix))]
fn warn_if_unsafe_directory(_path: &Path, _metadata: &fs::Metadata) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_auth::{recover_signer, TOKEN_HEX_LEN, TOKEN_LEN};
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Barrier,
        },
        thread,
    };
    use txgen_core::AccountPoolDef;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_secs(&self) -> Result<u64> {
            Ok(self.0)
        }
    }

    struct AdvancingClock(AtomicU64);

    impl AdvancingClock {
        fn new(initial: u64) -> Self {
            Self(AtomicU64::new(initial))
        }
    }

    impl Clock for AdvancingClock {
        fn now_secs(&self) -> Result<u64> {
            Ok(self.0.fetch_add(1, Ordering::Relaxed))
        }
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("txgen-auth-token-map-test-{}-{sequence}", std::process::id()));
            fs::create_dir(&path).expect("test directory should be unique");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_args(output: PathBuf) -> AuthTokenMapArgs {
        AuthTokenMapArgs {
            spec: PathBuf::from("spec.yaml"),
            pool: "users".to_string(),
            zone_id: 71,
            chain_id: 421_700_071,
            ttl_secs: DEFAULT_TTL_SECS,
            refresh_before_secs: DEFAULT_REFRESH_BEFORE_SECS,
            watch: false,
            force: false,
            output,
        }
    }

    fn test_config(output: PathBuf) -> Config {
        Config::try_from(test_args(output)).unwrap()
    }

    fn test_signers(start: u32, end: u32) -> Vec<EcdsaSigner> {
        AccountPoolDef {
            mnemonic: Some(TEST_MNEMONIC.to_string()),
            index: None,
            range: Some([start, end]),
            fast_signable: None,
        }
        .derive_signers()
        .unwrap()
    }

    fn write_spec(path: &Path, pool_body: &str) {
        fs::write(path, format!("chain_id: 1\naccounts:\n  users:\n{pool_body}")).unwrap();
    }

    #[test]
    fn validates_zone_ttl_refresh_pool_and_output() {
        let directory = TestDir::new();

        let mut args = test_args(directory.join("tokens.json"));
        args.zone_id = 0;
        assert_eq!(
            Config::try_from(args).err().expect("zero zone ID must fail").to_string(),
            "--zone-id must be nonzero"
        );

        let mut args = test_args(directory.join("tokens.json"));
        args.ttl_secs = 0;
        assert!(Config::try_from(args)
            .err()
            .expect("zero TTL must fail")
            .to_string()
            .contains("--ttl-secs"));

        let mut args = test_args(directory.join("tokens.json"));
        args.ttl_secs = MAX_TOKEN_VALIDITY_SECS + 1;
        assert!(Config::try_from(args)
            .err()
            .expect("oversized TTL must fail")
            .to_string()
            .contains("--ttl-secs"));

        let mut args = test_args(directory.join("tokens.json"));
        args.refresh_before_secs = args.ttl_secs;
        assert!(Config::try_from(args)
            .err()
            .expect("invalid refresh lead time must fail")
            .to_string()
            .contains("--refresh-before-secs"));

        let mut args = test_args(directory.join("tokens.json"));
        args.pool.clear();
        assert_eq!(
            Config::try_from(args).err().expect("empty pool name must fail").to_string(),
            "--pool must not be empty"
        );

        let args = test_args(PathBuf::from("/"));
        assert_eq!(
            Config::try_from(args).err().expect("directory output must fail").to_string(),
            "--output must name a file"
        );
    }

    #[test]
    fn selected_pool_uses_existing_range_semantics_and_rejects_missing_or_empty() {
        let directory = TestDir::new();
        let spec = directory.join("spec.yaml");
        write_spec(&spec, &format!("    mnemonic: \"{TEST_MNEMONIC}\"\n    range: [7, 10]\n"));
        let signers = load_pool_signers(&spec, "users").unwrap();
        assert_eq!(signers.len(), 3);
        assert_eq!(signers[0].address(), test_signers(7, 8)[0].address());
        assert_eq!(signers[2].address(), test_signers(9, 10)[0].address());

        assert!(load_pool_signers(&spec, "missing").unwrap_err().to_string().contains("not found"));

        write_spec(&spec, &format!("    mnemonic: \"{TEST_MNEMONIC}\"\n    range: [10, 10]\n"));
        assert!(load_pool_signers(&spec, "users").unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn generated_map_is_sorted_normalized_and_uses_one_validity_window() {
        let signers = test_signers(0, 8);
        let generated = generate_map(&signers, 71, 421_700_071, 1_700_000_000, 600).unwrap();
        assert_eq!(generated.entries.len(), signers.len());
        assert_eq!(generated.issued_at, 1_700_000_000);
        assert_eq!(generated.expires_at, 1_700_000_600);

        let keys = generated.entries.keys().cloned().collect::<Vec<_>>();
        let sorted = keys.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
        assert_eq!(keys, sorted);

        for (key, token_hex) in &generated.entries {
            assert_eq!(key.len(), 42);
            assert!(key.starts_with("0x"));
            assert!(key[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(key.bytes().all(|byte| !byte.is_ascii_uppercase()));
            assert_eq!(token_hex.0.len(), TOKEN_HEX_LEN);
            assert!(token_hex.0.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(token_hex.0.bytes().all(|byte| !byte.is_ascii_uppercase()));

            let token = hex::decode(&token_hex.0).unwrap();
            assert_eq!(token.len(), TOKEN_LEN);
            let fields = parse_token_fields(&token[SIGNATURE_LEN..]).unwrap();
            assert_eq!(fields.zone_id, 71);
            assert_eq!(fields.chain_id, 421_700_071);
            assert_eq!(fields.issued_at, generated.issued_at);
            assert_eq!(fields.expires_at, generated.expires_at);
            assert_eq!(format!("0x{}", hex::encode(recover_signer(&token).unwrap())), *key);
        }
    }

    #[test]
    fn generates_one_thousand_account_map() {
        let signers = test_signers(0, 1_000);
        let generated = generate_map(&signers, 71, 421_700_071, 1_700_000_000, 600).unwrap();
        assert_eq!(generated.entries.len(), 1_000);
    }

    #[test]
    #[ignore = "10,000-account sizing and performance check"]
    fn generates_ten_thousand_account_map() {
        let signers = test_signers(0, 10_000);
        let generated = generate_map(&signers, 71, 421_700_071, 1_700_000_000, 600).unwrap();
        assert_eq!(generated.entries.len(), 10_000);

        let json = serde_json::to_vec(&generated.entries).unwrap();
        assert!(json.len() < 3 * 1024 * 1024);
    }

    #[test]
    fn rejects_expiry_overflow_before_writing() {
        let signers = test_signers(0, 1);
        let error = generate_map(&signers, 71, 421_700_071, u64::MAX, 1)
            .err()
            .expect("overflow must fail")
            .to_string();
        assert_eq!(error, "token expiry timestamp overflow");
    }

    #[test]
    fn rejects_tokens_that_expire_before_atomic_publication() {
        let directory = TestDir::new();
        let output = directory.join("tokens.json");
        let mut config = test_config(output.clone());
        config.ttl_secs = 1;
        config.refresh_before_secs = 0;
        let signers = test_signers(0, 1);

        let error =
            generate_and_write(&config, &signers, &AdvancingClock::new(1_700_000_000), false)
                .err()
                .expect("expired generation must fail")
                .to_string();
        assert!(error.contains("expired before the map could be published"));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn one_shot_requires_force_and_replacement_is_mode_0600() {
        let directory = TestDir::new();
        let output = directory.join("tokens.json");

        atomic_write(&output, b"old", false).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"old");
        assert!(atomic_write(&output, b"new", false).unwrap_err().to_string().contains("--force"));
        assert_eq!(fs::read(&output).unwrap(), b"old");

        atomic_write(&output, b"new", true).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"new");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let leftovers = fs::read_dir(&directory.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_output_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = TestDir::new();
        let target = directory.join("real.json");
        let output = directory.join("tokens.json");
        fs::write(&target, b"last-valid-map").unwrap();
        symlink(&target, &output).unwrap();

        let error = atomic_write(&output, b"replacement", true).unwrap_err().to_string();
        assert!(error.contains("symlink"));
        assert_eq!(fs::read(&target).unwrap(), b"last-valid-map");
    }

    #[test]
    fn failed_refresh_keeps_previous_valid_map() {
        let directory = TestDir::new();
        let output = directory.join("tokens.json");
        let config = test_config(output.clone());
        let signers = test_signers(0, 2);

        generate_and_write(&config, &signers, &FixedClock(1_700_000_000), false).unwrap();
        let previous = fs::read(&output).unwrap();
        let error = generate_and_write(&config, &signers, &FixedClock(u64::MAX), true)
            .err()
            .expect("overflowing refresh must fail")
            .to_string();
        assert_eq!(error, "token expiry timestamp overflow");
        assert_eq!(fs::read(&output).unwrap(), previous);
    }

    #[test]
    fn refresh_changes_tokens_and_expiry_but_not_addresses() {
        let directory = TestDir::new();
        let output = directory.join("tokens.json");
        let config = test_config(output.clone());
        let signers = test_signers(0, 3);

        let first =
            generate_and_write(&config, &signers, &FixedClock(1_700_000_000), false).unwrap();
        let first_json: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        let second =
            generate_and_write(&config, &signers, &FixedClock(1_700_000_001), true).unwrap();
        let second_json: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();

        assert_eq!(
            first.entries.keys().collect::<Vec<_>>(),
            second.entries.keys().collect::<Vec<_>>()
        );
        assert_eq!(first_json.keys().collect::<Vec<_>>(), second_json.keys().collect::<Vec<_>>());
        assert_ne!(
            first_json.values().collect::<Vec<_>>(),
            second_json.values().collect::<Vec<_>>()
        );
        assert_eq!(second.expires_at, first.expires_at + 1);
    }

    #[test]
    fn readers_never_observe_partial_atomic_replacements() {
        let directory = TestDir::new();
        let output = directory.join("tokens.json");
        let first = Arc::new(vec![b'a'; 64 * 1024]);
        let second = Arc::new(vec![b'b'; 64 * 1024]);
        atomic_write(&output, &first, false).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let reader_output = output.clone();
        let reader_first = Arc::clone(&first);
        let reader_second = Arc::clone(&second);
        let reader_stop = Arc::clone(&stop);
        let reader = thread::spawn(move || {
            while !reader_stop.load(Ordering::Acquire) {
                let contents = fs::read(&reader_output).unwrap();
                assert!(contents == *reader_first || contents == *reader_second);
            }
        });

        for index in 0..20 {
            let contents = if index % 2 == 0 { &second } else { &first };
            atomic_write(&output, contents, true).unwrap();
        }
        stop.store(true, Ordering::Release);
        reader.join().unwrap();
    }

    #[test]
    fn concurrent_no_force_publications_never_clobber() {
        const WRITERS: usize = 8;

        let directory = TestDir::new();
        let output = directory.join("tokens.json");
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|index| {
                let temporary = directory.join(&format!("candidate-{index}.tmp"));
                fs::write(&temporary, index.to_string()).unwrap();
                let output = output.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    publish_temporary(&temporary, &output, false).is_ok()
                })
            })
            .collect::<Vec<_>>();

        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
        let winner = fs::read_to_string(output).unwrap().parse::<usize>().unwrap();
        assert!(winner < WRITERS);
    }

    #[test]
    fn invalid_mnemonic_is_not_echoed_in_errors() {
        let directory = TestDir::new();
        let spec = directory.join("spec.yaml");
        let secret = "this mnemonic must never appear in an error";
        write_spec(&spec, &format!("    mnemonic: \"{secret}\"\n    index: 0\n"));
        let error = load_pool_signers(&spec, "users").unwrap_err();
        assert!(!format!("{error:?}").contains(secret));
        assert_eq!(error.to_string(), "failed to derive signers for pool 'users'");
    }
}
