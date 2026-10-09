//! Atomic owner-only writes for secret key material.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use alloy::signers::local::PrivateKeySigner;
use rand::RngExt as _;
use zeroize::Zeroizing;

const TEMP_FILE_ATTEMPTS: usize = 16;

/// Options for writing a secret file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteSecretOptions {
    /// Replace an existing regular file using atomic inode replacement.
    pub overwrite: bool,
}

/// Write secret material without ever modifying an existing destination inode.
///
/// A forced replacement swaps the destination only after the new contents have
/// been fully written and synced. Readers holding a descriptor to a previous
/// file continue to observe the old material.
pub(crate) fn write_secret_file(
    output: &Path,
    contents: &[u8],
    options: WriteSecretOptions,
) -> eyre::Result<()> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if output.file_name().is_none() {
        eyre::bail!("secret destination `{}` must name a file", output.display());
    }

    match fs::symlink_metadata(output) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                eyre::bail!(
                    "refusing to replace non-regular secret destination `{}`",
                    output.display()
                );
            }
            if !options.overwrite {
                eyre::bail!(
                    "secret destination `{}` already exists; pass --force to replace it",
                    output.display()
                );
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(eyre::eyre!(
                "failed inspecting secret destination `{}`: {err}",
                output.display()
            ));
        }
    }

    let (temporary_path, temporary_file) = create_temporary_secret_file(parent, output)?;
    let result = write_and_commit_secret_file(
        &temporary_path,
        temporary_file,
        output,
        options.overwrite,
        contents,
    );

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }

    result
}

fn write_and_commit_secret_file(
    temporary_path: &Path,
    mut temporary_file: File,
    output: &Path,
    overwrite: bool,
    contents: &[u8],
) -> eyre::Result<()> {
    temporary_file
        .write_all(contents)
        .map_err(|err| eyre::eyre!("failed writing `{}`: {err}", output.display()))?;
    temporary_file
        .sync_all()
        .map_err(|err| eyre::eyre!("failed syncing `{}`: {err}", output.display()))?;
    drop(temporary_file);

    if overwrite {
        fs::rename(temporary_path, output)
            .map_err(|err| eyre::eyre!("failed replacing `{}`: {err}", output.display()))?;
    } else {
        fs::hard_link(temporary_path, output)
            .map_err(|err| eyre::eyre!("failed installing `{}`: {err}", output.display()))?;
        fs::remove_file(temporary_path).map_err(|err| {
            eyre::eyre!(
                "failed removing temporary file `{}`: {err}",
                temporary_path.display()
            )
        })?;
    }

    Ok(())
}

fn create_temporary_secret_file(parent: &Path, output: &Path) -> eyre::Result<(PathBuf, File)> {
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let temporary_path = parent.join(format!(
            ".secret-{}-{:016x}.tmp",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }

        match options.open(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(eyre::eyre!(
                    "failed creating temporary file beside `{}`: {err}",
                    output.display()
                ));
            }
        }
    }

    Err(eyre::eyre!(
        "failed creating a unique temporary file beside `{}`",
        output.display()
    ))
}

/// Read a single secp256k1 private key from `path`.
///
/// Errors never include the file contents.
pub(crate) fn read_private_key_file(path: &Path) -> eyre::Result<PrivateKeySigner> {
    let contents = Zeroizing::new(std::fs::read_to_string(path).map_err(|err| {
        eyre::eyre!(
            "failed reading private key file `{}`: {err}",
            path.display()
        )
    })?);
    contents
        .trim()
        .parse::<PrivateKeySigner>()
        .map_err(|_| eyre::eyre!("invalid secp256k1 private key in `{}`", path.display()))
}

/// Read nonblank secp256k1 private-key lines from a keyring file.
///
/// Errors never include key material from the file.
pub(crate) fn read_private_keyring_file(path: &Path) -> eyre::Result<Vec<PrivateKeySigner>> {
    let contents = Zeroizing::new(std::fs::read_to_string(path).map_err(|err| {
        eyre::eyre!(
            "failed reading decryption keyring file `{}`: {err}",
            path.display()
        )
    })?);
    let mut keys = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let key = line.trim();
        if key.is_empty() {
            continue;
        }
        let signer = key.parse::<PrivateKeySigner>().map_err(|_| {
            eyre::eyre!(
                "invalid secp256k1 private key on nonblank line {} in `{}`",
                index + 1,
                path.display()
            )
        })?;
        keys.push(signer);
    }
    Ok(keys)
}

/// Encode a private key as `0x`-prefixed hex plus a trailing newline.
pub(crate) fn encode_private_key(signer: &PrivateKeySigner) -> String {
    format!("{}\n", const_hex::encode_prefixed(signer.to_bytes()))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read as _,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        WriteSecretOptions, read_private_key_file, read_private_keyring_file, write_secret_file,
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tempo-xtask-secret-file-{}-{}",
                std::process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed),
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
    fn refuses_to_overwrite_without_force() {
        let directory = TestDirectory::new();
        let output = directory.path().join("key");
        write_secret_file(&output, b"first\n", WriteSecretOptions { overwrite: false }).unwrap();
        let err = write_secret_file(
            &output,
            b"second\n",
            WriteSecretOptions { overwrite: false },
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read(&output).unwrap(), b"first\n");
    }

    #[test]
    fn force_replaces_the_inode_held_by_existing_readers() {
        let directory = TestDirectory::new();
        let output = directory.path().join("key");
        let legacy = b"legacy-world-readable-key\n";
        fs::write(&output, legacy).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let mut existing_reader = fs::File::open(&output).unwrap();
        write_secret_file(
            &output,
            b"replacement-key\n",
            WriteSecretOptions { overwrite: true },
        )
        .unwrap();

        let mut retained = Vec::new();
        existing_reader.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, legacy);
        assert_eq!(fs::read(&output).unwrap(), b"replacement-key\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn force_rejects_a_symlink_destination() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let target = directory.path().join("target.key");
        let output = directory.path().join("key");
        fs::write(&target, b"do-not-replace\n").unwrap();
        symlink(&target, &output).unwrap();

        let err = write_secret_file(
            &output,
            b"replacement-key\n",
            WriteSecretOptions { overwrite: true },
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-regular"));
        assert_eq!(fs::read(&target).unwrap(), b"do-not-replace\n");
    }

    #[test]
    fn read_private_key_file_rejects_invalid_keys_without_leaking_contents() {
        let directory = TestDirectory::new();
        let output = directory.path().join("bad.key");
        fs::write(&output, "not-a-key\n").unwrap();
        let err = read_private_key_file(&output).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("invalid secp256k1 private key"));
        assert!(!message.contains("not-a-key"));
    }

    #[test]
    fn read_private_keyring_file_skips_blank_lines_and_does_not_leak_invalid_contents() {
        let directory = TestDirectory::new();
        let output = directory.path().join("keyring");
        fs::write(
            &output,
            "\n  0x1111111111111111111111111111111111111111111111111111111111111111  \n\n",
        )
        .unwrap();
        let keys = read_private_keyring_file(&output).unwrap();
        assert_eq!(keys.len(), 1);

        fs::write(&output, "\nprivate-material-that-must-not-appear\n").unwrap();
        let err = read_private_keyring_file(&output).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("nonblank line 2"));
        assert!(!message.contains("private-material-that-must-not-appear"));
    }
}
