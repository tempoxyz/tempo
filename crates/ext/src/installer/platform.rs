//! Platform detection and binary path utilities.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use crate::installer::error::InstallerError;

/// Builds the platform-specific binary name (e.g. `tempo-wallet-darwin-arm64`).
pub(super) fn platform_binary_name(extension: &str) -> String {
    let (os, arch) = platform_tuple();
    format!("tempo-{extension}-{os}-{arch}")
}

fn platform_tuple() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else {
        "unknown"
    };

    (os, arch)
}

/// Searches `PATH` for a binary by name, returning the first match.
pub(crate) fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_env = env::var_os("PATH")?;
    let candidates = binary_candidates(binary);

    for dir in env::split_paths(&path_env) {
        for name in &candidates {
            let path = dir.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
    }

    None
}

/// Returns the user's home directory via `dirs_next`.
pub(crate) fn home_dir() -> Option<PathBuf> {
    dirs_next::home_dir()
}

/// Returns `~/.local/bin`, the default install directory on Unix.
pub(crate) fn default_local_bin() -> Result<PathBuf, InstallerError> {
    let home = home_dir().ok_or(InstallerError::HomeDirMissing)?;
    Ok(home.join(".local").join("bin"))
}

/// Returns the platform executable filename (identity on Unix, `.exe` on Windows).
pub(super) fn executable_name(binary: &str) -> String {
    binary.to_string()
}

/// Returns candidate filenames to search for a binary (platform-dependent).
pub(crate) fn binary_candidates(base: &str) -> Vec<String> {
    vec![base.to_string()]
}

/// Verifies that `dir` is writable by creating a temporary file in it.
pub(super) fn check_dir_writable(dir: &Path) -> Result<(), InstallerError> {
    tempfile::NamedTempFile::new_in(dir).map_err(|err| {
        InstallerError::Io(std::io::Error::new(
            err.kind(),
            format!("directory not writable: {}: {err}", dir.display()),
        ))
    })?;
    Ok(())
}

/// Sets the file mode to `0o755` (owner rwx, group/other rx).
pub(super) fn set_executable_permissions(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::ENV_MUTEX;

    #[test]
    fn platform_binary_name_format() {
        let name = platform_binary_name("wallet");
        assert!(
            name.starts_with("tempo-wallet-"),
            "expected prefix 'tempo-wallet-', got: {name}"
        );

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(name, "tempo-wallet-darwin-arm64");

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        assert_eq!(name, "tempo-wallet-darwin-amd64");

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        assert_eq!(name, "tempo-wallet-linux-arm64");

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(name, "tempo-wallet-linux-amd64");
    }

    #[test]
    fn executable_name_passthrough() {
        assert_eq!(executable_name("tempo-wallet"), "tempo-wallet");
    }

    #[test]
    fn binary_candidates_single() {
        assert_eq!(
            binary_candidates("tempo-wallet"),
            vec!["tempo-wallet".to_string()]
        );
    }

    #[test]
    fn home_dir_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let original = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/test/home") };
        assert_eq!(home_dir(), Some(PathBuf::from("/test/home")));
        match original {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn default_local_bin_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let original = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/test/home") };
        let result = default_local_bin().unwrap();
        assert_eq!(result, PathBuf::from("/test/home/.local/bin"));
        match original {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn check_dir_writable_on_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_dir_writable(dir.path()).is_ok());
    }

    #[test]
    fn check_dir_writable_on_nonexistent() {
        let result = check_dir_writable(Path::new("/nonexistent-test-dir-12345"));
        assert!(result.is_err());
    }

    #[test]
    fn set_executable_permissions_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        set_executable_permissions(tmp.as_file()).unwrap();
        let perms = tmp.as_file().metadata().unwrap().permissions();
        assert_eq!(perms.mode() & 0o755, 0o755);
    }

    #[test]
    fn find_in_path_finds_binary() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("test-tempo-binary");
        fs::write(&bin_path, "fake binary").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let original = std::env::var_os("PATH");
        let new_path = format!(
            "{}:{}",
            dir.path().display(),
            original.as_deref().unwrap_or_default().to_string_lossy()
        );
        unsafe { std::env::set_var("PATH", &new_path) };

        let found = find_in_path("test-tempo-binary");
        assert_eq!(found, Some(bin_path));

        match original {
            Some(v) => unsafe { std::env::set_var("PATH", v) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }

    #[test]
    fn find_in_path_returns_none_for_missing() {
        assert!(find_in_path("nonexistent-binary-xyz-12345").is_none());
    }
}
