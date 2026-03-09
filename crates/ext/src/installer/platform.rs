//! Platform detection and binary path utilities.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use crate::installer::error::InstallerError;

pub(super) fn platform_binary_name(extension: &str) -> String {
    let (os, arch) = platform_tuple();
    format!("tempo-{extension}-{os}-{arch}")
}

fn platform_tuple() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
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

pub(crate) fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

pub(crate) fn default_local_bin() -> Result<PathBuf, InstallerError> {
    let home = home_dir().ok_or(InstallerError::HomeDirMissing)?;
    Ok(home.join(".local").join("bin"))
}

pub(super) fn executable_name(binary: &str) -> String {
    #[cfg(windows)]
    {
        format!("{binary}.exe")
    }
    #[cfg(not(windows))]
    {
        binary.to_string()
    }
}

pub(crate) fn binary_candidates(base: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![format!("{base}.exe"), base.to_string()]
    }
    #[cfg(not(windows))]
    {
        vec![base.to_string()]
    }
}

pub(super) fn check_dir_writable(dir: &Path) -> Result<(), InstallerError> {
    tempfile::NamedTempFile::new_in(dir).map_err(|err| {
        InstallerError::Io(std::io::Error::new(
            err.kind(),
            format!("directory not writable: {}: {err}", dir.display()),
        ))
    })?;
    Ok(())
}

pub(super) fn set_executable_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }

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
    #[cfg(not(windows))]
    fn executable_name_unix() {
        assert_eq!(executable_name("tempo-wallet"), "tempo-wallet");
    }

    #[test]
    #[cfg(not(windows))]
    fn binary_candidates_unix() {
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
    #[cfg(unix)]
    fn set_executable_permissions_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        set_executable_permissions(tmp.path()).unwrap();
        let perms = fs::metadata(tmp.path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o755, 0o755);
    }

    #[test]
    fn find_in_path_finds_binary() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("test-tempo-binary");
        fs::write(&bin_path, "fake binary").unwrap();
        #[cfg(unix)]
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
