//! Platform detection and binary path utilities.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

    #[test]
    fn platform_binary_name_format() {
        let name = platform_binary_name("wallet");
        assert!(name.starts_with("tempo-wallet-"), "expected prefix 'tempo-wallet-', got: {name}");

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
        assert_eq!(binary_candidates("tempo-wallet"), vec!["tempo-wallet".to_string()]);
    }
}
