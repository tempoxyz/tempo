//! Release manifest signing for `tempo` extensions.
//!
//! Produces the manifests and minisign signatures that the installer
//! verifies. Trusted comments carry `file:<binary>` and `version:<version>`
//! for binaries and `skill:<package>` for skill files, which the installer
//! checks to block cross-extension substitution and version replay.

mod error;

use std::{
    collections::BTreeMap,
    io::Cursor,
    path::{Path, PathBuf},
};

use minisign::{KeyPair, PublicKey, SecretKey, SecretKeyBox};
use serde_json::json;
use sha2::{Digest, Sha256};

pub use error::SignError;

/// Artifact suffixes that are never signed as binaries.
const SKIP_EXTENSIONS: &[&str] = &[".json", ".md", ".sh", ".txt", ".py", ".sha256"];

/// Inputs for [`build_manifest`].
#[derive(Debug, Clone)]
pub struct ManifestOptions {
    /// Directory containing the release binaries.
    pub artifacts_dir: PathBuf,
    /// Release version, with or without a leading `v`.
    pub version: String,
    /// Base URL binaries are served from, ending in the package name
    /// (e.g. `https://cli.tempo.xyz/extensions/tempo-wallet`).
    pub base_url: String,
    /// One-line extension description.
    pub description: Option<String>,
    /// URL of the extension's `SKILL.md`.
    pub skill: Option<String>,
    /// SHA-256 hex digest of the `SKILL.md`.
    pub skill_sha256: Option<String>,
    /// Local `SKILL.md` to sign.
    pub skill_file: Option<PathBuf>,
}

/// Generates an unencrypted minisign keypair, writes the secret key box to
/// `path` (mode 0600 on Unix), and returns the base64 public key.
pub fn generate_key(path: &Path) -> Result<String, SignError> {
    let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair()
        .map_err(|err| SignError::crypto("generate keypair", err))?;
    let sk_box = sk
        .to_box(None)
        .map_err(|err| SignError::crypto("box secret key", err))?;

    std::fs::write(path, sk_box.to_string())
        .map_err(|err| SignError::io("write key file", path, err))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|err| SignError::io("set key file permissions", path, err))?;
    }

    Ok(pk.to_base64())
}

/// Loads an unencrypted minisign secret key box from `path`.
pub fn load_secret_key(path: &Path) -> Result<SecretKey, SignError> {
    let contents =
        std::fs::read_to_string(path).map_err(|err| SignError::io("read key file", path, err))?;
    SecretKeyBox::from_string(&contents)
        .map_err(|err| SignError::crypto("parse secret key box", err))?
        .into_unencrypted_secret_key()
        .map_err(|err| SignError::crypto("decode secret key", err))
}

/// Returns the base64 public key for `sk`.
pub fn public_key(sk: &SecretKey) -> Result<String, SignError> {
    PublicKey::from_secret_key(sk)
        .map(|pk| pk.to_base64())
        .map_err(|err| SignError::crypto("derive public key", err))
}

/// Signs every binary in `options.artifacts_dir` and returns the release
/// manifest the installer reads.
pub fn build_manifest(
    options: &ManifestOptions,
    sk: &SecretKey,
) -> Result<serde_json::Value, SignError> {
    let base_url = options.base_url.trim_end_matches('/');
    let version = if options.version.starts_with('v') {
        options.version.clone()
    } else {
        format!("v{}", options.version)
    };

    let dir = &options.artifacts_dir;
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|err| SignError::io("read artifacts directory", dir, err))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut binaries = BTreeMap::new();
    for entry in entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().into_owned();
        if SKIP_EXTENSIONS.iter().any(|ext| filename.ends_with(ext)) {
            continue;
        }

        let data =
            std::fs::read(&path).map_err(|err| SignError::io("read artifact", &path, err))?;
        let signature = sign(&data, &format!("file:{filename}\tversion:{version}"), sk)?;
        binaries.insert(
            filename.clone(),
            json!({
                "url": format!("{base_url}/{version}/{filename}"),
                "sha256": sha256_hex(&data),
                "signature": signature,
            }),
        );
    }

    let mut manifest = json!({ "version": version, "binaries": binaries });
    if let Some(description) = &options.description {
        manifest["description"] = json!(description);
    }
    if let Some(skill) = &options.skill {
        manifest["skill"] = json!(skill);
    }
    if let Some(sha256) = &options.skill_sha256 {
        manifest["skill_sha256"] = json!(sha256);
    }
    if let Some(path) = &options.skill_file {
        // The installer expects `skill:<package>`, where the package is the
        // last segment of the base URL (e.g. `tempo-wallet`).
        let package = base_url.rsplit('/').next().unwrap_or_default();
        let data =
            std::fs::read(path).map_err(|err| SignError::io("read skill file", path, err))?;
        manifest["skill_signature"] = json!(sign(
            &data,
            &format!("skill:{package}\tversion:{version}"),
            sk
        )?);
    }

    Ok(manifest)
}

/// Returns a minisign signature box over `data` with `trusted_comment`.
fn sign(data: &[u8], trusted_comment: &str, sk: &SecretKey) -> Result<String, SignError> {
    let pk = PublicKey::from_secret_key(sk)
        .map_err(|err| SignError::crypto("derive public key", err))?;
    minisign::sign(
        Some(&pk),
        sk,
        Cursor::new(data),
        Some(trusted_comment),
        Some("tempo release signature"),
    )
    .map(|sig| sig.into_string())
    .map_err(|err| SignError::crypto("sign artifact", err))
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_skips_non_binaries_and_prefixes_version() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("release.key");
        generate_key(&key).unwrap();
        let sk = load_secret_key(&key).unwrap();

        let artifacts = tmp.path().join("artifacts");
        std::fs::create_dir(&artifacts).unwrap();
        std::fs::write(artifacts.join("tempo-x-linux-amd64"), b"bin").unwrap();
        std::fs::write(artifacts.join("tempo-x-linux-amd64.sha256"), b"hash").unwrap();
        std::fs::write(artifacts.join("tempo-x.spdx.json"), b"{}").unwrap();

        let manifest = build_manifest(
            &ManifestOptions {
                artifacts_dir: artifacts,
                version: "1.2.3".into(),
                base_url: "https://cli.tempo.xyz/extensions/tempo-x/".into(),
                description: Some("X".into()),
                skill: None,
                skill_sha256: None,
                skill_file: None,
            },
            &sk,
        )
        .unwrap();

        assert_eq!(manifest["version"], "v1.2.3");
        assert_eq!(manifest["description"], "X");
        let binaries = manifest["binaries"].as_object().unwrap();
        assert_eq!(binaries.len(), 1);
        let binary = &binaries["tempo-x-linux-amd64"];
        assert_eq!(
            binary["url"],
            "https://cli.tempo.xyz/extensions/tempo-x/v1.2.3/tempo-x-linux-amd64"
        );
        assert_eq!(binary["sha256"], sha256_hex(b"bin"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("release.key");
        let pk = generate_key(&key).unwrap();

        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(public_key(&load_secret_key(&key).unwrap()).unwrap(), pk);
    }
}
