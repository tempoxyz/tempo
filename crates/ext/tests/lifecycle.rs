//! Integration tests exercising the full extension lifecycle:
//! add → update → remove, with real signature verification against
//! local `file://` manifests.
//!
//! Each test gets its own temp directory (`TEMPO_HOME`), test keypair,
//! and locally-signed dummy binary. No network access required.

use minisign::{KeyPair, PublicKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, fs, io::Cursor, path::PathBuf, sync::Mutex};

/// Serialize integration tests — they mutate process-wide env vars.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Fixture helpers ─────────────────────────────────────────────────

struct Fixture {
    home: PathBuf,
    base_dir: PathBuf,
    pk: PublicKey,
    sk: minisign::SecretKey,
    _tmp: tempfile::TempDir,
    prev_env: Vec<(&'static str, Option<String>)>,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let base_dir = tmp.path().join("cdn");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&base_dir).unwrap();

        let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().unwrap();
        let pk_base64 = pk.to_base64();

        let prev_env = vec![
            ("TEMPO_HOME", env::var("TEMPO_HOME").ok()),
            ("TEMPO_EXT_BASE_URL", env::var("TEMPO_EXT_BASE_URL").ok()),
            (
                "TEMPO_EXT_PUBLIC_KEY",
                env::var("TEMPO_EXT_PUBLIC_KEY").ok(),
            ),
        ];

        unsafe {
            env::set_var("TEMPO_HOME", &home);
            env::set_var(
                "TEMPO_EXT_BASE_URL",
                format!("file://{}", base_dir.display()),
            );
            env::set_var("TEMPO_EXT_PUBLIC_KEY", &pk_base64);
        }

        Self {
            home,
            base_dir,
            pk,
            sk,
            _tmp: tmp,
            prev_env,
        }
    }

    fn bin_dir(&self) -> PathBuf {
        self.home.join("bin")
    }

    fn binary_path(&self, extension: &str) -> PathBuf {
        self.bin_dir().join(format!("tempo-{extension}"))
    }

    /// Create a signed extension with a dummy binary and publish a manifest
    /// at the expected CDN path.
    fn publish_extension(&self, extension: &str, version: &str) {
        self.publish_extension_inner(extension, version, None);
    }

    /// Publish an extension with a custom trusted comment (for substitution tests).
    fn publish_extension_with_comment(
        &self,
        extension: &str,
        version: &str,
        trusted_comment: &str,
    ) {
        self.publish_extension_inner(extension, version, Some(trusted_comment));
    }

    fn publish_extension_inner(
        &self,
        extension: &str,
        version: &str,
        trusted_comment_override: Option<&str>,
    ) {
        let platform_key = platform_binary_name(extension);
        let ext_dir = self
            .base_dir
            .join("extensions")
            .join(format!("tempo-{extension}"));
        fs::create_dir_all(&ext_dir).unwrap();

        let binary_content = format!("#!/bin/sh\necho tempo-{extension} {version}\n");
        let binary_path = ext_dir.join(&platform_key);
        fs::write(&binary_path, &binary_content).unwrap();

        let tc = trusted_comment_override
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("file:{platform_key}\tversion:{version}"));

        let sig_box = minisign::sign(
            Some(&self.pk),
            &self.sk,
            Cursor::new(binary_content.as_bytes()),
            Some(&tc),
            Some("test release signature"),
        )
        .unwrap();

        let sha256 = sha256_hex(binary_content.as_bytes());

        let mut binaries = HashMap::new();
        binaries.insert(
            platform_key,
            serde_json::json!({
                "url": format!("file://{}", binary_path.display()),
                "sha256": sha256,
                "signature": sig_box.into_string(),
            }),
        );

        let manifest = serde_json::json!({
            "version": version,
            "binaries": binaries,
        });

        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(ext_dir.join("manifest.json"), &manifest_json).unwrap();
        // Also write a versioned manifest so `tempo add <ext> <version>` works.
        let v = version.strip_prefix('v').unwrap_or(version);
        let versioned_dir = ext_dir.join(format!("v{v}"));
        fs::create_dir_all(&versioned_dir).unwrap();
        fs::write(versioned_dir.join("manifest.json"), &manifest_json).unwrap();
    }

    /// Publish a manifest that references a binary from a different extension
    /// (cross-extension substitution attack).
    fn publish_cross_substitution(&self, target_ext: &str, version: &str, source_ext: &str) {
        let target_platform = platform_binary_name(target_ext);
        let source_platform = platform_binary_name(source_ext);
        let target_dir = self
            .base_dir
            .join("extensions")
            .join(format!("tempo-{target_ext}"));
        let source_dir = self
            .base_dir
            .join("extensions")
            .join(format!("tempo-{source_ext}"));
        fs::create_dir_all(&target_dir).unwrap();

        // Read the source binary and its signature from the source manifest.
        let source_manifest_path = source_dir.join("manifest.json");
        let source_manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&source_manifest_path).unwrap()).unwrap();
        let source_binary = &source_manifest["binaries"][&source_platform];

        // Copy the source binary to the target path.
        let source_binary_path = source_dir.join(&source_platform);
        let target_binary_path = target_dir.join(&target_platform);
        fs::copy(&source_binary_path, &target_binary_path).unwrap();

        // Build a manifest for target_ext that points to the source binary
        // with the source's valid signature.
        let mut binaries = HashMap::new();
        binaries.insert(
            target_platform,
            serde_json::json!({
                "url": format!("file://{}", target_binary_path.display()),
                "sha256": source_binary["sha256"],
                "signature": source_binary["signature"],
            }),
        );

        let manifest = serde_json::json!({
            "version": version,
            "binaries": binaries,
        });
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(target_dir.join("manifest.json"), &manifest_json).unwrap();
    }

    /// Publish a manifest with a missing signature field.
    fn publish_unsigned(&self, extension: &str, version: &str) {
        let platform_key = platform_binary_name(extension);
        let ext_dir = self
            .base_dir
            .join("extensions")
            .join(format!("tempo-{extension}"));
        fs::create_dir_all(&ext_dir).unwrap();

        let binary_content = format!("#!/bin/sh\necho tempo-{extension} {version}\n");
        let binary_path = ext_dir.join(&platform_key);
        fs::write(&binary_path, &binary_content).unwrap();

        let sha256 = sha256_hex(binary_content.as_bytes());

        let mut binaries = HashMap::new();
        binaries.insert(
            platform_key,
            serde_json::json!({
                "url": format!("file://{}", binary_path.display()),
                "sha256": sha256,
            }),
        );

        let manifest = serde_json::json!({
            "version": version,
            "binaries": binaries,
        });
        fs::write(
            ext_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// Publish a manifest where the binary URL uses http://.
    fn publish_with_http_url(&self, extension: &str, version: &str) {
        let platform_key = platform_binary_name(extension);
        let ext_dir = self
            .base_dir
            .join("extensions")
            .join(format!("tempo-{extension}"));
        fs::create_dir_all(&ext_dir).unwrap();

        let binary_content = format!("#!/bin/sh\necho tempo-{extension} {version}\n");

        let sig_box = minisign::sign(
            Some(&self.pk),
            &self.sk,
            Cursor::new(binary_content.as_bytes()),
            Some(&format!("file:{platform_key}\tversion:{version}")),
            Some("test"),
        )
        .unwrap();

        let mut binaries = HashMap::new();
        binaries.insert(
            platform_key,
            serde_json::json!({
                "url": "http://insecure.example.com/binary",
                "sha256": sha256_hex(binary_content.as_bytes()),
                "signature": sig_box.into_string(),
            }),
        );

        let manifest = serde_json::json!({
            "version": version,
            "binaries": binaries,
        });
        fs::write(
            ext_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// Record an installed version in extensions.json (simulating a prior install).
    fn record_installed_version(&self, extension: &str, version: &str) {
        self.record_installed_version_inner(extension, version, false);
    }

    fn record_installed_version_inner(&self, extension: &str, version: &str, pinned: bool) {
        let reg_path = self.home.join("extensions.json");
        let mut reg: serde_json::Value = if reg_path.exists() {
            serde_json::from_str(&fs::read_to_string(&reg_path).unwrap()).unwrap()
        } else {
            serde_json::json!({"extensions": {}})
        };
        reg["extensions"][extension] = serde_json::json!({
            "checked_at": 0,
            "installed_version": version,
            "pinned": pinned,
        });
        fs::write(&reg_path, serde_json::to_string_pretty(&reg).unwrap()).unwrap();
    }

    /// Read the registry and check if an extension is pinned.
    fn is_pinned(&self, extension: &str) -> bool {
        let reg_path = self.home.join("extensions.json");
        if !reg_path.exists() {
            return false;
        }
        let reg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&reg_path).unwrap()).unwrap();
        reg["extensions"][extension]["pinned"]
            .as_bool()
            .unwrap_or(false)
    }

    /// Read the installed version from the registry.
    fn installed_version(&self, extension: &str) -> Option<String> {
        let reg_path = self.home.join("extensions.json");
        if !reg_path.exists() {
            return None;
        }
        let reg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&reg_path).unwrap()).unwrap();
        reg["extensions"][extension]["installed_version"]
            .as_str()
            .map(|s| s.to_string())
    }

    fn run(&self, args: &[&str]) -> Result<i32, tempo_ext::LauncherError> {
        tempo_ext::run(args.iter().map(|s| s.to_string()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (key, prev) in &self.prev_env {
            match prev {
                Some(v) => unsafe { env::set_var(key, v) },
                None => unsafe { env::remove_var(key) },
            }
        }
    }
}

fn platform_binary_name(extension: &str) -> String {
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
    format!("tempo-{extension}-{os}-{arch}")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ── Basic lifecycle tests ───────────────────────────────────────────

#[test]
fn add_installs_extension() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    let code = fix.run(&["tempo", "add", "testpkg"]).unwrap();
    assert_eq!(code, 0);
    assert!(fix.binary_path("testpkg").exists());
}

#[test]
fn add_dry_run_does_not_install() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    let code = fix.run(&["tempo", "add", "testpkg", "--dry-run"]).unwrap();
    assert_eq!(code, 0);
    assert!(!fix.binary_path("testpkg").exists());
}

#[test]
fn remove_deletes_binary() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    assert!(fix.binary_path("testpkg").exists());
    assert!(fix.installed_version("testpkg").is_some());

    let code = fix.run(&["tempo", "remove", "testpkg"]).unwrap();
    assert_eq!(code, 0);
    assert!(!fix.binary_path("testpkg").exists());
    assert!(
        fix.installed_version("testpkg").is_none(),
        "remove should clear registry entry"
    );
}

#[test]
fn update_reinstalls_extension() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "1.0.0");
    let before = fs::read(fix.binary_path("testpkg")).unwrap();

    fix.publish_extension("testpkg", "2.0.0");
    fix.run(&["tempo", "update", "testpkg"]).unwrap();

    let after = fs::read(fix.binary_path("testpkg")).unwrap();
    assert_ne!(before, after, "binary should change after update");
}

#[test]
fn add_rejects_invalid_extension_name() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&["tempo", "add", "../evil"]);
    assert!(result.is_err());
}

#[test]
fn add_unknown_extension_fails_gracefully() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&["tempo", "add", "nonexistent"]);
    assert!(result.is_err());
}

#[test]
fn add_with_explicit_manifest() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    let manifest_path = fix.base_dir.join("extensions/tempo-testpkg/manifest.json");
    let manifest_url = format!("file://{}", manifest_path.display());

    let code = fix
        .run(&[
            "tempo",
            "add",
            "testpkg",
            "--release-manifest",
            &manifest_url,
            "--release-public-key",
            &fix.pk.to_base64(),
        ])
        .unwrap();
    assert_eq!(code, 0);
    assert!(fix.binary_path("testpkg").exists());
}

#[test]
fn full_lifecycle() {
    let _lock = lock();
    let fix = Fixture::new();

    // 1. Install
    fix.publish_extension("lifecycle", "1.0.0");
    assert_eq!(fix.run(&["tempo", "add", "lifecycle"]).unwrap(), 0);
    assert!(fix.binary_path("lifecycle").exists());
    fix.record_installed_version("lifecycle", "1.0.0");

    // 2. Update to newer version
    fix.publish_extension("lifecycle", "2.0.0");
    assert_eq!(fix.run(&["tempo", "update", "lifecycle"]).unwrap(), 0);
    let content = fs::read_to_string(fix.binary_path("lifecycle")).unwrap();
    assert!(content.contains("2.0.0"));

    // 3. Remove
    assert_eq!(fix.run(&["tempo", "remove", "lifecycle"]).unwrap(), 0);
    assert!(!fix.binary_path("lifecycle").exists());

    // 4. Re-add
    assert_eq!(fix.run(&["tempo", "add", "lifecycle"]).unwrap(), 0);
    assert!(fix.binary_path("lifecycle").exists());
}

// ── Security: downgrade prevention ──────────────────────────────────

#[test]
fn update_rejects_downgrade() {
    let _lock = lock();
    let fix = Fixture::new();

    // Install v2.0.0, then try to "update" to v1.0.0.
    fix.publish_extension("testpkg", "2.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "2.0.0");

    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "update", "testpkg"]).unwrap();

    // Binary should still be v2.0.0 content.
    let content = fs::read_to_string(fix.binary_path("testpkg")).unwrap();
    assert!(
        content.contains("2.0.0"),
        "update should not downgrade: {content}"
    );
}

#[test]
fn update_skips_same_version() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "1.0.0");

    // "Update" when manifest has the same version — should be a no-op.
    let code = fix.run(&["tempo", "update", "testpkg"]).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn update_normalizes_v_prefix() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("testpkg", "v2.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "v2.0.0");

    // Manifest says "2.0.0" (no v prefix) — same version, should skip.
    fix.publish_extension("testpkg", "2.0.0");
    fix.run(&["tempo", "update", "testpkg"]).unwrap();

    let content = fs::read_to_string(fix.binary_path("testpkg")).unwrap();
    assert!(
        content.contains("v2.0.0"),
        "should not reinstall same version"
    );
}

#[test]
fn update_non_semver_different_version_reinstalls() {
    let _lock = lock();
    let fix = Fixture::new();

    // Install with a non-semver version string.
    fix.publish_extension("testpkg", "nightly-2025-01-01");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "nightly-2025-01-01");

    // Publish a different non-semver version — should reinstall.
    fix.publish_extension("testpkg", "nightly-2025-03-09");
    fix.run(&["tempo", "update", "testpkg"]).unwrap();

    let content = fs::read_to_string(fix.binary_path("testpkg")).unwrap();
    assert!(
        content.contains("nightly-2025-03-09"),
        "non-semver update with different version should reinstall: {content}"
    );
}

#[test]
fn update_non_semver_same_version_skips() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("testpkg", "nightly-2025-01-01");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "nightly-2025-01-01");

    // Same non-semver version — should be a no-op.
    let code = fix.run(&["tempo", "update", "testpkg"]).unwrap();
    assert_eq!(code, 0);
}

// ── Security: signature verification ────────────────────────────────

#[test]
fn tampered_binary_rejected() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("tampered", "1.0.0");

    // Tamper with the binary after signing.
    let platform_key = platform_binary_name("tampered");
    let binary_path = fix
        .base_dir
        .join("extensions/tempo-tampered")
        .join(&platform_key);
    fs::write(&binary_path, "TAMPERED CONTENT").unwrap();

    let result = fix.run(&["tempo", "add", "tampered"]);
    assert!(result.is_err(), "tampered binary should be rejected");
    assert!(!fix.binary_path("tampered").exists());
}

#[test]
fn wrong_key_rejected() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    // Override with a different public key.
    let other_kp = KeyPair::generate_unencrypted_keypair().unwrap();
    unsafe { env::set_var("TEMPO_EXT_PUBLIC_KEY", other_kp.pk.to_base64()) };

    let result = fix.run(&["tempo", "add", "testpkg"]);
    assert!(result.is_err(), "wrong key should be rejected");
    assert!(!fix.binary_path("testpkg").exists());
}

#[test]
fn missing_signature_rejected() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_unsigned("nosig", "1.0.0");

    let result = fix.run(&["tempo", "add", "nosig"]);
    assert!(result.is_err(), "unsigned binary should be rejected");
    assert!(!fix.binary_path("nosig").exists());
}

// ── Security: cross-extension substitution ──────────────────────────

#[test]
fn cross_extension_substitution_rejected() {
    let _lock = lock();
    let fix = Fixture::new();

    // Publish a legitimate mpp extension.
    fix.publish_extension("mpp", "1.0.0");

    // Create a wallet manifest that points to the mpp binary (with mpp's
    // valid signature). The trusted comment says "file:tempo-mpp-..." but
    // the installer expects "file:tempo-wallet-...".
    fix.publish_cross_substitution("wallet", "1.0.0", "mpp");

    let result = fix.run(&["tempo", "add", "wallet"]);
    assert!(
        result.is_err(),
        "cross-extension substitution should be rejected"
    );
    assert!(!fix.binary_path("wallet").exists());
}

#[test]
fn wrong_trusted_comment_rejected() {
    let _lock = lock();
    let fix = Fixture::new();

    // Publish with an incorrect trusted comment.
    fix.publish_extension_with_comment("testpkg", "1.0.0", "file:wrong-name");

    let result = fix.run(&["tempo", "add", "testpkg"]);
    assert!(result.is_err(), "wrong trusted comment should be rejected");
    assert!(!fix.binary_path("testpkg").exists());
}

// ── Security: URL scheme enforcement ────────────────────────────────

#[test]
fn http_download_url_rejected() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_with_http_url("httptest", "1.0.0");

    let result = fix.run(&["tempo", "add", "httptest"]);
    assert!(result.is_err(), "http:// download URL should be rejected");
    assert!(!fix.binary_path("httptest").exists());
}

// ── Security: failed update preserves existing binary ───────────────

#[test]
fn failed_update_preserves_existing_binary() {
    let _lock = lock();
    let fix = Fixture::new();

    // Install a good v1.
    fix.publish_extension("preserved", "1.0.0");
    fix.run(&["tempo", "add", "preserved"]).unwrap();
    fix.record_installed_version("preserved", "1.0.0");
    let original = fs::read(fix.binary_path("preserved")).unwrap();

    // Publish a tampered v2.
    fix.publish_extension("preserved", "2.0.0");
    let platform_key = platform_binary_name("preserved");
    let binary_path = fix
        .base_dir
        .join("extensions/tempo-preserved")
        .join(&platform_key);
    fs::write(&binary_path, "TAMPERED").unwrap();

    // Update should fail.
    let _ = fix.run(&["tempo", "update", "preserved"]);

    // Original binary must survive.
    assert!(fix.binary_path("preserved").exists());
    let after = fs::read(fix.binary_path("preserved")).unwrap();
    assert_eq!(original, after, "original binary must be preserved");
}

// ── Security: insecure manifest URL rejection ──────────────────────

#[test]
fn add_rejects_http_manifest_url() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&[
        "tempo",
        "add",
        "testpkg",
        "--release-manifest",
        "http://evil.com/manifest.json",
        "--release-public-key",
        &fix.pk.to_base64(),
    ]);
    assert!(result.is_err(), "http:// manifest URL should be rejected");
    assert!(!fix.binary_path("testpkg").exists());
}

#[test]
fn add_rejects_ftp_manifest_url() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&[
        "tempo",
        "add",
        "testpkg",
        "--release-manifest",
        "ftp://evil.com/manifest.json",
        "--release-public-key",
        &fix.pk.to_base64(),
    ]);
    assert!(result.is_err(), "ftp:// manifest URL should be rejected");
    assert!(!fix.binary_path("testpkg").exists());
}

#[test]
fn add_rejects_data_manifest_url() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&[
        "tempo",
        "add",
        "testpkg",
        "--release-manifest",
        "data:text/json,{}",
        "--release-public-key",
        &fix.pk.to_base64(),
    ]);
    assert!(result.is_err(), "data: manifest URL should be rejected");
    assert!(!fix.binary_path("testpkg").exists());
}

// ── State integrity on failure ─────────────────────────────────────

#[test]
fn failed_install_does_not_pollute_state() {
    let _lock = lock();
    let fix = Fixture::new();

    // Publish then tamper the binary so install fails.
    fix.publish_extension("statepkg", "1.0.0");
    let platform_key = platform_binary_name("statepkg");
    let binary_path = fix
        .base_dir
        .join("extensions/tempo-statepkg")
        .join(&platform_key);
    fs::write(&binary_path, "TAMPERED").unwrap();

    let _ = fix.run(&["tempo", "add", "statepkg"]);

    // extensions.json should either not exist or not contain statepkg.
    let state_path = fix.home.join("extensions.json");
    if state_path.exists() {
        let state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        assert!(
            state
                .get("extensions")
                .and_then(|e| e.get("statepkg"))
                .is_none(),
            "extensions.json should not record a failed install"
        );
    }
}

// ── Remove edge cases ──────────────────────────────────────────────

#[test]
fn remove_nonexistent_extension_succeeds() {
    let _lock = lock();
    let fix = Fixture::new();

    // Removing an extension that was never installed should succeed.
    let code = fix.run(&["tempo", "remove", "ghost"]).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn remove_dry_run_preserves_binary() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("drytest", "1.0.0");
    fix.run(&["tempo", "add", "drytest"]).unwrap();
    assert!(fix.binary_path("drytest").exists());

    let code = fix
        .run(&["tempo", "remove", "drytest", "--dry-run"])
        .unwrap();
    assert_eq!(code, 0);
    assert!(
        fix.binary_path("drytest").exists(),
        "dry-run remove should not delete the binary"
    );
    assert!(
        fix.installed_version("drytest").is_some(),
        "dry-run remove should not clear registry entry"
    );
}

#[test]
fn remove_clears_registry_entry() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("regtest", "1.0.0");
    fix.run(&["tempo", "add", "regtest"]).unwrap();
    assert_eq!(
        fix.installed_version("regtest").as_deref(),
        Some("1.0.0"),
        "add should record version in registry"
    );

    fix.run(&["tempo", "remove", "regtest"]).unwrap();
    assert!(
        fix.installed_version("regtest").is_none(),
        "remove should clear the registry entry so list no longer shows it"
    );

    // Re-add should work cleanly after remove.
    fix.publish_extension("regtest", "2.0.0");
    fix.run(&["tempo", "add", "regtest"]).unwrap();
    assert_eq!(
        fix.installed_version("regtest").as_deref(),
        Some("2.0.0"),
        "re-add after remove should record new version"
    );
}

// ── Update: explicit manifest ───────────────────────────────────────

#[test]
fn update_with_explicit_manifest() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    fix.record_installed_version("testpkg", "1.0.0");

    fix.publish_extension("testpkg", "2.0.0");
    let manifest_path = fix.base_dir.join("extensions/tempo-testpkg/manifest.json");
    let manifest_url = format!("file://{}", manifest_path.display());

    let code = fix
        .run(&[
            "tempo",
            "update",
            "testpkg",
            "--release-manifest",
            &manifest_url,
            "--release-public-key",
            &fix.pk.to_base64(),
        ])
        .unwrap();
    assert_eq!(code, 0);

    let content = fs::read_to_string(fix.binary_path("testpkg")).unwrap();
    assert!(
        content.contains("2.0.0"),
        "update with explicit manifest should install new version: {content}"
    );
}

// ── Update: extension name validation ──────────────────────────────

#[test]
fn update_rejects_invalid_extension_name() {
    let _lock = lock();
    let fix = Fixture::new();

    let result = fix.run(&["tempo", "update", "../evil"]);
    assert!(
        result.is_err(),
        "update should reject invalid extension names"
    );
}

// ── Pinned versions ────────────────────────────────────────────────

#[test]
fn add_with_version_pins_extension() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    let code = fix.run(&["tempo", "add", "testpkg", "1.0.0"]).unwrap();
    assert_eq!(code, 0);
    assert!(fix.is_pinned("testpkg"), "explicit version should pin");
}

#[test]
fn add_without_version_does_not_pin() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    let code = fix.run(&["tempo", "add", "testpkg"]).unwrap();
    assert_eq!(code, 0);
    assert!(!fix.is_pinned("testpkg"), "no version should not pin");
}

#[test]
fn update_unpins_extension() {
    let _lock = lock();
    let fix = Fixture::new();

    // Install pinned v1.
    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg", "1.0.0"]).unwrap();
    assert!(fix.is_pinned("testpkg"));

    // Update to latest — should unpin.
    fix.publish_extension("testpkg", "2.0.0");
    fix.run(&["tempo", "update", "testpkg"]).unwrap();
    assert!(!fix.is_pinned("testpkg"), "update should unpin");
}

#[test]
fn add_records_version_in_registry() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    fix.run(&["tempo", "add", "testpkg"]).unwrap();
    assert_eq!(
        fix.installed_version("testpkg").as_deref(),
        Some("1.0.0"),
        "add should record installed version in registry"
    );
}

// ── List command ───────────────────────────────────────────────────

#[test]
fn list_shows_installed_extensions() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("alpha", "1.0.0");
    fix.publish_extension("beta", "2.0.0");
    fix.run(&["tempo", "add", "alpha"]).unwrap();
    fix.run(&["tempo", "add", "beta"]).unwrap();

    let code = fix.run(&["tempo", "list"]).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn list_succeeds_with_no_extensions() {
    let _lock = lock();
    let fix = Fixture::new();

    let code = fix.run(&["tempo", "list"]).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn list_shows_pinned_status() {
    let _lock = lock();
    let fix = Fixture::new();

    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg", "1.0.0"]).unwrap();
    assert!(fix.is_pinned("testpkg"));

    let code = fix.run(&["tempo", "list"]).unwrap();
    assert_eq!(code, 0);
}

// ── Corrupt registry ──────────────────────────────────────────────

#[test]
fn corrupt_registry_blocks_add() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    // Write invalid JSON to the registry file.
    fs::write(fix.home.join("extensions.json"), "NOT VALID JSON").unwrap();

    let err = fix.run(&["tempo", "add", "testpkg"]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("registry corrupt"),
        "expected 'registry corrupt', got: {msg}"
    );
}

#[test]
fn corrupt_registry_blocks_update() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();

    // Corrupt the registry after a successful install.
    fs::write(fix.home.join("extensions.json"), "{bad json}").unwrap();

    let err = fix.run(&["tempo", "update", "testpkg"]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("registry corrupt"), "got: {msg}");
}

#[test]
fn corrupt_registry_blocks_update_all() {
    let _lock = lock();
    let fix = Fixture::new();

    fs::write(fix.home.join("extensions.json"), "<<<").unwrap();

    let err = fix.run(&["tempo", "update"]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("registry corrupt"), "got: {msg}");
}

#[test]
fn corrupt_registry_blocks_remove() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");
    fix.run(&["tempo", "add", "testpkg"]).unwrap();

    fs::write(fix.home.join("extensions.json"), "oops").unwrap();

    let err = fix.run(&["tempo", "remove", "testpkg"]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("registry corrupt"), "got: {msg}");
}

#[test]
fn corrupt_registry_blocks_list() {
    let _lock = lock();
    let fix = Fixture::new();

    fs::write(fix.home.join("extensions.json"), "~").unwrap();

    let err = fix.run(&["tempo", "list"]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("registry corrupt"), "got: {msg}");
}

#[test]
fn corrupt_registry_error_contains_path() {
    let _lock = lock();
    let fix = Fixture::new();

    fs::write(fix.home.join("extensions.json"), "garbage").unwrap();

    let err = fix.run(&["tempo", "list"]).unwrap_err();
    let msg = err.to_string();
    let expected = fix.home.join("extensions.json").display().to_string();
    assert!(
        msg.contains(&expected),
        "error should contain path '{expected}', got: {msg}"
    );
}

#[test]
fn missing_registry_allows_all_commands() {
    let _lock = lock();
    let fix = Fixture::new();

    // No extensions.json exists — all commands should succeed.
    assert_eq!(fix.run(&["tempo", "list"]).unwrap(), 0);
    assert_eq!(fix.run(&["tempo", "update"]).unwrap(), 0);

    // Add should work fine with no prior registry.
    fix.publish_extension("testpkg", "1.0.0");
    assert_eq!(fix.run(&["tempo", "add", "testpkg"]).unwrap(), 0);
    assert_eq!(fix.installed_version("testpkg").as_deref(), Some("1.0.0"));

    // Remove should also work.
    assert_eq!(fix.run(&["tempo", "remove", "testpkg"]).unwrap(), 0);
}

#[test]
fn corrupt_registry_during_auto_install_is_non_fatal() {
    let _lock = lock();
    let fix = Fixture::new();
    fix.publish_extension("testpkg", "1.0.0");

    // Corrupt the registry before attempting auto-install via extension dispatch.
    // Auto-install swallows errors (including registry corruption) to avoid
    // blocking extension execution — the binary still gets installed but the
    // registry write is lost.
    fs::write(fix.home.join("extensions.json"), "!!!").unwrap();

    // The command doesn't error — it installs the binary, fails to record in
    // the registry, and the error is swallowed by handle_extension's catch-all.
    let code = fix.run(&["tempo", "testpkg"]).unwrap();
    assert_eq!(code, 1, "should fall through to 'not found' hint");
}
