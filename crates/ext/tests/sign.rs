//! Signer-to-installer compatibility: manifests from `tempo_ext::sign`
//! install through the launcher with real signature verification.

use std::{env, fs, io::Cursor, path::Path};

use tempo_ext::sign::{self, ManifestOptions};

fn platform_suffix() -> &'static str {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux-amd64",
        _ => "unknown-unknown",
    }
}

/// Signs `artifacts` and publishes the manifest at the launcher's CDN layout.
fn publish(cdn: &Path, package: &str, version: &str, artifacts: &Path, sk: &minisign::SecretKey) {
    let package_dir = cdn.join("extensions").join(package);
    let base_url = format!("file://{}", package_dir.display());
    let manifest = sign::build_manifest(
        &ManifestOptions {
            artifacts_dir: artifacts.to_path_buf(),
            version: version.into(),
            base_url,
            description: Some("compat".into()),
            skill: None,
            skill_sha256: None,
            skill_file: None,
        },
        sk,
    )
    .unwrap();

    // The signer emits `<base>/<version>/<file>` URLs; place the binaries there.
    let version_dir = package_dir.join(manifest["version"].as_str().unwrap());
    fs::create_dir_all(&version_dir).unwrap();
    for entry in fs::read_dir(artifacts).unwrap() {
        let path = entry.unwrap().path();
        fs::copy(&path, version_dir.join(path.file_name().unwrap())).unwrap();
    }

    let json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(package_dir.join("manifest.json"), &json).unwrap();
}

#[test]
fn signed_manifest_installs_and_rejects_substitution() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let cdn = tmp.path().join("cdn");
    fs::create_dir_all(&home).unwrap();

    let key = tmp.path().join("release.key");
    let pk = sign::generate_key(&key).unwrap();
    let sk = sign::load_secret_key(&key).unwrap();

    // SAFETY: the other test in this binary does not read these variables.
    unsafe {
        env::set_var("TEMPO_HOME", &home);
        env::set_var("TEMPO_EXT_BASE_URL", format!("file://{}", cdn.display()));
        env::set_var("TEMPO_EXT_PUBLIC_KEY", &pk);
    }

    let artifacts = tmp.path().join("artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    let binary = format!("tempo-compat-{}", platform_suffix());
    fs::write(artifacts.join(&binary), "#!/bin/sh\necho compat\n").unwrap();
    fs::write(artifacts.join(format!("{binary}.sha256")), "ignored").unwrap();
    publish(&cdn, "tempo-compat", "1.0.0", &artifacts, &sk);

    let run = |args: &[&str]| tempo_ext::run(args.iter().map(|s| s.to_string()));
    assert_eq!(run(&["tempo", "add", "compat"]).unwrap(), 0);
    assert!(home.join("bin").join("tempo-compat").exists());

    // A validly signed binary from one extension must not install as another.
    let other = tmp.path().join("other");
    fs::create_dir_all(&other).unwrap();
    fs::copy(
        artifacts.join(&binary),
        other.join(format!("tempo-other-{}", platform_suffix())),
    )
    .unwrap();
    publish(&cdn, "tempo-other", "1.0.0", &other, &sk);
    let other_manifest = cdn.join("extensions/tempo-other/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&other_manifest).unwrap()).unwrap();
    let compat: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(cdn.join("extensions/tempo-compat/manifest.json")).unwrap(),
    )
    .unwrap();
    let key = format!("tempo-other-{}", platform_suffix());
    manifest["binaries"][&key]["signature"] = compat["binaries"][&binary]["signature"].clone();
    fs::write(&other_manifest, manifest.to_string()).unwrap();
    assert!(run(&["tempo", "add", "other"]).is_err());
}

#[test]
fn skill_signature_carries_package_comment() {
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("release.key");
    sign::generate_key(&key).unwrap();
    let sk = sign::load_secret_key(&key).unwrap();
    let pk = minisign::PublicKey::from_secret_key(&sk).unwrap();

    let artifacts = tmp.path().join("artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    let skill = tmp.path().join("SKILL.md");
    fs::write(&skill, "# skill\n").unwrap();

    let manifest = sign::build_manifest(
        &ManifestOptions {
            artifacts_dir: artifacts,
            version: "v2.0.0".into(),
            base_url: "https://cli.tempo.xyz/extensions/tempo-wallet".into(),
            description: None,
            skill: Some("https://cli.tempo.xyz/extensions/tempo-wallet/v2.0.0/SKILL.md".into()),
            skill_sha256: None,
            skill_file: Some(skill.clone()),
        },
        &sk,
    )
    .unwrap();

    let sig =
        minisign::SignatureBox::from_string(manifest["skill_signature"].as_str().unwrap()).unwrap();
    let data = fs::read(&skill).unwrap();
    minisign::verify(&pk, &sig, Cursor::new(&data), true, false, false).unwrap();
    let comment = sig.trusted_comment().unwrap();
    let tokens: Vec<_> = comment.split('\t').collect();
    assert!(tokens.contains(&"skill:tempo-wallet"), "{comment}");
    assert!(tokens.contains(&"version:v2.0.0"), "{comment}");
}
