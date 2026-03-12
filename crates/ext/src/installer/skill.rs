//! Agent skill installation and removal across coding assistants.

use minisign_verify::PublicKey;
use std::fs;

use crate::installer::{
    error::InstallerError,
    file_url_to_path, home_dir, http_client,
    verify::{sha256_hex, verify_signature},
};

const AGENT_SKILL_DIRS: &[(&str, &str)] = &[
    (".agents", "universal"),
    (".claude", "Claude Code"),
    (".config/agents", "Amp"),
    (".cursor", "Cursor"),
    (".copilot", "GitHub Copilot"),
    (".codex", "Codex"),
    (".gemini", "Gemini CLI"),
    (".config/opencode", "OpenCode"),
    (".config/goose", "Goose"),
    (".windsurf", "Windsurf"),
    (".codeium/windsurf", "Windsurf"),
    (".continue", "Continue"),
    (".roo", "Roo"),
    (".kiro", "Kiro"),
    (".augment", "Augment"),
    (".trae", "Trae"),
];

/// Downloads, verifies, and installs an extension's agent skill file into every
/// detected coding assistant's skills directory.
#[allow(clippy::too_many_arguments)]
pub(super) fn install_skill(
    extension: &str,
    version: &str,
    url: &str,
    expected_sha256: Option<&str>,
    encoded_signature: Option<&str>,
    public_key: &PublicKey,
    dry_run: bool,
    quiet: bool,
) {
    let skill_dir_name = format!("tempo-{extension}");

    if dry_run {
        println!("dry-run: install skill from {url}");
        return;
    }

    let content = match download_skill(url) {
        Ok(content) => content,
        Err(err) => {
            tracing::warn!("skill download failed for tempo-{extension}: {err}");
            return;
        }
    };

    if let Some(expected) = expected_sha256 {
        let actual = sha256_hex(content.as_bytes());
        if actual != expected.to_lowercase() {
            tracing::warn!("skill checksum mismatch for tempo-{extension}, skipping");
            return;
        }
        tracing::debug!("skill checksum ok for tempo-{extension}");
    }

    let skill_name = format!("tempo-{extension} skill");
    let expected_comment = format!("skill:tempo-{extension}");
    let version_comment = format!("version:{version}");
    match encoded_signature {
        Some(sig) => {
            if let Err(err) = verify_signature(
                &skill_name,
                content.as_bytes(),
                sig,
                public_key,
                &[&expected_comment, &version_comment],
            ) {
                tracing::warn!("{err}, skipping skill install");
                return;
            }
            tracing::debug!("skill signature ok for tempo-{extension}");
        }
        None => {
            tracing::warn!("skill signature missing for tempo-{extension}, skipping skill install");
            return;
        }
    }

    let home = match home_dir() {
        Some(h) => h,
        None => {
            tracing::warn!("skill install skipped for tempo-{extension}: home directory not found");
            return;
        }
    };

    let mut installed_names: Vec<&str> = Vec::new();
    for &(parent_rel, agent_name) in AGENT_SKILL_DIRS {
        let parent = home.join(parent_rel);
        if !parent.is_dir() {
            continue;
        }
        let skill_dir = parent.join("skills").join(&skill_dir_name);
        if fs::create_dir_all(&skill_dir).is_err() {
            continue;
        }
        if fs::write(skill_dir.join("SKILL.md"), &content).is_ok() {
            installed_names.push(agent_name);
        }
    }

    if !quiet && !installed_names.is_empty() {
        println!(
            "installed tempo-{extension} skill to {} agent(s): {}",
            installed_names.len(),
            installed_names.join(", ")
        );
    }
}

/// Fetches the skill file content from `url` (HTTPS or `file://`).
fn download_skill(url: &str) -> Result<String, InstallerError> {
    tracing::debug!("downloading skill from {url}");

    if url.starts_with("https://") {
        Ok(http_client()?.get(url).send()?.error_for_status()?.text()?)
    } else if let Some(path) = file_url_to_path(url) {
        Ok(fs::read_to_string(path)?)
    } else {
        Err(InstallerError::InsecureDownloadUrl(url.to_string()))
    }
}

/// Removes an extension's skill directory from all detected coding assistants.
pub(super) fn remove_skill(extension: &str, dry_run: bool) {
    let skill_dir_name = format!("tempo-{extension}");

    let home = match home_dir() {
        Some(h) => h,
        None => return,
    };

    for &(parent_rel, _) in AGENT_SKILL_DIRS {
        let skill_dir = home.join(parent_rel).join("skills").join(&skill_dir_name);
        if skill_dir.is_dir() {
            if dry_run {
                println!("dry-run: remove skill {}", skill_dir.display());
            } else if fs::remove_dir_all(&skill_dir).is_ok() {
                tracing::debug!("removed skill {}", skill_dir.display());
            }
        }
    }
}
