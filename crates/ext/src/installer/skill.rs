//! Agent skill installation and removal across coding assistants.

use ed25519_dalek::VerifyingKey;
use std::env;
use std::fs;
use std::path::PathBuf;

use super::error::InstallerError;
use super::debug_log;
use super::verify::{sha256_of_bytes, verify_signature};

// Keep in sync with cli/install AGENT_SKILL_DIRS.
pub(super) const AGENT_SKILL_DIRS: &[(&str, &str, &str)] = &[
    (".agents", ".agents/skills", "universal"),
    (".claude", ".claude/skills", "Claude Code"),
    (".config/agents", ".config/agents/skills", "Amp"),
    (".cursor", ".cursor/skills", "Cursor"),
    (".copilot", ".copilot/skills", "GitHub Copilot"),
    (".codex", ".codex/skills", "Codex"),
    (".gemini", ".gemini/skills", "Gemini CLI"),
    (".config/opencode", ".config/opencode/skills", "OpenCode"),
    (".config/goose", ".config/goose/skills", "Goose"),
    (".windsurf", ".windsurf/skills", "Windsurf"),
    (".codeium/windsurf", ".codeium/windsurf/skills", "Windsurf"),
    (".continue", ".continue/skills", "Continue"),
    (".roo", ".roo/skills", "Roo"),
    (".kiro", ".kiro/skills", "Kiro"),
    (".augment", ".augment/skills", "Augment"),
    (".trae", ".trae/skills", "Trae"),
];

pub(super) fn install_skill(
    extension: &str,
    url: &str,
    expected_sha256: Option<&str>,
    encoded_signature: Option<&str>,
    verifying_key: &VerifyingKey,
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
            eprintln!("warn: skill download failed for tempo-{extension}: {err}");
            return;
        }
    };

    let skill_name = format!("tempo-{extension} skill");
    match encoded_signature {
        Some(sig) => {
            if let Err(err) = verify_signature(&skill_name, content.as_bytes(), sig, verifying_key)
            {
                eprintln!("warn: {err}, skipping skill install");
                return;
            }
            debug_log(&format!("skill signature ok for tempo-{extension}"));
        }
        None => {
            eprintln!(
                "warn: skill signature missing for tempo-{extension}, skipping skill install"
            );
            return;
        }
    }

    if let Some(expected) = expected_sha256 {
        let actual = sha256_of_bytes(content.as_bytes());
        if actual != expected {
            eprintln!("warn: skill checksum mismatch for tempo-{extension}, skipping");
            return;
        }
        debug_log(&format!("skill checksum ok for tempo-{extension}"));
    }

    let home = match env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        Some(h) => PathBuf::from(h),
        None => {
            eprintln!(
                "warn: skill install skipped for tempo-{extension}: home directory not found"
            );
            return;
        }
    };

    let mut installed_names: Vec<&str> = Vec::new();
    for &(parent_rel, skills_rel, agent_name) in AGENT_SKILL_DIRS {
        let parent = home.join(parent_rel);
        if !parent.is_dir() {
            continue;
        }
        let skill_dir = home.join(skills_rel).join(&skill_dir_name);
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

fn download_skill(url: &str) -> Result<String, InstallerError> {
    debug_log(&format!("downloading skill from {url}"));

    if url.starts_with("https://") {
        Ok(reqwest::blocking::get(url)?.error_for_status()?.text()?)
    } else if let Some(path) = url.strip_prefix("file://") {
        Ok(fs::read_to_string(path)?)
    } else if !url.contains("://") {
        Ok(fs::read_to_string(url)?)
    } else {
        Err(InstallerError::InsecureDownloadUrl(url.to_string()))
    }
}

pub(super) fn remove_skill(extension: &str, dry_run: bool) {
    let skill_dir_name = format!("tempo-{extension}");

    let home = match env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        Some(h) => PathBuf::from(h),
        None => return,
    };

    for &(_, skills_rel, _) in AGENT_SKILL_DIRS {
        let skill_dir = home.join(skills_rel).join(&skill_dir_name);
        if skill_dir.is_dir() {
            if dry_run {
                println!("dry-run: remove skill {}", skill_dir.display());
            } else if fs::remove_dir_all(&skill_dir).is_ok() {
                debug_log(&format!("removed skill {}", skill_dir.display()));
            }
        }
    }
}
