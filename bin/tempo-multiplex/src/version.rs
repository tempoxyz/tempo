use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::Command;

/// Read the embedded revision, not the checkout containing the executable.
pub(crate) async fn node_sha(binary: &Path) -> eyre::Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(binary)
            .arg("--version")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    eyre::ensure!(
        output.status.success(),
        "node --version failed: {}",
        binary.display()
    );
    parse_sha(std::str::from_utf8(&output.stdout)?)
}

fn parse_sha(version: &str) -> eyre::Result<String> {
    let sha = version
        .lines()
        .find_map(|line| line.strip_prefix("Commit SHA: "))
        .ok_or_else(|| eyre::eyre!("node --version did not report its commit SHA"))?
        .trim();
    eyre::ensure!(
        sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "node did not report a full Git SHA"
    );
    Ok(sha.to_ascii_lowercase())
}

pub(crate) fn matches_client_version(sha: &str, client_version: &str) -> bool {
    let Some(revision) = client_version
        .strip_prefix("tempo/")
        .and_then(|version| version.split('/').next())
        .and_then(|version| version.rsplit_once('-').map(|(_, revision)| revision))
    else {
        return false;
    };
    revision.len() >= 7
        && revision.bytes().all(|b| b.is_ascii_hexdigit())
        && sha.starts_with(&revision.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_verifies_embedded_revision() {
        let sha = "1ec5653e39c97e02807dddf5e7106e979f3ad909";
        assert_eq!(
            parse_sha(&format!("Tempo Version: 1.14.0\nCommit SHA: {sha}\n")).unwrap(),
            sha
        );
        assert!(matches_client_version(
            sha,
            "tempo/v1.14.0-1ec5653/x86_64-unknown-linux-gnu"
        ));
        assert!(!matches_client_version(
            sha,
            "tempo/v1.14.0-dd43692/x86_64-unknown-linux-gnu"
        ));
        assert!(!matches_client_version(
            sha,
            "tempo/v1.14.0-1/x86_64-unknown-linux-gnu"
        ));
        assert!(parse_sha("Commit SHA: 1ec5653").is_err());
        assert!(parse_sha(&format!("Commit SHA: {}", "z".repeat(40))).is_err());
        assert!(parse_sha("Tempo Version: 1.14.0").is_err());
    }
}
