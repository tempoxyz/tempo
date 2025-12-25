use std::process::Command;

/// Generates Rust API documentation for all workspace crates.
/// This uses `cargo doc` with `--no-deps`.
pub fn generate() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args(["doc", "--workspace", "--no-deps"])
        .status()?;
    if !status.success() {
        anyhow::bail!("cargo doc failed");
    }
    println!("Documentation generated at target/doc.");
    Ok(())
}
