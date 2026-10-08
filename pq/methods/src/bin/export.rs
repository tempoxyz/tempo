//! Export the public guest ELF and its verifier image ID.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: export <guest.elf>")?;
    std::fs::write(path, oidc_pq_methods::OIDC_MLDSA_GUEST_ELF)?;
    if let Some(path) = std::env::args().nth(2) {
        let mut genesis: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/chainspec/src/genesis/dev.json"
        ))?;
        genesis["config"]["accountMigrationTime"] = 0.into();
        genesis["config"]["multisigRecoveryFactory"] =
            "0x7171717171717171717171717171717171717171".into();
        genesis["config"]["zkVerifyingKeys"]["128"] = format!(
            "0x{}",
            risc0_zkvm::sha::Digest::from(oidc_pq_methods::OIDC_MLDSA_GUEST_ID)
        )
        .into();
        std::fs::write(path, serde_json::to_vec_pretty(&genesis)?)?;
    }
    println!(
        "{}",
        risc0_zkvm::sha::Digest::from(oidc_pq_methods::OIDC_MLDSA_GUEST_ID)
    );
    Ok(())
}
