//! Export the public guest ELF and its verifier image ID.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: export <guest.elf>")?;
    std::fs::write(path, oidc_pq_methods::OIDC_MLDSA_GUEST_ELF)?;
    println!(
        "{}",
        risc0_zkvm::sha::Digest::from(oidc_pq_methods::OIDC_MLDSA_GUEST_ID)
    );
    Ok(())
}
