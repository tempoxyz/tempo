//! Times setup, witness generation, commitment, proving, and verification for
//! the alice (secp256k1) + carol (passkey) + eve (secp256k1) approval.
//!
//! ```sh
//! RAYON_NUM_THREADS=1 cargo run --release --example bench -- [mixed|split]
//! ```

#[path = "../tests/common/mod.rs"]
mod fixtures;

use std::time::Instant;

use fixtures::*;
use tip_1136_bitz::{
    Authorizer,
    policy::{Profile, Witness},
    relation::witness_bits,
};

fn main() -> anyhow::Result<()> {
    let profile = match std::env::args().nth(1).as_deref() {
        None | Some("mixed") => Profile::Mixed,
        Some("split") => Profile::Split,
        Some(other) => anyhow::bail!("unknown profile {other}"),
    };
    let approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let witness = Witness::new(profile, &policy(), &approvals, &digest())?;

    let start = Instant::now();
    let mut authorizer = Authorizer::new(profile)?;
    let setup_time = start.elapsed();
    authorizer.bind(statement());
    let system = authorizer.system();
    let stats = system.stats();

    let start = Instant::now();
    let bits = witness_bits(&statement(), &witness);
    let assignment = system.witness(&bits)?;
    let witness_time = start.elapsed();

    let start = Instant::now();
    let commitment = system.commit(&assignment)?;
    let commit_time = start.elapsed();

    let start = Instant::now();
    let proof = system.prove(assignment, commitment)?;
    let prove_time = start.elapsed();

    let start = Instant::now();
    system.verify(&proof)?;
    let verify_time = start.elapsed();

    // Q100 elements are encoded in 16 bytes.
    let spartan_elements = proof.spartan.outer.sumcheck.round_polynomials.len() * 4
        + 3
        + proof.spartan.inner.round_polynomials.len() * 3;
    let proof_bytes =
        32 + proof.opening.narg_string.len() + proof.opening.hints.len() + 16 * spartan_elements;

    println!("profile            {profile:?}");
    println!("threads            {}", rayon::current_num_threads());
    println!("input bits         {}", bits.len());
    println!("r1cs constraints   {}", stats.constraints);
    println!("assignment bits    {}", stats.assignment_bits);
    println!(
        "committed bits     {} (padded {})",
        stats.committed_bits, stats.padded_committed_bits
    );
    println!("setup (once per profile) {setup_time:?}");
    println!("witness            {witness_time:?}");
    println!("commit             {commit_time:?}");
    println!("prove (after commit) {prove_time:?}");
    println!(
        "prover total       {:?}",
        witness_time + commit_time + prove_time
    );
    println!("verify             {verify_time:?}");
    println!(
        "proof bytes        {proof_bytes} (transcript {}, hints {}, spartan {})",
        proof.opening.narg_string.len(),
        proof.opening.hints.len(),
        16 * spartan_elements
    );
    Ok(())
}
