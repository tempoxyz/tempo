//! Proves an ML-DSA OIDC sign-in without publishing the token or identity.

#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let witness = env::read::<tempo_pq_oidc::Witness>();
    let statement = tempo_pq_oidc::evaluate(&witness).expect("invalid sign-in");
    env::commit_slice(&statement.journal());
}
