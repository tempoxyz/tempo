use tempo_consensus::VerificationMode;
pub use tempo_e2e::*;

const VERIFICATION_MODE: VerificationMode = VerificationMode::Deferred;

#[path = "suite/mod.rs"]
mod tests;
