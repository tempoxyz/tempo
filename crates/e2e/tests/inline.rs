use tempo_consensus::VerificationMode;
pub use tempo_e2e::*;

const VERIFICATION_MODE: VerificationMode = VerificationMode::Immediate;

#[path = "suite/mod.rs"]
mod tests;
