//! Tempo's own signature checks. Under `mock-crypto` they also accept mock signatures once
//! `mock::install` ran.

mod ed25519;
mod p256;
#[cfg(feature = "std")]
mod p384;
mod webauthn;

pub use ed25519::verify_ed25519;
pub use p256::{P256_ORDER, P256N_HALF, derive_p256_address, normalize_p256_s, verify_p256};
#[cfg(feature = "std")]
pub use p384::{verify_p384_der, verify_p384_fixed};
pub use webauthn::verify_webauthn;

#[cfg(feature = "mock-crypto")]
pub mod mock;
