//! Tempo's own signature checks. Under `mock-crypto` they also accept mock signatures once
//! `mock::install` ran.

#[cfg(feature = "nitro")]
mod nitro;
#[cfg(feature = "nitro")]
pub use nitro::NitroVerifier;

mod ed25519;
mod p256;
mod webauthn;

pub use ed25519::verify_ed25519;
pub use p256::{P256_ORDER, P256N_HALF, derive_p256_address, normalize_p256_s, verify_p256};
pub use webauthn::verify_webauthn;

#[cfg(feature = "mock-crypto")]
pub mod mock;
