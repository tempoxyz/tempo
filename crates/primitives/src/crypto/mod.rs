//! Tempo's own signature checks. Under `mock-crypto` they also accept mock signatures once
//! `mock::install` ran.

mod ed25519;
#[cfg(feature = "mock-crypto")]
pub mod mock;
#[cfg(feature = "nitro")]
mod nitro;
mod p256;
mod webauthn;

pub use ed25519::verify_ed25519;
#[cfg(feature = "nitro")]
pub use nitro::NitroVerifier;
#[cfg(test)]
pub(crate) use p256::verify_p256_signature_internal;
pub use p256::{P256_ORDER, P256N_HALF, derive_p256_address, normalize_p256_s, verify_p256};
pub use webauthn::verify_webauthn;
#[cfg(test)]
pub(crate) use webauthn::verify_webauthn_data_internal;
