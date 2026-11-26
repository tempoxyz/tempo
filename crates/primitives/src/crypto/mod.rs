//! Tempo's own signature checks. Under `mock-crypto` they also accept mock signatures once
//! `mock::install` ran.

mod ed25519;
mod p256;
#[cfg(feature = "std")]
mod p384;
mod slh_dsa;
mod webauthn;

pub use ed25519::verify_ed25519;
pub use p256::{P256_ORDER, P256N_HALF, derive_p256_address, normalize_p256_s, verify_p256};
#[cfg(feature = "std")]
pub use p384::{verify_p384_der, verify_p384_fixed};
pub use slh_dsa::{
    SLH_DSA_ADDRESS_DOMAIN, SLH_DSA_PUBLIC_KEY_LENGTH, SLH_DSA_SHA2_128S_PARAM_ID,
    SLH_DSA_SIGNATURE_LENGTH, derive_slh_dsa_address, verify_slh_dsa,
};
pub use webauthn::verify_webauthn;

#[cfg(feature = "mock-crypto")]
pub mod mock;
