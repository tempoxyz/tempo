//! Canonical Zones runtime hashes installed by TIP-1091 at T9.
//!
//! The corresponding contracts must be deployed and verified before activation so validators can
//! load their bytecode from state by hash instead of embedding it in the node binary.

use alloy_primitives::{B256, b256};

/// Canonical tempoxyz/zones revision selected for T9 activation.
pub const T9_ZONES_REVISION: &str = "9a0faf29e5a06b3087afcd8cae0169a3e88785c3";

/// Keccak-256 of the deployed `ZonePortal` implementation runtime.
pub const ZONE_PORTAL_RUNTIME_HASH: B256 =
    b256!("0xd26a7be122403a18eb1df09106a5630ed34cefcc3ec834185aa209c4a5b9fe49");

/// Keccak-256 of the deployed `Verifier` runtime.
pub const ZONE_VERIFIER_RUNTIME_HASH: B256 =
    b256!("0x161409856e1951ac366af96cfdc403d8ed2395894157d841960e87a329e22ac8");

/// Keccak-256 of the deployed `ZoneMessenger` runtime with the canonical factory embedded.
pub const ZONE_MESSENGER_RUNTIME_HASH: B256 =
    b256!("0x7d4b2185698c192b61d23c9989ab547876f92563213b4990b50e2f01b17a00e7");
