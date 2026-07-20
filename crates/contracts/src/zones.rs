//! Canonical Zones deployments installed by TIP-1091 at T9.
//!
//! The corresponding contracts must be deployed and verified before activation so validators can
//! load their bytecode from the source accounts instead of embedding it in the node binary.

use alloy_primitives::{Address, address};

/// Canonical tempoxyz/zones revision selected for T9 activation.
pub const T9_ZONES_REVISION: &str = "9a0faf29e5a06b3087afcd8cae0169a3e88785c3";

// TODO: Set the finalized source deployment addresses before T9 activation.
/// Verified source deployment of the canonical `ZonePortal` implementation runtime.
pub const ZONE_PORTAL_IMPL_SOURCE_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000000");

/// Verified source deployment of the canonical `Verifier` runtime.
pub const ZONE_VERIFIER_SOURCE_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000000");

/// Verified source deployment of the canonical `ZoneMessenger` runtime.
pub const ZONE_MESSENGER_SOURCE_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000000");
