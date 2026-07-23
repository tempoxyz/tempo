//! Canonical Zone runtimes installed directly by the T9 hardfork.

use alloy_primitives::Bytes;

/// Canonical ZonePortal implementation deployed runtime.
pub const ZONE_PORTAL_RUNTIME: Bytes = Bytes::from_static(include_bytes!("zone_portal.bin"));

/// Canonical ZoneMessenger deployed runtime.
pub const ZONE_MESSENGER_RUNTIME: Bytes = Bytes::from_static(include_bytes!("zone_messenger.bin"));

/// Canonical ZoneVerifier deployed runtime.
pub const ZONE_VERIFIER_RUNTIME: Bytes = Bytes::from_static(include_bytes!("zone_verifier.bin"));
