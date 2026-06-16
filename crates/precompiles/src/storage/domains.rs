//! Storage key namespaces for precompile-controlled layouts.

/// Namespace byte for hash-derived storage keys.
pub const HASHED_NAMESPACE: u8 = 0x00;

/// Namespace byte for typed raw storage keys.
pub const RAW_NAMESPACE: u8 = 0x01;

/// Compact storage-domain id for TIP-20.
pub const PRECOMPILE_TIP20: u8 = 0x20;

/// Compact storage-domain id for TIP-403.
pub const PRECOMPILE_TIP403: u8 = 0x43;

/// Builds a raw storage domain from a precompile id and field id.
pub const fn raw_domain(precompile: u8, field: u8) -> u16 {
    ((precompile as u16) << 8) | field as u16
}

/// Extracts the precompile id from a raw storage domain.
pub const fn precompile_id(domain: u16) -> u8 {
    (domain >> 8) as u8
}

/// Extracts the field id from a raw storage domain.
pub const fn field_id(domain: u16) -> u8 {
    domain as u8
}

pub const TIP20_BALANCES: u16 = raw_domain(PRECOMPILE_TIP20, 0x01);
pub const TIP20_PERMIT_NONCES: u16 = raw_domain(PRECOMPILE_TIP20, 0x02);
pub const TIP20_USER_REWARD_INFO: u16 = raw_domain(PRECOMPILE_TIP20, 0x03);

pub const TIP403_RECEIVE_POLICIES: u16 = raw_domain(PRECOMPILE_TIP403, 0x01);
