//! IP address validation utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpWithPortParseError {
    #[error("input was not of the form `<ip>:<port>`")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IPv6 zone IDs are not allowed")]
    Ipv6Zone,
}

/// Validates that `input` is of the form `<ip>:<port>`.
pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    if input.contains('%') {
        return Err(IpWithPortParseError::Ipv6Zone);
    }
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

/// Like [`ensure_address_is_ip_port`] but without the IPv6 zone check.
/// Used for pre-T2 consensus compatibility where zones were previously accepted.
pub(crate) fn ensure_address_is_ip_port_legacy(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    input
        .parse::<std::net::SocketAddr>()
        .map_err(IpWithPortParseError::Parse)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpParseError {
    #[error("input was not a valid IP address")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IPv6 zone IDs are not allowed")]
    Ipv6Zone,
}

pub(crate) fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    if input.contains('%') {
        return Err(IpParseError::Ipv6Zone);
    }
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}
