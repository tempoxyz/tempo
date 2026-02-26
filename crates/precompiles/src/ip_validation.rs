//! IP address validation utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpWithPortParseError {
    #[error("input was not of the form `<ip>:<port>`")]
    Parse(#[from] std::net::AddrParseError),
}

/// Validates that `input` is of the form `<ip>:<port>`.
pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpParseError {
    #[error("input was not a valid IP address")]
    Parse(#[from] std::net::AddrParseError),
}

pub(crate) fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}
