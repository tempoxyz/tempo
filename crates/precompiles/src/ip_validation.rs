//! IP address validation utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

#[derive(Debug, thiserror::Error)]
#[error("input was not of the form `<ip>:<port>`")]
pub(crate) struct IpWithPortParseError {
    #[from]
    source: std::net::AddrParseError,
}

pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("input was not a valid IP address")]
pub(crate) struct IpParseError {
    #[from]
    source: std::net::AddrParseError,
}

pub(crate) fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}
