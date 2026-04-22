//! IP address validation utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

use core::net::{AddrParseError, IpAddr, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpWithPortParseError {
    #[error("input was not of the form `<ip>:<port>`")]
    Parse(#[from] AddrParseError),
}

/// Validates that `input` is of the form `<ip>:<port>`.
pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    input.parse::<SocketAddr>()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpParseError {
    #[error("input was not a valid IP address")]
    Parse(#[from] AddrParseError),
}

/// Validates that `input` is a valid IP address (v4 or v6, no port).
pub(crate) fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    input.parse::<IpAddr>()?;
    Ok(())
}
