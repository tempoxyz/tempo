//! Validated IP address types and parsing utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

use std::net::SocketAddr;
use tempo_chainspec::TempoHardfork;

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpParseError {
    #[error("input was not a valid IP address")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IP address exceeds 255 bytes")]
    TooLong,
}

/// A parsed IP address.
///
/// Retains the ip str because validator signatures cover the exact input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpAddr<'a> {
    input: &'a str,
}

impl<'a> IpAddr<'a> {
    /// Validates the IP format, enforcing the 255-byte limit from T14 onward.
    pub(crate) fn parse(input: &'a str, spec: TempoHardfork) -> Result<Self, IpParseError> {
        if spec.is_t14() {
            u8::try_from(input.len()).map_err(|_| IpParseError::TooLong)?;
        }
        ensure_address_is_ip(input)?;
        Ok(Self { input })
    }

    /// Panics for oversized legacy input, as pre-T14 signature encoding did.
    pub(crate) fn len(&self) -> u8 {
        u8::try_from(self.input.len()).expect("validator egress length must fit in uint8")
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpWithPortParseError {
    #[error("input was not of the form `<ip>:<port>`")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IP address exceeds 255 bytes")]
    TooLong,
}

/// A parsed IP address with a port.
///
/// Retains the ip str because validator signatures covers the exact input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpAddrWithPort<'a> {
    input: &'a str,
}

impl<'a> IpAddrWithPort<'a> {
    /// Validates the IP and port format, enforcing the 255-byte limit from T14 onward.
    pub(crate) fn parse(input: &'a str, spec: TempoHardfork) -> Result<Self, IpWithPortParseError> {
        if spec.is_t14() {
            u8::try_from(input.len()).map_err(|_| IpWithPortParseError::TooLong)?;
        }
        ensure_address_is_ip_port(input)?;
        Ok(Self { input })
    }

    /// Panics for oversized legacy input, as pre-T14 signature encoding did.
    pub(crate) fn len(&self) -> u8 {
        u8::try_from(self.input.len()).expect("validator ingress length must fit in uint8")
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

/// Validates that `input` is of the form `<ip>:<port>`.
pub(crate) fn ensure_address_is_ip_port(input: &str) -> Result<(), IpWithPortParseError> {
    input.parse::<SocketAddr>()?;
    Ok(())
}

/// Validates that `input` is a valid IP address.
pub(crate) fn ensure_address_is_ip(input: &str) -> Result<(), IpParseError> {
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}
