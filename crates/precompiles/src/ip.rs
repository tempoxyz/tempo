//! Validated IP address types and parsing utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

use std::net::SocketAddr;

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
    pub(crate) fn len(&self) -> u8 {
        self.input.len() as u8
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for IpAddr<'a> {
    type Error = IpParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        u8::try_from(input.len()).map_err(|_| IpParseError::TooLong)?;
        ensure_address_is_ip(input)?;

        Ok(Self { input })
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
    pub(crate) fn len(&self) -> u8 {
        self.input.len() as u8
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for IpAddrWithPort<'a> {
    type Error = IpWithPortParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        u8::try_from(input.len()).map_err(|_| IpWithPortParseError::TooLong)?;
        ensure_address_is_ip_port(input)?;

        Ok(Self { input })
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
