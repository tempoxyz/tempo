//! Validated IP address types and parsing utilities for validator configuration.
//!
//! This module provides validation functions for ensuring that addresses conform
//! to expected IP address formats (with or without ports).

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpParseError {
    #[error("input was not a valid IP address")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IP address exceeds 255 bytes")]
    TooLong,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IpWithPortParseError {
    #[error("input was not of the form `<ip>:<port>`")]
    Parse(#[from] std::net::AddrParseError),
    #[error("IP address exceeds 255 bytes")]
    TooLong,
}

/// A parsed IP address.
///
/// Retains the original text because validator signatures cover the input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpAddress<'a> {
    input: &'a str,
}

/// A parsed IP address with a port.
///
/// Retains the original because validator signatures cover the input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpAddressWithPort<'a> {
    input: &'a str,
}

impl<'a> IpAddressWithPort<'a> {
    pub(crate) fn len(&self) -> u8 {
        self.input.len() as u8
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

impl<'a> IpAddress<'a> {
    pub(crate) fn len(&self) -> u8 {
        self.input.len() as u8
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.input.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for IpAddressWithPort<'a> {
    type Error = IpWithPortParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        u8::try_from(input.len()).map_err(|_| IpWithPortParseError::TooLong)?;
        ensure_address_is_ip_port(input)?;

        Ok(Self { input })
    }
}

impl<'a> TryFrom<&'a str> for IpAddress<'a> {
    type Error = IpParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        u8::try_from(input.len()).map_err(|_| IpParseError::TooLong)?;
        input.parse::<IpAddr>()?;

        Ok(Self { input })
    }
}

/// Validates that `input` is of the form `<ip>:<port>`.
///
/// Kept separate for ValidatorConfig V1, which validates the format without
/// enforcing the one-byte length limit required by V2 signatures.
pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    input.parse::<SocketAddr>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_addresses_validate_format_and_preserve_text() {
        for input in [
            "127.0.0.1",
            "::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        ] {
            let address = IpAddress::try_from(input).unwrap();
            assert_eq!(usize::from(address.len()), input.len());
            assert_eq!(address.as_bytes(), input.as_bytes());
        }
        for input in ["", "localhost", "127.0.0.1:80", "[::1]:80"] {
            assert!(matches!(
                IpAddress::try_from(input),
                Err(IpParseError::Parse(_))
            ));
        }
        let input = "0".repeat(256);
        assert!(matches!(
            IpAddress::try_from(input.as_str()),
            Err(IpParseError::TooLong)
        ));
    }

    #[test]
    fn ip_addresses_with_ports_enforce_length_limit() {
        for prefix in ["127.0.0.1:", "[::1]:", "[fe80::1%"] {
            let suffix = if prefix.ends_with('%') { "1]:80" } else { "80" };
            for len in [254, 255, 256, 1024] {
                let input = format!(
                    "{prefix}{}{suffix}",
                    "0".repeat(len - prefix.len() - suffix.len())
                );
                // Padding the port or IPv6 scope ID is accepted by the standard parser.
                assert!(input.parse::<SocketAddr>().is_ok());
                if len <= 255 {
                    let address = IpAddressWithPort::try_from(input.as_str()).unwrap();
                    assert_eq!(usize::from(address.len()), len);
                    assert_eq!(address.as_bytes(), input.as_bytes());
                } else {
                    assert!(matches!(
                        IpAddressWithPort::try_from(input.as_str()),
                        Err(IpWithPortParseError::TooLong)
                    ));
                }
            }
        }
        for input in ["", "localhost:80", "127.0.0.1", "::1", "127.0.0.1:65536"] {
            assert!(matches!(
                IpAddressWithPort::try_from(input),
                Err(IpWithPortParseError::Parse(_))
            ));
        }
    }
}
