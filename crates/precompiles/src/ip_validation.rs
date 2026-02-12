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

/// Validates that the input string is a valid IP address (v4 or v6) with a port.
///
/// # Errors
///
/// Returns `IpWithPortParseError` if the input is not a valid `<ip>:<port>` format.
///
/// # Examples
///
/// ```ignore
/// assert!(ensure_address_is_ip_port("192.168.1.1:8000").is_ok());
/// assert!(ensure_address_is_ip_port("[::1]:8000").is_ok());
/// assert!(ensure_address_is_ip_port("hostname:8000").is_err());
/// assert!(ensure_address_is_ip_port("192.168.1.1").is_err());
/// ```
pub(crate) fn ensure_address_is_ip_port(
    input: &str,
) -> core::result::Result<(), IpWithPortParseError> {
    // Only accept IP addresses (v4 or v6) with port
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("input was not a valid IP address")]
pub(crate) struct IpParseError {
    #[from]
    source: std::net::AddrParseError,
}

/// Validates that the input string is a valid IP address (v4 or v6).
///
/// # Errors
///
/// Returns `IpParseError` if the input is not a valid IP address.
///
/// # Examples
///
/// ```ignore
/// assert!(ensure_address_is_ip("192.168.1.1").is_ok());
/// assert!(ensure_address_is_ip("::1").is_ok());
/// assert!(ensure_address_is_ip("hostname").is_err());
/// assert!(ensure_address_is_ip("192.168.1.1:8000").is_err());
/// ```
pub(crate) fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_address_is_ip_port_rejects_invalid() {
        // Test invalid formats are rejected (not silently returning Ok)
        let invalid_cases = [
            "not-an-ip:8000",    // hostname, not IP
            "192.168.1.1",       // missing port
            "8000",              // just port
            "",                  // empty
            "192.168.1.1:abc",   // non-numeric port
            "192.168.1.1:99999", // port out of range
        ];

        for invalid in invalid_cases {
            let result = ensure_address_is_ip_port(invalid);
            assert!(result.is_err(), "Expected error for '{invalid}', got Ok");
        }

        // Valid IP:port should succeed
        assert!(ensure_address_is_ip_port("192.168.1.1:8000").is_ok());
        assert!(ensure_address_is_ip_port("[::1]:8000").is_ok());
    }

    #[test]
    fn test_ensure_address_is_ip_port_accepts_valid() {
        // IPv4 addresses with port
        assert!(ensure_address_is_ip_port("127.0.0.1:8000").is_ok());
        assert!(ensure_address_is_ip_port("192.168.1.1:9000").is_ok());
        assert!(ensure_address_is_ip_port("0.0.0.0:80").is_ok());
        assert!(ensure_address_is_ip_port("255.255.255.255:65535").is_ok());

        // IPv6 addresses with port
        assert!(ensure_address_is_ip_port("[::1]:8000").is_ok());
        assert!(ensure_address_is_ip_port("[::]:9000").is_ok());
        assert!(ensure_address_is_ip_port("[2001:db8::1]:8080").is_ok());
        assert!(ensure_address_is_ip_port("[fe80::1]:443").is_ok());
    }

    #[test]
    fn test_ensure_address_is_ip_rejects_invalid() {
        let invalid_cases = [
            "not-an-ip",        // hostname
            "192.168.1.1:8000", // IP with port (not allowed)
            "",                 // empty
            "192.168.1",        // incomplete IP
            "256.1.1.1",        // out of range octet
            "[::1]:8000",       // IPv6 with port (brackets indicate socket addr format)
        ];

        for invalid in invalid_cases {
            let result = ensure_address_is_ip(invalid);
            assert!(result.is_err(), "Expected error for '{invalid}', got Ok");
        }

        // Valid IPs should succeed
        assert!(ensure_address_is_ip("192.168.1.1").is_ok());
        assert!(ensure_address_is_ip("::1").is_ok());
    }

    #[test]
    fn test_ensure_address_is_ip_accepts_valid() {
        // IPv4 addresses
        assert!(ensure_address_is_ip("127.0.0.1").is_ok());
        assert!(ensure_address_is_ip("192.168.1.1").is_ok());
        assert!(ensure_address_is_ip("0.0.0.0").is_ok());
        assert!(ensure_address_is_ip("255.255.255.255").is_ok());

        // IPv6 addresses
        assert!(ensure_address_is_ip("::1").is_ok());
        assert!(ensure_address_is_ip("::").is_ok());
        assert!(ensure_address_is_ip("2001:db8::1").is_ok());
        assert!(ensure_address_is_ip("fe80::1").is_ok());
        assert!(ensure_address_is_ip("::ffff:192.0.2.1").is_ok());
    }
}
