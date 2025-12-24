//! Error handling tests for `validator_config` module
//!
//! This test file focuses on testing error scenarios for the `ensure_address_is_ip_port`
//! function and related validator configuration error cases.

use tempo_precompiles::validator_config::{
    ensure_address_is_ip_port, IpWithPortParseError, ValidatorConfig,
};
use tempo_contracts::precompiles::IValidatorConfig;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_contracts::precompiles::ValidatorConfigError;
use alloy::primitives::Address;
use alloy_primitives::FixedBytes;

/// Helper function to create a validator config with initialized owner
fn setup_validator_config(owner: Address) -> (HashMapStorageProvider, ValidatorConfig) {
    let mut storage = HashMapStorageProvider::new(1);
    let mut validator_config = ValidatorConfig::new();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();
    });
    (storage, validator_config)
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_empty_string() {
    let result = ensure_address_is_ip_port("");
    assert!(result.is_err(), "Empty string should fail validation");
    assert!(matches!(
        result.unwrap_err(),
        IpWithPortParseError { .. }
    ));
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_missing_port() {
    let test_cases = vec![
        "127.0.0.1",
        "192.168.1.1",
        "::1",
        "[::1]",
        "localhost",
        "example.com",
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Address without port should fail: {}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_invalid_port() {
    let test_cases = vec![
        "127.0.0.1:",
        "192.168.1.1:abc",
        "127.0.0.1:99999", // Port out of range
        "[::1]:",
        "[::1]:xyz",
        "127.0.0.1:-1",
        "127.0.0.1:0", // Port 0 might be invalid depending on context
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Address with invalid port should fail: {}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_invalid_ip_format() {
    let test_cases = vec![
        "256.256.256.256:8000", // Invalid IPv4 octets
        "999.999.999.999:8000",
        "127.0.0.1.1:8000", // Too many octets
        "127.0:8000", // Too few octets
        "not.an.ip:8000",
        "localhost:8000", // Hostname not allowed
        "example.com:8000", // Hostname not allowed
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Invalid IP format should fail: {}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_invalid_ipv6_format() {
    let test_cases = vec![
        "::1:8000", // Missing brackets
        "[::1:8000", // Missing closing bracket
        "::1]:8000", // Missing opening bracket
        "[::1:8000]", // Port inside brackets
        "[invalid:ipv6]:8000", // Invalid IPv6 format
        "[gggg::1]:8000", // Invalid hex in IPv6
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Invalid IPv6 format should fail: {}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_whitespace() {
    let test_cases = vec![
        " 127.0.0.1:8000",
        "127.0.0.1:8000 ",
        " 127.0.0.1:8000 ",
        "\t127.0.0.1:8000",
        "127.0.0.1:8000\n",
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Address with whitespace should fail: {:?}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_multiple_colons() {
    let test_cases = vec![
        "127.0.0.1:8000:9000", // Multiple ports
        "::1:8000:9000", // Multiple ports with IPv6
    ];

    for input in test_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_err(),
            "Address with multiple colons should fail: {}",
            input
        );
        assert!(matches!(
            result.unwrap_err(),
            IpWithPortParseError { .. }
        ));
    }
}

#[tokio::test]
async fn test_add_validator_invalid_inbound_address() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: Address::random(),
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "invalid-address".to_string(), // Invalid address
                active: true,
                outboundAddress: "192.168.1.1:9000".to_string(),
            },
        );

        assert!(result.is_err(), "Should fail with invalid inbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotHostPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_add_validator_invalid_outbound_address() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: Address::random(),
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "192.168.1.1:8000".to_string(),
                active: true,
                outboundAddress: "localhost:9000".to_string(), // Invalid: hostname not IP
            },
        );

        assert!(result.is_err(), "Should fail with invalid outbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotIpPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_add_validator_missing_port_inbound() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: Address::random(),
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "192.168.1.1".to_string(), // Missing port
                active: true,
                outboundAddress: "192.168.1.1:9000".to_string(),
            },
        );

        assert!(result.is_err(), "Should fail with missing port in inbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotHostPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_add_validator_missing_port_outbound() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: Address::random(),
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "192.168.1.1:8000".to_string(),
                active: true,
                outboundAddress: "192.168.1.1".to_string(), // Missing port
            },
        );

        assert!(result.is_err(), "Should fail with missing port in outbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotIpPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_update_validator_invalid_inbound_address() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    let validator = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        // First add a validator
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: FixedBytes::<32>::from([0x44; 32]),
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )
            .unwrap();

        // Try to update with invalid inbound address
        let result = validator_config.update_validator(
            validator,
            IValidatorConfig::updateValidatorCall {
                newValidatorAddress: validator,
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "not-an-ip:8000".to_string(), // Invalid
                outboundAddress: "192.168.1.1:9000".to_string(),
            },
        );

        assert!(result.is_err(), "Should fail with invalid inbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotHostPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_update_validator_invalid_outbound_address() {
    let (mut storage, mut validator_config) = setup_validator_config(Address::random());
    let owner = Address::random();
    let validator = Address::random();
    StorageCtx::enter(&mut storage, || {
        validator_config.initialize(owner).unwrap();

        // First add a validator
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: FixedBytes::<32>::from([0x44; 32]),
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )
            .unwrap();

        // Try to update with invalid outbound address
        let result = validator_config.update_validator(
            validator,
            IValidatorConfig::updateValidatorCall {
                newValidatorAddress: validator,
                publicKey: FixedBytes::<32>::from([0x44; 32]),
                inboundAddress: "192.168.1.1:8000".to_string(),
                outboundAddress: "example.com:9000".to_string(), // Invalid: hostname
            },
        );

        assert!(result.is_err(), "Should fail with invalid outbound address");
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::ValidatorConfigError(
                ValidatorConfigError::NotIpPort { .. }
            )
        ));
    });
}

#[tokio::test]
async fn test_ensure_address_is_ip_port_valid_edge_cases() {
    // These should succeed - testing edge cases that are valid
    let valid_cases = vec![
        "0.0.0.0:0", // All zeros
        "255.255.255.255:65535", // Max values
        "127.0.0.1:1", // Minimum port
        "[::]:0", // IPv6 all zeros
        "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080", // Full IPv6
        "[2001:db8::1]:80", // Compressed IPv6
    ];

    for input in valid_cases {
        let result = ensure_address_is_ip_port(input);
        assert!(
            result.is_ok(),
            "Valid address should succeed: {}",
            input
        );
    }
}

