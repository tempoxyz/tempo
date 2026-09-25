//! Tempo Zone private-RPC authorization-token encoding.
//!
//! The protocol is intentionally kept here rather than in `txgen-core`: it is
//! Tempo-specific, and the Zones repository remains the canonical implementation.

use alloy_primitives::{keccak256, Address, Signature, B256};
use alloy_signer::SignerSync;
use eyre::{bail, eyre, Result};
use txgen_core::EcdsaSigner;

/// Current Tempo Zone authorization-token version.
pub const TOKEN_VERSION: u8 = 0;

/// Length of the fixed version and scope suffix.
pub const TOKEN_FIELDS_LEN: usize = 1 + 4 + 8 + 8 + 8;

/// Length of an `r || s || v` secp256k1 signature.
pub const SIGNATURE_LEN: usize = 65;

/// Length of a normal secp256k1 Zone authorization token.
pub const TOKEN_LEN: usize = SIGNATURE_LEN + TOKEN_FIELDS_LEN;

/// Length of a lowercase, prefix-free hex-encoded token.
pub const TOKEN_HEX_LEN: usize = TOKEN_LEN * 2;

/// Protocol maximum authorization-token validity window (30 days).
pub const MAX_TOKEN_VALIDITY_SECS: u64 = 2_592_000;

// `TempoZoneRPC` followed by zero bytes to fill the 32-byte domain separator.
// This byte layout matches the canonical Zones implementation.
const TEMPO_ZONE_RPC_MAGIC: [u8; 32] = {
    let mut magic = [0u8; 32];
    let prefix = b"TempoZoneRPC";
    let mut index = 0;
    while index < prefix.len() {
        magic[index] = prefix[index];
        index += 1;
    }
    magic
};

/// Parsed non-secret fields from the fixed 29-byte token suffix.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenFields {
    pub version: u8,
    pub zone_id: u32,
    pub chain_id: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Build the canonical 29-byte token suffix using big-endian integers.
pub fn build_token_fields(
    zone_id: u32,
    chain_id: u64,
    issued_at: u64,
    expires_at: u64,
) -> [u8; TOKEN_FIELDS_LEN] {
    let mut fields = [0u8; TOKEN_FIELDS_LEN];
    fields[0] = TOKEN_VERSION;
    fields[1..5].copy_from_slice(&zone_id.to_be_bytes());
    fields[5..13].copy_from_slice(&chain_id.to_be_bytes());
    fields[13..21].copy_from_slice(&issued_at.to_be_bytes());
    fields[21..29].copy_from_slice(&expires_at.to_be_bytes());
    fields
}

/// Parse a canonical fixed token suffix.
pub fn parse_token_fields(fields: &[u8]) -> Result<TokenFields> {
    if fields.len() != TOKEN_FIELDS_LEN {
        bail!(
            "invalid Zone authorization-token suffix length: expected {TOKEN_FIELDS_LEN}, got {}",
            fields.len()
        );
    }

    Ok(TokenFields {
        version: fields[0],
        zone_id: u32::from_be_bytes(fields[1..5].try_into().expect("length checked")),
        chain_id: u64::from_be_bytes(fields[5..13].try_into().expect("length checked")),
        issued_at: u64::from_be_bytes(fields[13..21].try_into().expect("length checked")),
        expires_at: u64::from_be_bytes(fields[21..29].try_into().expect("length checked")),
    })
}

/// Compute the raw digest signed by a Zone authorization token.
pub fn signing_digest(fields: &[u8; TOKEN_FIELDS_LEN]) -> B256 {
    let mut message = [0u8; 32 + TOKEN_FIELDS_LEN];
    message[..32].copy_from_slice(&TEMPO_ZONE_RPC_MAGIC);
    message[32..].copy_from_slice(fields);
    keccak256(message)
}

/// Sign a fixed suffix and return `<r:32><s:32><v:1><suffix:29>`.
///
/// The recovery byte is serialized as parity `0` or `1`; the digest is signed
/// directly without EIP-191 message prefixing.
pub fn sign_token(
    signer: &EcdsaSigner,
    fields: &[u8; TOKEN_FIELDS_LEN],
) -> Result<[u8; TOKEN_LEN]> {
    let digest = signing_digest(fields);
    let signature = signer
        .sign_hash_sync(&digest)
        .map_err(|_| eyre!("failed to sign Zone authorization token"))?;

    let mut token = [0u8; TOKEN_LEN];
    token[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
    token[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
    token[64] = u8::from(signature.v());
    token[SIGNATURE_LEN..].copy_from_slice(fields);
    Ok(token)
}

/// Encode a token as lowercase hex without a `0x` prefix.
pub fn encode_token_hex(token: &[u8; TOKEN_LEN]) -> String {
    hex::encode(token)
}

/// Recover the logical signer from a normal 94-byte secp256k1 token.
pub fn recover_signer(token: &[u8]) -> Result<Address> {
    if token.len() != TOKEN_LEN {
        bail!("invalid Zone authorization-token length: expected {TOKEN_LEN}, got {}", token.len());
    }
    if token[64] > 1 {
        bail!("invalid Zone authorization-token recovery parity");
    }

    let signature = Signature::try_from(&token[..SIGNATURE_LEN])
        .map_err(|_| eyre!("invalid Zone authorization-token signature"))?;
    let fields: &[u8; TOKEN_FIELDS_LEN] =
        token[SIGNATURE_LEN..].try_into().expect("token length checked");
    signature
        .recover_address_from_prehash(&signing_digest(fields))
        .map_err(|_| eyre!("invalid Zone authorization-token signature"))
}

/// Verify that a token recovers to the expected logical signer.
pub fn verify_token(token: &[u8], expected_signer: Address) -> Result<()> {
    if recover_signer(token)? != expected_signer {
        bail!("Zone authorization-token signer mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use txgen_core::derive_mnemonic_signer;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const EXPECTED_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const EXPECTED_FIELDS_HEX: &str = "0000000047000000001922a1e7000000006553f100000000006553f358";
    const EXPECTED_DIGEST: &str =
        "0x053b345b9e852de1e086414b9780d8ab004da495a2abd360905b5811f82ef2f9";
    const EXPECTED_TOKEN_HEX: &str = concat!(
        "690e62bf73044f50d93a0d59066fca4921a3c33a048be7758c8b2901cc7c62b6",
        "466f2aab1e0064c4b3c6c28e7401886926a6ff543af3552eeb63fad2b840a079",
        "00",
        "0000000047000000001922a1e7000000006553f100000000006553f358",
    );

    /// Fixed conformance vector for the Zone private-RPC token format in
    /// `tempoxyz/zones` at commit cf055f24b8e8d22a4e774c004cd935d74dba71fc,
    /// `crates/rpc/src/auth/token.rs` and `crates/rpc/src/provider.rs`.
    #[test]
    fn canonical_zone_token_vector() -> Result<()> {
        let signer = derive_mnemonic_signer(TEST_MNEMONIC, 0)?;
        let expected_address = EXPECTED_ADDRESS.parse::<Address>()?;
        assert_eq!(signer.address(), expected_address);

        let fields = build_token_fields(71, 421_700_071, 1_700_000_000, 1_700_000_600);
        assert_eq!(hex::encode(fields), EXPECTED_FIELDS_HEX);
        assert_eq!(signing_digest(&fields), EXPECTED_DIGEST.parse::<B256>()?);

        let token = sign_token(&signer, &fields)?;
        assert_eq!(encode_token_hex(&token), EXPECTED_TOKEN_HEX);
        assert_eq!(token.len(), TOKEN_LEN);
        assert_eq!(encode_token_hex(&token).len(), TOKEN_HEX_LEN);
        assert!(encode_token_hex(&token).bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(encode_token_hex(&token).bytes().all(|byte| !byte.is_ascii_uppercase()));

        let parsed = parse_token_fields(&token[SIGNATURE_LEN..])?;
        assert_eq!(parsed.version, TOKEN_VERSION);
        assert_eq!(parsed.zone_id, 71);
        assert_eq!(parsed.chain_id, 421_700_071);
        assert_eq!(parsed.issued_at, 1_700_000_000);
        assert_eq!(parsed.expires_at, 1_700_000_600);

        assert_eq!(recover_signer(&token)?, expected_address);
        verify_token(&token, expected_address)
    }

    #[test]
    fn rejects_malformed_token_shapes_without_echoing_token_data() {
        assert!(parse_token_fields(&[0u8; TOKEN_FIELDS_LEN - 1]).is_err());
        assert!(recover_signer(&[0u8; TOKEN_LEN - 1]).is_err());

        let mut invalid_parity = [0u8; TOKEN_LEN];
        invalid_parity[64] = 2;
        let error = recover_signer(&invalid_parity).unwrap_err().to_string();
        assert_eq!(error, "invalid Zone authorization-token recovery parity");
    }
}
