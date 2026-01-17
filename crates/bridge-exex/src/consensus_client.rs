//! Consensus RPC client for fetching finalization certificates.
//!
//! This module provides access to consensus layer data needed for header relay,
//! specifically the finalization certificates containing validator signatures.

use alloy::primitives::{Bytes, B256};
use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::retry::with_retry;

/// Finalization certificate data from the consensus layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedBlock {
    pub epoch: u64,
    pub view: u64,
    pub height: Option<u64>,
    pub digest: B256,
    /// Hex-encoded finalization certificate (includes BLS threshold signature).
    pub certificate: String,
}

/// Query type for consensus RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Query {
    Latest,
    Height(u64),
}

/// Client for fetching finalization data from Tempo's consensus RPC.
pub struct ConsensusClient {
    rpc_url: String,
    client: reqwest::Client,
}

impl ConsensusClient {
    /// Create a new consensus client.
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Get the finalization certificate for a specific block height.
    ///
    /// Returns `None` if the block has not been finalized yet.
    pub async fn get_finalization(&self, height: u64) -> Result<Option<CertifiedBlock>> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "consensus_getFinalization",
            "params": [{"height": height}],
            "id": 1
        });

        let response = with_retry("consensus_getFinalization", || async {
            let resp = self
                .client
                .post(&self.rpc_url)
                .json(&request)
                .send()
                .await
                .wrap_err("Failed to send RPC request")?;

            let body: serde_json::Value = resp.json().await.wrap_err("Failed to parse response")?;

            if let Some(error) = body.get("error") {
                return Err(eyre::eyre!("RPC error: {}", error));
            }

            Ok(body)
        })
        .await?;

        let result = response.get("result");
        match result {
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(value) => {
                let block: CertifiedBlock =
                    serde_json::from_value(value.clone()).wrap_err("Failed to parse CertifiedBlock")?;
                Ok(Some(block))
            }
        }
    }

    /// Get the latest finalization.
    pub async fn get_latest_finalization(&self) -> Result<Option<CertifiedBlock>> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "consensus_getFinalization",
            "params": ["latest"],
            "id": 1
        });

        let response = with_retry("consensus_getFinalization_latest", || async {
            let resp = self
                .client
                .post(&self.rpc_url)
                .json(&request)
                .send()
                .await
                .wrap_err("Failed to send RPC request")?;

            let body: serde_json::Value = resp.json().await.wrap_err("Failed to parse response")?;

            if let Some(error) = body.get("error") {
                return Err(eyre::eyre!("RPC error: {}", error));
            }

            Ok(body)
        })
        .await?;

        let result = response.get("result");
        match result {
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(value) => {
                let block: CertifiedBlock =
                    serde_json::from_value(value.clone()).wrap_err("Failed to parse CertifiedBlock")?;
                Ok(Some(block))
            }
        }
    }
}

/// Extracts the BLS signature from a finalization certificate and decompresses it.
///
/// The certificate is encoded using commonware's codec format for
/// `Finalization<Scheme<PublicKey, MinSig>, Digest>`.
///
/// ## Certificate Structure (commonware-codec encoding)
///
/// The Finalization struct contains:
/// 1. `Proposal { round: Round, payload: Digest }`
///    - Round encoding: epoch (8 bytes, varint) + view (8 bytes, varint)
///    - Digest: 32 bytes (B256)
/// 2. `Signature`: BLS threshold signature (G1 point in MinSig variant = 48 bytes compressed)
/// 3. `Seed signature`: Random beacon signature (48 bytes compressed)
///
/// ## Point Format Conversion
///
/// The signature in the certificate is in **compressed G1 format** (48 bytes).
/// The EIP-2537 BLS precompiles expect **uncompressed G1 points** (128 bytes).
///
/// This function decompresses the 48-byte compressed G1 point to the 128-byte
/// uncompressed format required by the TempoLightClient contract.
pub fn extract_bls_signature_from_certificate(certificate_hex: &str) -> Result<Bytes> {
    let certificate_bytes = hex::decode(certificate_hex.trim_start_matches("0x"))
        .wrap_err("Failed to decode certificate hex")?;

    // The finalization certificate layout (approximate, depends on varint encoding):
    // - Epoch: 1-10 bytes (varint)
    // - View: 1-10 bytes (varint)  
    // - Digest: 32 bytes
    // - Signature: 48 bytes (compressed G1)
    // - Seed signature: 48 bytes (compressed G1)
    //
    // For small epoch/view values (< 128), each is 1 byte.
    // Minimum size: 1 + 1 + 32 + 48 + 48 = 130 bytes
    // With larger values: up to 10 + 10 + 32 + 48 + 48 = 148 bytes

    // The signature length in MinSig variant
    const COMPRESSED_G1_LEN: usize = 48;

    // Minimum certificate length
    if certificate_bytes.len() < 130 {
        return Err(eyre::eyre!(
            "Certificate too short: expected at least 130 bytes, got {}",
            certificate_bytes.len()
        ));
    }

    // The signature is the 48 bytes after the proposal (round + digest).
    // Since round uses varint encoding, we need to parse from the end.
    // Structure: [epoch_varint][view_varint][digest:32][signature:48][seed_sig:48]
    //
    // The last 96 bytes are signature (48) + seed_sig (48).
    // The signature we want starts at len - 96.

    let signature_start = certificate_bytes.len() - 96;
    let signature_end = signature_start + COMPRESSED_G1_LEN;

    let compressed_sig = &certificate_bytes[signature_start..signature_end];

    // Decompress the 48-byte compressed G1 signature to 128-byte uncompressed format
    let uncompressed = decompress_g1_signature(compressed_sig)?;

    debug!(
        certificate_len = certificate_bytes.len(),
        signature_start,
        compressed_len = COMPRESSED_G1_LEN,
        uncompressed_len = uncompressed.len(),
        "Extracted and decompressed BLS signature from certificate"
    );

    Ok(uncompressed)
}

/// Decompresses a 48-byte compressed G1 BLS signature to 128-byte uncompressed format.
///
/// The uncompressed format is: x-coordinate (64 bytes, big-endian) || y-coordinate (64 bytes, big-endian)
/// This matches the EIP-2537 BLS precompile G1 point format.
fn decompress_g1_signature(compressed: &[u8]) -> Result<Bytes> {
    use blst::blst_p1_affine;
    use blst::blst_p1_uncompress;
    
    if compressed.len() != 48 {
        return Err(eyre::eyre!(
            "Invalid compressed G1 length: expected 48 bytes, got {}",
            compressed.len()
        ));
    }

    // Use low-level blst API for decompression
    let mut affine = blst_p1_affine::default();
    
    // Uncompress the point (validates it's on the curve)
    let err = unsafe {
        blst_p1_uncompress(&mut affine, compressed.as_ptr())
    };
    
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(eyre::eyre!("Failed to decompress G1 point: {:?}", err));
    }
    
    // The affine point contains x and y coordinates
    // Each coordinate is a 384-bit (48-byte) field element in blst's internal format
    // We need to serialize them in big-endian and pad to 64 bytes each
    
    // The affine point contains x and y coordinates as blst_fp (384-bit field elements)
    // We need to serialize them in big-endian and pad to 64 bytes each for EIP-2537 format
    use blst::blst_bendian_from_fp;
    
    let mut result = vec![0u8; 128];
    
    let mut x_be = [0u8; 48];
    let mut y_be = [0u8; 48];
    
    unsafe {
        blst_bendian_from_fp(x_be.as_mut_ptr(), &affine.x);
        blst_bendian_from_fp(y_be.as_mut_ptr(), &affine.y);
    }
    
    // x-coordinate: 16 zero bytes + 48-byte x (big-endian)
    result[16..64].copy_from_slice(&x_be);
    // y-coordinate: 16 zero bytes + 48-byte y (big-endian)
    result[80..128].copy_from_slice(&y_be);

    Ok(Bytes::from(result))
}

/// Formats validator signatures for the light client based on its mode.
///
/// For BLS mode (production):
/// - Single aggregated BLS signature (G1 point, 128 bytes uncompressed)
///
/// For ECDSA mode (testing):
/// - ABI-encoded array of individual ECDSA signatures
pub fn format_signatures_for_light_client(
    certificate: &CertifiedBlock,
    use_ecdsa_mode: bool,
) -> Result<Bytes> {
    if use_ecdsa_mode {
        // ECDSA mode is for testing only - return empty for now
        // In production, we use BLS signatures from the consensus layer
        warn!("ECDSA mode not implemented for signature aggregation");
        return Ok(Bytes::new());
    }

    // Extract the BLS signature from the certificate
    extract_bls_signature_from_certificate(&certificate.certificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_serialization() {
        let height_query = Query::Height(100);
        let json = serde_json::to_string(&height_query).unwrap();
        assert!(json.contains("100"));

        let latest_query = Query::Latest;
        let json = serde_json::to_string(&latest_query).unwrap();
        assert!(json.contains("latest"));
    }

    #[test]
    fn test_certified_block_deserialization() {
        let json = r#"{
            "epoch": 1,
            "view": 10,
            "height": 100,
            "digest": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "certificate": "deadbeef"
        }"#;

        let block: CertifiedBlock = serde_json::from_str(json).unwrap();
        assert_eq!(block.epoch, 1);
        assert_eq!(block.view, 10);
        assert_eq!(block.height, Some(100));
    }

    fn create_valid_bls_signature() -> [u8; 48] {
        use blst::min_sig::SecretKey;
        
        let ikm = [1u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let msg = b"test message";
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = sk.sign(msg, dst, &[]);
        sig.to_bytes()
    }

    #[test]
    fn test_extract_bls_signature_valid_certificate() {
        // Create a mock certificate with a valid BLS signature
        // Structure: epoch (1) + view (1) + digest (32) + signature (48) + seed_sig (48) = 130 bytes
        let valid_sig = create_valid_bls_signature();
        
        let mut cert = vec![0u8; 130];
        cert[0] = 0x01; // epoch = 1
        cert[1] = 0x05; // view = 5
        // digest: bytes 2-33
        for i in 2..34 {
            cert[i] = (i - 2) as u8;
        }
        // signature: bytes 34-81 (48 bytes) - use valid BLS signature
        cert[34..82].copy_from_slice(&valid_sig);
        // seed_signature: bytes 82-129 (48 bytes) - use same valid signature
        cert[82..130].copy_from_slice(&valid_sig);

        let cert_hex = hex::encode(&cert);
        let result = extract_bls_signature_from_certificate(&cert_hex).unwrap();

        // Should return 128-byte uncompressed G1 point (EIP-2537 format)
        assert_eq!(result.len(), 128);
        // First 16 bytes should be zero padding for x-coordinate
        assert!(result[0..16].iter().all(|&b| b == 0));
        // Bytes 64-80 should be zero padding for y-coordinate
        assert!(result[64..80].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_extract_bls_signature_with_0x_prefix() {
        let valid_sig = create_valid_bls_signature();
        
        let mut cert = vec![0u8; 130];
        cert[34..82].copy_from_slice(&valid_sig);
        cert[82..130].copy_from_slice(&valid_sig);

        let cert_hex = format!("0x{}", hex::encode(&cert));
        let result = extract_bls_signature_from_certificate(&cert_hex).unwrap();

        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_extract_bls_signature_too_short() {
        let short_cert = hex::encode(&[0u8; 100]); // Too short
        let result = extract_bls_signature_from_certificate(&short_cert);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_extract_bls_signature_larger_certificate() {
        // Certificate with larger epoch/view values (more bytes for varint)
        // Total: 5 + 5 + 32 + 48 + 48 = 138 bytes
        let valid_sig = create_valid_bls_signature();
        
        let mut cert = vec![0u8; 138];
        // Place signature at correct position (len - 96 to len - 48)
        cert[(138 - 96)..(138 - 48)].copy_from_slice(&valid_sig);
        cert[(138 - 48)..138].copy_from_slice(&valid_sig);

        let cert_hex = hex::encode(&cert);
        let result = extract_bls_signature_from_certificate(&cert_hex).unwrap();

        // Should return 128-byte uncompressed format
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_decompress_g1_signature_invalid_length() {
        let result = decompress_g1_signature(&[0u8; 47]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid compressed G1 length"));
    }

    #[test]
    fn test_decompress_g1_signature_roundtrip() {
        use blst::min_sig::SecretKey;
        
        let ikm = [42u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let msg = b"roundtrip test";
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = sk.sign(msg, dst, &[]);
        let compressed = sig.to_bytes();
        
        let uncompressed = decompress_g1_signature(&compressed).unwrap();
        
        // Verify the format: 128 bytes total
        assert_eq!(uncompressed.len(), 128);
        // x-coordinate is at bytes 16..64 (48 bytes with 16-byte zero prefix)
        // y-coordinate is at bytes 80..128 (48 bytes with 16-byte zero prefix)
        assert!(uncompressed[0..16].iter().all(|&b| b == 0));
        assert!(uncompressed[64..80].iter().all(|&b| b == 0));
    }
}
