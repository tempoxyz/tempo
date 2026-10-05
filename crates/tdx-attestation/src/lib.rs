//! Experimental TDX evidence profile. Verification is offline and uses caller-supplied time.
//! No HTTP, native DCAP library, wall clock, or mutable collateral registry is used by `verify`.

use alloy_primitives::FixedBytes;
use dcap_qvl::{
    QuoteCollateralV3, QuotePolicy,
    configs::RustCryptoConfig,
    quote::{Quote, Report, TDReport10},
    verify::QuoteVerifier,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Maximum raw quote length.
pub const MAX_QUOTE_BYTES: usize = 64 * 1024;
/// Maximum serialized collateral length.
pub const MAX_COLLATERAL_BYTES: usize = 128 * 1024;
/// Maximum complete evidence envelope length.
pub const MAX_EVIDENCE_BYTES: usize = 16 + MAX_QUOTE_BYTES + MAX_COLLATERAL_BYTES;
const MAGIC: &[u8; 8] = b"TZTDXB01";

/// Exact guest measurement tuple; tuples cannot be mixed between releases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub mr_td: FixedBytes<48>,
    pub mr_config_id: FixedBytes<48>,
    pub mr_owner: FixedBytes<48>,
    pub mr_owner_config: FixedBytes<48>,
    pub rtmrs: [FixedBytes<48>; 4],
    pub td_attributes: u64,
    pub xfam: u64,
}

/// Explicit measurement allowlist. The same schema is used by Zone transport clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename = "tdx", deny_unknown_fields)]
pub struct Policy {
    pub measurements: Vec<Measurements>,
}

/// A malformed, untrusted, expired, or policy-rejected evidence bundle.
#[derive(Debug, thiserror::Error)]
#[error("invalid TDX evidence: {0}")]
pub struct Error(String);
fn invalid(message: impl ToString) -> Error {
    Error(message.to_string())
}

impl Policy {
    /// Reject empty/oversized allowlists, zero MRTD, and debug guests.
    pub fn validate(&self) -> Result<(), Error> {
        if self.measurements.is_empty()
            || self.measurements.len() > 32
            || self
                .measurements
                .iter()
                .any(|m| m.mr_td.is_zero() || m.td_attributes & 1 != 0)
        {
            return Err(invalid("invalid measurement policy"));
        }
        Ok(())
    }
}
impl From<&TDReport10> for Measurements {
    fn from(r: &TDReport10) -> Self {
        Self {
            mr_td: r.mr_td.into(),
            mr_config_id: r.mr_config_id.into(),
            mr_owner: r.mr_owner.into(),
            mr_owner_config: r.mr_owner_config.into(),
            rtmrs: [
                r.rt_mr0.into(),
                r.rt_mr1.into(),
                r.rt_mr2.into(),
                r.rt_mr3.into(),
            ],
            td_attributes: u64::from_le_bytes(r.td_attributes),
            xfam: u64::from_le_bytes(r.xfam),
        }
    }
}

/// Quote plus self-contained Intel-signed collateral. Lengths are big-endian u32s.
pub fn encode(quote: &[u8], collateral: &QuoteCollateralV3) -> Result<Vec<u8>, Error> {
    validate_quote(quote)?;
    let json = serde_json::to_vec(collateral).map_err(invalid)?;
    if json.len() > MAX_COLLATERAL_BYTES {
        return Err(invalid("collateral too large"));
    }
    validate_collateral(collateral)?;
    let mut out = Vec::with_capacity(16 + quote.len() + json.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(quote.len() as u32).to_be_bytes());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(quote);
    out.extend_from_slice(&json);
    Ok(out)
}

/// Borrow the raw quote from a bounded envelope; parsing alone authenticates nothing.
pub fn raw_quote(evidence: &[u8]) -> Result<&[u8], Error> {
    split(evidence).map(|(quote, _)| quote)
}
fn split(evidence: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if evidence.len() < 16 || evidence.len() > MAX_EVIDENCE_BYTES || &evidence[..8] != MAGIC {
        return Err(invalid("invalid envelope"));
    }
    let q = u32::from_be_bytes(evidence[8..12].try_into().map_err(invalid)?) as usize;
    let c = u32::from_be_bytes(evidence[12..16].try_into().map_err(invalid)?) as usize;
    if q > MAX_QUOTE_BYTES
        || c == 0
        || c > MAX_COLLATERAL_BYTES
        || q.checked_add(c).and_then(|n| n.checked_add(16)) != Some(evidence.len())
    {
        return Err(invalid("invalid envelope lengths"));
    }
    Ok((&evidence[16..16 + q], &evidence[16 + q..]))
}
fn validate_quote(raw: &[u8]) -> Result<Quote, Error> {
    if raw.len() < 637 || raw.len() > MAX_QUOTE_BYTES || raw[..8] != [4, 0, 2, 0, 0x81, 0, 0, 0] {
        return Err(invalid("requires TDX ECDSA quote v4"));
    }
    // Check all nested lengths before SCALE decoding can allocate from attacker-controlled sizes.
    let sig_len = u32::from_le_bytes(raw[632..636].try_into().map_err(invalid)?) as usize;
    if sig_len != raw.len() - 636 || sig_len < 134 {
        return Err(invalid("signature bounds"));
    }
    let outer = 636 + 128;
    let kind = u16::from_le_bytes(raw[outer..outer + 2].try_into().map_err(invalid)?);
    let len = u32::from_le_bytes(raw[outer + 2..outer + 6].try_into().map_err(invalid)?) as usize;
    if kind != 6 || len != raw.len() - outer - 6 || len < 456 {
        return Err(invalid("QE certification bounds"));
    }
    let auth = outer + 6 + 448;
    let auth_len = u16::from_le_bytes(raw[auth..auth + 2].try_into().map_err(invalid)?) as usize;
    let cert = auth + 2 + auth_len;
    if auth_len > 1024 || cert + 6 > raw.len() {
        return Err(invalid("QE authentication bounds"));
    }
    let kind = u16::from_le_bytes(raw[cert..cert + 2].try_into().map_err(invalid)?);
    let len = u32::from_le_bytes(raw[cert + 2..cert + 6].try_into().map_err(invalid)?) as usize;
    if kind != 5 || len > 16 * 1024 || len != raw.len() - cert - 6 {
        return Err(invalid("PCK certification bounds"));
    }
    let mut input = raw;
    let quote = Quote::decode(&mut input).map_err(invalid)?;
    // Also reject trailing bytes inside nested authentication/certification structures.
    if !input.is_empty() || quote.encode() != raw {
        return Err(invalid("noncanonical quote"));
    }
    if quote.header.qe_vendor_id != dcap_qvl::INTEL_QE_VENDOR_ID {
        return Err(invalid("wrong QE vendor"));
    }
    Ok(quote)
}
fn validate_collateral(c: &QuoteCollateralV3) -> Result<(), Error> {
    for chain in [
        &c.pck_crl_issuer_chain,
        &c.tcb_info_issuer_chain,
        &c.qe_identity_issuer_chain,
    ]
    .into_iter()
    .chain(c.pck_certificate_chain.as_ref())
    {
        let count = chain.matches("-----BEGIN CERTIFICATE-----").count();
        if !(1..=4).contains(&count) || chain.len() > 16 * 1024 {
            return Err(invalid("certificate chain bounds"));
        }
    }
    if c.root_ca_crl.len() > 32 * 1024
        || c.pck_crl.len() > 32 * 1024
        || c.tcb_info.len() > 48 * 1024
        || c.qe_identity.len() > 16 * 1024
        || c.tcb_info_signature.len() != 64
        || c.qe_identity_signature.len() != 64
    {
        return Err(invalid("collateral field bounds"));
    }
    // Cap TCB iteration and JSON depth before cryptographic work.
    for (json, key, cap) in [
        (&c.tcb_info, "tcbLevels", 128),
        (&c.qe_identity, "tcbLevels", 64),
    ] {
        let v: serde_json::Value = serde_json::from_str(json).map_err(invalid)?;
        if !v
            .get(key)
            .and_then(|x| x.as_array())
            .is_some_and(|a| !a.is_empty() && a.len() <= cap)
        {
            return Err(invalid("TCB level bounds"));
        }
    }
    Ok(())
}

/// Verify an envelope at the L1 block timestamp against Intel's pinned production root.
/// Only current TCBs and collateral are accepted; debug and service TDs are rejected.
pub fn verify(
    evidence: &[u8],
    report_data: &[u8; 64],
    policy: &Policy,
    block_timestamp: u64,
) -> Result<(), Error> {
    policy.validate()?;
    let (raw, json) = split(evidence)?;
    validate_quote(raw)?;
    // Bound embedded PCK chain too (the collateral's optional copy is not trusted).
    if raw
        .windows(27)
        .filter(|w| *w == b"-----BEGIN CERTIFICATE-----")
        .count()
        > 4
    {
        return Err(invalid("embedded certificate chain bounds"));
    }
    let collateral: QuoteCollateralV3 = serde_json::from_slice(json).map_err(invalid)?;
    validate_collateral(&collateral)?;
    let appraisal = QuotePolicy::strict(block_timestamp)
        .allow_smt(true)
        .allow_cached_keys(true)
        .allow_dynamic_platform(true);
    let claims = QuoteVerifier::new_prod()
        .with_config::<RustCryptoConfig>()
        .verify_with_policy(raw, collateral, block_timestamp, &appraisal)
        .map_err(invalid)?;
    let Report::TD10(report) = claims.report else {
        return Err(invalid("wrong report type"));
    };
    if report.report_data != *report_data
        || !policy.measurements.contains(&Measurements::from(&report))
    {
        return Err(invalid("report binding or measurement mismatch"));
    }
    Ok(())
}

/// Fetch collateral outside consensus, then build the same bounded envelope verified on L1.
#[cfg(feature = "client")]
pub async fn collect(quote: &[u8]) -> Result<Vec<u8>, Error> {
    validate_quote(quote)?;
    let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(
        "https://api.trustedservices.intel.com",
    )
    .map_err(invalid)?
    .fetch(quote)
    .await
    .map_err(invalid)?;
    encode(quote, &collateral)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_750_377_600; // 2025-06-20
    fn fixture() -> (Vec<u8>, Policy, [u8; 64]) {
        let raw = include_bytes!("../testdata/tdx_quote");
        let collateral =
            serde_json::from_slice(include_bytes!("../testdata/tdx_quote_collateral.json"))
                .unwrap();
        let Report::TD10(report) = validate_quote(raw).unwrap().report else {
            panic!("TDX fixture");
        };
        (
            encode(raw, &collateral).unwrap(),
            Policy {
                measurements: vec![Measurements::from(&report)],
            },
            report.report_data,
        )
    }
    #[test]
    fn verifies_intel_signed_evidence_offline() {
        let (evidence, policy, data) = fixture();
        verify(&evidence, &data, &policy, NOW).unwrap();
    }
    #[test]
    fn rejects_binding_measurement_and_expiration() {
        let (evidence, mut policy, mut data) = fixture();
        data[0] ^= 1;
        assert!(verify(&evidence, &data, &policy, NOW).is_err());
        data[0] ^= 1;
        policy.measurements[0].rtmrs[1][0] ^= 1;
        assert!(verify(&evidence, &data, &policy, NOW).is_err());
        policy.measurements[0].rtmrs[1][0] ^= 1;
        assert!(verify(&evidence, &data, &policy, NOW + 60 * 86400).is_err());
        assert!(verify(&evidence, &data, &policy, NOW - 60 * 86400).is_err());
    }
    #[test]
    fn rejects_tampered_quote_and_signed_collateral() {
        let (mut evidence, policy, data) = fixture();
        evidence[16 + 48 + 136] ^= 1;
        assert!(verify(&evidence, &data, &policy, NOW).is_err());
        let raw = include_bytes!("../testdata/tdx_quote");
        let mut collateral: QuoteCollateralV3 =
            serde_json::from_slice(include_bytes!("../testdata/tdx_quote_collateral.json"))
                .unwrap();
        collateral.tcb_info_signature[0] ^= 1;
        let evidence = encode(raw, &collateral).unwrap();
        assert!(verify(&evidence, &data, &policy, NOW).is_err());
        collateral.tcb_info_signature[0] ^= 1;
        collateral.pck_crl[20] ^= 1;
        assert!(verify(&encode(raw, &collateral).unwrap(), &data, &policy, NOW).is_err());
    }
    #[test]
    fn envelope_bounds_and_quote_types_fail_closed() {
        let (evidence, _, _) = fixture();
        for size in [0, 8, 15, 16, evidence.len() - 1] {
            assert!(raw_quote(&evidence[..size]).is_err());
        }
        let mut extra = evidence.clone();
        extra.push(0);
        assert!(raw_quote(&extra).is_err());
        let mut bad = evidence;
        bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(raw_quote(&bad).is_err());
        for offset in [0, 2, 4, 12] {
            let mut q = include_bytes!("../testdata/tdx_quote").to_vec();
            q[offset] ^= 1;
            assert!(validate_quote(&q).is_err());
        }
    }
    #[test]
    fn debug_zero_and_empty_policy_are_rejected() {
        let (_, mut policy, _) = fixture();
        policy.measurements[0].td_attributes |= 1;
        assert!(policy.validate().is_err());
        policy.measurements[0].td_attributes &= !1;
        policy.measurements[0].mr_td = FixedBytes::ZERO;
        assert!(policy.validate().is_err());
        policy.measurements.clear();
        assert!(policy.validate().is_err());
    }
}
