//! Bounded AWS Nitro attestation validation.

use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use minicbor::{Decoder, Encoder, data::Type};
use x509_cert::{
    Certificate, Version,
    der::{Decode, Encode, asn1::ObjectIdentifier, oid::AssociatedOid},
    ext::pkix::{BasicConstraints, KeyUsage},
};

use crate::storage::StorageCtx;

pub(super) const MAX_DOCUMENT_LEN: usize = 24_576;
const MAX_PAYLOAD_LEN: usize = 16_384;
const MAX_CERT_LEN: usize = 1_024;
const MAX_CA_BUNDLE: usize = 32;
const MAX_PCRS: usize = 32;
const MAX_DEPTH: usize = 16;
pub(super) const BASE_GAS: u64 = 40_000;
pub(super) const SIGNATURE_GAS: u64 = 35_000;

const ECDSA_SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// AWS Nitro Enclaves commercial-partition root G1, extracted from AWS's published archive.
pub(super) const AWS_NITRO_ROOT_DER: &[u8] = &alloy::primitives::hex!(
    "3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6"
);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AttestationError {
    Format,
    Certificate,
    Signature,
    OutOfGas,
}

pub(super) struct VerifiedAttestation {
    pub timestamp: u64,
    pub pcrs: [Option<Vec<u8>>; 3],
    pub user_data: Vec<u8>,
}

struct CoseDocument {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

struct ParsedAttestation {
    timestamp: u64,
    pcrs: [Option<Vec<u8>>; 3],
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    user_data: Vec<u8>,
}

pub(super) fn verify_attestation_with_root(
    storage: &mut StorageCtx,
    document: &[u8],
    block_timestamp: u64,
    root_der: &[u8],
) -> core::result::Result<VerifiedAttestation, AttestationError> {
    if document.len() > MAX_DOCUMENT_LEN {
        return Err(AttestationError::Format);
    }
    storage
        .deduct_gas(BASE_GAS)
        .map_err(|_| AttestationError::OutOfGas)?;

    let cose = parse_cose(document)?;
    let parsed = parse_payload(&cose.payload)?;
    let verification_count = parsed
        .cabundle
        .len()
        .checked_add(1)
        .ok_or(AttestationError::Format)?;
    storage
        .deduct_gas(SIGNATURE_GAS.saturating_mul(verification_count as u64))
        .map_err(|_| AttestationError::OutOfGas)?;

    let leaf_key = validate_certificate_chain(
        &parsed.certificate,
        &parsed.cabundle,
        block_timestamp,
        root_der,
    )?;
    verify_cose_signature(&leaf_key, &cose)?;

    Ok(VerifiedAttestation {
        timestamp: parsed.timestamp,
        pcrs: parsed.pcrs,
        user_data: parsed.user_data,
    })
}

fn parse_cose(document: &[u8]) -> Result<CoseDocument, AttestationError> {
    let mut decoder = Decoder::new(document);
    if decoder.datatype().map_err(format_error)? == Type::Tag
        && decoder.tag().map_err(format_error)?.as_u64() != 18
    {
        return Err(AttestationError::Format);
    }
    let array_len = decoder.array().map_err(format_error)?;
    if array_len.is_some_and(|len| len != 4) {
        return Err(AttestationError::Format);
    }

    let protected = read_bytes(&mut decoder, 64)?;
    validate_protected_header(&protected)?;
    if !matches!(
        decoder.datatype().map_err(format_error)?,
        Type::Map | Type::MapIndef
    ) {
        return Err(AttestationError::Format);
    }
    skip_value(&mut decoder, 1)?;
    let payload = read_bytes(&mut decoder, MAX_PAYLOAD_LEN)?;
    if payload.is_empty() {
        return Err(AttestationError::Format);
    }
    let signature = read_bytes(&mut decoder, 96)?;
    if signature.len() != 96 {
        return Err(AttestationError::Format);
    }
    if array_len.is_none() {
        if decoder.datatype().map_err(format_error)? != Type::Break {
            return Err(AttestationError::Format);
        }
        decoder.skip().map_err(format_error)?;
    }
    if decoder.position() != document.len() {
        return Err(AttestationError::Format);
    }
    Ok(CoseDocument {
        protected,
        payload,
        signature,
    })
}

fn validate_protected_header(protected: &[u8]) -> Result<(), AttestationError> {
    let mut decoder = Decoder::new(protected);
    let len = decoder.map().map_err(format_error)?;
    if len.is_some_and(|len| len != 1) {
        return Err(AttestationError::Format);
    }
    if decoder.i64().map_err(format_error)? != 1 || decoder.i64().map_err(format_error)? != -35 {
        return Err(AttestationError::Format);
    }
    if len.is_none() {
        if decoder.datatype().map_err(format_error)? != Type::Break {
            return Err(AttestationError::Format);
        }
        decoder.skip().map_err(format_error)?;
    }
    if decoder.position() != protected.len() {
        return Err(AttestationError::Format);
    }
    Ok(())
}

fn parse_payload(payload: &[u8]) -> Result<ParsedAttestation, AttestationError> {
    let mut decoder = Decoder::new(payload);
    let map_len = decoder.map().map_err(format_error)?;
    let mut remaining = map_len;
    let mut seen = 0u16;
    let mut module_id = None;
    let mut digest = None;
    let mut timestamp = None;
    let mut pcrs = None;
    let mut certificate = None;
    let mut cabundle = None;
    let mut user_data = Vec::new();

    while container_has_item(&mut decoder, &mut remaining)? {
        let key = read_text(&mut decoder, 64)?;
        let field = match key.as_str() {
            "module_id" => Some(0),
            "digest" => Some(1),
            "timestamp" => Some(2),
            "pcrs" => Some(3),
            "certificate" => Some(4),
            "cabundle" => Some(5),
            "public_key" => Some(6),
            "user_data" => Some(7),
            "nonce" => Some(8),
            _ => None,
        };
        if let Some(field) = field {
            let bit = 1u16 << field;
            if seen & bit != 0 || matches!(decoder.datatype().map_err(format_error)?, Type::Null) {
                return Err(AttestationError::Format);
            }
            seen |= bit;
        }

        match key.as_str() {
            "module_id" => module_id = Some(read_text(&mut decoder, MAX_PAYLOAD_LEN)?),
            "digest" => digest = Some(read_text(&mut decoder, 16)?),
            "timestamp" => timestamp = Some(decoder.u64().map_err(format_error)?),
            "pcrs" => pcrs = Some(parse_pcrs(&mut decoder)?),
            "certificate" => certificate = Some(read_nonempty_bytes(&mut decoder, MAX_CERT_LEN)?),
            "cabundle" => cabundle = Some(parse_cabundle(&mut decoder)?),
            "public_key" => {
                read_nonempty_bytes(&mut decoder, MAX_CERT_LEN)?;
            }
            "user_data" => user_data = read_bytes(&mut decoder, 512)?,
            "nonce" => {
                read_bytes(&mut decoder, 512)?;
            }
            _ => skip_value(&mut decoder, 1)?,
        }
    }
    if decoder.position() != payload.len()
        || module_id.as_ref().is_none_or(String::is_empty)
        || digest.as_deref() != Some("SHA384")
        || timestamp.is_none_or(|value| value == 0)
        || pcrs.is_none()
        || certificate.is_none()
        || cabundle.is_none()
    {
        return Err(AttestationError::Format);
    }

    Ok(ParsedAttestation {
        timestamp: timestamp.expect("checked above"),
        pcrs: pcrs.expect("checked above"),
        certificate: certificate.expect("checked above"),
        cabundle: cabundle.expect("checked above"),
        user_data,
    })
}

fn parse_pcrs(decoder: &mut Decoder<'_>) -> Result<[Option<Vec<u8>>; 3], AttestationError> {
    let map_len = decoder.map().map_err(format_error)?;
    if map_len.is_some_and(|len| len == 0 || len > MAX_PCRS as u64) {
        return Err(AttestationError::Format);
    }
    let mut remaining = map_len;
    let mut count = 0usize;
    let mut seen = [false; MAX_PCRS];
    let mut selected: [Option<Vec<u8>>; 3] = [None, None, None];
    while container_has_item(decoder, &mut remaining)? {
        count += 1;
        if count > MAX_PCRS {
            return Err(AttestationError::Format);
        }
        let index = decoder.u8().map_err(format_error)? as usize;
        if index >= MAX_PCRS || seen[index] {
            return Err(AttestationError::Format);
        }
        seen[index] = true;
        let value = read_bytes(decoder, 64)?;
        if !matches!(value.len(), 32 | 48 | 64) {
            return Err(AttestationError::Format);
        }
        if index < selected.len() {
            selected[index] = Some(value);
        }
    }
    if count == 0 {
        return Err(AttestationError::Format);
    }
    Ok(selected)
}

fn parse_cabundle(decoder: &mut Decoder<'_>) -> Result<Vec<Vec<u8>>, AttestationError> {
    let array_len = decoder.array().map_err(format_error)?;
    if array_len.is_some_and(|len| len == 0 || len > MAX_CA_BUNDLE as u64) {
        return Err(AttestationError::Format);
    }
    let mut remaining = array_len;
    let mut certificates = Vec::new();
    while container_has_item(decoder, &mut remaining)? {
        if certificates.len() == MAX_CA_BUNDLE {
            return Err(AttestationError::Format);
        }
        certificates.push(read_nonempty_bytes(decoder, MAX_CERT_LEN)?);
    }
    if certificates.is_empty() {
        return Err(AttestationError::Format);
    }
    Ok(certificates)
}

fn validate_certificate_chain(
    leaf_der: &[u8],
    cabundle: &[Vec<u8>],
    block_timestamp: u64,
    root_der: &[u8],
) -> Result<Vec<u8>, AttestationError> {
    if cabundle.first().map(Vec::as_slice) != Some(root_der) {
        return Err(AttestationError::Certificate);
    }
    let mut chain = Vec::new();
    for der in cabundle
        .iter()
        .map(Vec::as_slice)
        .chain(core::iter::once(leaf_der))
    {
        let certificate = Certificate::from_der(der).map_err(|_| AttestationError::Certificate)?;
        if certificate
            .to_der()
            .map_err(|_| AttestationError::Certificate)?
            != der
        {
            return Err(AttestationError::Certificate);
        }
        validate_certificate_profile(&certificate, block_timestamp)?;
        chain.push(certificate);
    }

    for (index, certificate) in chain.iter().enumerate() {
        let is_leaf = index + 1 == chain.len();
        validate_constraints(certificate, is_leaf, chain.len().saturating_sub(index + 2))?;
        if index > 0 {
            let parent = &chain[index - 1];
            if certificate
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|_| AttestationError::Certificate)?
                != parent
                    .tbs_certificate
                    .subject
                    .to_der()
                    .map_err(|_| AttestationError::Certificate)?
            {
                return Err(AttestationError::Certificate);
            }
            verify_certificate_signature(certificate, parent)?;
        }
    }
    public_key_bytes(chain.last().expect("cabundle is non-empty"))
}

fn validate_certificate_profile(
    certificate: &Certificate,
    block_timestamp: u64,
) -> Result<(), AttestationError> {
    if certificate.tbs_certificate.version != Version::V3
        || certificate.signature_algorithm.oid != ECDSA_SHA384_OID
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.tbs_certificate.signature.oid != ECDSA_SHA384_OID
        || certificate.tbs_certificate.signature.parameters.is_some()
        || certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            != EC_PUBLIC_KEY_OID
    {
        return Err(AttestationError::Certificate);
    }
    let curve = certificate
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
        .as_ref()
        .ok_or(AttestationError::Certificate)?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| AttestationError::Certificate)?;
    if curve != P384_OID {
        return Err(AttestationError::Certificate);
    }
    let validity = &certificate.tbs_certificate.validity;
    if validity.not_before.to_unix_duration().as_secs() > block_timestamp
        || validity.not_after.to_unix_duration().as_secs() < block_timestamp
    {
        return Err(AttestationError::Certificate);
    }
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    if extensions.iter().enumerate().any(|(index, extension)| {
        extensions[..index]
            .iter()
            .any(|previous| previous.extn_id == extension.extn_id)
    }) || extensions.iter().any(|extension| {
        extension.critical
            && extension.extn_id != BasicConstraints::OID
            && extension.extn_id != KeyUsage::OID
    }) {
        return Err(AttestationError::Certificate);
    }
    Ok(())
}

fn validate_constraints(
    certificate: &Certificate,
    is_leaf: bool,
    ca_below: usize,
) -> Result<(), AttestationError> {
    let basic = certificate
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| AttestationError::Certificate)?;
    let key_usage = certificate
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|_| AttestationError::Certificate)?
        .ok_or(AttestationError::Certificate)?;
    if is_leaf {
        if basic.is_some_and(|(_, value)| value.ca || value.path_len_constraint.is_some())
            || !key_usage.1.digital_signature()
        {
            return Err(AttestationError::Certificate);
        }
    } else {
        let (critical, basic) = basic.ok_or(AttestationError::Certificate)?;
        if !critical
            || !basic.ca
            || basic
                .path_len_constraint
                .is_some_and(|limit| ca_below > limit as usize)
            || !key_usage.1.key_cert_sign()
        {
            return Err(AttestationError::Certificate);
        }
    }
    Ok(())
}

fn verify_certificate_signature(
    certificate: &Certificate,
    parent: &Certificate,
) -> Result<(), AttestationError> {
    let key = public_key_bytes(parent)?;
    let message = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| AttestationError::Certificate)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(AttestationError::Certificate)?;
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key)
        .verify(&message, signature)
        .map_err(|_| AttestationError::Signature)
}

fn public_key_bytes(certificate: &Certificate) -> Result<Vec<u8>, AttestationError> {
    let key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(AttestationError::Certificate)?;
    if key.len() != 97 || key.first() != Some(&4) {
        return Err(AttestationError::Certificate);
    }
    Ok(key.to_vec())
}

fn verify_cose_signature(key: &[u8], cose: &CoseDocument) -> Result<(), AttestationError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).map_err(format_error)?;
    encoder.str("Signature1").map_err(format_error)?;
    encoder.bytes(&cose.protected).map_err(format_error)?;
    encoder.bytes(&[]).map_err(format_error)?;
    encoder.bytes(&cose.payload).map_err(format_error)?;
    let structure = encoder.into_writer();
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key)
        .verify(&structure, &cose.signature)
        .map_err(|_| AttestationError::Signature)
}

fn read_nonempty_bytes(
    decoder: &mut Decoder<'_>,
    max_len: usize,
) -> Result<Vec<u8>, AttestationError> {
    let bytes = read_bytes(decoder, max_len)?;
    if bytes.is_empty() {
        return Err(AttestationError::Format);
    }
    Ok(bytes)
}

fn read_bytes(decoder: &mut Decoder<'_>, max_len: usize) -> Result<Vec<u8>, AttestationError> {
    let mut output = Vec::new();
    for chunk in decoder.bytes_iter().map_err(format_error)? {
        let chunk = chunk.map_err(format_error)?;
        if output.len().saturating_add(chunk.len()) > max_len {
            return Err(AttestationError::Format);
        }
        output.extend_from_slice(chunk);
    }
    Ok(output)
}

fn read_text(decoder: &mut Decoder<'_>, max_len: usize) -> Result<String, AttestationError> {
    let mut output = String::new();
    for chunk in decoder.str_iter().map_err(format_error)? {
        let chunk = chunk.map_err(format_error)?;
        if output.len().saturating_add(chunk.len()) > max_len {
            return Err(AttestationError::Format);
        }
        output.push_str(chunk);
    }
    Ok(output)
}

fn container_has_item(
    decoder: &mut Decoder<'_>,
    remaining: &mut Option<u64>,
) -> Result<bool, AttestationError> {
    match remaining {
        Some(0) => Ok(false),
        Some(count) => {
            *count -= 1;
            Ok(true)
        }
        None if decoder.datatype().map_err(format_error)? == Type::Break => {
            decoder.skip().map_err(format_error)?;
            Ok(false)
        }
        None => Ok(true),
    }
}

fn skip_value(decoder: &mut Decoder<'_>, depth: usize) -> Result<(), AttestationError> {
    if depth > MAX_DEPTH {
        return Err(AttestationError::Format);
    }
    match decoder.datatype().map_err(format_error)? {
        Type::Array | Type::ArrayIndef => {
            let mut remaining = decoder.array().map_err(format_error)?;
            while container_has_item(decoder, &mut remaining)? {
                skip_value(decoder, depth + 1)?;
            }
        }
        Type::Map | Type::MapIndef => {
            let mut remaining = decoder.map().map_err(format_error)?;
            while container_has_item(decoder, &mut remaining)? {
                skip_value(decoder, depth + 1)?;
                skip_value(decoder, depth + 1)?;
            }
        }
        Type::Tag => {
            decoder.tag().map_err(format_error)?;
            skip_value(decoder, depth + 1)?;
        }
        Type::Break => return Err(AttestationError::Format),
        _ => decoder.skip().map_err(format_error)?,
    }
    Ok(())
}

fn format_error<E>(_error: E) -> AttestationError {
    AttestationError::Format
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use p384::ecdsa::{DerSignature, Signature, SigningKey, signature::Signer};
    use sha2::{Digest, Sha256};
    use std::{
        str::FromStr,
        time::{Duration, UNIX_EPOCH},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, Profile},
        name::Name,
        serial_number::SerialNumber,
        spki::SubjectPublicKeyInfoOwned,
        time::{Time, Validity},
    };

    pub(in crate::zone_verifier) const BLOCK_TIMESTAMP: u64 = 1_800_000_000;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 48]).unwrap()
    }

    fn validity() -> Validity {
        Validity {
            not_before: Time::try_from(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).unwrap(),
            not_after: Time::try_from(UNIX_EPOCH + Duration::from_secs(1_900_000_000)).unwrap(),
        }
    }

    fn build_certificate(
        profile: Profile,
        serial: u32,
        subject: Name,
        subject_key: &SigningKey,
        issuer_key: &SigningKey,
    ) -> Vec<u8> {
        let spki = SubjectPublicKeyInfoOwned::from_key(*subject_key.verifying_key()).unwrap();
        CertificateBuilder::new(
            profile,
            SerialNumber::from(serial),
            validity(),
            subject,
            spki,
            issuer_key,
        )
        .unwrap()
        .build::<DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
    }

    pub(in crate::zone_verifier) fn fixture(
        user_data: &[u8; 32],
    ) -> (Vec<u8>, Vec<u8>, [[u8; 48]; 3]) {
        fixture_at(user_data, BLOCK_TIMESTAMP * 1_000)
    }

    pub(in crate::zone_verifier) fn fixture_at(
        user_data: &[u8; 32],
        attestation_timestamp: u64,
    ) -> (Vec<u8>, Vec<u8>, [[u8; 48]; 3]) {
        let root_key = signing_key(1);
        let intermediate_key = signing_key(2);
        let leaf_key = signing_key(3);
        let root_name = Name::from_str("CN=Test Nitro Root,O=Tempo,C=US").unwrap();
        let intermediate_name = Name::from_str("CN=Test Nitro Intermediate,O=Tempo,C=US").unwrap();
        let leaf_name = Name::from_str("CN=Test Nitro Leaf,O=Tempo,C=US").unwrap();
        let root = build_certificate(Profile::Root, 1, root_name.clone(), &root_key, &root_key);
        let intermediate = build_certificate(
            Profile::SubCA {
                issuer: root_name,
                path_len_constraint: Some(0),
            },
            2,
            intermediate_name.clone(),
            &intermediate_key,
            &root_key,
        );
        let leaf = build_certificate(
            Profile::Leaf {
                issuer: intermediate_name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            3,
            leaf_name,
            &leaf_key,
            &intermediate_key,
        );
        let pcrs = [[0x10; 48], [0x11; 48], [0x12; 48]];

        let mut payload = Encoder::new(Vec::new());
        payload.map(7).unwrap();
        payload
            .str("module_id")
            .unwrap()
            .str("test-module")
            .unwrap();
        payload.str("digest").unwrap().str("SHA384").unwrap();
        payload
            .str("timestamp")
            .unwrap()
            .u64(attestation_timestamp)
            .unwrap();
        payload.str("pcrs").unwrap().map(3).unwrap();
        for (index, pcr) in pcrs.iter().enumerate() {
            payload.u8(index as u8).unwrap().bytes(pcr).unwrap();
        }
        payload.str("certificate").unwrap().bytes(&leaf).unwrap();
        payload.str("cabundle").unwrap().array(2).unwrap();
        payload.bytes(&root).unwrap().bytes(&intermediate).unwrap();
        payload.str("user_data").unwrap().bytes(user_data).unwrap();
        let payload = payload.into_writer();

        let mut protected = Encoder::new(Vec::new());
        protected.map(1).unwrap().i8(1).unwrap().i8(-35).unwrap();
        let protected = protected.into_writer();
        let mut structure = Encoder::new(Vec::new());
        structure.array(4).unwrap();
        structure.str("Signature1").unwrap();
        structure.bytes(&protected).unwrap();
        structure.bytes(&[]).unwrap();
        structure.bytes(&payload).unwrap();
        let signature: Signature = leaf_key.sign(&structure.into_writer());

        let mut cose = Encoder::new(Vec::new());
        cose.tag(minicbor::data::Tag::new(18)).unwrap();
        cose.array(4).unwrap();
        cose.bytes(&protected).unwrap();
        cose.map(0).unwrap();
        cose.bytes(&payload).unwrap();
        cose.bytes(signature.to_bytes().as_slice()).unwrap();
        (cose.into_writer(), root, pcrs)
    }

    #[test]
    fn pinned_root_is_stable_and_parses() {
        assert_eq!(AWS_NITRO_ROOT_DER.len(), 533);
        assert_eq!(
            Sha256::digest(AWS_NITRO_ROOT_DER).as_slice(),
            alloy::primitives::hex!(
                "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
            )
        );
        let root = Certificate::from_der(AWS_NITRO_ROOT_DER).unwrap();
        assert_eq!(root.tbs_certificate.issuer, root.tbs_certificate.subject);
        validate_certificate_profile(&root, BLOCK_TIMESTAMP).unwrap();
        validate_constraints(&root, false, 0).unwrap();
    }

    #[test]
    fn verifies_complete_synthetic_attestation() {
        let user_data = [0x44; 32];
        let (document, root, pcrs) = fixture(&user_data);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let verified = verify_attestation_with_root(
                &mut StorageCtx::default(),
                &document,
                BLOCK_TIMESTAMP,
                &root,
            )
            .unwrap();
            assert_eq!(verified.timestamp, BLOCK_TIMESTAMP * 1_000);
            assert_eq!(verified.user_data, user_data);
            for (index, pcr) in pcrs.iter().enumerate() {
                assert_eq!(verified.pcrs[index].as_deref(), Some(pcr.as_slice()));
            }
        });
    }

    #[test]
    fn accepts_untagged_and_indefinite_outer_cose() {
        let (tagged, root, _) = fixture(&[0x44; 32]);
        assert_eq!(tagged[0], 0xd2);
        let untagged = tagged[1..].to_vec();
        let mut indefinite = untagged.clone();
        assert_eq!(indefinite[0], 0x84);
        indefinite[0] = 0x9f;
        indefinite.push(0xff);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            for document in [&untagged, &indefinite] {
                verify_attestation_with_root(
                    &mut StorageCtx::default(),
                    document,
                    BLOCK_TIMESTAMP,
                    &root,
                )
                .unwrap();
            }
        });
    }

    #[test]
    fn certificate_validity_boundaries_are_inclusive() {
        let (document, root, _) = fixture(&[0x44; 32]);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            for timestamp in [1_700_000_000, 1_900_000_000] {
                verify_attestation_with_root(
                    &mut StorageCtx::default(),
                    &document,
                    timestamp,
                    &root,
                )
                .unwrap();
            }
            for timestamp in [1_699_999_999, 1_900_000_001] {
                assert!(matches!(
                    verify_attestation_with_root(
                        &mut StorageCtx::default(),
                        &document,
                        timestamp,
                        &root,
                    ),
                    Err(AttestationError::Certificate)
                ));
            }
        });
    }

    #[test]
    fn rejects_corrupted_document_signature() {
        let (mut document, root, _) = fixture(&[0x44; 32]);
        *document.last_mut().unwrap() ^= 1;
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            assert!(matches!(
                verify_attestation_with_root(
                    &mut StorageCtx::default(),
                    &document,
                    BLOCK_TIMESTAMP,
                    &root,
                ),
                Err(AttestationError::Signature)
            ));
        });
    }

    #[test]
    fn parser_rejects_wrong_tag_and_trailing_bytes() {
        assert!(matches!(
            parse_cose(&[0xd3, 0x80]),
            Err(AttestationError::Format)
        ));
        assert!(matches!(
            parse_cose(&[0x84, 0x41, 0xa0, 0xa0, 0x41, 0xa0, 0x58, 0x60]),
            Err(AttestationError::Format)
        ));
    }

    #[test]
    fn skip_enforces_depth_limit() {
        let nested = [0x81; MAX_DEPTH + 1];
        let mut decoder = Decoder::new(&nested);
        assert_eq!(skip_value(&mut decoder, 1), Err(AttestationError::Format));
    }
}
