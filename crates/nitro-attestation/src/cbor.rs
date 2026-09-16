use crate::{
    FormatError, MAX_CA_BUNDLE, MAX_CBOR_DEPTH, MAX_DOCUMENT_SIZE, MAX_PAYLOAD_SIZE, MAX_PCRS,
    P384_FIXED_SIGNATURE_SIZE, ParsedAttestation, Pcr,
};
use alloc::{string::String, vec::Vec};
use ciborium::Value;
use serde::{
    Deserialize, Deserializer,
    de::{DeserializeOwned, Error as _},
};
use serde_bytes::ByteBuf;

type Result<T> = core::result::Result<T, crate::Error>;

/// Typed Nitro payload. Serde rejects missing and duplicate recognized fields.
#[derive(Deserialize)]
struct AttestationDocument {
    #[serde(deserialize_with = "strict")]
    module_id: String,
    #[serde(deserialize_with = "strict")]
    digest: String,
    #[serde(deserialize_with = "strict")]
    timestamp: u64,
    #[serde(deserialize_with = "pcr_entries")]
    pcrs: Vec<(u64, ByteBuf)>,
    #[serde(deserialize_with = "strict")]
    certificate: ByteBuf,
    #[serde(deserialize_with = "strict")]
    cabundle: Vec<ByteBuf>,
    #[serde(default, deserialize_with = "strict")]
    public_key: Option<ByteBuf>,
    #[serde(default, deserialize_with = "strict")]
    user_data: Option<ByteBuf>,
    #[serde(default, deserialize_with = "strict")]
    nonce: Option<ByteBuf>,
}

// Ciborium's typed deserializer transparently unwraps tags. Known Nitro fields
// must instead have their specified types; unknown fields remain unrestricted.
fn strict<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> core::result::Result<T, D::Error> {
    let value = Value::deserialize(d)?;
    fn untagged(value: &Value) -> bool {
        match value {
            Value::Tag(..) => false,
            Value::Array(values) => values.iter().all(untagged),
            Value::Map(entries) => entries.iter().all(|(k, v)| untagged(k) && untagged(v)),
            _ => true,
        }
    }
    if !untagged(&value) {
        return Err(D::Error::custom("tagged Nitro field"));
    }
    value.deserialized().map_err(D::Error::custom)
}

// Preserve entries until validation: a BTreeMap would discard duplicate indices.
fn pcr_entries<'de, D: Deserializer<'de>>(
    d: D,
) -> core::result::Result<Vec<(u64, ByteBuf)>, D::Error> {
    let Value::Map(entries) = Value::deserialize(d)? else {
        return Err(D::Error::custom("expected PCR map"));
    };
    entries
        .iter()
        .map(|(k, v)| {
            if !matches!((k, v), (Value::Integer(_), Value::Bytes(_))) {
                return Err(D::Error::custom("invalid PCR entry"));
            }
            Ok((
                k.deserialized().map_err(D::Error::custom)?,
                v.deserialized().map_err(D::Error::custom)?,
            ))
        })
        .collect()
}

/// Ciborium owns all CBOR decoding, including indefinite strings and nesting limits.
/// Keep maps as entry lists: collecting them into a map would silently erase duplicate keys.
fn decode(mut input: &[u8]) -> Result<Value> {
    let value = ciborium::de::from_reader_with_recursion_limit(&mut input, MAX_CBOR_DEPTH)
        .map_err(|error| match error {
            ciborium::de::Error::RecursionLimitExceeded => FormatError::NestingTooDeep,
            _ => FormatError::InvalidCbor,
        })?;
    if !input.is_empty() {
        return Err(FormatError::InvalidCbor.into());
    }
    Ok(value)
}

pub(crate) fn parse_attestation(document: &[u8]) -> Result<ParsedAttestation> {
    if document.len() > MAX_DOCUMENT_SIZE {
        return Err(FormatError::DocumentTooLarge.into());
    }
    let envelope = match decode(document)? {
        Value::Tag(18, value) => *value,
        Value::Tag(..) => return Err(FormatError::InvalidCoseTag.into()),
        value => value,
    };
    let Value::Array(envelope) = envelope else {
        return Err(FormatError::InvalidCoseStructure.into());
    };
    let [protected, unprotected, payload, signature]: [Value; 4] = envelope
        .try_into()
        .map_err(|_| FormatError::InvalidCoseStructure)?;
    if !matches!(unprotected, Value::Map(_)) {
        return Err(FormatError::InvalidCoseStructure.into());
    }
    let protected = bytes(protected, 1, MAX_DOCUMENT_SIZE, "protected header")?;
    let header = decode(&protected).map_err(|_| FormatError::InvalidProtectedHeader)?;
    if header != Value::Map(alloc::vec![(Value::from(1), Value::from(-35))]) {
        return Err(FormatError::InvalidProtectedHeader.into());
    }
    let payload = bytes(payload, 1, MAX_PAYLOAD_SIZE, "payload")?;
    let signature = bytes(
        signature,
        P384_FIXED_SIGNATURE_SIZE,
        P384_FIXED_SIGNATURE_SIZE,
        "signature",
    )?
    .try_into()
    .map_err(|_| FormatError::InvalidSignatureEncoding)?;
    let Value::Map(mut fields) = decode(&payload)? else {
        return Err(FormatError::InvalidPayload.into());
    };

    // Non-text keys are unknown extensions, not Serde's numeric field identifiers.
    fields.retain(|(key, _)| key.as_text().is_some());
    let attestation: AttestationDocument = Value::Map(fields)
        .deserialized()
        .map_err(|_| FormatError::InvalidPayload)?;
    if attestation.module_id.is_empty() {
        return Err(FormatError::InvalidField("module_id").into());
    }
    if attestation.digest != "SHA384" {
        return Err(FormatError::InvalidField("digest").into());
    }
    if attestation.timestamp == 0 {
        return Err(FormatError::InvalidField("timestamp").into());
    }
    if attestation.cabundle.is_empty() || attestation.cabundle.len() > MAX_CA_BUNDLE {
        return Err(FormatError::TooManyCertificates.into());
    }
    Ok(ParsedAttestation {
        module_id: attestation.module_id,
        timestamp: attestation.timestamp,
        pcrs: pcrs(attestation.pcrs)?,
        certificate: bounded(attestation.certificate, 1, 1_024, "certificate")?,
        cabundle: attestation
            .cabundle
            .into_iter()
            .map(|cert| bounded(cert, 1, 1_024, "cabundle"))
            .collect::<Result<_>>()?,
        public_key: optional_bytes(attestation.public_key, 1, 1_024, "public_key")?,
        user_data: optional_bytes(attestation.user_data, 0, 512, "user_data")?,
        nonce: optional_bytes(attestation.nonce, 0, 512, "nonce")?,
        protected,
        payload,
        signature,
    })
}

fn bytes(value: Value, min: usize, max: usize, name: &'static str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(value) if (min..=max).contains(&value.len()) => Ok(value),
        _ => Err(FormatError::InvalidField(name).into()),
    }
}

fn bounded(value: ByteBuf, min: usize, max: usize, name: &'static str) -> Result<Vec<u8>> {
    if !(min..=max).contains(&value.len()) {
        return Err(FormatError::InvalidField(name).into());
    }
    Ok(value.into_vec())
}

fn optional_bytes(
    value: Option<ByteBuf>,
    min: usize,
    max: usize,
    name: &'static str,
) -> Result<Vec<u8>> {
    value
        .map(|value| bounded(value, min, max, name))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn pcrs(entries: Vec<(u64, ByteBuf)>) -> Result<Vec<Pcr>> {
    if entries.is_empty() || entries.len() > MAX_PCRS {
        return Err(FormatError::TooManyPcrs.into());
    }
    let mut seen = [false; MAX_PCRS];
    let mut pcrs = Vec::with_capacity(entries.len());
    for (index, value) in entries {
        if index >= MAX_PCRS as u64 {
            return Err(FormatError::InvalidField("pcrs").into());
        }
        if core::mem::replace(&mut seen[index as usize], true) {
            return Err(FormatError::DuplicatePcr(index as u8).into());
        }
        if !matches!(value.len(), 32 | 48 | 64) {
            return Err(FormatError::InvalidField("pcrs").into());
        }
        pcrs.push(Pcr {
            index: index as u8,
            value: value.into_vec(),
        });
    }
    pcrs.sort_unstable_by_key(|pcr| pcr.index);
    Ok(pcrs)
}

pub(crate) fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    let structure = (
        "Signature1",
        serde_bytes::Bytes::new(protected),
        serde_bytes::Bytes::new(&[]),
        serde_bytes::Bytes::new(payload),
    );
    ciborium::into_writer(&structure, &mut encoded).map_err(|_| FormatError::InvalidCbor)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests;
