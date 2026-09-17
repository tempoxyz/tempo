use crate::{
    FormatError, MAX_CA_BUNDLE, MAX_CBOR_DEPTH, MAX_DOCUMENT_SIZE, MAX_PAYLOAD_SIZE, MAX_PCRS,
    P384_FIXED_SIGNATURE_SIZE, ParsedAttestation, Pcr,
};
use alloc::{string::String, vec::Vec};
use ciborium::Value;
use serde::Deserialize;

type Result<T> = core::result::Result<T, crate::Error>;

/// Typed Nitro payload. Serde rejects missing and duplicate recognized fields.
#[derive(Deserialize)]
struct AttestationDocument {
    #[serde(deserialize_with = "deser::module_id")]
    module_id: String,
    #[serde(rename = "digest", deserialize_with = "deser::digest")]
    _digest: String,
    #[serde(deserialize_with = "deser::timestamp")]
    timestamp: u64,
    #[serde(deserialize_with = "deser::pcrs")]
    pcrs: Vec<Pcr>,
    #[serde(deserialize_with = "deser::certificate")]
    certificate: Vec<u8>,
    #[serde(deserialize_with = "deser::cabundle")]
    cabundle: Vec<Vec<u8>>,
    #[serde(default, deserialize_with = "deser::public_key")]
    public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deser::user_data")]
    user_data: Vec<u8>,
    #[serde(default, deserialize_with = "deser::nonce")]
    nonce: Vec<u8>,
}

/// Parses a tagged or untagged COSE_Sign1 Nitro attestation and validates its structure,
/// size limits, protected algorithm header, and payload fields. Preserves the exact
/// protected header and payload bytes for signature verification; does not verify
/// the signature or certificate chain.
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
    .map_err(|_| FormatError::InvalidField("signature"))?;
    let Value::Map(mut fields) = decode(&payload)? else {
        return Err(FormatError::InvalidPayload.into());
    };

    // Non-text keys are unknown extensions, not Serde's numeric field identifiers.
    fields.retain(|(key, _)| key.as_text().is_some());
    let attestation: AttestationDocument = Value::Map(fields)
        .deserialized()
        .map_err(|_| FormatError::InvalidPayload)?;
    Ok(ParsedAttestation {
        module_id: attestation.module_id,
        timestamp: attestation.timestamp,
        pcrs: attestation.pcrs,
        certificate: attestation.certificate,
        cabundle: attestation.cabundle,
        public_key: attestation.public_key,
        user_data: attestation.user_data,
        nonce: attestation.nonce,
        protected,
        payload,
        signature,
    })
}

/// Encodes the COSE Sig_structure used for signature verification:
/// `["Signature1", protected, external_aad, payload]`, with empty external AAD.
/// The protected header and payload are embedded as their original byte strings.
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

/// Extracts an untagged CBOR byte string whose length is within `min..=max`.
/// Wrong types and out-of-range lengths are reported as an invalid named field.
fn bytes(value: Value, min: usize, max: usize, name: &'static str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(value) if (min..=max).contains(&value.len()) => Ok(value),
        _ => Err(FormatError::InvalidField(name).into()),
    }
}

mod deser {
    use super::*;
    use serde::{
        Deserializer,
        de::{DeserializeOwned, Error as _},
    };
    use serde_bytes::ByteBuf;

    pub(super) fn module_id<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<String, D::Error> {
        let value: String = strict(d)?;
        if value.is_empty() {
            return Err(D::Error::custom("empty module ID"));
        }
        Ok(value)
    }

    pub(super) fn digest<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<String, D::Error> {
        let value: String = strict(d)?;
        if value != "SHA384" {
            return Err(D::Error::custom("expected SHA384 digest"));
        }
        Ok(value)
    }

    pub(super) fn timestamp<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<u64, D::Error> {
        let value: u64 = strict(d)?;
        if value == 0 {
            return Err(D::Error::custom("zero timestamp"));
        }
        Ok(value)
    }

    // Preserve entries until validation: a BTreeMap would discard duplicate indices.
    pub(super) fn pcrs<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<Pcr>, D::Error> {
        let Value::Map(entries) = Value::deserialize(d)? else {
            return Err(D::Error::custom("expected PCR map"));
        };
        if entries.is_empty() || entries.len() > MAX_PCRS {
            return Err(D::Error::custom("invalid PCR count"));
        }
        let mut seen = [false; MAX_PCRS];
        let mut pcrs = Vec::with_capacity(entries.len());
        for (index, value) in entries {
            let (Value::Integer(index), Value::Bytes(value)) = (index, value) else {
                return Err(D::Error::custom("invalid PCR entry"));
            };
            let index = u64::try_from(index).map_err(D::Error::custom)?;
            if index >= MAX_PCRS as u64 {
                return Err(D::Error::custom("invalid PCR index"));
            }
            if core::mem::replace(&mut seen[index as usize], true) {
                return Err(D::Error::custom("duplicate PCR index"));
            }
            if !matches!(value.len(), 32 | 48 | 64) {
                return Err(D::Error::custom("invalid PCR value length"));
            }
            pcrs.push(Pcr {
                index: index as u8,
                value,
            });
        }
        pcrs.sort_unstable_by_key(|pcr| pcr.index);
        Ok(pcrs)
    }

    pub(super) fn certificate<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        bounded_bytes::<D, 1, 1024>(d)
    }

    pub(super) fn cabundle<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<Vec<u8>>, D::Error> {
        let values: Vec<ByteBuf> = strict(d)?;
        if values.is_empty() || values.len() > MAX_CA_BUNDLE {
            return Err(D::Error::custom("invalid CA bundle count"));
        }
        values
            .into_iter()
            .map(|value| {
                if !(1..=1024).contains(&value.len()) {
                    return Err(D::Error::custom("invalid CA certificate length"));
                }
                Ok(value.into_vec())
            })
            .collect()
    }

    pub(super) fn public_key<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        optional_bytes::<D, 1, 1024>(d)
    }

    pub(super) fn user_data<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        optional_bytes::<D, 0, 512>(d)
    }

    pub(super) fn nonce<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        optional_bytes::<D, 0, 512>(d)
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

    fn bounded_bytes<'de, D: Deserializer<'de>, const MIN: usize, const MAX: usize>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        let value: ByteBuf = strict(d)?;
        if !(MIN..=MAX).contains(&value.len()) {
            return Err(D::Error::custom("invalid byte string length"));
        }
        Ok(value.into_vec())
    }

    fn optional_bytes<'de, D: Deserializer<'de>, const MIN: usize, const MAX: usize>(
        d: D,
    ) -> core::result::Result<Vec<u8>, D::Error> {
        let value: Option<ByteBuf> = strict(d)?;
        match value {
            Some(value) if (MIN..=MAX).contains(&value.len()) => Ok(value.into_vec()),
            Some(_) => Err(D::Error::custom("invalid optional byte string length")),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use minicbor::{Decoder, Encoder, data::Tag};

    fn payload(indefinite: bool, duplicate_module: bool, include_null_optionals: bool) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        if indefinite {
            e.begin_map().unwrap();
        } else {
            e.map(6 + u64::from(duplicate_module) + 3 * u64::from(include_null_optionals))
                .unwrap();
        }
        e.str("module_id").unwrap().str("module").unwrap();
        if duplicate_module {
            e.str("module_id").unwrap().str("again").unwrap();
        }
        e.str("digest").unwrap().str("SHA384").unwrap();
        e.str("timestamp").unwrap().u64(1).unwrap();
        e.str("pcrs").unwrap();
        if indefinite {
            e.begin_map().unwrap();
        } else {
            e.map(2).unwrap();
        }
        e.u8(7).unwrap().bytes(&[7; 48]).unwrap();
        e.u8(0).unwrap().bytes(&[0; 48]).unwrap();
        if indefinite {
            e.end().unwrap();
        }
        e.str("certificate").unwrap().bytes(&[0x30]).unwrap();
        e.str("cabundle").unwrap();
        if indefinite {
            e.begin_array()
                .unwrap()
                .bytes(&[0x30])
                .unwrap()
                .end()
                .unwrap();
        } else {
            e.array(1).unwrap().bytes(&[0x30]).unwrap();
        }
        if include_null_optionals {
            e.str("public_key").unwrap().null().unwrap();
            e.str("user_data").unwrap().null().unwrap();
            e.str("nonce").unwrap().null().unwrap();
        }
        if indefinite {
            e.end().unwrap();
        }
        e.into_writer()
    }

    fn document(tagged: bool, indefinite: bool, duplicate_module: bool) -> Vec<u8> {
        wrap_payload(
            tagged,
            indefinite,
            &payload(indefinite, duplicate_module, false),
        )
    }

    fn wrap_payload(tagged: bool, indefinite: bool, payload: &[u8]) -> Vec<u8> {
        let protected = {
            let mut e = Encoder::new(Vec::new());
            e.map(1).unwrap().u8(1).unwrap().i8(-35).unwrap();
            e.into_writer()
        };
        let mut e = Encoder::new(Vec::new());
        if tagged {
            e.tag(Tag::new(18)).unwrap();
        }
        if indefinite {
            e.begin_array().unwrap();
        } else {
            e.array(4).unwrap();
        }
        e.bytes(&protected)
            .unwrap()
            .map(0)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&[0; P384_FIXED_SIGNATURE_SIZE])
            .unwrap();
        if indefinite {
            e.end().unwrap();
        }
        e.into_writer()
    }

    #[derive(Clone)]
    struct TestField {
        name: &'static str,
        value: Vec<u8>,
    }

    fn encoded_value(encode: impl FnOnce(&mut Encoder<Vec<u8>>)) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode(&mut encoder);
        encoder.into_writer()
    }

    fn text_value(value: &str) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.str(value).unwrap();
        })
    }

    fn bytes_value(value: &[u8]) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.bytes(value).unwrap();
        })
    }

    fn unsigned_value(value: u64) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.u64(value).unwrap();
        })
    }

    fn null_value() -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.null().unwrap();
        })
    }

    fn bool_value(value: bool) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.bool(value).unwrap();
        })
    }

    fn pcrs_value(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.map(entries.len() as u64).unwrap();
            for (index, value) in entries {
                encoder.u8(*index).unwrap().bytes(value).unwrap();
            }
        })
    }

    fn cabundle_value(certificates: &[Vec<u8>]) -> Vec<u8> {
        encoded_value(|encoder| {
            encoder.array(certificates.len() as u64).unwrap();
            for certificate in certificates {
                encoder.bytes(certificate).unwrap();
            }
        })
    }

    fn default_fields() -> Vec<TestField> {
        vec![
            TestField {
                name: "module_id",
                value: text_value("module"),
            },
            TestField {
                name: "digest",
                value: text_value("SHA384"),
            },
            TestField {
                name: "timestamp",
                value: unsigned_value(1),
            },
            TestField {
                name: "pcrs",
                value: pcrs_value(&[(0, vec![0; 48])]),
            },
            TestField {
                name: "certificate",
                value: bytes_value(&[0x30]),
            },
            TestField {
                name: "cabundle",
                value: cabundle_value(&[vec![0x30]]),
            },
        ]
    }

    fn set_field(fields: &mut [TestField], name: &str, value: Vec<u8>) {
        fields
            .iter_mut()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("missing test field {name}"))
            .value = value;
    }

    fn encode_payload(fields: &[TestField]) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(fields.len() as u64).unwrap();
        let mut output = encoder.into_writer();
        for field in fields {
            let mut key = Encoder::new(Vec::new());
            key.str(field.name).unwrap();
            output.extend_from_slice(&key.into_writer());
            output.extend_from_slice(&field.value);
        }
        output
    }

    fn parse_fields(fields: &[TestField]) -> Result<ParsedAttestation> {
        parse_attestation(&wrap_payload(false, false, &encode_payload(fields)))
    }

    fn assert_field_error(fields: &[TestField], expected: FormatError) {
        assert_eq!(
            parse_fields(fields).unwrap_err(),
            crate::Error::InvalidFormat(expected)
        );
    }

    fn payload_with_exact_len(target: usize) -> Vec<u8> {
        let mut fields = default_fields();
        fields.push(TestField {
            name: "padding",
            value: bytes_value(&[]),
        });
        let base_len = encode_payload(&fields).len();
        let mut padding_len = target.checked_sub(base_len).expect("target fits payload");

        for _ in 0..4 {
            set_field(&mut fields, "padding", bytes_value(&vec![0; padding_len]));
            let payload = encode_payload(&fields);
            match payload.len().cmp(&target) {
                core::cmp::Ordering::Equal => return payload,
                core::cmp::Ordering::Less => padding_len += target - payload.len(),
                core::cmp::Ordering::Greater => padding_len -= payload.len() - target,
            }
        }
        panic!("failed to construct an exact-length payload")
    }

    fn wrap_payload_with_unprotected_padding(payload: &[u8], padding_len: usize) -> Vec<u8> {
        let protected = {
            let mut encoder = Encoder::new(Vec::new());
            encoder.map(1).unwrap().u8(1).unwrap().i8(-35).unwrap();
            encoder.into_writer()
        };
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(4)
            .unwrap()
            .bytes(&protected)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(0)
            .unwrap()
            .bytes(&vec![0; padding_len])
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&[0; P384_FIXED_SIGNATURE_SIZE])
            .unwrap();
        encoder.into_writer()
    }

    fn document_with_exact_len(target: usize) -> Vec<u8> {
        let payload = encode_payload(&default_fields());
        let base_len = wrap_payload_with_unprotected_padding(&payload, 0).len();
        let mut padding_len = target.checked_sub(base_len).expect("target fits document");

        for _ in 0..4 {
            let document = wrap_payload_with_unprotected_padding(&payload, padding_len);
            match document.len().cmp(&target) {
                core::cmp::Ordering::Equal => return document,
                core::cmp::Ordering::Less => padding_len += target - document.len(),
                core::cmp::Ordering::Greater => padding_len -= document.len() - target,
            }
        }
        panic!("failed to construct an exact-length document")
    }

    #[test]
    fn parses_tagged_and_untagged_documents() {
        for tagged in [false, true] {
            let parsed = parse_attestation(&document(tagged, false, false)).unwrap();
            assert_eq!(parsed.module_id, "module");
            assert_eq!(parsed.timestamp, 1);
            assert_eq!(parsed.pcrs[0].index, 0);
            assert_eq!(parsed.pcrs[1].index, 7);
            assert_eq!(parsed.signature_count(), 2);
        }
    }

    #[test]
    fn parses_indefinite_collections() {
        let parsed = parse_attestation(&document(true, true, false)).unwrap();
        assert_eq!(parsed.pcrs.len(), 2);
        assert_eq!(parsed.cabundle, vec![vec![0x30]]);
    }

    #[test]
    fn accepts_null_optional_fields_as_empty() {
        let payload = payload(false, false, true);
        let parsed = parse_attestation(&wrap_payload(false, false, &payload)).unwrap();
        assert!(parsed.public_key.is_empty());
        assert!(parsed.user_data.is_empty());
        assert!(parsed.nonce.is_empty());
    }

    #[test]
    fn rejects_duplicate_null_optional_fields() {
        for name in ["public_key", "user_data", "nonce"] {
            let mut fields = default_fields();
            for _ in 0..2 {
                fields.push(TestField {
                    name,
                    value: null_value(),
                });
            }
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
    }

    #[test]
    fn rejects_tagged_fields_and_arrays_in_byte_fields() {
        for field in default_fields() {
            let mut fields = default_fields();
            let mut tagged = encoded_value(|e| {
                e.tag(Tag::new(100)).unwrap();
            });
            tagged.extend_from_slice(&field.value);
            set_field(&mut fields, field.name, tagged);
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
        for name in ["public_key", "user_data", "nonce"] {
            for value in [
                vec![0x81, 0x01],         // an integer array is not a byte string
                vec![0xd8, 100, 0x41, 1], // a tag is not a byte string
            ] {
                let mut fields = default_fields();
                fields.push(TestField { name, value });
                assert_field_error(&fields, FormatError::InvalidPayload);
            }
        }
    }

    #[test]
    fn rejects_tagged_collection_entries() {
        for tag_key in [false, true] {
            let mut fields = default_fields();
            set_field(
                &mut fields,
                "pcrs",
                encoded_value(|e| {
                    e.map(1).unwrap();
                    if tag_key {
                        e.tag(Tag::new(100)).unwrap();
                    }
                    e.u8(0).unwrap();
                    if !tag_key {
                        e.tag(Tag::new(100)).unwrap();
                    }
                    e.bytes(&[0; 48]).unwrap();
                }),
            );
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
        let mut fields = default_fields();
        set_field(
            &mut fields,
            "cabundle",
            encoded_value(|e| {
                e.array(1)
                    .unwrap()
                    .tag(Tag::new(100))
                    .unwrap()
                    .bytes(&[1])
                    .unwrap();
            }),
        );
        assert_field_error(&fields, FormatError::InvalidPayload);
    }

    #[test]
    fn non_text_keys_cannot_supply_required_fields() {
        let mut fields = default_fields();
        fields.retain(|field| field.name != "module_id");
        for key in [unsigned_value(0), bytes_value(b"module_id")] {
            let mut payload = encode_payload(&fields);
            payload[0] = 0xa6;
            payload.extend(key);
            payload.extend(text_value("module"));
            assert_eq!(
                parse_attestation(&wrap_payload(false, false, &payload)).unwrap_err(),
                crate::Error::InvalidFormat(FormatError::InvalidPayload)
            );
        }
    }

    #[test]
    fn preserves_chunked_strings_and_exact_signed_payload() {
        let mut fields = default_fields();
        set_field(
            &mut fields,
            "module_id",
            encoded_value(|e| {
                e.begin_str()
                    .unwrap()
                    .str("mod")
                    .unwrap()
                    .str("ule")
                    .unwrap()
                    .end()
                    .unwrap();
            }),
        );
        set_field(
            &mut fields,
            "certificate",
            encoded_value(|e| {
                e.begin_bytes()
                    .unwrap()
                    .bytes(&[0x30])
                    .unwrap()
                    .bytes(&[1])
                    .unwrap()
                    .end()
                    .unwrap();
            }),
        );
        let payload = encode_payload(&fields);
        let parsed = parse_attestation(&wrap_payload(true, true, &payload)).unwrap();
        assert_eq!(parsed.module_id, "module");
        assert_eq!(parsed.certificate, [0x30, 1]);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn uses_ciboriums_data_model_for_unknown_values() {
        for (value, accepted) in [
            (vec![0xf0], false),      // unassigned simple value
            (vec![0xc2, 0xf6], true), // non-byte tag content remains opaque
        ] {
            let mut fields = default_fields();
            fields.push(TestField {
                name: "future_field",
                value,
            });
            assert_eq!(parse_fields(&fields).is_ok(), accepted);
        }
    }

    #[test]
    fn accepts_ciborium_null_and_integer_normalization() {
        let mut fields = default_fields();
        // Ciborium maps undefined to null and tag-2 bignums to integers when they fit.
        for name in ["public_key", "user_data", "nonce"] {
            fields.push(TestField {
                name,
                value: vec![0xf7],
            });
        }
        set_field(&mut fields, "timestamp", vec![0xc2, 0x41, 1]);
        let parsed = parse_fields(&fields).unwrap();
        assert_eq!(parsed.timestamp, 1);
        assert!(
            parsed.public_key.is_empty() && parsed.user_data.is_empty() && parsed.nonce.is_empty()
        );
    }

    #[test]
    fn rejects_missing_mandatory_fields() {
        for name in [
            "module_id",
            "digest",
            "timestamp",
            "pcrs",
            "certificate",
            "cabundle",
        ] {
            let mut fields = default_fields();
            fields.retain(|field| field.name != name);
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
    }

    #[test]
    fn rejects_duplicate_recognized_fields_matrix() {
        for name in [
            "module_id",
            "digest",
            "timestamp",
            "pcrs",
            "certificate",
            "cabundle",
        ] {
            let mut fields = default_fields();
            let duplicate = fields
                .iter()
                .find(|field| field.name == name)
                .unwrap()
                .clone();
            fields.push(duplicate);
            assert_field_error(&fields, FormatError::InvalidPayload);
        }

        for name in ["public_key", "user_data", "nonce"] {
            let mut fields = default_fields();
            fields.push(TestField {
                name,
                value: bytes_value(&[1]),
            });
            fields.push(TestField {
                name,
                value: null_value(),
            });
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
    }

    #[test]
    fn rejects_wrong_types_for_all_fields() {
        for name in [
            "module_id",
            "digest",
            "timestamp",
            "pcrs",
            "certificate",
            "cabundle",
        ] {
            let mut fields = default_fields();
            set_field(&mut fields, name, null_value());
            assert_field_error(&fields, FormatError::InvalidPayload);
        }

        for name in ["public_key", "user_data", "nonce"] {
            let mut fields = default_fields();
            fields.push(TestField {
                name,
                value: bool_value(false),
            });
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
    }

    #[test]
    fn enforces_scalar_and_byte_string_bounds() {
        let mut fields = default_fields();
        set_field(&mut fields, "module_id", text_value(""));
        assert_field_error(&fields, FormatError::InvalidPayload);

        let mut fields = default_fields();
        set_field(&mut fields, "digest", text_value("SHA256"));
        assert_field_error(&fields, FormatError::InvalidPayload);

        let mut fields = default_fields();
        set_field(&mut fields, "timestamp", unsigned_value(0));
        assert_field_error(&fields, FormatError::InvalidPayload);

        for (name, min, max) in [
            ("certificate", 1, 1_024),
            ("public_key", 1, 1_024),
            ("user_data", 0, 512),
            ("nonce", 0, 512),
        ] {
            if min > 0 {
                let mut fields = default_fields();
                if matches!(name, "public_key" | "user_data" | "nonce") {
                    fields.push(TestField {
                        name,
                        value: bytes_value(&[]),
                    });
                } else {
                    set_field(&mut fields, name, bytes_value(&[]));
                }
                assert_field_error(&fields, FormatError::InvalidPayload);
            }

            let mut fields = default_fields();
            let oversized = bytes_value(&vec![0; max + 1]);
            if matches!(name, "public_key" | "user_data" | "nonce") {
                fields.push(TestField {
                    name,
                    value: oversized,
                });
            } else {
                set_field(&mut fields, name, oversized);
            }
            assert_field_error(&fields, FormatError::InvalidPayload);
        }

        let mut fields = default_fields();
        fields.push(TestField {
            name: "public_key",
            value: bytes_value(&[1]),
        });
        fields.push(TestField {
            name: "user_data",
            value: bytes_value(&[]),
        });
        fields.push(TestField {
            name: "nonce",
            value: bytes_value(&[]),
        });
        let parsed = parse_fields(&fields).unwrap();
        assert_eq!(parsed.public_key, vec![1]);
        assert!(parsed.user_data.is_empty());
        assert!(parsed.nonce.is_empty());
    }

    #[test]
    fn accepts_exact_field_maxima_and_policy_neutral_values() {
        let module_id = "\0arbitrary module 🦀";
        let pcr_value = vec![0xff; 64];
        let certificate = vec![0xa5; 1_024];
        let ca_certificate = vec![0x5a; 1_024];
        let public_key = vec![0x11; 1_024];
        let user_data = vec![0x22; 512];
        let nonce = vec![0x33; 512];
        let mut fields = default_fields();
        set_field(&mut fields, "module_id", text_value(module_id));
        set_field(&mut fields, "timestamp", unsigned_value(u64::MAX));
        set_field(&mut fields, "pcrs", pcrs_value(&[(31, pcr_value.clone())]));
        set_field(&mut fields, "certificate", bytes_value(&certificate));
        set_field(
            &mut fields,
            "cabundle",
            cabundle_value(core::slice::from_ref(&ca_certificate)),
        );
        fields.push(TestField {
            name: "public_key",
            value: bytes_value(&public_key),
        });
        fields.push(TestField {
            name: "user_data",
            value: bytes_value(&user_data),
        });
        fields.push(TestField {
            name: "nonce",
            value: bytes_value(&nonce),
        });

        let parsed = parse_fields(&fields).unwrap();
        assert_eq!(parsed.module_id, module_id);
        assert_eq!(parsed.timestamp, u64::MAX);
        assert_eq!(
            parsed.pcrs,
            vec![Pcr {
                index: 31,
                value: pcr_value
            }]
        );
        assert_eq!(parsed.certificate, certificate);
        assert_eq!(parsed.cabundle, vec![ca_certificate]);
        assert_eq!(parsed.public_key, public_key);
        assert_eq!(parsed.user_data, user_data);
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn enforces_pcr_constraints_and_accepts_all_value_lengths() {
        let mut fields = default_fields();
        set_field(
            &mut fields,
            "pcrs",
            pcrs_value(&[(2, vec![2; 64]), (0, vec![0; 32]), (1, vec![1; 48])]),
        );
        let parsed = parse_fields(&fields).unwrap();
        assert_eq!(
            parsed
                .pcrs
                .iter()
                .map(|pcr| (pcr.index, pcr.value.len()))
                .collect::<Vec<_>>(),
            vec![(0, 32), (1, 48), (2, 64)]
        );

        for invalid_len in [0, 31, 33, 47, 49, 63, 65] {
            let mut fields = default_fields();
            set_field(
                &mut fields,
                "pcrs",
                pcrs_value(&[(0, vec![0; invalid_len])]),
            );
            assert_field_error(&fields, FormatError::InvalidPayload);
        }

        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&[]));
        assert_field_error(&fields, FormatError::InvalidPayload);

        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&[(32, vec![0; 48])]));
        assert_field_error(&fields, FormatError::InvalidPayload);

        let mut fields = default_fields();
        set_field(
            &mut fields,
            "pcrs",
            pcrs_value(&[(7, vec![0; 48]), (7, vec![1; 48])]),
        );
        assert_field_error(&fields, FormatError::InvalidPayload);

        for malformed_pcrs in [
            encoded_value(|encoder| {
                encoder
                    .map(1)
                    .unwrap()
                    .str("zero")
                    .unwrap()
                    .bytes(&[0; 48])
                    .unwrap();
            }),
            encoded_value(|encoder| {
                encoder
                    .map(1)
                    .unwrap()
                    .u8(0)
                    .unwrap()
                    .str("not bytes")
                    .unwrap();
            }),
        ] {
            let mut fields = default_fields();
            set_field(&mut fields, "pcrs", malformed_pcrs);
            assert_field_error(&fields, FormatError::InvalidPayload);
        }
    }

    #[test]
    fn enforces_pcr_and_cabundle_count_limits() {
        let pcrs = (0..MAX_PCRS)
            .map(|index| (index as u8, vec![index as u8; 48]))
            .collect::<Vec<_>>();
        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&pcrs));
        assert_eq!(parse_fields(&fields).unwrap().pcrs.len(), MAX_PCRS);

        let pcrs = (0..=MAX_PCRS)
            .map(|index| (index as u8, vec![index as u8; 48]))
            .collect::<Vec<_>>();
        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&pcrs));
        assert_field_error(&fields, FormatError::InvalidPayload);

        let certificates = (0..MAX_CA_BUNDLE)
            .map(|index| vec![index as u8])
            .collect::<Vec<_>>();
        let mut fields = default_fields();
        set_field(&mut fields, "cabundle", cabundle_value(&certificates));
        assert_eq!(parse_fields(&fields).unwrap().cabundle.len(), MAX_CA_BUNDLE);

        let certificates = (0..=MAX_CA_BUNDLE)
            .map(|index| vec![index as u8])
            .collect::<Vec<_>>();
        let mut fields = default_fields();
        set_field(&mut fields, "cabundle", cabundle_value(&certificates));
        assert_field_error(&fields, FormatError::InvalidPayload);
    }

    #[test]
    fn enforces_cabundle_entry_bounds() {
        let mut fields = default_fields();
        set_field(&mut fields, "cabundle", cabundle_value(&[]));
        assert_field_error(&fields, FormatError::InvalidPayload);

        for invalid in [Vec::new(), vec![0; 1_025]] {
            let mut fields = default_fields();
            set_field(
                &mut fields,
                "cabundle",
                cabundle_value(core::slice::from_ref(&invalid)),
            );
            assert_field_error(&fields, FormatError::InvalidPayload);
        }

        let mut fields = default_fields();
        set_field(
            &mut fields,
            "cabundle",
            encoded_value(|encoder| {
                encoder.array(1).unwrap().bool(false).unwrap();
            }),
        );
        assert_field_error(&fields, FormatError::InvalidPayload);
    }

    #[test]
    fn accepts_unknown_payload_fields() {
        let mut fields = default_fields();
        fields.push(TestField {
            name: "future_field",
            value: encoded_value(|encoder| {
                encoder
                    .array(2)
                    .unwrap()
                    .map(1)
                    .unwrap()
                    .str("nested")
                    .unwrap()
                    .u64(42)
                    .unwrap()
                    .tag(Tag::new(1_000))
                    .unwrap()
                    .null()
                    .unwrap();
            }),
        });
        let parsed = parse_fields(&fields).unwrap();
        assert_eq!(parsed.module_id, "module");
    }

    #[test]
    fn accepts_unknown_non_text_payload_keys() {
        let mut payload = encode_payload(&default_fields());
        assert_eq!(payload[0], 0xa6, "fixture must start with a six-entry map");
        payload[0] = 0xa7;
        let mut unknown = Encoder::new(Vec::new());
        unknown
            .u8(42)
            .unwrap()
            .array(2)
            .unwrap()
            .bool(true)
            .unwrap()
            .null()
            .unwrap();
        payload.extend_from_slice(&unknown.into_writer());

        let parsed = parse_attestation(&wrap_payload(false, false, &payload)).unwrap();
        assert_eq!(parsed.module_id, "module");
    }

    #[test]
    fn enforces_payload_and_document_size_limits() {
        let payload = payload_with_exact_len(MAX_PAYLOAD_SIZE);
        assert_eq!(payload.len(), MAX_PAYLOAD_SIZE);
        assert!(parse_attestation(&wrap_payload(false, false, &payload)).is_ok());

        let oversized_payload = vec![0; MAX_PAYLOAD_SIZE + 1];
        assert_eq!(
            parse_attestation(&wrap_payload(false, false, &oversized_payload)).unwrap_err(),
            crate::Error::InvalidFormat(FormatError::InvalidField("payload"))
        );

        let document = document_with_exact_len(MAX_DOCUMENT_SIZE);
        assert_eq!(document.len(), MAX_DOCUMENT_SIZE);
        assert!(parse_attestation(&document).is_ok());

        let mut oversized_document = document;
        oversized_document.push(0);
        assert_eq!(
            parse_attestation(&oversized_document).unwrap_err(),
            crate::Error::InvalidFormat(FormatError::DocumentTooLarge)
        );
    }

    #[test]
    fn rejects_duplicate_recognized_fields() {
        let error = parse_attestation(&document(false, false, true)).unwrap_err();
        assert_eq!(
            error,
            crate::Error::InvalidFormat(FormatError::InvalidPayload)
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_wrong_tag() {
        let mut trailing = document(false, false, false);
        trailing.push(0);
        assert!(parse_attestation(&trailing).is_err());

        let mut wrong_tag = document(true, false, false);
        wrong_tag[0] = 0xd1; // tag 17 instead of tag 18
        assert_eq!(
            parse_attestation(&wrong_tag).unwrap_err(),
            crate::Error::InvalidFormat(FormatError::InvalidCoseTag)
        );
    }

    #[test]
    fn sig_structure_uses_exact_protected_and_payload_bytes() {
        let encoded = encode_sig_structure(&[0xa1, 1, 0x38, 0x22], &[1, 2, 3]).unwrap();
        assert_eq!(
            encoded,
            b"\x84\x6aSignature1\x44\xa1\x01\x38\x22\x40\x43\x01\x02\x03"
        );
        let mut d = Decoder::new(&encoded);
        assert_eq!(d.array().unwrap(), Some(4));
        assert_eq!(d.str().unwrap(), "Signature1");
        assert_eq!(d.bytes().unwrap(), &[0xa1, 1, 0x38, 0x22]);
        assert_eq!(d.bytes().unwrap(), &[]);
        assert_eq!(d.bytes().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn bounds_nested_unknown_values_at_sixteen_containers() {
        let nested = |arrays: usize| {
            let mut e = Encoder::new(Vec::new());
            for _ in 0..arrays {
                e.array(1).unwrap();
            }
            e.null().unwrap();
            e.into_writer()
        };

        let mut fields = default_fields();
        fields.push(TestField {
            name: "future_field",
            value: nested(MAX_CBOR_DEPTH - 1),
        });
        assert!(parse_fields(&fields).is_ok());
        set_field(&mut fields, "future_field", nested(MAX_CBOR_DEPTH));
        assert_field_error(&fields, FormatError::NestingTooDeep);
    }
}
