use crate::{
    FormatError, MAX_CA_BUNDLE, MAX_CBOR_DEPTH, MAX_DOCUMENT_SIZE, MAX_PAYLOAD_SIZE, MAX_PCRS,
    P384_FIXED_SIGNATURE_SIZE, ParsedAttestation, Pcr,
};
use alloc::{string::String, vec::Vec};
use minicbor::{Decoder, Encoder, data::Type};

type Result<T> = core::result::Result<T, crate::Error>;

#[derive(Clone, Copy)]
struct Collection {
    remaining: Option<u64>,
}

impl Collection {
    fn new(remaining: Option<u64>) -> Self {
        Self { remaining }
    }

    fn next(&mut self, decoder: &mut Decoder<'_>) -> Result<bool> {
        match self.remaining {
            Some(0) => Ok(false),
            Some(ref mut remaining) => {
                *remaining -= 1;
                Ok(true)
            }
            None if decoder.datatype().map_err(cbor_error)? == Type::Break => {
                decoder.skip().map_err(cbor_error)?;
                Ok(false)
            }
            None => Ok(true),
        }
    }
}

fn cbor_error(_: minicbor::decode::Error) -> crate::Error {
    FormatError::InvalidCbor.into()
}

fn encode_error<E>(_: minicbor::encode::Error<E>) -> crate::Error {
    FormatError::InvalidCbor.into()
}

pub(crate) fn parse_attestation(document: &[u8]) -> Result<ParsedAttestation> {
    if document.len() > MAX_DOCUMENT_SIZE {
        return Err(FormatError::DocumentTooLarge.into());
    }

    let mut decoder = Decoder::new(document);
    let tagged = decoder.datatype().map_err(cbor_error)? == Type::Tag;
    if tagged && decoder.tag().map_err(cbor_error)?.as_u64() != 18 {
        return Err(FormatError::InvalidCoseTag.into());
    }

    let outer_len = decoder.array().map_err(cbor_error)?;
    if outer_len.is_some_and(|len| len != 4) {
        return Err(FormatError::InvalidCoseStructure.into());
    }

    let protected = read_bytes(&mut decoder, 1, MAX_DOCUMENT_SIZE, "protected header")?;
    validate_protected_header(&protected)?;

    // A COSE Header is a map. Its contents do not participate in validation, but still need to
    // be well-formed and depth-bounded.
    if !matches!(
        decoder.datatype().map_err(cbor_error)?,
        Type::Map | Type::MapIndef
    ) {
        return Err(FormatError::InvalidCoseStructure.into());
    }
    skip_value(&mut decoder, if tagged { 3 } else { 2 })?;

    let payload = read_bytes(&mut decoder, 1, MAX_PAYLOAD_SIZE, "payload")?;
    let signature_bytes = read_bytes(
        &mut decoder,
        P384_FIXED_SIGNATURE_SIZE,
        P384_FIXED_SIGNATURE_SIZE,
        "signature",
    )?;
    let signature = signature_bytes
        .try_into()
        .map_err(|_| FormatError::InvalidSignatureEncoding)?;

    if outer_len.is_none() {
        if decoder.datatype().map_err(cbor_error)? != Type::Break {
            return Err(FormatError::InvalidCoseStructure.into());
        }
        decoder.skip().map_err(cbor_error)?;
    }
    if decoder.position() != document.len() {
        return Err(FormatError::InvalidCoseStructure.into());
    }

    parse_payload(protected, payload, signature)
}

fn validate_protected_header(protected: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(protected);
    let len = decoder
        .map()
        .map_err(|_| crate::Error::from(FormatError::InvalidProtectedHeader))?;
    if len.is_some_and(|len| len != 1) {
        return Err(FormatError::InvalidProtectedHeader.into());
    }

    let key = decoder
        .u64()
        .map_err(|_| crate::Error::from(FormatError::InvalidProtectedHeader))?;
    let value = decoder
        .i64()
        .map_err(|_| crate::Error::from(FormatError::InvalidProtectedHeader))?;
    if key != 1 || value != -35 {
        return Err(FormatError::InvalidProtectedHeader.into());
    }

    if len.is_none() {
        if decoder
            .datatype()
            .map_err(|_| crate::Error::from(FormatError::InvalidProtectedHeader))?
            != Type::Break
        {
            return Err(FormatError::InvalidProtectedHeader.into());
        }
        decoder
            .skip()
            .map_err(|_| crate::Error::from(FormatError::InvalidProtectedHeader))?;
    }
    if decoder.position() != protected.len() {
        return Err(FormatError::InvalidProtectedHeader.into());
    }
    Ok(())
}

fn parse_payload(
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: [u8; P384_FIXED_SIGNATURE_SIZE],
) -> Result<ParsedAttestation> {
    let mut decoder = Decoder::new(&payload);
    let mut entries = Collection::new(
        decoder
            .map()
            .map_err(|_| crate::Error::from(FormatError::InvalidPayload))?,
    );

    let mut module_id = None;
    let mut digest_seen = false;
    let mut timestamp = None;
    let mut pcrs = None;
    let mut certificate = None;
    let mut cabundle = None;
    let mut public_key = None;
    let mut user_data = None;
    let mut nonce = None;

    while entries.next(&mut decoder)? {
        let key = if matches!(
            decoder.datatype().map_err(cbor_error)?,
            Type::String | Type::StringIndef
        ) {
            Some(read_text(&mut decoder, MAX_PAYLOAD_SIZE, "payload key")?)
        } else {
            skip_value(&mut decoder, 2)?;
            None
        };

        match key.as_deref() {
            Some("module_id") => {
                mark_absent(&module_id, "module_id")?;
                let value = read_text(&mut decoder, MAX_PAYLOAD_SIZE, "module_id")?;
                if value.is_empty() {
                    return Err(FormatError::InvalidField("module_id").into());
                }
                module_id = Some(value);
            }
            Some("digest") => {
                if digest_seen {
                    return Err(FormatError::DuplicateField("digest").into());
                }
                digest_seen = true;
                if read_text(&mut decoder, 6, "digest")? != "SHA384" {
                    return Err(FormatError::InvalidField("digest").into());
                }
            }
            Some("timestamp") => {
                mark_absent(&timestamp, "timestamp")?;
                let value = decoder
                    .u64()
                    .map_err(|_| crate::Error::from(FormatError::InvalidField("timestamp")))?;
                if value == 0 {
                    return Err(FormatError::InvalidField("timestamp").into());
                }
                timestamp = Some(value);
            }
            Some("pcrs") => {
                mark_absent(&pcrs, "pcrs")?;
                pcrs = Some(parse_pcrs(&mut decoder)?);
            }
            Some("certificate") => {
                mark_absent(&certificate, "certificate")?;
                certificate = Some(read_bytes(&mut decoder, 1, 1_024, "certificate")?);
            }
            Some("cabundle") => {
                mark_absent(&cabundle, "cabundle")?;
                cabundle = Some(parse_cabundle(&mut decoder)?);
            }
            Some("public_key") => {
                mark_absent(&public_key, "public_key")?;
                public_key = Some(read_optional_bytes(&mut decoder, 1, 1_024, "public_key")?);
            }
            Some("user_data") => {
                mark_absent(&user_data, "user_data")?;
                user_data = Some(read_optional_bytes(&mut decoder, 0, 512, "user_data")?);
            }
            Some("nonce") => {
                mark_absent(&nonce, "nonce")?;
                nonce = Some(read_optional_bytes(&mut decoder, 0, 512, "nonce")?);
            }
            _ => skip_value(&mut decoder, 2)?,
        }
    }

    if decoder.position() != payload.len() {
        return Err(FormatError::InvalidPayload.into());
    }
    if !digest_seen {
        return Err(FormatError::MissingField("digest").into());
    }

    Ok(ParsedAttestation {
        protected,
        payload,
        signature,
        module_id: module_id.ok_or(FormatError::MissingField("module_id"))?,
        timestamp: timestamp.ok_or(FormatError::MissingField("timestamp"))?,
        pcrs: pcrs.ok_or(FormatError::MissingField("pcrs"))?,
        certificate: certificate.ok_or(FormatError::MissingField("certificate"))?,
        cabundle: cabundle.ok_or(FormatError::MissingField("cabundle"))?,
        public_key: public_key.unwrap_or_default(),
        user_data: user_data.unwrap_or_default(),
        nonce: nonce.unwrap_or_default(),
    })
}

fn mark_absent<T>(slot: &Option<T>, field: &'static str) -> Result<()> {
    if slot.is_some() {
        Err(FormatError::DuplicateField(field).into())
    } else {
        Ok(())
    }
}

fn parse_pcrs(decoder: &mut Decoder<'_>) -> Result<Vec<Pcr>> {
    let len = decoder
        .map()
        .map_err(|_| crate::Error::from(FormatError::InvalidField("pcrs")))?;
    if len.is_some_and(|len| len == 0 || len > MAX_PCRS as u64) {
        return Err(FormatError::TooManyPcrs.into());
    }

    let mut entries = Collection::new(len);
    let mut seen = [false; MAX_PCRS];
    let mut pcrs = Vec::new();
    while entries.next(decoder)? {
        if pcrs.len() == MAX_PCRS {
            return Err(FormatError::TooManyPcrs.into());
        }
        let index = decoder
            .u8()
            .map_err(|_| crate::Error::from(FormatError::InvalidField("pcrs")))?;
        if usize::from(index) >= MAX_PCRS {
            return Err(FormatError::InvalidField("pcrs").into());
        }
        if seen[usize::from(index)] {
            return Err(FormatError::DuplicatePcr(index).into());
        }
        seen[usize::from(index)] = true;

        let value = read_bytes(decoder, 0, 64, "pcrs")?;
        if !matches!(value.len(), 32 | 48 | 64) {
            return Err(FormatError::InvalidField("pcrs").into());
        }
        pcrs.push(Pcr { index, value });
    }
    if pcrs.is_empty() {
        return Err(FormatError::InvalidField("pcrs").into());
    }
    pcrs.sort_unstable_by_key(|pcr| pcr.index);
    Ok(pcrs)
}

fn parse_cabundle(decoder: &mut Decoder<'_>) -> Result<Vec<Vec<u8>>> {
    let len = decoder
        .array()
        .map_err(|_| crate::Error::from(FormatError::InvalidField("cabundle")))?;
    if len.is_some_and(|len| len == 0 || len > MAX_CA_BUNDLE as u64) {
        return Err(FormatError::TooManyCertificates.into());
    }

    let mut entries = Collection::new(len);
    let mut cabundle = Vec::new();
    while entries.next(decoder)? {
        if cabundle.len() == MAX_CA_BUNDLE {
            return Err(FormatError::TooManyCertificates.into());
        }
        cabundle.push(read_bytes(decoder, 1, 1_024, "cabundle")?);
    }
    if cabundle.is_empty() {
        return Err(FormatError::InvalidField("cabundle").into());
    }
    Ok(cabundle)
}

fn read_bytes(
    decoder: &mut Decoder<'_>,
    min: usize,
    max: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let chunks = decoder
        .bytes_iter()
        .map_err(|_| crate::Error::from(FormatError::InvalidField(field)))?;
    for chunk in chunks {
        let chunk = chunk.map_err(cbor_error)?;
        let new_len = output
            .len()
            .checked_add(chunk.len())
            .ok_or(FormatError::InvalidField(field))?;
        if new_len > max {
            return Err(FormatError::InvalidField(field).into());
        }
        output.extend_from_slice(chunk);
    }
    if output.len() < min {
        return Err(FormatError::InvalidField(field).into());
    }
    Ok(output)
}

fn read_optional_bytes(
    decoder: &mut Decoder<'_>,
    min: usize,
    max: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if decoder.datatype().map_err(cbor_error)? == Type::Null {
        decoder.null().map_err(cbor_error)?;
        Ok(Vec::new())
    } else {
        read_bytes(decoder, min, max, field)
    }
}

fn read_text(decoder: &mut Decoder<'_>, max: usize, field: &'static str) -> Result<String> {
    let mut output = String::new();
    let chunks = decoder
        .str_iter()
        .map_err(|_| crate::Error::from(FormatError::InvalidField(field)))?;
    for chunk in chunks {
        let chunk = chunk.map_err(cbor_error)?;
        let new_len = output
            .len()
            .checked_add(chunk.len())
            .ok_or(FormatError::InvalidField(field))?;
        if new_len > max {
            return Err(FormatError::InvalidField(field).into());
        }
        output.push_str(chunk);
    }
    Ok(output)
}

fn skip_value(decoder: &mut Decoder<'_>, depth: usize) -> Result<()> {
    let datatype = decoder.datatype().map_err(cbor_error)?;
    if depth > MAX_CBOR_DEPTH
        && matches!(
            datatype,
            Type::Array | Type::ArrayIndef | Type::Map | Type::MapIndef | Type::Tag
        )
    {
        return Err(FormatError::NestingTooDeep.into());
    }

    match datatype {
        Type::Array | Type::ArrayIndef => {
            let mut items = Collection::new(decoder.array().map_err(cbor_error)?);
            while items.next(decoder)? {
                skip_value(decoder, depth + 1)?;
            }
        }
        Type::Map | Type::MapIndef => {
            let mut entries = Collection::new(decoder.map().map_err(cbor_error)?);
            while entries.next(decoder)? {
                skip_value(decoder, depth + 1)?;
                skip_value(decoder, depth + 1)?;
            }
        }
        Type::Tag => {
            decoder.tag().map_err(cbor_error)?;
            skip_value(decoder, depth + 1)?;
        }
        Type::Bytes | Type::BytesIndef => {
            for chunk in decoder.bytes_iter().map_err(cbor_error)? {
                chunk.map_err(cbor_error)?;
            }
        }
        Type::String | Type::StringIndef => {
            for chunk in decoder.str_iter().map_err(cbor_error)? {
                chunk.map_err(cbor_error)?;
            }
        }
        Type::Break => return Err(FormatError::InvalidCbor.into()),
        _ => decoder.skip().map_err(cbor_error)?,
    }
    Ok(())
}

pub(crate) fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).map_err(encode_error)?;
    encoder.str("Signature1").map_err(encode_error)?;
    encoder.bytes(protected).map_err(encode_error)?;
    encoder.bytes(&[]).map_err(encode_error)?;
    encoder.bytes(payload).map_err(encode_error)?;
    Ok(encoder.into_writer())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;
    use minicbor::data::Tag;

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
            assert_field_error(&fields, FormatError::MissingField(name));
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
            assert_field_error(&fields, FormatError::DuplicateField(name));
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
            assert_field_error(&fields, FormatError::DuplicateField(name));
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
            assert_field_error(&fields, FormatError::InvalidField(name));
        }

        for name in ["public_key", "user_data", "nonce"] {
            let mut fields = default_fields();
            fields.push(TestField {
                name,
                value: bool_value(false),
            });
            assert_field_error(&fields, FormatError::InvalidField(name));
        }
    }

    #[test]
    fn enforces_scalar_and_byte_string_bounds() {
        let mut fields = default_fields();
        set_field(&mut fields, "module_id", text_value(""));
        assert_field_error(&fields, FormatError::InvalidField("module_id"));

        let mut fields = default_fields();
        set_field(&mut fields, "digest", text_value("SHA256"));
        assert_field_error(&fields, FormatError::InvalidField("digest"));

        let mut fields = default_fields();
        set_field(&mut fields, "timestamp", unsigned_value(0));
        assert_field_error(&fields, FormatError::InvalidField("timestamp"));

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
                assert_field_error(&fields, FormatError::InvalidField(name));
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
            assert_field_error(&fields, FormatError::InvalidField(name));
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
            assert_field_error(&fields, FormatError::InvalidField("pcrs"));
        }

        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&[]));
        assert_field_error(&fields, FormatError::TooManyPcrs);

        let mut fields = default_fields();
        set_field(&mut fields, "pcrs", pcrs_value(&[(32, vec![0; 48])]));
        assert_field_error(&fields, FormatError::InvalidField("pcrs"));

        let mut fields = default_fields();
        set_field(
            &mut fields,
            "pcrs",
            pcrs_value(&[(7, vec![0; 48]), (7, vec![1; 48])]),
        );
        assert_field_error(&fields, FormatError::DuplicatePcr(7));

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
            assert_field_error(&fields, FormatError::InvalidField("pcrs"));
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
        assert_field_error(&fields, FormatError::TooManyPcrs);

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
        assert_field_error(&fields, FormatError::TooManyCertificates);
    }

    #[test]
    fn enforces_cabundle_entry_bounds() {
        let mut fields = default_fields();
        set_field(&mut fields, "cabundle", cabundle_value(&[]));
        assert_field_error(&fields, FormatError::TooManyCertificates);

        for invalid in [Vec::new(), vec![0; 1_025]] {
            let mut fields = default_fields();
            set_field(
                &mut fields,
                "cabundle",
                cabundle_value(core::slice::from_ref(&invalid)),
            );
            assert_field_error(&fields, FormatError::InvalidField("cabundle"));
        }

        let mut fields = default_fields();
        set_field(
            &mut fields,
            "cabundle",
            encoded_value(|encoder| {
                encoder.array(1).unwrap().bool(false).unwrap();
            }),
        );
        assert_field_error(&fields, FormatError::InvalidField("cabundle"));
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
            crate::Error::InvalidFormat(FormatError::DuplicateField("module_id"))
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

        // Simulate an unknown value inside the payload map (which is depth one).
        let accepted = nested(MAX_CBOR_DEPTH - 1);
        let mut decoder = Decoder::new(&accepted);
        skip_value(&mut decoder, 2).unwrap();
        assert_eq!(decoder.position(), accepted.len());

        let rejected = nested(MAX_CBOR_DEPTH);
        let mut decoder = Decoder::new(&rejected);
        assert_eq!(
            skip_value(&mut decoder, 2).unwrap_err(),
            crate::Error::InvalidFormat(FormatError::NestingTooDeep)
        );
    }
}
