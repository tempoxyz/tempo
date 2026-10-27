//! PCR measurement parsing shared with `build.rs`, which includes this file via `#[path]`.

/// Error returned when parsing PCR measurements.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PcrError {
    /// Not exactly three 48-byte hex measurements.
    #[error("expected three 48-byte hex PCR measurements (PCR0,PCR1,PCR2)")]
    Invalid,
    /// A zero (debug enclave) measurement.
    #[error("zero/debug enclave PCR measurements are not permitted")]
    Debug,
}

/// Parses PCR0, PCR1 and PCR2 as 48-byte hex measurements with an optional `0x` prefix, rejecting
/// zero (debug enclave) values.
pub(crate) fn parse_pcrs<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<[[u8; 48]; 3], PcrError> {
    let mut values = values.into_iter();
    let mut pcrs = [[0; 48]; 3];
    for pcr in &mut pcrs {
        let value = values.next().ok_or(PcrError::Invalid)?;
        let hex = value.strip_prefix("0x").unwrap_or(value).as_bytes();
        if hex.len() != 96 {
            return Err(PcrError::Invalid);
        }
        for (byte, pair) in pcr.iter_mut().zip(hex.chunks(2)) {
            let nibble = |c: u8| char::from(c).to_digit(16).ok_or(PcrError::Invalid);
            *byte = (nibble(pair[0])? << 4 | nibble(pair[1])?) as u8;
        }
        if *pcr == [0; 48] {
            return Err(PcrError::Debug);
        }
    }
    if values.next().is_some() {
        return Err(PcrError::Invalid);
    }
    Ok(pcrs)
}
