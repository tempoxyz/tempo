//! Streaming reader for the version-one TIP20 dump format.

use std::io::Read;

use alloy_primitives::{Address, B256, U256};
use eyre::{Context as _, ensure};

/// Visit every storage entry without buffering an entire dump.
///
/// Consumers decide which accounts and slots are allowed. Truncated headers or
/// entries, unknown versions/flags, and empty dumps are rejected.
pub fn read_dump(
    mut reader: impl Read,
    mut visit: impl FnMut(Address, B256, U256) -> eyre::Result<()>,
) -> eyre::Result<u64> {
    let mut count = 0u64;
    while let Some((address, pairs)) = read_header(&mut reader)? {
        for _ in 0..pairs {
            let (slot, value) = read_entry(&mut reader)?;
            visit(address, slot, value)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("entry count overflow"))?;
        }
    }
    ensure!(count > 0, "empty state dump");
    Ok(count)
}

pub(crate) fn read_header(reader: &mut impl Read) -> eyre::Result<Option<(Address, u64)>> {
    let mut header = [0u8; 40];
    // Only EOF before the first byte denotes the end of a complete dump.
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    reader
        .read_exact(&mut header[1..])
        .wrap_err("truncated state dump header")?;
    ensure!(&header[..8] == b"TEMPOSB\0", "invalid state dump magic");
    ensure!(
        u16::from_be_bytes(header[8..10].try_into()?) == 1,
        "unsupported state dump version"
    );
    ensure!(header[10..12] == [0, 0], "unsupported state dump flags");
    let address = Address::from_slice(&header[12..32]);
    let pairs = u64::from_be_bytes(header[32..40].try_into()?);
    ensure!(pairs > 0, "empty state dump block");
    Ok(Some((address, pairs)))
}

pub(crate) fn read_entry(reader: &mut impl Read) -> eyre::Result<(B256, U256)> {
    let mut entry = [0u8; 64];
    reader
        .read_exact(&mut entry)
        .wrap_err("truncated state dump entry")?;
    Ok((
        B256::from_slice(&entry[..32]),
        U256::from_be_slice(&entry[32..]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(pairs: u64, entries: usize) -> Vec<u8> {
        let mut block = Vec::from(&b"TEMPOSB\0\0\x01\0\0"[..]);
        block.extend_from_slice(Address::ZERO.as_slice());
        block.extend_from_slice(&pairs.to_be_bytes());
        for _ in 0..entries {
            block.extend_from_slice(&[1; 64]);
        }
        block
    }

    #[test]
    fn rejects_truncation_and_unknown_format() {
        let dump = block(1, 1);
        for len in 0..dump.len() {
            assert!(read_dump(&dump[..len], |_, _, _| Ok(())).is_err());
        }
        assert_eq!(read_dump(dump.as_slice(), |_, _, _| Ok(())).unwrap(), 1);
        for offset in [0, 8, 9, 10, 11] {
            let mut invalid = dump.clone();
            invalid[offset] = 42;
            assert!(read_dump(invalid.as_slice(), |_, _, _| Ok(())).is_err());
        }
        assert!(read_dump(block(0, 0).as_slice(), |_, _, _| Ok(())).is_err());
    }

    #[test]
    fn accepts_only_complete_multi_block_dumps() {
        let first = block(2, 2);
        let dump = [first.clone(), block(1, 1)].concat();
        assert_eq!(read_dump(dump.as_slice(), |_, _, _| Ok(())).unwrap(), 3);
        assert_eq!(read_dump(first.as_slice(), |_, _, _| Ok(())).unwrap(), 2);
        for len in first.len() + 1..dump.len() {
            assert!(read_dump(&dump[..len], |_, _, _| Ok(())).is_err());
        }
        let trailing_empty = [first, block(0, 0)].concat();
        assert!(read_dump(trailing_empty.as_slice(), |_, _, _| Ok(())).is_err());
    }
}
