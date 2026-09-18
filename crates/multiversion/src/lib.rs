//! A flat, checksummed archive appended to a native launcher.
//!
//! Fork identifiers come from `tempo-hardfork`, including Genesis and T1A/T1B/T1C.
//! The archive does not select execution rules or change the node's database: those are
//! responsibilities of the execution dispatcher. A checksum detects corruption, not an
//! untrusted publisher; release provenance must cover the complete bundled artifact.

use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use tempo_hardfork::TempoHardfork;

const MAGIC: &[u8; 8] = b"TEMPMV01";
const FOOTER_LEN: u64 = 56;
const INDEX_HEADER_LEN: usize = 12;
const ENTRY_LEN: usize = 49;

/// A binary range in the containing file. Offsets are absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The only hardfork this entry is intended to execute.
    pub hardfork: TempoHardfork,
    /// Start of the embedded executable.
    pub offset: u64,
    /// Length of the embedded executable.
    pub length: u64,
    /// SHA-256 of the executable, excluding the launcher and index.
    pub sha256: [u8; 32],
}

/// An opened bundle. The same reader is retained for verification and extraction.
#[derive(Debug)]
pub struct Bundle<R> {
    reader: R,
    launcher_len: u64,
    entries: Vec<Entry>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated index size"),
    )
}

impl<R: Read + Seek> Bundle<R> {
    /// Checks the index checksum and every range before accepting a bundle.
    /// Payload checksums are verified by [`Self::verify`] or [`Self::copy_executable`].
    pub fn open(mut reader: R) -> io::Result<Self> {
        let len = reader.seek(SeekFrom::End(0))?;
        if len < FOOTER_LEN {
            return Err(invalid("missing multiversion footer"));
        }
        reader.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
        let mut footer = [0; FOOTER_LEN as usize];
        reader.read_exact(&mut footer)?;
        if &footer[..8] != MAGIC {
            return Err(invalid("unknown or missing multiversion format"));
        }
        let index_offset = u64_at(&footer, 8);
        let index_len = u64_at(&footer, 16);
        let max_index_len = INDEX_HEADER_LEN + ENTRY_LEN * TempoHardfork::VARIANTS.len();
        if index_len < INDEX_HEADER_LEN as u64
            || index_len > max_index_len as u64
            || index_offset.checked_add(index_len) != Some(len - FOOTER_LEN)
        {
            return Err(invalid("invalid index bounds"));
        }
        reader.seek(SeekFrom::Start(index_offset))?;
        let mut index = vec![0; index_len as usize];
        reader.read_exact(&mut index)?;
        let digest: [u8; 32] = Sha256::digest(&index).into();
        if digest != footer[24..] {
            return Err(invalid("index checksum mismatch"));
        }
        let launcher_len = u64_at(&index, 0);
        let count = u32::from_le_bytes(index[8..12].try_into().unwrap()) as usize;
        if count == 0
            || count > TempoHardfork::VARIANTS.len()
            || index.len() != INDEX_HEADER_LEN + count * ENTRY_LEN
            || launcher_len == 0
            || launcher_len >= index_offset
        {
            return Err(invalid("invalid executable count or launcher length"));
        }
        let mut entries = Vec::with_capacity(count);
        let mut next_offset = launcher_len;
        for (i, record) in index[INDEX_HEADER_LEN..]
            .as_chunks::<ENTRY_LEN>()
            .0
            .iter()
            .enumerate()
        {
            let hardfork = TempoHardfork::VARIANTS[i];
            if record[0] != hardfork.variant_index() {
                return Err(invalid(
                    "hardforks must appear exactly once in canonical order",
                ));
            }
            let offset = u64_at(record, 1);
            let length = u64_at(record, 9);
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("range overflow"))?;
            if offset != next_offset || length == 0 || end > index_offset {
                return Err(invalid("invalid executable bounds"));
            }
            entries.push(Entry {
                hardfork,
                offset,
                length,
                sha256: record[17..].try_into().unwrap(),
            });
            next_offset = end;
        }
        if next_offset != index_offset {
            return Err(invalid("unexpected bytes before index"));
        }
        Ok(Self {
            reader,
            launcher_len,
            entries,
        })
    }

    /// The flat list of embedded executables, in protocol order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The length of the launcher, excluding embedded executables and metadata.
    pub const fn launcher_len(&self) -> u64 {
        self.launcher_len
    }

    /// Copies one executable, verifying its hash before returning success.
    /// The caller must discard the output on error and must not execute it before success.
    /// No fallback to the latest hardfork is allowed.
    pub fn copy_executable(
        &mut self,
        hardfork: TempoHardfork,
        mut output: impl Write,
    ) -> io::Result<()> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.hardfork == hardfork)
            .ok_or_else(|| invalid("requested hardfork is absent from bundle"))?;
        self.reader.seek(SeekFrom::Start(entry.offset))?;
        let mut payload = (&mut self.reader).take(entry.length);
        let (length, sha256) = copy_hash(&mut payload, &mut output)?;
        if length != entry.length || sha256 != entry.sha256 {
            return Err(invalid("executable checksum mismatch"));
        }
        Ok(())
    }

    /// Verifies all executable checksums without loading the bundle into memory.
    pub fn verify(&mut self) -> io::Result<()> {
        let forks: Vec<_> = self.entries.iter().map(|entry| entry.hardfork).collect();
        for hardfork in forks {
            self.copy_executable(hardfork, io::sink())?;
        }
        Ok(())
    }
}

/// Writes one executable for every known hardfork after an unbundled launcher.
///
/// Inputs must be in [`TempoHardfork::VARIANTS`] order. This function does not establish
/// that an input implements its declared rules; that requires fork-specific builds and
/// execution tests. Output must be staged and discarded if any input or write fails.
pub fn pack<R: Read>(
    mut launcher: impl Read,
    executables: &mut [(TempoHardfork, R)],
    mut output: impl Write,
) -> io::Result<()> {
    if executables.len() != TempoHardfork::VARIANTS.len()
        || executables
            .iter()
            .zip(TempoHardfork::VARIANTS)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(invalid(
            "supply one executable per hardfork in canonical order",
        ));
    }
    let launcher_len = io::copy(&mut launcher, &mut output)?;
    if launcher_len == 0 {
        return Err(invalid("empty launcher"));
    }
    let mut index = Vec::with_capacity(INDEX_HEADER_LEN + ENTRY_LEN * executables.len());
    index.extend_from_slice(&launcher_len.to_le_bytes());
    index.extend_from_slice(&(executables.len() as u32).to_le_bytes());
    let mut offset = launcher_len;
    for (hardfork, executable) in executables {
        let (length, sha256) = copy_hash(executable, &mut output)?;
        if length == 0 {
            return Err(invalid("empty executable"));
        }
        index.push(hardfork.variant_index());
        index.extend_from_slice(&offset.to_le_bytes());
        index.extend_from_slice(&length.to_le_bytes());
        index.extend_from_slice(&sha256);
        offset = offset
            .checked_add(length)
            .ok_or_else(|| invalid("bundle size overflow"))?;
    }
    output.write_all(&index)?;
    output.write_all(MAGIC)?;
    output.write_all(&offset.to_le_bytes())?;
    output.write_all(&(index.len() as u64).to_le_bytes())?;
    output.write_all(&Sha256::digest(&index))?;
    Ok(())
}

fn copy_hash(mut input: impl Read, mut output: impl Write) -> io::Result<(u64, [u8; 32])> {
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = match input.read(&mut buffer) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            return Ok((length, hash.finalize().into()));
        }
        output.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
        length = length
            .checked_add(n as u64)
            .ok_or_else(|| invalid("payload size overflow"))?;
    }
}

#[cfg(test)]
mod tests;
