use super::*;
use std::io::Cursor;

fn fixture() -> Vec<u8> {
    let mut binaries: Vec<_> = TempoHardfork::VARIANTS
        .iter()
        .map(|fork| (*fork, Cursor::new(format!("executable-{fork}"))))
        .collect();
    let mut output = Vec::new();
    pack(&b"launcher"[..], &mut binaries, &mut output).unwrap();
    output
}

// Recompute the index checksum to exercise structural checks independently of hashing.
fn mutate_index(bytes: &mut [u8], mutate: impl FnOnce(&mut [u8])) {
    let footer = bytes.len() - FOOTER_LEN as usize;
    let offset = u64_at(&bytes[footer..], 8) as usize;
    mutate(&mut bytes[offset..footer]);
    let hash = Sha256::digest(&bytes[offset..footer]);
    bytes[footer + 24..].copy_from_slice(&hash);
}

#[test]
fn deterministic_round_trip_includes_every_hardfork() {
    let bytes = fixture();
    assert_eq!(bytes, fixture());
    let mut bundle = Bundle::open(Cursor::new(bytes)).unwrap();
    assert_eq!(bundle.launcher_len(), 8);
    assert_eq!(bundle.entries().len(), TempoHardfork::VARIANTS.len());
    for fork in TempoHardfork::VARIANTS {
        let mut extracted = Vec::new();
        bundle.copy_executable(*fork, &mut extracted).unwrap();
        assert_eq!(extracted, format!("executable-{fork}").as_bytes());
    }
    bundle.verify().unwrap();
}

#[test]
fn rejects_corruption_in_each_payload() {
    let bytes = fixture();
    let entries = Bundle::open(Cursor::new(&bytes))
        .unwrap()
        .entries()
        .to_vec();
    for entry in entries {
        let mut corrupt = bytes.clone();
        corrupt[entry.offset as usize] ^= 1;
        let mut bundle = Bundle::open(Cursor::new(corrupt)).unwrap();
        assert!(bundle.copy_executable(entry.hardfork, io::sink()).is_err());
        assert!(bundle.verify().is_err());
    }
}

#[test]
fn rejects_truncation_and_trailing_bytes() {
    let bytes = fixture();
    for end in 0..bytes.len() {
        assert!(Bundle::open(Cursor::new(&bytes[..end])).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Bundle::open(Cursor::new(trailing)).is_err());
}

#[test]
fn rejects_corrupt_index_and_footer() {
    let bytes = fixture();
    let footer = bytes.len() - FOOTER_LEN as usize;
    let index = u64_at(&bytes[footer..], 8) as usize;
    for at in index..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0x80;
        assert!(
            Bundle::open(Cursor::new(corrupt)).is_err(),
            "accepted corruption at {at}"
        );
    }
}

#[test]
fn rejects_duplicate_forks_gaps_overlap_overflow_and_empty_payloads() {
    for (offset, value) in [
        (INDEX_HEADER_LEN + ENTRY_LEN, vec![0]),
        (INDEX_HEADER_LEN + 1, 0u64.to_le_bytes().to_vec()),
        (INDEX_HEADER_LEN + 1, 9u64.to_le_bytes().to_vec()),
        (INDEX_HEADER_LEN + 9, u64::MAX.to_le_bytes().to_vec()),
        (INDEX_HEADER_LEN + 9, 0u64.to_le_bytes().to_vec()),
        (8, u32::MAX.to_le_bytes().to_vec()),
    ] {
        let mut bytes = fixture();
        mutate_index(&mut bytes, |index| {
            index[offset..offset + value.len()].copy_from_slice(&value)
        });
        assert!(Bundle::open(Cursor::new(bytes)).is_err());
    }
}

#[test]
fn pack_rejects_missing_duplicate_and_misordered_inputs() {
    let mut inputs: Vec<_> = TempoHardfork::VARIANTS
        .iter()
        .map(|fork| (*fork, &b"binary"[..]))
        .collect();
    inputs.pop();
    assert!(pack(&b"launcher"[..], &mut inputs, io::sink()).is_err());
    inputs.push((TempoHardfork::Genesis, &b"binary"[..]));
    assert!(pack(&b"launcher"[..], &mut inputs, io::sink()).is_err());
    inputs.last_mut().unwrap().0 = TempoHardfork::latest();
    inputs.swap(1, 2);
    assert!(pack(&b"launcher"[..], &mut inputs, io::sink()).is_err());
}

#[test]
fn older_bundle_never_falls_forward_to_a_missing_fork() {
    let mut bytes = fixture();
    let footer = bytes.len() - FOOTER_LEN as usize;
    let index_offset = u64_at(&bytes[footer..], 8) as usize;
    let old_count = TempoHardfork::VARIANTS.len() - 1;
    let old_end = u64_at(
        &bytes[index_offset..],
        INDEX_HEADER_LEN + old_count * ENTRY_LEN + 1,
    ) as usize;
    let mut index =
        bytes[index_offset..index_offset + INDEX_HEADER_LEN + old_count * ENTRY_LEN].to_vec();
    index[8..12].copy_from_slice(&(old_count as u32).to_le_bytes());
    bytes.truncate(old_end);
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(old_end as u64).to_le_bytes());
    bytes.extend_from_slice(&(index.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&index));
    let mut bundle = Bundle::open(Cursor::new(bytes)).unwrap();
    bundle.verify().unwrap();
    assert!(
        bundle
            .copy_executable(TempoHardfork::latest(), io::sink())
            .is_err()
    );
}
