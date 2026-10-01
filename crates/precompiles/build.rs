#![allow(missing_docs)]

use serde::Deserialize;
use std::{env, error::Error, fmt::Write, fs, path::PathBuf};

const PCRS_PATH: &str = "src/zone_verifier/pcrs.json";
const COMMIT_PREFIX: &str = "https://github.com/tempoxyz/zones/commit/";
const IMAGE_PREFIX: &str = "ghcr.io/tempoxyz/tempo-zone-prover@sha256:";

/// One approved PCR0/1/2 tuple and the release that produced it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    hardfork: String,
    commit: String,
    image: String,
    /// PCR0, PCR1 and PCR2.
    pcrs: [String; 3],
}

/// Generates `APPROVED_PCRS` from `pcrs.json` so measurements are reviewed as data and checked
/// against their source image in CI.
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PCRS_PATH}");

    let entries: Vec<Entry> = serde_json::from_str(&fs::read_to_string(PCRS_PATH)?)
        .map_err(|e| format!("{PCRS_PATH}: {e}"))?;

    let mut out = String::from("&[\n");
    for entry in &entries {
        let fork = &entry.hardfork;
        if fork.is_empty() || !fork.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(format!("{PCRS_PATH}: invalid hardfork `{fork}`").into());
        }
        check_hex(&entry.commit, COMMIT_PREFIX, 40, "commit")?;
        check_hex(&entry.image, IMAGE_PREFIX, 64, "image")?;

        writeln!(out, "    (TempoHardfork::{fork}, [")?;
        for pcr in &entry.pcrs {
            writeln!(out, "        {:?},", decode_pcr(fork, pcr)?)?;
        }
        writeln!(out, "    ]),")?;
    }
    out.push(']');

    fs::write(PathBuf::from(env::var("OUT_DIR")?).join("pcrs.rs"), out)?;
    Ok(())
}

/// Requires `value` to be `prefix` followed by `len` lowercase hex digits.
fn check_hex(value: &str, prefix: &str, len: usize, field: &str) -> Result<(), Box<dyn Error>> {
    let is_hex = |hex: &str| hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if value
        .strip_prefix(prefix)
        .is_some_and(|hex| hex.len() == len && is_hex(hex))
    {
        return Ok(());
    }
    Err(format!("{PCRS_PATH}: {field} `{value}` must be `{prefix}<{len} lowercase hex>`").into())
}

/// Decodes a 48-byte measurement, rejecting zero (debug enclave) values.
fn decode_pcr(fork: &str, pcr: &str) -> Result<[u8; 48], Box<dyn Error>> {
    check_hex(pcr, "", 96, &format!("{fork} PCR"))?;
    let mut bytes = [0; 48];
    for (byte, chunk) in bytes.iter_mut().zip(pcr.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    if bytes == [0; 48] {
        return Err(format!("{PCRS_PATH}: {fork} has zero/debug PCR measurements").into());
    }
    Ok(bytes)
}
