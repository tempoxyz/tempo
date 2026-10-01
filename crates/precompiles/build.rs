#![allow(missing_docs)]

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::{
    env,
    error::Error,
    fmt::{self, Write},
    fs,
    path::PathBuf,
};

#[path = "src/zone_verifier/pcr.rs"]
#[allow(unreachable_pub)]
mod pcr;

const PCRS_PATH: &str = "src/zone_verifier/pcrs.json";
const COMMIT_PREFIX: &str = "https://github.com/tempoxyz/zones/commit/";
const IMAGE_PREFIX: &str = "ghcr.io/tempoxyz/tempo-zone-prover@sha256:";

/// One approved PCR0/1/2 tuple and the release that produced it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    commit: String,
    image: String,
    /// PCR0, PCR1 and PCR2.
    pcrs: [String; 3],
}

/// Entries keyed by hardfork, kept in file order so the ordering test in `mod.rs` sees them as
/// written. Duplicate hardforks are rejected.
struct Entries(Vec<(String, Entry)>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map from hardfork to PCR entry")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                let mut entries = Vec::new();
                while let Some((fork, entry)) = map.next_entry()? {
                    if entries.iter().any(|(seen, _)| *seen == fork) {
                        return Err(de::Error::custom(format!("duplicate hardfork `{fork}`")));
                    }
                    entries.push((fork, entry));
                }
                Ok(Entries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

/// Generates `APPROVED_PCRS` from `pcrs.json` so measurements are reviewed as data and checked
/// against their source image in CI.
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PCRS_PATH}");

    let Entries(entries) = serde_json::from_str(&fs::read_to_string(PCRS_PATH)?)
        .map_err(|e| format!("{PCRS_PATH}: {e}"))?;

    let mut out = String::from("&[\n");
    for (fork, entry) in &entries {
        if fork.is_empty() || !fork.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(format!("{PCRS_PATH}: invalid hardfork `{fork}`").into());
        }
        check_hex(&entry.commit, COMMIT_PREFIX, 40, "commit")?;
        check_hex(&entry.image, IMAGE_PREFIX, 64, "image")?;

        let pcrs = pcr::parse_pcrs(entry.pcrs.iter().map(String::as_str))
            .map_err(|e| format!("{PCRS_PATH}: {fork}: {e}"))?;
        writeln!(out, "    (TempoHardfork::{fork}, [")?;
        for pcr in pcrs {
            writeln!(out, "        {pcr:?},")?;
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
