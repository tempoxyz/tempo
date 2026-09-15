use crate::{journal::Journal, model::Class};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub chain_id: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub first_hash: String,
    pub last_hash: String,
    pub blocks: u64,
    pub duration_ms: u64,
    pub users: u64,
    pub systems: u64,
    pub subblocks: u64,
    pub raw_bytes: u64,
    pub gas_limit: u64,
    pub transaction_types: BTreeMap<u8, u64>,
    pub expiring_nonces: u64,
    pub nonzero_nonce_keys: u64,
    pub deadlines: u64,
    pub earliest_valid_before: Option<u64>,
    pub latest_valid_before: Option<u64>,
    pub mean_tps: f64,
    pub peak_block_users: u64,
    pub peak_block_raw_bytes: u64,
    pub peak_sender_block_users: u64,
    pub capture_p99_ms: u64,
    pub deadline_note: String,
}
pub fn profile(j: &Journal, from: Option<u64>, to: Option<u64>) -> Result<Profile> {
    let end = j
        .state
        .cursors
        .captured_through
        .as_ref()
        .context("no captured blocks")?
        .height;
    let start = from.unwrap_or(j.state.first_height);
    let end = to.unwrap_or(end).min(end);
    ensure!(
        start >= j.state.first_height && start <= end,
        "invalid captured profile interval"
    );
    let first = j.block(start)?.context("first profile block missing")?;
    let last = j.block(end)?.context("last profile block missing")?;
    let mut p = Profile { schema_version: 1, chain_id: j.state.chain_id, first_height: start, last_height: end,
        first_hash: first.point.hash.to_string(), last_hash: last.point.hash.to_string(), blocks: end - start + 1,
        duration_ms: last.timestamp_ms.saturating_sub(first.timestamp_ms), users: 0, systems: 0, subblocks: 0,
        raw_bytes: 0, gas_limit: 0, transaction_types: BTreeMap::new(), expiring_nonces: 0, nonzero_nonce_keys: 0,
        deadlines: 0, earliest_valid_before: None, latest_valid_before: None, mean_tps: 0., peak_block_users: 0,
        peak_block_raw_bytes: 0, peak_sender_block_users: 0, capture_p99_ms: 0,
        deadline_note: "valid_before only; access-key and state-dependent deadlines require deployment measurements".into() };
    let mut capture_histogram = BTreeMap::<u64, u64>::new();
    for h in start..=end {
        let b = j.block(h)?.context("profile block missing")?;
        let mut senders = BTreeMap::new();
        let mut count = 0;
        let mut bytes = 0;
        *capture_histogram
            .entry(b.committed_ms.saturating_sub(b.timestamp_ms) / 100 * 100)
            .or_default() += 1;
        for tx in b.transactions {
            if tx.class == Class::System {
                p.systems += 1;
                continue;
            }
            count += 1;
            p.users += 1;
            p.subblocks += u64::from(tx.class == Class::Subblock);
            bytes += tx.raw_len();
            p.raw_bytes += tx.raw_len();
            p.gas_limit = p.gas_limit.saturating_add(tx.gas_limit);
            *p.transaction_types.entry(tx.tx_type).or_default() += 1;
            p.expiring_nonces += u64::from(tx.expiring);
            p.nonzero_nonce_keys += u64::from(!tx.nonce_key.is_zero());
            let sender_count = senders.entry(tx.sender).or_insert(0);
            *sender_count += 1;
            p.peak_sender_block_users = p.peak_sender_block_users.max(*sender_count);
            if let Some(v) = tx.valid_before {
                p.deadlines += 1;
                p.earliest_valid_before = Some(p.earliest_valid_before.map_or(v, |old| old.min(v)));
                p.latest_valid_before = Some(p.latest_valid_before.map_or(v, |old| old.max(v)));
            }
        }
        p.peak_block_users = p.peak_block_users.max(count);
        p.peak_block_raw_bytes = p.peak_block_raw_bytes.max(bytes);
    }
    p.mean_tps = p.users as f64 * 1000. / p.duration_ms.max(1) as f64;
    let mut seen = 0;
    for (latency, n) in capture_histogram {
        seen += n;
        if seen * 100 >= p.blocks * 99 {
            p.capture_p99_ms = latency + 99;
            break;
        }
    }
    Ok(p)
}
