//! Wall time of every stage between a block of encrypted transactions arriving and its bodies
//! being opened, on all cores, against the reference implementation.
//!
//! Env: `VALIDATORS` (default 16), `BLOCK_TXS` (comma-separated, default
//! 1000,5000,10000,20000), `RUNS` (default 5; the median is reported).

use alloy_primitives::{Address, B256, U256};
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal_anonymous,
    primitives::{sharing::Mode, variant::MinSig},
};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{N3f1, NZU32, NZUsize};
use rand::{SeedableRng, rngs::StdRng};
use std::{env, hint::black_box, time::Instant};
use tempo_encrypted_tx::{EncryptedBody, Envelope, fast, key_shares, recover_keys, verify_keys};

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn median_ms(runs: usize, mut f: impl FnMut()) -> f64 {
    let mut times: Vec<f64> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    times.sort_by(f64::total_cmp);
    times[times.len() / 2]
}

fn main() {
    let validators: u32 = env_or("VALIDATORS", 16);
    let runs: usize = env_or("RUNS", 5);
    let sizes: Vec<usize> = env::var("BLOCK_TXS")
        .unwrap_or_else(|_| "1000,5000,10000,20000".into())
        .split(',')
        .map(|s| s.trim().parse().expect("BLOCK_TXS"))
        .collect();
    let cores = std::thread::available_parallelism()
        .expect("core count")
        .get();
    let all = Rayon::new(NZUsize!(cores)).expect("thread pool");

    let mut rng = StdRng::seed_from_u64(0);
    let (sharing, shares) =
        deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::NonZeroCounter, NZU32!(validators));
    let network = *sharing.public();
    let network_point = fast::network_point(&network).unwrap();
    let quorum_size = sharing.required() as usize;
    println!("validators={validators} quorum={quorum_size} threads={cores} runs={runs}");
    println!(
        "| txs | prepare | sign | decode 48B | decode 96B | recover | verify keys | pair+FO | AEAD | critical (96B) | reference critical |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");

    for &count in &sizes {
        let bodies: Vec<(B256, EncryptedBody)> = all.map_collect_vec(0..count, |i| {
            let mut rng = StdRng::seed_from_u64(i as u64 + 1);
            let envelope = Envelope {
                chain_id: 4217,
                sender: Address::with_last_byte((i % 251) as u8),
                nonce_key: U256::ZERO,
                nonce: i as u64,
                gas_limit: 50_000,
            };
            let body = vec![0xab; 200];
            let (encrypted, id) =
                EncryptedBody::encrypt(&mut rng, network, &envelope, &body).unwrap();
            (id, encrypted)
        });
        let ids: Vec<B256> = bodies.iter().map(|(id, _)| *id).collect();

        let prepare = median_ms(runs, || {
            black_box(fast::prepare(&bodies, &all).unwrap());
        });
        let prepared = fast::prepare(&bodies, &all).unwrap();
        let sign = median_ms(runs, || {
            black_box(fast::sign(&shares[0], &prepared, &all));
        });
        let quorum_shares: Vec<_> = shares[..quorum_size]
            .iter()
            .map(|share| (share.index, fast::sign(share, &prepared, &all)))
            .collect();
        let compressed: Vec<_> = quorum_shares
            .iter()
            .map(|(_, s)| fast::encode_compressed(s))
            .collect();
        let uncompressed: Vec<_> = quorum_shares
            .iter()
            .map(|(_, s)| fast::encode_uncompressed(s))
            .collect();
        // Decoding a quorum: every share message after the first quorum - 1 arrives last at worst,
        // so report one validator's decode, which is what remains when the last message lands.
        let decode_48 = median_ms(runs, || {
            black_box(fast::decode(&compressed[0], true, &all).unwrap());
        });
        let decode_96 = median_ms(runs, || {
            black_box(fast::decode(&uncompressed[0], false, &all).unwrap());
        });
        let recover = median_ms(runs, || {
            black_box(fast::recover(&quorum_shares, &all).unwrap());
        });
        let keys = fast::recover(&quorum_shares, &all).unwrap();
        let verify = median_ms(runs, || {
            fast::verify_keys(&mut rng, &network_point, &prepared, &keys, &all).unwrap();
        });
        let open = median_ms(runs, || {
            black_box(fast::open_keys(&mut rng, &prepared, &keys, &all).unwrap());
        });
        let body_keys = fast::open_keys(&mut rng, &prepared, &keys, &all).unwrap();
        assert!(body_keys.iter().all(Option::is_some));
        let aead = median_ms(runs, || {
            black_box(fast::open_bodies(&bodies, &body_keys, &all));
        });

        // Reference: commonware recovery, batched verification (hashing every identity again) and
        // per-body tle decryption with its own Fujisaki-Okamoto multiplication.
        let reference_quorum: Vec<_> = shares[..quorum_size]
            .iter()
            .map(|share| key_shares(share, &ids, &all))
            .collect();
        let reference = median_ms(runs.min(3), || {
            let keys = recover_keys(&sharing, &reference_quorum, &all).unwrap();
            verify_keys(&mut rng, &network, &ids, &keys, &all).unwrap();
            black_box(
                all.map_collect_vec(bodies.iter().zip(&keys), |((_, body), key)| {
                    body.decrypt(key).unwrap()
                }),
            );
        });

        let critical = decode_96 + recover + verify + open + aead;
        println!(
            "| {count} | {prepare:.1} | {sign:.1} | {decode_48:.1} | {decode_96:.1} | {recover:.1} | {verify:.1} | {open:.1} | {aead:.1} | {critical:.1} | {reference:.1} |"
        );
    }

    // CPU cost per transaction on one core, from a 1,000-body block.
    let count: u32 = 1_000;
    let bodies: Vec<(B256, EncryptedBody)> = all.map_collect_vec(0..count, |i| {
        let mut rng = StdRng::seed_from_u64(u64::from(i) + 1);
        let envelope = Envelope {
            chain_id: 4217,
            sender: Address::ZERO,
            nonce_key: U256::ZERO,
            nonce: u64::from(i),
            gas_limit: 50_000,
        };
        EncryptedBody::encrypt(&mut rng, network, &envelope, &[0xab; 200])
            .map(|(b, id)| (id, b))
            .unwrap()
    });
    let seq = &Sequential;
    let per_tx = |ms: f64| ms * 1e3 / f64::from(count);
    let encrypt = median_ms(runs, || {
        let mut rng = StdRng::seed_from_u64(9);
        let envelope = Envelope {
            chain_id: 4217,
            sender: Address::ZERO,
            nonce_key: U256::ZERO,
            nonce: 0,
            gas_limit: 50_000,
        };
        black_box(EncryptedBody::encrypt(&mut rng, network, &envelope, &[0xab; 200]).unwrap());
    });
    let prepare = median_ms(runs, || {
        black_box(fast::prepare(&bodies, seq).unwrap());
    });
    let prepared = fast::prepare(&bodies, seq).unwrap();
    let sign = median_ms(runs, || {
        black_box(fast::sign(&shares[0], &prepared, seq));
    });
    let quorum_shares: Vec<_> = shares[..quorum_size]
        .iter()
        .map(|s| (s.index, fast::sign(s, &prepared, seq)))
        .collect();
    let compressed = fast::encode_compressed(&quorum_shares[0].1);
    let uncompressed = fast::encode_uncompressed(&quorum_shares[0].1);
    let decode_48 = median_ms(runs, || {
        black_box(fast::decode(&compressed, true, seq).unwrap());
    });
    let decode_96 = median_ms(runs, || {
        black_box(fast::decode(&uncompressed, false, seq).unwrap());
    });
    let recover = median_ms(runs, || {
        black_box(fast::recover(&quorum_shares, seq).unwrap());
    });
    let keys = fast::recover(&quorum_shares, seq).unwrap();
    let verify = median_ms(runs, || {
        fast::verify_keys(&mut rng, &network_point, &prepared, &keys, seq).unwrap();
    });
    let open = median_ms(runs, || {
        black_box(fast::open_keys(&mut rng, &prepared, &keys, seq).unwrap());
    });
    println!();
    println!(
        "one core, us per tx: encrypt(sender) {:.1} | prepare {:.1} | sign {:.1} | decode 48B {:.1} | decode 96B {:.2} | recover {:.1} | verify keys {:.1} | pair+FO {:.1}",
        encrypt * 1e3,
        per_tx(prepare),
        per_tx(sign),
        per_tx(decode_48),
        per_tx(decode_96),
        per_tx(recover),
        per_tx(verify),
        per_tx(open)
    );
}
