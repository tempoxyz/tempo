//! Per-block cost of each encrypted-transaction stage with 16 validators, on one core and on all.

use alloy_primitives::{Address, U256};
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal_anonymous,
    primitives::{sharing::Mode, variant::MinSig},
};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{N3f1, NZU32, NZUsize};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use tempo_encrypted_tx::{
    EncryptedBody, Envelope, key_shares, recover_keys, verify_key_shares, verify_keys,
};

const VALIDATORS: u32 = 16;
const BATCH: usize = 1_000;

fn envelope(nonce: u64) -> Envelope {
    Envelope {
        chain_id: 4217,
        sender: Address::repeat_byte(0x11),
        nonce_key: U256::ZERO,
        nonce,
        gas_limit: 100_000,
    }
}

fn pipeline(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let (sharing, shares) =
        deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::NonZeroCounter, NZU32!(VALIDATORS));
    let network = *sharing.public();
    let cores = std::thread::available_parallelism()
        .expect("core count")
        .get();
    let rayon = Rayon::new(NZUsize!(cores)).expect("thread pool");
    let body = vec![0xab; 256];

    let (bodies, ids): (Vec<_>, Vec<_>) = (0..BATCH as u64)
        .map(|nonce| EncryptedBody::encrypt(&mut rng, network, &envelope(nonce), &body).unwrap())
        .unzip();
    let quorum: Vec<_> = shares[..sharing.required() as usize]
        .iter()
        .map(|share| key_shares(share, &ids, &Sequential))
        .collect();
    let keys = recover_keys(&sharing, &quorum, &Sequential).unwrap();

    let mut group = c.benchmark_group("encrypted_tx");
    group.sample_size(10);
    group.bench_function("encrypt_256B", |b| {
        b.iter(|| EncryptedBody::encrypt(&mut rng, network, &envelope(0), &body).unwrap())
    });
    group.throughput(Throughput::Elements(BATCH as u64));

    macro_rules! stage {
        ($name:literal, |$s:ident| $run:expr) => {
            group.bench_function(BenchmarkId::new($name, "sequential"), |b| {
                let $s = &Sequential;
                b.iter(|| $run)
            });
            group.bench_function(BenchmarkId::new($name, format!("rayon-{cores}")), |b| {
                let $s = &rayon;
                b.iter(|| $run)
            });
        };
    }

    stage!("sign_shares", |s| key_shares(&shares[0], &ids, s));
    stage!("verify_shares", |s| verify_key_shares(
        &mut StdRng::seed_from_u64(1),
        &sharing,
        shares[0].index,
        &ids,
        &quorum[0],
        s
    )
    .unwrap());
    stage!("recover_keys", |s| recover_keys(&sharing, &quorum, s)
        .unwrap());
    stage!("verify_keys", |s| verify_keys(
        &mut StdRng::seed_from_u64(1),
        &network,
        &ids,
        &keys,
        s
    )
    .unwrap());
    stage!("decrypt", |s| s
        .map_collect_vec(bodies.iter().zip(&keys), |(body, key)| body
            .decrypt(key)
            .unwrap()));
    group.finish();
}

criterion_group!(benches, pipeline);
criterion_main!(benches);
