#![allow(missing_docs)]

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use tempo_zk::{Fr, Proof, poseidon::poseidon7, test_utils::TestTrapdoor, verify_many};

fn proofs(trapdoor: &TestTrapdoor, n: u64) -> Vec<(Proof, Fr)> {
    (0..n)
        .map(|i| {
            let input = Fr::from(1_000 + i);
            (Proof::decode(&trapdoor.prove(&input, i)).unwrap(), input)
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let trapdoor = TestTrapdoor::new(1);
    let key = trapdoor.verifying_key().prepare();
    let proofs = proofs(&trapdoor, 256);
    let bytes = *proofs[0].0.as_bytes();

    c.bench_function("poseidon7", |b| {
        let inputs = [1u64, 2, 3, 4, 5, 6, 7].map(Fr::from);
        b.iter(|| poseidon7(black_box(&inputs)))
    });
    c.bench_function("decode proof", |b| {
        b.iter(|| Proof::decode(black_box(&bytes)).unwrap())
    });
    c.bench_function("verify one", |b| {
        b.iter(|| assert!(key.verify(black_box(&proofs[0].0), &proofs[0].1)))
    });
    for n in [16, 64] {
        c.bench_function(&format!("verify batch of {n}"), |b| {
            b.iter_batched(
                || proofs[..n].iter().map(|(p, x)| (p, *x)).collect::<Vec<_>>(),
                |items| assert!(key.verify_batch(&items)),
                BatchSize::SmallInput,
            )
        });
    }
    c.bench_function("verify many 256 (parallel)", |b| {
        let items: Vec<_> = proofs.iter().map(|(p, x)| (p, *x)).collect();
        b.iter(|| assert!(verify_many(&key, black_box(&items)).iter().all(|ok| *ok)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
