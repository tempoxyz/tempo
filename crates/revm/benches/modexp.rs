//! MODEXP precompile benchmarks based on public ethPandaOps/EEST perfnet cases.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use revm::precompile::{u64_to_address, Precompiles};
use std::hint::black_box;

const MODEXP_ADDRESS: u64 = 5;
const GAS_LIMIT: u64 = u64::MAX;
const RESERVOIR: u64 = 0;

struct ModexpCase {
    name: &'static str,
    base: Vec<u8>,
    exponent: Vec<u8>,
    modulus: Vec<u8>,
}

impl ModexpCase {
    fn new(name: &'static str, base: Vec<u8>, exponent: Vec<u8>, modulus: Vec<u8>) -> Self {
        Self {
            name,
            base,
            exponent,
            modulus,
        }
    }
}

fn repeated(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn mod_even_case(name: &'static str, bytes: usize, exponent_bytes: usize) -> ModexpCase {
    let mut modulus = repeated(0xff, bytes);
    *modulus.last_mut().expect("modulus is non-empty") = 0x00;

    ModexpCase::new(
        name,
        repeated(0xff, bytes),
        repeated(0xff, exponent_bytes),
        modulus,
    )
}

fn mod_odd_32b_exp_cover_windows() -> ModexpCase {
    ModexpCase::new(
        "mod_odd_32b_exp_cover_windows",
        repeated(0xff, 32),
        b"\x12\x34\x56\x70".repeat(8),
        {
            let mut modulus = repeated(0xff, 32);
            *modulus.last_mut().expect("modulus is non-empty") = 0x01;
            modulus
        },
    )
}

fn perfnet_cases() -> Vec<ModexpCase> {
    vec![
        mod_even_case("mod_even_8b_exp_896", 8, 112),
        mod_even_case("mod_even_16b_exp_320", 16, 40),
        mod_even_case("mod_even_24b_exp_168", 24, 21),
        mod_even_case("mod_even_32b_exp_40", 32, 5),
        mod_odd_32b_exp_cover_windows(),
    ]
}

fn push_len(input: &mut Vec<u8>, len: usize) {
    input.extend_from_slice(&[0; 24]);
    input.extend_from_slice(&(len as u64).to_be_bytes());
}

fn encode_modexp_input(case: &ModexpCase) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(96 + case.base.len() + case.exponent.len() + case.modulus.len());

    push_len(&mut input, case.base.len());
    push_len(&mut input, case.exponent.len());
    push_len(&mut input, case.modulus.len());
    input.extend_from_slice(&case.base);
    input.extend_from_slice(&case.exponent);
    input.extend_from_slice(&case.modulus);
    input
}

fn modexp_bench(c: &mut Criterion) {
    let precompiles = Precompiles::berlin();
    let modexp = precompiles
        .get(&u64_to_address(MODEXP_ADDRESS))
        .expect("MODEXP precompile exists in Berlin");

    let mut group = c.benchmark_group("revm/modexp");

    for case in perfnet_cases() {
        let input = encode_modexp_input(&case);
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(case.name),
            &input,
            |b, input| {
                b.iter(|| {
                    let output = modexp
                        .execute(black_box(input), GAS_LIMIT, RESERVOIR)
                        .expect("MODEXP benchmark input succeeds");
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, modexp_bench);
criterion_main!(benches);
