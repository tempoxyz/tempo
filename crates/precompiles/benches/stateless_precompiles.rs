//! Direct stateless precompile microbenchmarks.
//!
//! This target measures only the resolved precompile implementation. Transaction decoding, EVM
//! call machinery, block validation, and state-root work belong to separate benchmark layers.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use revm::{
    handler::EthPrecompiles,
    precompile::{Precompile as RevmPrecompile, PrecompileSpecId, PrecompileStatus},
};
use serde::Serialize;
use std::{env, fs, hint::black_box, path::PathBuf};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    benchmark::{BenchmarkProvenance, StatelessPrecompileCase, identity_benchmark_cases},
    ethereum_precompile_spec,
};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const BENCHMARK_GROUP: &str = "stateless_precompiles/direct";
const MANIFEST_ENV: &str = "TEMPO_BENCH_MANIFEST";
const TARGET_HARDFORK: TempoHardfork = TempoHardfork::T7;

fn stateless_precompiles(c: &mut Criterion) {
    let cases = identity_benchmark_cases(TARGET_HARDFORK);

    preflight(&cases);
    write_manifest_if_requested(&cases);

    let mut group = c.benchmark_group(BENCHMARK_GROUP);
    for case in &cases {
        let precompile = resolve_precompile(case);
        let case_name = case_name(case);

        // One element represents one unit of charged regular gas.
        group.throughput(Throughput::Elements(case.expected.gas_used));
        group.bench_with_input(
            BenchmarkId::new(case.precompile.name.as_str(), case_name),
            case,
            |b, case| {
                b.iter(|| {
                    // The returned Bytes and Result are consumed and dropped inside the timed
                    // closure. This intentionally includes output allocation, copying, and
                    // deallocation using the same jemalloc configuration as the EVM benches.
                    black_box(precompile.execute(
                        black_box(case.input.as_ref()),
                        black_box(case.gas_limit),
                        black_box(case.state_gas_reservoir),
                    ))
                });
            },
        );
    }
    group.finish();
}

fn resolve_precompile(case: &StatelessPrecompileCase) -> &'static RevmPrecompile {
    let spec = ethereum_precompile_spec(case.hardfork);
    EthPrecompiles::new(spec)
        .precompiles
        .get(&case.precompile.address)
        .unwrap_or_else(|| {
            panic!(
                "{} is not registered at {} for {:?}",
                case.precompile.name, case.precompile.address, case.hardfork
            )
        })
}

fn preflight(cases: &[StatelessPrecompileCase]) {
    for case in cases {
        let precompile = resolve_precompile(case);
        assert_eq!(
            precompile.id(),
            &case.precompile.registry_id,
            "{} resolved registry ID {:?}, expected {:?}",
            case.id,
            precompile.id(),
            case.precompile.registry_id,
        );

        let result = precompile.execute(
            case.input.as_ref(),
            case.gas_limit,
            case.state_gas_reservoir,
        );
        case.validate_result(&result)
            .unwrap_or_else(|error| panic!("preflight failed: {error}"));
    }
}

fn case_name(case: &StatelessPrecompileCase) -> &str {
    let (namespace, name) = case
        .id
        .split_once('/')
        .unwrap_or_else(|| panic!("benchmark case ID {} has no namespace", case.id));
    assert_eq!(
        namespace, case.precompile.name,
        "benchmark case ID {} does not use the {} namespace",
        case.id, case.precompile.name
    );
    name
}

fn criterion_id(case: &StatelessPrecompileCase) -> String {
    format!("{BENCHMARK_GROUP}/{}", case.id)
}

fn write_manifest_if_requested(cases: &[StatelessPrecompileCase]) {
    let Some(path) = env::var_os(MANIFEST_ENV).map(PathBuf::from) else {
        return;
    };

    let manifest = CaseManifest {
        schema_version: 1,
        suite: SuiteManifest {
            id: "stateless-precompiles",
            version: 1,
            benchmark_layer: "direct",
        },
        cases: cases.iter().map(CaseManifestEntry::from).collect(),
    };
    let mut json = serde_json::to_string_pretty(&manifest).expect("serialize benchmark manifest");
    json.push('\n');

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "create benchmark manifest directory {}: {error}",
                parent.display()
            )
        });
    }
    fs::write(&path, json)
        .unwrap_or_else(|error| panic!("write benchmark manifest {}: {error}", path.display()));
}

#[derive(Serialize)]
struct CaseManifest {
    schema_version: u32,
    suite: SuiteManifest,
    cases: Vec<CaseManifestEntry>,
}

#[derive(Serialize)]
struct SuiteManifest {
    id: &'static str,
    version: u32,
    benchmark_layer: &'static str,
}

#[derive(Serialize)]
struct CaseManifestEntry {
    case_id: String,
    criterion_id: String,
    precompile: PrecompileManifest,
    protocol: ProtocolManifest,
    input: InputManifest,
    gas_limit: u64,
    state_gas_reservoir: u64,
    gas_used: u64,
    gas_refunded: i64,
    state_gas_used: u64,
    expected: ExpectedManifest,
    provenance: Option<ProvenanceManifest>,
}

impl From<&StatelessPrecompileCase> for CaseManifestEntry {
    fn from(case: &StatelessPrecompileCase) -> Self {
        let precompile_spec =
            PrecompileSpecId::from_spec_id(ethereum_precompile_spec(case.hardfork));
        Self {
            case_id: case.id.clone(),
            criterion_id: criterion_id(case),
            precompile: PrecompileManifest {
                name: case.precompile.name.clone(),
                registry_id: case.precompile.registry_id.name().into(),
                address: format!("{:#x}", case.precompile.address),
            },
            protocol: ProtocolManifest {
                hardfork: case.hardfork.to_string(),
                precompile_spec: format!("{precompile_spec:?}"),
            },
            input: InputManifest {
                kind: case.input.kind.clone(),
                length: case.input.len(),
            },
            gas_limit: case.gas_limit,
            state_gas_reservoir: case.state_gas_reservoir,
            gas_used: case.expected.gas_used,
            gas_refunded: case.expected.gas_refunded,
            state_gas_used: case.expected.state_gas_used,
            expected: ExpectedManifest {
                status: status_name(&case.expected.status),
                output_length: case.expected.output.len(case.input.as_ref()),
                state_gas_reservoir_remaining: case.expected.state_gas_reservoir_remaining,
            },
            provenance: case.provenance.as_ref().map(ProvenanceManifest::from),
        }
    }
}

#[derive(Serialize)]
struct PrecompileManifest {
    name: String,
    registry_id: String,
    address: String,
}

#[derive(Serialize)]
struct ProtocolManifest {
    hardfork: String,
    precompile_spec: String,
}

#[derive(Serialize)]
struct InputManifest {
    kind: String,
    length: usize,
}

#[derive(Serialize)]
struct ExpectedManifest {
    status: &'static str,
    output_length: usize,
    state_gas_reservoir_remaining: u64,
}

#[derive(Serialize)]
struct ProvenanceManifest {
    source: String,
    reference: String,
}

impl From<&BenchmarkProvenance> for ProvenanceManifest {
    fn from(provenance: &BenchmarkProvenance) -> Self {
        Self {
            source: provenance.source.clone(),
            reference: provenance.reference.clone(),
        }
    }
}

fn status_name(status: &PrecompileStatus) -> &'static str {
    match status {
        PrecompileStatus::Success => "success",
        PrecompileStatus::Revert => "revert",
        PrecompileStatus::Halt(_) => "halt",
    }
}

criterion_group!(benches, stateless_precompiles);
criterion_main!(benches);
