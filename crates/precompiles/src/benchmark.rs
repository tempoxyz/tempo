//! Shared models for direct precompile benchmarks.
//!
//! Benchmark case definitions are Tempo-owned. External suites such as EEST can be translated
//! into this model, but do not define its storage or execution format.

use alloy::primitives::{Address, Bytes};
use revm::precompile::{PrecompileId, PrecompileResult, PrecompileStatus, u64_to_address};
use tempo_chainspec::hardfork::TempoHardfork;

/// Describes the precompile selected by a benchmark case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkPrecompile {
    /// Stable human-readable precompile name.
    pub name: String,
    /// Expected identifier of the implementation resolved from the registry.
    pub registry_id: PrecompileId,
    /// Address used to resolve the implementation from the production precompile registry.
    pub address: Address,
}

/// Describes where a benchmark case originated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkProvenance {
    /// Source suite or project, for example `tempo` or `eest`.
    pub source: String,
    /// Stable source identifier such as an issue or pinned upstream case.
    pub reference: String,
}

/// Materialized benchmark input and a stable description of how it was produced.
///
/// `kind` is deliberately Tempo-owned rather than tied to an external fixture format. Examples
/// include `zero-filled`, `inline`, or a future Tempo-specific proof generator name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkInput {
    /// Stable input source or materialization kind.
    pub kind: String,
    /// Bytes passed directly to the precompile.
    pub bytes: Bytes,
}

impl BenchmarkInput {
    /// Returns the materialized input length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the materialized input is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for BenchmarkInput {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// Expected bytes for a successful, reverted, or halted precompile result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedOutput {
    /// The output must be byte-for-byte equal to the input.
    SameAsInput,
    /// The output must equal these exact bytes.
    Exact(Bytes),
}

impl ExpectedOutput {
    /// Returns the expected output length for `input`.
    pub fn len(&self, input: &[u8]) -> usize {
        match self {
            Self::SameAsInput => input.len(),
            Self::Exact(bytes) => bytes.len(),
        }
    }

    fn as_bytes<'a>(&'a self, input: &'a [u8]) -> &'a [u8] {
        match self {
            Self::SameAsInput => input,
            Self::Exact(bytes) => bytes,
        }
    }
}

/// Correctness expectations checked before a case is benchmarked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPrecompileResult {
    /// Expected execution status.
    pub status: PrecompileStatus,
    /// Expected regular gas charged by the precompile.
    pub gas_used: u64,
    /// Expected regular gas refund.
    pub gas_refunded: i64,
    /// Expected state gas charged by the precompile.
    pub state_gas_used: u64,
    /// Expected state-gas reservoir returned after execution.
    pub state_gas_reservoir_remaining: u64,
    /// Expected output bytes.
    pub output: ExpectedOutput,
}

/// A materialized, fixture-format-independent stateless precompile benchmark case.
///
/// Input generation and external fixture formats intentionally sit outside this type. Generators
/// and adapters only need to produce this materialized representation for the direct runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatelessPrecompileCase {
    /// Stable case identifier, namespaced by precompile (for example `identity/32-bytes`).
    pub id: String,
    /// Precompile to resolve and execute.
    pub precompile: BenchmarkPrecompile,
    /// Explicit Tempo hardfork under which the case runs.
    pub hardfork: TempoHardfork,
    /// Materialized precompile input and its Tempo-owned kind.
    pub input: BenchmarkInput,
    /// Regular gas supplied to the precompile.
    pub gas_limit: u64,
    /// State-gas reservoir supplied to the precompile.
    pub state_gas_reservoir: u64,
    /// Correctness expectations checked outside the timed region.
    pub expected: ExpectedPrecompileResult,
    /// Optional source attribution for supplemental cases.
    pub provenance: Option<BenchmarkProvenance>,
}

impl StatelessPrecompileCase {
    /// Validates a direct precompile result against this case's expectations.
    pub fn validate_result(
        &self,
        result: &PrecompileResult,
    ) -> Result<(), PrecompileCaseValidationError> {
        let output = result
            .as_ref()
            .map_err(|error| PrecompileCaseValidationError::Fatal {
                case_id: self.id.clone(),
                error: error.to_string(),
            })?;

        if output.status != self.expected.status {
            return Err(PrecompileCaseValidationError::Status {
                case_id: self.id.clone(),
                expected: self.expected.status.clone(),
                actual: output.status.clone(),
            });
        }
        if output.gas_used != self.expected.gas_used {
            return Err(PrecompileCaseValidationError::GasUsed {
                case_id: self.id.clone(),
                expected: self.expected.gas_used,
                actual: output.gas_used,
            });
        }
        if output.gas_refunded != self.expected.gas_refunded {
            return Err(PrecompileCaseValidationError::GasRefunded {
                case_id: self.id.clone(),
                expected: self.expected.gas_refunded,
                actual: output.gas_refunded,
            });
        }
        if output.state_gas_used != self.expected.state_gas_used {
            return Err(PrecompileCaseValidationError::StateGasUsed {
                case_id: self.id.clone(),
                expected: self.expected.state_gas_used,
                actual: output.state_gas_used,
            });
        }
        if output.reservoir != self.expected.state_gas_reservoir_remaining {
            return Err(PrecompileCaseValidationError::StateGasReservoirRemaining {
                case_id: self.id.clone(),
                expected: self.expected.state_gas_reservoir_remaining,
                actual: output.reservoir,
            });
        }

        let expected = self.expected.output.as_bytes(self.input.as_ref());
        if output.bytes.as_ref() != expected {
            return Err(PrecompileCaseValidationError::Output {
                case_id: self.id.clone(),
                expected_len: expected.len(),
                actual_len: output.bytes.len(),
            });
        }

        Ok(())
    }
}

/// Failure returned when a benchmark case does not execute as declared.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileCaseValidationError {
    /// The precompile returned a fatal provider error.
    #[error("benchmark case {case_id} returned a fatal precompile error: {error}")]
    Fatal {
        /// Stable benchmark case ID.
        case_id: String,
        /// Provider error text.
        error: String,
    },
    /// The returned precompile status differed from the expected status.
    #[error("benchmark case {case_id} returned status {actual:?}, expected {expected:?}")]
    Status {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected status.
        expected: PrecompileStatus,
        /// Actual status.
        actual: PrecompileStatus,
    },
    /// The regular gas charge differed from the expected charge.
    #[error("benchmark case {case_id} used {actual} gas, expected {expected}")]
    GasUsed {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected gas charge.
        expected: u64,
        /// Actual gas charge.
        actual: u64,
    },
    /// The regular gas refund differed from the expected refund.
    #[error("benchmark case {case_id} refunded {actual} gas, expected {expected}")]
    GasRefunded {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected gas refund.
        expected: i64,
        /// Actual gas refund.
        actual: i64,
    },
    /// The state gas charge differed from the expected charge.
    #[error("benchmark case {case_id} used {actual} state gas, expected {expected}")]
    StateGasUsed {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected state gas charge.
        expected: u64,
        /// Actual state gas charge.
        actual: u64,
    },
    /// The returned state-gas reservoir differed from the expected remainder.
    #[error("benchmark case {case_id} returned state-gas reservoir {actual}, expected {expected}")]
    StateGasReservoirRemaining {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected remaining reservoir.
        expected: u64,
        /// Actual remaining reservoir.
        actual: u64,
    },
    /// The output differed from the expected bytes.
    #[error(
        "benchmark case {case_id} returned incorrect output ({actual_len} bytes, expected {expected_len})"
    )]
    Output {
        /// Stable benchmark case ID.
        case_id: String,
        /// Expected output length.
        expected_len: usize,
        /// Actual output length.
        actual_len: usize,
    },
}

/// Returns the direct Identity benchmark cases for an explicit Tempo hardfork.
///
/// Cases around 32-byte word boundaries are Tempo-native. The fixed 0/32/256/1024-byte sizes
/// overlap the pinned EEST benchmark suite and carry that supplemental provenance. Inputs are
/// materialized here because Identity only needs deterministic zero-filled byte strings; a general
/// workload generator is intentionally outside the scope of this direct benchmark.
pub fn identity_benchmark_cases(hardfork: TempoHardfork) -> Vec<StatelessPrecompileCase> {
    const EEST_REFERENCE: &str = concat!(
        "execution-specs/tests-benchmark@v0.0.9/",
        "tests/benchmark/compute/precompile/test_identity.py::test_identity_fixed_size"
    );

    [
        ("empty", 0, Some(EEST_REFERENCE)),
        ("1-byte", 1, None),
        ("31-bytes", 31, None),
        ("32-bytes", 32, Some(EEST_REFERENCE)),
        ("33-bytes", 33, None),
        ("256-bytes", 256, Some(EEST_REFERENCE)),
        ("1024-bytes", 1_024, Some(EEST_REFERENCE)),
        ("128-kib", 128 * 1_024, None),
    ]
    .into_iter()
    .map(|(name, input_len, eest_reference)| {
        let gas_used = identity_gas(input_len);
        let provenance = eest_reference.map_or_else(
            || BenchmarkProvenance {
                source: "tempo".into(),
                reference: "RETH-1014".into(),
            },
            |reference| BenchmarkProvenance {
                source: "eest".into(),
                reference: reference.into(),
            },
        );

        StatelessPrecompileCase {
            id: format!("identity/{name}"),
            precompile: BenchmarkPrecompile {
                name: "identity".into(),
                registry_id: PrecompileId::Identity,
                address: u64_to_address(4),
            },
            hardfork,
            input: BenchmarkInput {
                kind: "zero-filled".into(),
                bytes: Bytes::from(vec![0_u8; input_len]),
            },
            // Use the exact schedule charge so the case validates the successful boundary without
            // emitting an unbounded sentinel into downstream JSON consumers.
            gas_limit: gas_used,
            state_gas_reservoir: 0,
            expected: ExpectedPrecompileResult {
                status: PrecompileStatus::Success,
                gas_used,
                gas_refunded: 0,
                state_gas_used: 0,
                state_gas_reservoir_remaining: 0,
                output: ExpectedOutput::SameAsInput,
            },
            provenance: Some(provenance),
        }
    })
    .collect()
}

const fn identity_gas(input_len: usize) -> u64 {
    const BASE_GAS: u64 = 15;
    const GAS_PER_WORD: u64 = 3;
    let words = (input_len as u64).div_ceil(32);
    BASE_GAS + GAS_PER_WORD * words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_precompile_spec;
    use revm::{precompile::PrecompileOutput, primitives::hardfork::SpecId};

    fn case() -> StatelessPrecompileCase {
        StatelessPrecompileCase {
            id: "identity/test".into(),
            precompile: BenchmarkPrecompile {
                name: "identity".into(),
                registry_id: PrecompileId::Identity,
                address: Address::from([0_u8; 20]),
            },
            hardfork: TempoHardfork::T7,
            input: BenchmarkInput {
                kind: "inline".into(),
                bytes: Bytes::from_static(b"tempo"),
            },
            gas_limit: 18,
            state_gas_reservoir: 7,
            expected: ExpectedPrecompileResult {
                status: PrecompileStatus::Success,
                gas_used: 18,
                gas_refunded: 0,
                state_gas_used: 0,
                state_gas_reservoir_remaining: 7,
                output: ExpectedOutput::SameAsInput,
            },
            provenance: None,
        }
    }

    #[test]
    fn validates_expected_result() {
        let case = case();
        let result = Ok(PrecompileOutput::new(18, case.input.bytes.clone(), 7));
        assert!(case.validate_result(&result).is_ok());
    }

    #[test]
    fn rejects_wrong_gas_and_output() {
        let case = case();

        let wrong_gas = Ok(PrecompileOutput::new(19, case.input.bytes.clone(), 7));
        assert!(matches!(
            case.validate_result(&wrong_gas),
            Err(PrecompileCaseValidationError::GasUsed { .. })
        ));

        let wrong_output = Ok(PrecompileOutput::new(18, Bytes::from_static(b"wrong"), 7));
        assert!(matches!(
            case.validate_result(&wrong_output),
            Err(PrecompileCaseValidationError::Output { .. })
        ));

        let wrong_reservoir = Ok(PrecompileOutput::new(18, case.input.bytes.clone(), 6));
        assert!(matches!(
            case.validate_result(&wrong_reservoir),
            Err(PrecompileCaseValidationError::StateGasReservoirRemaining { .. })
        ));
    }

    #[test]
    fn identity_cases_have_stable_ids_and_gas() {
        let cases = identity_benchmark_cases(TempoHardfork::T7);

        assert_eq!(
            cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            [
                "identity/empty",
                "identity/1-byte",
                "identity/31-bytes",
                "identity/32-bytes",
                "identity/33-bytes",
                "identity/256-bytes",
                "identity/1024-bytes",
                "identity/128-kib",
            ]
        );
        assert_eq!(
            cases
                .iter()
                .map(|case| case.expected.gas_used)
                .collect::<Vec<_>>(),
            [15, 18, 18, 18, 21, 39, 111, 12_303]
        );
        assert!(cases.iter().all(|case| case.hardfork == TempoHardfork::T7));
        assert!(cases.iter().all(|case| case.input.kind == "zero-filled"));
        assert!(cases.iter().all(|case| {
            case.precompile.registry_id == PrecompileId::Identity
                && case.gas_limit == case.expected.gas_used
        }));
    }

    #[test]
    fn tempo_precompile_spec_boundary_is_explicit() {
        assert_eq!(ethereum_precompile_spec(TempoHardfork::T1B), SpecId::PRAGUE);
        assert_eq!(ethereum_precompile_spec(TempoHardfork::T1C), SpecId::OSAKA);
        assert_eq!(ethereum_precompile_spec(TempoHardfork::T7), SpecId::OSAKA);
    }
}
