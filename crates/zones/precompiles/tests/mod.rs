//! Zone precompile test suite.

use std::path::PathBuf;

use tempo_precompiles::test_util::foundry_artifact_path;

mod storage_layouts;

fn artifact(contract: &str) -> PathBuf {
    foundry_artifact_path(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/out"),
        &format!("{contract}.sol"),
        contract,
    )
}
