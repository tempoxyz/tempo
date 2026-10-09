//! ABI compatibility checker between Zone Rust bindings and Solidity interfaces.

use std::{collections::BTreeMap, path::PathBuf};

use alloy::{
    json_abi::{Error, Event, Function, JsonAbi},
    sol_types::JsonAbiExt,
};
use eyre::{WrapErr, bail, ensure};
use tempo_contracts::zones::{self, IZoneInbox, IZoneOutbox, TempoState, ZoneFactory, ZonePortal};
use tempo_precompiles::test_util::{
    abi_conformance::{AbiSurface, compare_abi},
    foundry_artifact_path,
};

struct InterfaceSpec {
    name: &'static str,
    artifact_name: &'static str,
    source: &'static str,
    rust: fn() -> eyre::Result<AbiSurface>,
    ignored_functions: &'static [&'static str],
}

macro_rules! interface {
    ($name:ident, $artifact:literal) => {
        InterfaceSpec {
            name: stringify!($name),
            artifact_name: $artifact,
            source: "IZone.sol",
            rust: || Ok(AbiSurface::from_abi(&$name::abi::contract())),
            ignored_functions: &[],
        }
    };
}

/// Projects a cumulative ABI to one hardfork by removing typed historical fragments.
struct AbiProjection {
    retired: JsonAbi,
}

impl AbiProjection {
    /// Applies this projection to an ABI containing both historical and current entries.
    fn apply(self, mut base: JsonAbi) -> eyre::Result<JsonAbi> {
        ensure!(
            self.retired.constructor.is_none()
                && self.retired.fallback.is_none()
                && self.retired.receive.is_none(),
            "retired ABI fragments may only contain functions, events, and errors"
        );

        remove_items(
            &mut base.functions,
            self.retired.functions,
            "function",
            function_key,
        )?;
        remove_items(&mut base.events, self.retired.events, "event", event_key)?;
        remove_items(&mut base.errors, self.retired.errors, "error", error_key)?;

        Ok(base)
    }
}

fn remove_items<T>(
    base: &mut BTreeMap<String, Vec<T>>,
    retired: BTreeMap<String, Vec<T>>,
    kind: &str,
    key: fn(&T) -> String,
) -> eyre::Result<()> {
    for (name, retired) in retired {
        let Some(current) = base.get_mut(&name) else {
            bail!("cannot retire {kind} `{name}` because it is absent from the cumulative ABI");
        };
        for item in retired {
            let item_key = key(&item);
            let Some(index) = current
                .iter()
                .position(|candidate| key(candidate) == item_key)
            else {
                bail!(
                    "cannot retire {kind} `{item_key}` because it is absent from the cumulative ABI"
                );
            };
            current.remove(index);
        }
        if current.is_empty() {
            base.remove(&name);
        }
    }
    Ok(())
}

fn function_key(function: &Function) -> String {
    format!(
        "{} [{:?}]",
        function.signature_with_outputs(),
        function.state_mutability
    )
}

fn event_key(event: &Event) -> String {
    let indexed = event
        .inputs
        .iter()
        .map(|input| input.indexed)
        .collect::<Vec<_>>();
    format!(
        "{} [indexed={indexed:?}, anonymous={}]",
        event.signature(),
        event.anonymous
    )
}

fn error_key(error: &Error) -> String {
    error.signature()
}

fn tempo_state_t13_surface() -> eyre::Result<AbiSurface> {
    let abi = AbiProjection {
        retired: JsonAbi::from_iter([zones::legacyFinalizeTempoCall::abi().into()]),
    }
    .apply(TempoState::abi::contract())?;
    Ok(AbiSurface::from_abi(&abi))
}

fn zone_inbox_t13_surface() -> eyre::Result<AbiSurface> {
    let abi = AbiProjection {
        retired: JsonAbi::from_iter([zones::LegacyTempoAdvanced::abi().into()]),
    }
    .apply(IZoneInbox::abi::contract())?;
    Ok(AbiSurface::from_abi(&abi))
}

fn zone_portal_t13_surface() -> eyre::Result<AbiSurface> {
    let abi = AbiProjection {
        retired: JsonAbi::from_iter([
            zones::LegacyBatchSubmitted::abi().into(),
            ZonePortal::MAX_DEPOSITS_PER_TEMPO_BLOCKCall::abi().into(),
            ZonePortal::MAX_TOKENS_ENABLED_PER_TEMPO_BLOCKCall::abi().into(),
            zones::legacySubmitBatchCall::abi().into(),
        ]),
    }
    .apply(ZonePortal::abi::contract())?;
    Ok(AbiSurface::from_abi(&abi))
}

const INTERFACES: &[InterfaceSpec] = &[
    InterfaceSpec {
        name: "TempoState",
        artifact_name: "ITempoState",
        source: "IZone.sol",
        rust: tempo_state_t13_surface,
        ignored_functions: &[
            "readTempoStorageSlot(address,bytes32) returns (bytes32) [view]",
            "readTempoStorageSlots(address,bytes32[]) returns (bytes32[]) [view]",
        ],
    },
    InterfaceSpec {
        name: "IZoneInbox",
        artifact_name: "IZoneInbox",
        source: "IZone.sol",
        rust: zone_inbox_t13_surface,
        ignored_functions: &[],
    },
    interface!(IZoneOutbox, "IZoneOutbox"),
    interface!(ZoneFactory, "IZoneFactory"),
    InterfaceSpec {
        name: "ZonePortal",
        artifact_name: "IZonePortal",
        source: "IZone.sol",
        rust: zone_portal_t13_surface,
        ignored_functions: &[],
    },
];

#[derive(Debug, clap::Args)]
pub(crate) struct CheckAbi {
    /// Foundry output directory produced from `crates/contracts`.
    #[arg(long, default_value = "crates/contracts/out")]
    artifacts: PathBuf,
}

impl CheckAbi {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let mut failed = false;
        for spec in INTERFACES {
            let path = foundry_artifact_path(&self.artifacts, spec.source, spec.artifact_name);
            let rust = (spec.rust)()
                .wrap_err_with(|| format!("failed to construct the effective {} ABI", spec.name))?;
            let errors = compare_abi(&path, &rust, spec.ignored_functions)
                .err()
                .unwrap_or_default();
            if errors.is_empty() {
                eprintln!("  ✓  {}", spec.name);
                continue;
            }
            failed = true;
            eprintln!("  ✗  {}", spec.name);
            for error in errors {
                eprintln!("    {error}");
            }
        }
        if failed {
            bail!("Zone ABI compatibility check found differences");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_bindings_match_solidity_artifacts() {
        CheckAbi {
            artifacts: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../crates/contracts/out"),
        }
        .run()
        .unwrap();
    }

    #[test]
    fn projection_removes_typed_historical_entries() {
        let base = JsonAbi::parse([
            "function changed(bytes value)",
            "function changed(bytes[] values)",
            "event Changed(bytes value)",
            "event Changed(bytes[] values)",
            "error OldError()",
            "error NewError()",
        ])
        .unwrap();
        let retired = JsonAbi::parse([
            "function changed(bytes value)",
            "event Changed(bytes value)",
            "error OldError()",
        ])
        .unwrap();

        let actual = AbiProjection { retired }.apply(base).unwrap();
        let expected = AbiSurface::from_abi(
            &JsonAbi::parse([
                "function changed(bytes[] values)",
                "event Changed(bytes[] values)",
                "error NewError()",
            ])
            .unwrap(),
        );

        assert_eq!(AbiSurface::from_abi(&actual), expected);
    }

    #[test]
    fn projection_rejects_a_retired_entry_missing_from_the_union() {
        let error = AbiProjection {
            retired: JsonAbi::parse(["function missing()"]).unwrap(),
        }
        .apply(JsonAbi::new())
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot retire function `missing`")
        );
    }
}
