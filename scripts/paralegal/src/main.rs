use anyhow::{Context as _, Result, ensure};
use paralegal_policy::{
    Context, EdgeSelection, GraphLocation, IntoIterGlobalNodes, NodeQueries,
    paralegal_pdg::{Identifier, NodeCluster},
};
use std::{collections::BTreeSet, path::PathBuf};

const ROLE_ROOTS: &[&str] = &[
    "grant_role",
    "revoke_role",
    "renounce_role",
    "set_role_admin",
];
const TRANSFER_ROOTS: &[&str] = &[
    "transfer",
    "transfer_from",
    "transfer_with_memo",
    "transfer_from_with_memo",
];

fn main() -> Result<()> {
    let graph = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("expected graph artifact path")?,
    );
    let result = GraphLocation::custom(graph).with_context(|ctx| {
        let expected: BTreeSet<_> = ROLE_ROOTS.iter().chain(TRANSFER_ROOTS).copied().collect();
        let mut seen = BTreeSet::new();
        let mut obligations = 0;
        let mut failures = Vec::new();
        for (controller, pdg) in ctx.all_controllers() {
            let name = pdg.name.to_string();
            ensure!(
                expected.contains(name.as_str()),
                "unexpected controller {name}"
            );
            ensure!(seen.insert(name.clone()), "duplicate controller {name}");
            let requirements: &[(&str, &str)] = if ROLE_ROOTS.contains(&name.as_str()) {
                &[("role_authorization", "role_write")]
            } else {
                &[
                    ("pause_check", "transfer_effect"),
                    ("transfer_authorization", "transfer_effect"),
                ]
            };
            for &(check, effect) in requirements {
                let checks: Vec<_> = ctx
                    .marked_nodes(Identifier::new_intern(check))
                    .filter(|node| node.controller_id() == controller)
                    .collect();
                let effects: Vec<_> = ctx
                    .marked_nodes(Identifier::new_intern(effect))
                    .filter(|node| node.controller_id() == controller)
                    .collect();
                ensure!(!checks.is_empty(), "{name}: missing {check} marker");
                ensure!(!effects.is_empty(), "{name}: missing {effect} marker");
                let sources = NodeCluster::try_from_iter(checks.iter().copied()).unwrap();
                // Batch the upstream control-influence relation: zero or more
                // data edges followed by control edges. Including the sources
                // also handles unused results without upstream's empty-set panic.
                let seeds = NodeCluster::try_from_iter(
                    checks
                        .into_iter()
                        .chain((&sources).influencees(&ctx, EdgeSelection::Data)),
                )
                .unwrap();
                let sinks = NodeCluster::try_from_iter(effects.iter().copied()).unwrap();
                let missing = (&seeds).flows_to_all(&sinks, &ctx, EdgeSelection::Control);
                let passed = effects.len()
                    - missing
                        .as_ref()
                        .map_or(0, |nodes| nodes.iter_nodes().count());
                println!("{name}: {check} -> {effect}: {passed}/{}", effects.len());
                obligations += effects.len();
                if passed != effects.len() {
                    failures.push(format!("{name}: {check} does not control every {effect}"));
                }
            }
        }
        let seen_refs: BTreeSet<_> = seen.iter().map(String::as_str).collect();
        ensure!(
            seen_refs == expected,
            "controller coverage mismatch: expected {expected:?}, got {seen:?}"
        );
        ensure!(failures.is_empty(), "{}", failures.join("\n"));
        println!(
            "PASS: 3 policies, {} entrypoints, {obligations} control-dependence obligations",
            seen.len()
        );
        Ok(())
    })?;
    ensure!(result.success, "Paralegal diagnostics reported errors");
    println!("{}", result.stats);
    Ok(())
}
