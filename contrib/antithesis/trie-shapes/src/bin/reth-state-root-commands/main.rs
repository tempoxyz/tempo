//! The reth-state-root test template's commands (`test/v1/reth_state_root`). Each asks the `serve`
//! process of reth-state-root-antithesis over the harness socket. Built without coverage
//! instrumentation (see contrib/antithesis/reth-state-root/Dockerfile), so only the server reports
//! coverage and has its threads paused.

mod check;

use antithesis_sdk::{
    assert_always, assert_always_or_unreachable, assert_unreachable, random::AntithesisRng,
};
use antithesis_trie_shapes::{
    harness::{self, BlockRoot, Client, Request, Response},
    proofs::Proved,
};
use eyre::{bail, eyre, Result, WrapErr};
use rand_09::Rng;
use serde_json::json;

/// Checks that the root the overlay serves at the tip equals the model's. Returns false when the
/// server went away.
fn check_root(client: &mut Client) -> Result<bool> {
    match client.call(&Request::CheckRoot)? {
        None => harness::unavailable().map(|()| false),
        Some(Response::Root { number, root }) => {
            println!("{}", json!({"root": {"number": number, "root": root}}));
            Ok(true)
        }
        Some(other) => bail!("unexpected answer to check_root: {other:?}"),
    }
}

/// Requests proofs at count random blocks of the summary's round, for targets drawn from its
/// accounts, and verifies each against the model's state root at that block. Returns false when
/// the server went away or the round ended before every proof was checked.
fn request_proofs(client: &mut Client, count: usize) -> Result<bool> {
    let Some(summary) = client.summary()? else { return harness::unavailable().map(|()| false) };
    let mut rng = AntithesisRng;
    for _ in 0..count {
        let BlockRoot { number, root } = summary.roots[rng.random_range(0..summary.roots.len())];
        let targets = check::targets(&mut rng, &summary.accounts, &summary.collider);
        let request =
            Request::GetProof { round: summary.round, block: number, targets: targets.clone() };
        let Proved { proofs, witness } = match client.call(&request)? {
            None => return harness::unavailable().map(|()| false),
            Some(Response::Proofs { proofs }) => serde_json::from_value(proofs)?,
            Some(Response::Rejected { reason }) => {
                return harness::rejected(&reason).map(|()| false)
            }
            Some(other) => bail!("unexpected answer to get_proof: {other:?}"),
        };
        let result = check::check(root, &targets, &proofs);
        assert_always!(
            result.is_ok(),
            "eth_getMultiProof proofs verify against the model's state root",
            &json!({"block": number, "targets": targets,
                "error": result.as_ref().err().map(|error| format!("{error:#}"))})
        );
        result.wrap_err_with(|| format!("proofs at block {number}"))?;
        let result = check::from_witness(root, &targets, &witness)
            .and_then(|proofs| check::check(root, &targets, &proofs));
        assert_always!(
            result.is_ok(),
            "Proofs rebuilt from the execution witness verify against the model's state root",
            &json!({"block": number, "targets": targets,
                "error": result.as_ref().err().map(|error| format!("{error:#}"))})
        );
        result.wrap_err_with(|| format!("witness proofs at block {number}"))?;
    }
    Ok(true)
}

/// anytime_root: the root the overlay serves at the tip equals the model's.
fn anytime_root() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return harness::unavailable() };
    check_root(&mut client).map(drop)
}

/// parallel_driver_proofs: one to four proof requests.
fn parallel_driver_proofs() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return harness::unavailable() };
    request_proofs(&mut client, AntithesisRng.random_range(1..=4)).map(drop)
}

/// eventually_persisted and finally_recovered: once every block is persisted, which makes the
/// server check the persisted state, the root at the tip and proofs, most of them reverted from
/// the tip. Returns false when the server went away or the round ended before they were checked.
fn persisted_checks() -> Result<bool> {
    let Some(mut client) = harness::persisted()? else { return Ok(false) };
    Ok(check_root(&mut client)? && request_proofs(&mut client, 8)?)
}

fn main() -> Result<()> {
    antithesis_sdk::antithesis_init();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |information| {
        assert_unreachable!(
            "Trie workload or worker thread panicked",
            &json!({"panic": information.to_string()})
        );
        previous_hook(information);
    }));
    let command = std::env::args().nth(1).unwrap_or_default();
    let result = match command.as_str() {
        "first_genesis" => harness::first_genesis(),
        "parallel_driver_writes" => harness::parallel_driver_writes(),
        "parallel_driver_blocks" => harness::parallel_driver_blocks(),
        "parallel_driver_proofs" => parallel_driver_proofs(),
        "anytime_root" => anytime_root(),
        "eventually_persisted" => persisted_checks().map(drop),
        "finally_recovered" => harness::finally(persisted_checks),
        other => Err(eyre!("unknown command {other:?}")),
    };
    assert_always_or_unreachable!(
        result.is_ok(),
        "Trie workload completes without errors",
        &json!({
            "command": command,
            "error": result.as_ref().err().map(|error| format!("{error:#}"))
        })
    );
    result
}
