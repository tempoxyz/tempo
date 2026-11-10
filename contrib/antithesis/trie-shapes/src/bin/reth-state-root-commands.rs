//! The reth-state-root test template's commands (`test/v1/reth_state_root`). Each asks the `serve`
//! process of reth-state-root-antithesis over the harness socket. Built without coverage
//! instrumentation (see contrib/antithesis/reth-state-root/Dockerfile), so only the server reports
//! coverage and has its threads paused.

use antithesis_sdk::{assert_always_or_unreachable, assert_unreachable};
use antithesis_trie_shapes::harness::{self, Client, Request, Response};
use eyre::{bail, eyre, Result};
use serde_json::json;

/// anytime_root: the root the overlay serves at the tip equals the model's.
fn anytime_root() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return harness::unavailable() };
    match client.call(&Request::CheckRoot)? {
        None => harness::unavailable(),
        Some(Response::Root { number, root }) => {
            println!("{}", json!({"root": {"number": number, "root": root}}));
            Ok(())
        }
        Some(other) => bail!("unexpected answer to check_root: {other:?}"),
    }
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
        "anytime_root" => anytime_root(),
        "eventually_persisted" => harness::persisted().map(drop),
        "finally_recovered" => harness::finally(|| Ok(harness::persisted()?.is_some())),
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
