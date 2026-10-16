//! Prints a per-span timing tree for one proof (stderr).

#[path = "../tests/common/mod.rs"]
mod fixtures;

use std::time::Instant;

use fixtures::*;
use tip_1136_bitz::{
    Authorizer,
    policy::{Profile, Witness},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();
    let approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let profile = match std::env::args().nth(1).as_deref() {
        Some("split") => Profile::Split,
        _ => Profile::Mixed,
    };
    let witness = Witness::new(profile, &policy(), &approvals, &digest())?;
    let mut authorizer = Authorizer::new(profile)?;
    let t = Instant::now();
    let proof = authorizer.prove(statement(), &witness)?;
    eprintln!("PROVE {:?}", t.elapsed());
    let t = Instant::now();
    authorizer.verify(statement(), &proof)?;
    eprintln!("VERIFY {:?}", t.elapsed());
    Ok(())
}
