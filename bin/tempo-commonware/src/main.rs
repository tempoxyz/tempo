//! A Tempo node.
//!
//! Run with argument `--help` to see a list of options.
use tempo_commonware_node::cli;

fn main() {
    // XXX: ensures that the error source chain is preserved in
    // tracing-instrument generated error events. That is, this hook ensures
    // that functions instrumented like `#[instrument(err)]` will emit an event
    // that contains the entire error source chain.
    //
    // TODO: Can remove this if https://github.com/tokio-rs/tracing/issues/2648
    // ever gets addressed.
    tempo_eyre::install()
        .expect("must install the eyre error hook before constructing any eyre reports");
    if let Err(err) = cli::run() {
        eprintln!("node failed with error\n{err:?}");
    }
}
