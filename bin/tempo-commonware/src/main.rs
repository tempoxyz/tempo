//! A Tempo node.
//!
//! Run with argument `--help` to see a list of options.
use tempo_commonware_node::cli;

fn main() {
    tempo_eyre::install()
        .expect("must install the eyre error hook before constructing any eyre reports");
    if let Err(err) = cli::run() {
        eprintln!("node failed with error\n{err:?}");
    }
}
