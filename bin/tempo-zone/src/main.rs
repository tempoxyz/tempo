//! Tempo Zone L2 Node.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod defaults;

use zone_node::cli::ZoneCli;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() {
    reth_cli_util::sigsegv_handler::install();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    zone_node::init_version_metadata();
    defaults::init_defaults();

    if let Err(err) = ZoneCli::parse().run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
